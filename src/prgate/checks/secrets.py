"""Secret scan over added lines. A finding names the path, line and kind, never the value."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..models import CheckResult, FileChange, Finding, RunStatus, Severity

CHECK = "secrets"

# Values published in vendor documentation. They are not credentials. Any AWS key ID that ends
# in EXAMPLE, as all of AWS's documented ones do, is treated the same way.
KNOWN_EXAMPLES = frozenset({"AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"})
_AWS = "AWS access key ID"
_KEY = "private key"

_TEST_DIRS = {"tests", "test", "testdata", "fixtures", "examples"}
_SEQUENCE = "0123456789abcdefghijklmnopqrstuvwxyz"


@dataclass(frozen=True)
class _Format:
    kind: str
    pattern: re.Pattern[str]
    # ghp_ tokens carry a CRC32 checksum, but its exact encoding cannot be confirmed here,
    # so a ghp_ match is only ever a suspicion.
    proof: bool = True


def _fmt(kind: str, regex: str, proof: bool = True) -> _Format:
    return _Format(kind, re.compile(regex), proof)


_B = r"(?<![A-Za-z0-9_-])"  # token boundaries, so an over-long run fails the length rule
_E = r"(?![A-Za-z0-9_-])"
_KEY_HEADER_RE = r"-----BEGIN (?P<label>(?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?)-----"
_KEY_HEADER_ANYWHERE = re.compile(f"(?=({_KEY_HEADER_RE}))")  # overlapping matches too
_FORMATS = (
    _fmt(_AWS, _B + r"AKIA(?P<tok>[0-9A-Z]{16})" + _E),
    _fmt("GitHub personal access token", _B + r"ghp_(?P<tok>[A-Za-z0-9]{36})" + _E, proof=False),
    _fmt("Stripe live secret key", _B + r"sk_live_(?P<tok>[A-Za-z0-9]{24,99})" + _E),
    _fmt("Slack bot token", _B + r"xoxb-[0-9]{10,13}-[0-9]{10,13}-(?P<tok>[A-Za-z0-9]{24})" + _E),
    _fmt(_KEY, _KEY_HEADER_RE),
    _fmt("Google API key", _B + r"AIza(?P<tok>[0-9A-Za-z_-]{35})" + _E),
    _fmt("Anthropic API key", _B + r"sk-ant-(?:[a-z0-9]+-)?(?P<tok>[A-Za-z0-9_-]{32,})" + _E),
)


def _trivial(token: str) -> bool:
    """One repeated character, or a run such as 0123... / abcd... (either direction)."""
    letters = re.sub(r"[^A-Za-z0-9]", "", token).lower()
    return (len(set(letters)) <= 1 or letters in _SEQUENCE or letters in _SEQUENCE[::-1]
            or len(set(token)) <= 1)


def _in_fixture_dir(path: str) -> bool:
    return bool(_TEST_DIRS & set(path.lower().split("/")[:-1]))


def _matches(line: str) -> Iterable[tuple[_Format, str]]:
    for fmt in _FORMATS:
        # Key headers can share dashes with a decoy before them, so they are found overlapping,
        # and each label is reported once per line so overlaps do not repeat a finding.
        pattern = _KEY_HEADER_ANYWHERE if fmt.kind == _KEY else fmt.pattern
        seen_labels: set[str] = set()
        for m in pattern.finditer(line):
            value = m.group(1) if fmt.kind == _KEY else m.group(0)
            if fmt.kind == _KEY:
                if value in seen_labels:
                    continue
                seen_labels.add(value)
            if value in KNOWN_EXAMPLES or (fmt.kind == _AWS and value.endswith("EXAMPLE")):
                continue
            token = m.groupdict().get("tok")
            if token is not None and _trivial(token):
                continue
            yield fmt, value


def _lines(change: FileChange, read_blob: Callable[[str], bytes] | None) -> Iterable[tuple[int, str]]:
    """Lines to scan. A file git calls binary has no usable added lines (and a PR can mark any
    file binary with .gitattributes), so its whole head blob is scanned. A blob that cannot be
    read raises, which makes the check COULD_NOT_RUN instead of skipping the file."""
    if not change.binary:
        return change.added
    if read_blob is None:
        raise ValueError("a binary file cannot be scanned without reading its blob")
    blob = read_blob(change.path).decode("latin-1")
    return enumerate(blob.split("\n"), 1)


# A line that looks like PEM key body: base64 only. The last body line of a real key is short,
# so only the first one is judged, and a short threshold keeps this failing closed.
_BODY = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_PEM_HEADER_FIELD = re.compile(r"[A-Za-z-]+: ")  # Proc-Type:, DEK-Info: in an encrypted key
_WRAPPING = " \t\r'\",+;\\()"  # quotes and joins around a key pasted into source code


def _segments(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Each line, also split at a literal backslash-n, with code wrapping stripped from the ends."""
    out = []
    for number, line in lines:
        for part in line.split("\\n"):
            out.append((number, part.strip(_WRAPPING)))
    return out


class _KeyBodies:
    """Answers "is this header followed by a key body?" for one file in linear time overall.

    A header alone, or one followed by something other than base64 (a name in a key parser, a
    sentence in documentation), is not a key. A header followed by a body is, END line or not.
    Every occurrence is checked, so a decoy header earlier on the line cannot hide a real key.
    """

    def __init__(self, segments: list[tuple[int, str]]):
        # One reverse pass: below[i] is whether the first real content after segment i is a body.
        below = [False] * len(segments)
        follows = False
        for i in range(len(segments) - 1, -1, -1):
            below[i] = follows
            text = segments[i][1]
            if text and not _PEM_HEADER_FIELD.match(text):
                follows = bool(_BODY.fullmatch(text))
        # One forward pass: every header occurrence of every label, each judged once. A decoy can
        # share its dashes with the real header ("...KEY-----BEGIN RSA..."), so overlapping
        # occurrences are judged too, whatever their label.
        self._answers: dict[tuple[int, str], bool] = {}
        for i, (number, text) in enumerate(segments):
            end = len(text.rstrip(_WRAPPING))
            for m in _KEY_HEADER_ANYWHERE.finditer(text):
                key = (number, m.group("label"))
                if self._answers.get(key):
                    continue
                start = m.end(1)
                while start < end and text[start] in _WRAPPING:
                    start += 1
                if start >= end or _PEM_HEADER_FIELD.match(text, start):
                    found = below[i]  # the rest of the line is empty: look below it
                else:
                    found = bool(_BODY.fullmatch(text, start, end))
                self._answers[key] = found

    def has_body(self, number: int, label: str) -> bool:
        return self._answers.get((number, label), False)


def scan(changes: Iterable[FileChange], read_blob: Callable[[str], bytes] | None = None) -> CheckResult:
    findings: list[Finding] = []
    for change in changes:
        if change.status == "D":
            continue
        fixture = _in_fixture_dir(change.path)
        lines = list(_lines(change, read_blob))
        bodies: _KeyBodies | None = None
        for number, line in lines:
            for fmt, value in _matches(line):
                proof = fmt.proof
                if proof and fmt.kind == _KEY:
                    bodies = _KeyBodies(_segments(lines)) if bodies is None else bodies
                    label = value[len("-----BEGIN "):-len("-----")]
                    proof = bodies.has_body(number, label)
                if proof and not fixture:
                    findings.append(Finding(CHECK, Severity.PROOF, f"{fmt.kind} in an added line",
                                            change.path, number))
                else:
                    findings.append(Finding(
                        CHECK, Severity.SUSPICION, f"possible {fmt.kind} in an added line",
                        change.path, number,
                        question=f"Is the {fmt.kind} on line {number} a real credential?"))
    return CheckResult(CHECK, RunStatus.RAN, tuple(findings))
