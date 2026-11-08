"""The verdict side: the stage 1 artifact as data, and the check conclusion.

The artifact is produced by `prgate stage1` in a job with no secrets and read by the verdict
job, which holds the App token. It is validated field by field: anything missing, malformed or
for another commit sends the PR to a person. It never carries diff line content.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .commands import Command
from .config import Config
from .decide import decide
from .github import valid_sha
from .models import CheckResult, Evidence, FileChange, Finding, Outcome, RunStatus, Severity, Verdict

ARTIFACT_VERSION = 1
MAX_ARTIFACT = 50 * 1024 * 1024
_STATUSES = frozenset("ACDMRTUX")
_TOP = {"version", "base_sha", "head_sha", "diff_base", "diff_ok", "changes", "checks"}
_CHANGE = {"path", "old_path", "status", "removed_count", "binary"}
_CHECK = {"name", "status", "detail", "findings"}
_FINDING = {"check", "severity", "message", "path", "line", "question"}


class ArtifactError(ValueError):
    """The stage 1 artifact is missing a field, has a wrong type, or is not JSON."""


@dataclass(frozen=True)
class Stage1:
    base_sha: str
    head_sha: str
    diff_base: str | None
    diff_ok: bool
    changes: tuple[FileChange, ...]
    checks: tuple[CheckResult, ...]


def conclusion(verdict: Verdict, granted: Command | None, mode: str) -> str:
    """Report-only: the check never passes or fails a merge, whatever the verdict or mode."""
    return "neutral"


def dump_stage1(base_sha: str, head_sha: str, diff_base: str | None, changes: tuple[FileChange, ...],
                checks: tuple[CheckResult, ...], diff_ok: bool) -> str:
    """ASCII JSON. ensure_ascii escapes lone surrogates in paths, so writing never fails."""
    data = {
        "version": ARTIFACT_VERSION, "base_sha": base_sha, "head_sha": head_sha, "diff_base": diff_base,
        "diff_ok": diff_ok,
        "changes": [{"path": c.path, "old_path": c.old_path, "status": c.status,
                     "removed_count": c.removed_count, "binary": c.binary} for c in changes],
        "checks": [{"name": c.name, "status": c.status.value, "detail": c.detail,
                    "findings": [{"check": f.check, "severity": f.severity.value, "message": f.message,
                                  "path": f.path, "line": f.line, "question": f.question}
                                 for f in c.findings]} for c in checks],
    }
    return json.dumps(data, ensure_ascii=True, separators=(",", ":"))


def _need(cond: bool, what: str) -> None:
    if not cond:
        raise ArtifactError(what)


def _obj(d: object, keys: set[str], what: str) -> dict:
    _need(isinstance(d, dict) and set(d) == keys, f"{what} has the wrong fields")
    return d  # type: ignore[return-value]


def _str(v: object, what: str, *, optional: bool = False) -> str | None:
    _need(isinstance(v, str) or (optional and v is None), f"{what} must be a string")
    return v  # type: ignore[return-value]


def _int(v: object, what: str, *, optional: bool = False) -> int | None:
    _need((type(v) is int and v >= 0) or (optional and v is None), f"{what} must be a non-negative integer")
    return v  # type: ignore[return-value]


def _finding(d: object) -> Finding:
    f = _obj(d, _FINDING, "a finding")
    _need(f["severity"] in Severity._value2member_map_, "a finding has an unknown severity")
    return Finding(_str(f["check"], "finding check"), Severity(f["severity"]), _str(f["message"], "message"),
                   _str(f["path"], "finding path", optional=True), _int(f["line"], "line", optional=True),
                   _str(f["question"], "question", optional=True))


def _check(d: object) -> CheckResult:
    c = _obj(d, _CHECK, "a check")
    _need(c["status"] in RunStatus._value2member_map_, "a check has an unknown status")
    _need(isinstance(c["findings"], list), "check findings must be a list")
    return CheckResult(_str(c["name"], "check name"), RunStatus(c["status"]),
                       tuple(_finding(f) for f in c["findings"]), _str(c["detail"], "check detail"))


def _change(d: object) -> FileChange:
    c = _obj(d, _CHANGE, "a change")
    _need(c["status"] in _STATUSES, "a change has an unknown status")
    _need(type(c["binary"]) is bool, "binary must be true or false")
    return FileChange(_str(c["path"], "path"), _str(c["old_path"], "old path", optional=True), c["status"], (),
                      _int(c["removed_count"], "removed count"), c["binary"])


def load_stage1(raw: bytes) -> Stage1:
    _need(isinstance(raw, bytes) and len(raw) <= MAX_ARTIFACT, "artifact is not bytes or is too large")
    try:
        d = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise ArtifactError(f"artifact is not JSON ({type(e).__name__})") from None
    top = _obj(d, _TOP, "the artifact")
    _need(type(top["version"]) is int and top["version"] == ARTIFACT_VERSION, "unknown artifact version")
    _need(valid_sha(top["base_sha"]) and valid_sha(top["head_sha"]), "artifact SHAs must be full SHAs")
    _need(type(top["diff_ok"]) is bool, "diff_ok must be true or false")
    _need(valid_sha(top["diff_base"]) or (top["diff_base"] is None and not top["diff_ok"]),
          "diff base must be a full SHA")
    _need(isinstance(top["changes"], list) and isinstance(top["checks"], list), "changes and checks must be lists")
    try:
        changes = tuple(_change(c) for c in top["changes"])
        checks = tuple(_check(c) for c in top["checks"])
    except (TypeError, KeyError) as e:
        raise ArtifactError(f"artifact is wrongly shaped ({type(e).__name__})") from None
    return Stage1(top["base_sha"], top["head_sha"], top["diff_base"], top["diff_ok"], changes, checks)


def person_verdict(head_sha: str, reason: str) -> Verdict:
    return Verdict(Outcome.PERSON, head_sha, (reason,), f"Please review this pull request: {reason}.", (), False)


def build_verdict(raw: bytes | None, base_sha: str, head_sha: str,
                  config: Config) -> tuple[Verdict, tuple[CheckResult, ...]]:
    """The verdict for the event's head SHA. `base_sha` and `head_sha` come from the event, not the artifact."""
    if raw is None:
        return person_verdict(head_sha, "stage 1 results are missing, so nothing was checked"), ()
    try:
        a = load_stage1(raw)
    except ArtifactError as e:
        return person_verdict(head_sha, f"stage 1 results are malformed ({e}), so they cannot be used"), ()
    if a.head_sha != head_sha or a.base_sha != base_sha:
        return person_verdict(head_sha, "stage 1 results are for a different commit than this event"), ()
    if not a.diff_ok or a.diff_base is None:
        return person_verdict(head_sha, "the diff could not be read"), a.checks
    evidence = Evidence(a.diff_base, head_sha, a.changes, a.checks, ci_passed=None, has_llm=False, additive=None)
    try:
        return decide(evidence, config), a.checks
    except Exception as e:  # the decision must never take the report down
        return person_verdict(head_sha, f"the decision could not be made ({type(e).__name__})"), a.checks
