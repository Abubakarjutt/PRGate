"""The gate files `prgate init` writes, how they reach the default branch, and the workflow-safety rule."""
from __future__ import annotations

import base64
import binascii
import difflib
import re
from collections.abc import Callable
from dataclasses import dataclass
from importlib import resources
from typing import Any, Literal, NamedTuple
from urllib.parse import quote

from prgate.config import CONFIG_PATH, parse_config
from prgate.setup.gh import Gh, GhError
from prgate.setup.preflight import RepoInfo
from prgate.setup.store import ENV_VERDICT, SetupAborted
from prgate.setup.ui import Prompter

INIT_HEADER = "# Written by prgate init. Edit freely; re-running init will ask before replacing."
CONFIG_FILE = CONFIG_PATH
WORKFLOWS_DIR = ".github/workflows"
WORKFLOW_NAME = "pr-gate.yml"
WORKFLOW_FILE = f"{WORKFLOWS_DIR}/{WORKFLOW_NAME}"
GATE_FILES = (CONFIG_FILE, WORKFLOW_FILE)
SETUP_BRANCH = "prgate-setup"
ACTION_REF_TOKEN = "__PRGATE_ACTION_REF__"

_ACTION_REF = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+@[A-Za-z0-9._/-]+")
_INDEX_URL = re.compile(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~%/-]*)?")
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_PROTECTION = re.compile(r"protect|rule violation|ruleset|repository rule", re.IGNORECASE)
_EMPTY_REPO = "the repository has no commits yet; push an initial commit first, then re-run prgate init"
_FOREIGN_BRANCH = f"Replace branch {SETUP_BRANCH}? It has commits prgate did not make."
_SQUASH = re.compile(r"[\s\"'\\]")
_EMPTY_OR_MISSING = ("the repository has no commits yet (or its default branch is missing); push an initial commit "
                     "first, then re-run prgate init")
# Every regex below is anchored per line and has no nested or adjacent overlapping unbounded quantifiers.
_ENV_KEY = re.compile(r"([ \t-]*)environment[ \t]*:(.*)")
_USES_KEY = re.compile(r"[ \t-]*uses[ \t]*:[ \t]*[\"']?([^\s\"'#]*)")
_HEX_ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))")
_SIMPLE_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f",
                   "r": "\r", "e": "\x1b", " ": " ", "/": "/", '"': '"', "\\": "\\", "N": "\x85", "_": "\xa0",
                   "L": "\u2028", "P": "\u2029"}
_HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}
_HEX = frozenset("0123456789abcdefABCDEF")
_LISTING_CAP = 1000  # the contents API returns at most 1000 entries for a directory
_COMMIT_MESSAGE = "Set up prgate (experimental, report-only PR gate)"
_PR_BODY = ("This adds the files `prgate init` writes: `.prgate.toml` and `.github/workflows/pr-gate.yml`.\n\n"
            "prgate is experimental and report-only: its `pr-gate` check always concludes `neutral` and never "
            "blocks a merge. Merge this PR, then re-run `prgate init` to finish setup.\n")


@dataclass(frozen=True)
class SetupAnswers:
    language: str | None
    ci_checks: tuple[str, ...]
    approvers: tuple[str, ...]


class WorkflowSafety(NamedTuple):
    """The workflow-safety verdict. `warnings` name files worth a look; they never make `ok` False."""
    ok: bool
    reason: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class Publish:
    kind: Literal["unchanged", "committed", "pr"]
    url: str | None


# --- rendering ------------------------------------------------------------------------------------

def _toml_str(s: object) -> str:
    if not isinstance(s, str):
        raise ValueError("config values must be strings")
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("config values must be valid Unicode text") from None
    out = []
    for ch in s:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _toml_list(items: tuple[str, ...]) -> str:
    return "[" + ", ".join(_toml_str(i) for i in items) + "]"


def render_config(a: SetupAnswers) -> str:
    """`.prgate.toml` for these answers. Always silent; docs-only PRs may clear. Checked to load as valid."""
    lines = [
        INIT_HEADER,
        "# prgate is experimental and report-only: the pr-gate check always concludes neutral.",
        'mode = "silent"',
        "clear_docs = true",
        f"approvers = {_toml_list(tuple(a.approvers))}",
        f"ci_checks = {_toml_list(tuple(a.ci_checks))}",
    ]
    if a.language is not None:
        lines.append(f"language = {_toml_str(a.language)}")
    text = "\n".join(lines) + "\n"
    if not parse_config(text.encode("utf-8")).valid:
        raise ValueError("the rendered .prgate.toml would not be a valid config")
    return text


def render_workflow(action_ref: str, index_url: str | None = None) -> str:
    """The gate workflow with both `uses:` of the prgate action set to `action_ref` (owner/repo@ref).

    `index_url` (development only) becomes the action's `index-url` input on both steps; None keeps its default."""
    if not isinstance(action_ref, str) or not _ACTION_REF.fullmatch(action_ref):
        raise ValueError("action ref must look like owner/repo@ref")
    if index_url is not None and not (isinstance(index_url, str) and _INDEX_URL.fullmatch(index_url)):
        raise ValueError("index URL must be a plain https URL")
    template = resources.files("prgate.templates").joinpath("pr-gate.yml").read_text(encoding="utf-8")
    text = template.replace(ACTION_REF_TOKEN, action_ref)
    if "__PRGATE_" in text:
        raise ValueError("the workflow template has a token render_workflow does not fill")
    if index_url is not None:
        step = f"uses: {action_ref}\n        with:\n"
        if text.count(step) != 2:
            raise ValueError("the workflow template's prgate steps are not laid out as render_workflow expects")
        text = text.replace(step, f"{step}          index-url: {index_url}\n")
    return INIT_HEADER + "\n" + text


# --- reading the default branch -------------------------------------------------------------------

class _Undecodable(Exception):
    pass


def _contents_path(info: RepoInfo, path: str) -> str:
    return f"repos/{info.full_name}/contents/{quote(path, safe='/')}?ref={quote(info.default_branch, safe='')}"


def _decode(data: Any) -> str:
    if not isinstance(data, dict) or data.get("type") != "file" or data.get("encoding") != "base64" \
            or not isinstance(data.get("content"), str):
        raise _Undecodable("GitHub did not return it as a base64 file (too large, or not a regular file)")
    try:
        raw = base64.b64decode("".join(data["content"].split()), validate=True)
    except (binascii.Error, ValueError):
        raise _Undecodable("its content is not valid base64") from None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _Undecodable("it is not UTF-8 text") from None


def _read_existing(gh: Gh, info: RepoInfo, path: str) -> tuple[bool, str | None]:
    """(exists, text). text is None when the file exists but cannot be read as text. Other errors raise."""
    try:
        data = gh.api("GET", _contents_path(info, path))
    except GhError as e:
        if e.status == 404:
            return False, None
        raise
    try:
        return True, _decode(data)
    except _Undecodable:
        return True, None


def read_default(gh: Gh, info: RepoInfo, path: str) -> tuple[bool, str | None]:
    """(exists, text) of `path` on the default branch; text is None when it cannot be read as text."""
    return _read_existing(gh, info, path)


def files_on_default(gh: Gh, info: RepoInfo, files: dict[str, str]) -> bool:
    """True when every file in `files` is on the default branch exactly as given. Read-only."""
    return all(read_default(gh, info, path) == (True, text) for path, text in files.items())


# --- publishing -----------------------------------------------------------------------------------

def _check_files(files: object) -> dict[str, str]:
    if not isinstance(files, dict) or not files:
        raise ValueError("publish_files needs at least one gate file")
    for path, text in files.items():
        if path not in GATE_FILES:
            raise ValueError(f"prgate init only writes {' and '.join(GATE_FILES)}, not {path!r}")
        if not isinstance(text, str):
            raise ValueError(f"the content for {path} must be text")
    return dict(files)


def _sha(data: Any, *keys: str) -> str:
    v = data
    for k in keys:
        v = v.get(k) if isinstance(v, dict) else None
    if not isinstance(v, str) or not _SHA.fullmatch(v):
        raise GhError(None, f"GitHub returned an unexpected reply (no {'.'.join(keys)})")
    return v


def _is_protection(e: GhError) -> bool:
    return e.status in (409, 422) or bool(_PROTECTION.search(e.message or ""))


def _confirm_replace(path: str, old: str | None, new: str, info: RepoInfo, prompter: Prompter) -> None:
    if old is None:
        prompter.say(f"{path} on {info.default_branch} cannot be shown as text.")
    else:
        diff = "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                            fromfile=f"{path} (on {info.default_branch})",
                                            tofile=f"{path} (from prgate init)"))
        prompter.say(f"{path} on {info.default_branch} differs from what prgate init would write. Changes:\n{diff}")
    if not prompter.confirm(f"Replace {path} on {info.default_branch}?", False):
        raise SetupAborted(f"left {path} as it is; prgate init cannot continue without it")


def _pr_url(pr: Any) -> str:
    url = pr.get("html_url") if isinstance(pr, dict) else None
    if not isinstance(url, str) or not url:
        raise GhError(None, "GitHub returned a pull request without a URL")
    return url


def _find_open_pr(gh: Gh, info: RepoInfo) -> str | None:
    head = quote(f"{info.owner}:{SETUP_BRANCH}", safe="")
    prs = gh.api("GET", f"repos/{info.full_name}/pulls?head={head}&base={quote(info.default_branch, safe='')}&state=open")
    if not isinstance(prs, list):
        raise GhError(None, "GitHub returned an unexpected pull request list")
    return _pr_url(prs[0]) if prs else None


def _is_prgate_commit(gh: Gh, info: RepoInfo, data: Any, default_head: str) -> bool:
    """prgate's own commit: our message, one parent, and that parent is the default head or an ancestor of it."""
    if not isinstance(data, dict) or data.get("message") != _COMMIT_MESSAGE:
        return False
    parents = data.get("parents")
    if not isinstance(parents, list) or len(parents) != 1:
        return False
    try:
        parent = _sha(parents[0], "sha")
        # GitHub's compare: status "ahead" or "identical" means base (parent) is an ancestor of head, or equal.
        cmp = gh.api("GET", f"repos/{info.full_name}/compare/{parent}...{default_head}")
    except GhError:
        return False
    return isinstance(cmp, dict) and cmp.get("status") in ("identical", "ahead")


def _point_setup_branch(gh: Gh, info: RepoInfo, commit_sha: str, default_head: str, prompter: Prompter) -> None:
    r = info.full_name
    try:
        current = _sha(gh.api("GET", f"repos/{r}/git/ref/heads/{SETUP_BRANCH}"), "object", "sha")
    except GhError as e:
        if e.status != 404:
            raise
        gh.api("POST", f"repos/{r}/git/refs", {"ref": f"refs/heads/{SETUP_BRANCH}", "sha": commit_sha})
        return
    if not _is_prgate_commit(gh, info, gh.api("GET", f"repos/{r}/git/commits/{current}"), default_head):
        if not prompter.confirm(_FOREIGN_BRANCH, False):
            raise SetupAborted(f"left branch {SETUP_BRANCH} as it is; rename or delete it, then re-run prgate init")
    gh.api("PATCH", f"repos/{r}/git/refs/heads/{SETUP_BRANCH}", {"sha": commit_sha, "force": True})


def _open_pr(gh: Gh, info: RepoInfo, commit_sha: str, default_head: str, prompter: Prompter) -> str:
    _point_setup_branch(gh, info, commit_sha, default_head, prompter)
    existing = _find_open_pr(gh, info)
    if existing:
        return existing
    try:
        pr = gh.api("POST", f"repos/{info.full_name}/pulls", {"title": _COMMIT_MESSAGE, "head": SETUP_BRANCH,
                                                               "base": info.default_branch, "body": _PR_BODY})
    except GhError as e:
        if e.status != 422:
            raise
        existing = _find_open_pr(gh, info)  # 422: one already exists (opened concurrently)
        if not existing:
            raise
        return existing
    return _pr_url(pr)


def publish_files(gh: Gh, info: RepoInfo, files: dict[str, str], prompter: Prompter) -> Publish:
    """Put the gate files on the default branch in one commit, or in a PR when the branch is protected."""
    files = _check_files(files)
    changed: dict[str, str] = {}
    for path in GATE_FILES:
        if path not in files:
            continue
        new = files[path]
        exists, old = _read_existing(gh, info, path)
        if exists and old is not None and _drop_one_newline(old) == _drop_one_newline(new):
            continue
        if exists:  # content differs (identical was skipped above): always ask, whoever wrote it
            _confirm_replace(path, old, new, info, prompter)
        changed[path] = new
    if not changed:
        return Publish("unchanged", None)

    r = info.full_name
    branch = quote(info.default_branch, safe="/")
    try:
        ref = gh.api("GET", f"repos/{r}/git/ref/heads/{branch}")
    except GhError as e:
        if e.status not in (404, 409):
            raise
        empty_status = e.status
    else:
        empty_status = None
    if empty_status is not None:
        raise SetupAborted(_EMPTY_REPO if empty_status == 409 else _EMPTY_OR_MISSING)
    base = _sha(ref, "object", "sha")
    base_tree = _sha(gh.api("GET", f"repos/{r}/git/commits/{base}"), "tree", "sha")
    entries = []
    for path, text in changed.items():
        blob = _sha(gh.api("POST", f"repos/{r}/git/blobs", {"content": text, "encoding": "utf-8"}), "sha")
        entries.append({"path": path, "mode": "100644", "type": "blob", "sha": blob})
    tree = _sha(gh.api("POST", f"repos/{r}/git/trees", {"base_tree": base_tree, "tree": entries}), "sha")
    commit = gh.api("POST", f"repos/{r}/git/commits", {"message": _COMMIT_MESSAGE, "tree": tree, "parents": [base]})
    commit_sha = _sha(commit, "sha")
    try:
        gh.api("PATCH", f"repos/{r}/git/refs/heads/{branch}", {"sha": commit_sha, "force": False})
    except GhError as e:
        if not _is_protection(e):
            raise
        return Publish("pr", _open_pr(gh, info, commit_sha, base, prompter))
    url = commit.get("html_url") if isinstance(commit, dict) else None
    return Publish("committed", url if isinstance(url, str) else None)


# --- the workflow-safety rule ---------------------------------------------------------------------

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _decode_hex_escape(m: re.Match[str]) -> str:
    code = int(m[1] or m[2] or m[3], 16)
    return m[0] if code > 0x10FFFF else chr(code)


def _decode_escapes_anywhere(text: str) -> str:
    """Every \\xNN, \\uNNNN and \\UNNNNNNNN in `text` decoded, whatever its YAML context; invalid ones stay.

    For the refusal only: decoding too much can only add refusals, never hide a `prgate-verdict`."""
    return _HEX_ESCAPE.sub(_decode_hex_escape, text)


def _squashed(text: str) -> str:
    return _SQUASH.sub("", text.lower())


def _decode_yaml_scalars(text: str) -> str:
    """Best-effort YAML scalar decoding for the warnings. Linear time; never raises.

    A quote opens a scalar only where a node starts: at the start of a line, after `key:` or `-` or `?` and
    whitespace, or after `[` `{` `,` inside a flow collection. `!tag` and `&anchor` tokens are transparent
    there. Block scalar (`|`, `>`) contents are passed through raw. Double-quoted escapes are decoded (an
    escape YAML does not define is kept as written) and an escaped line break drops the next line's indent."""
    out: list[str] = []
    mode = "plain"  # plain, dq, sq
    block_parent: int | None = None
    flow = 0
    join_next = False  # an escaped line break: drop the next line's leading whitespace
    for line in text.split("\n"):
        if mode == "plain" and block_parent is not None:
            if not line.strip() or _indent(line) > block_parent:
                out.append(line + "\n")
                continue
            block_parent = None
        i, n = 0, len(line)
        if join_next:
            i = _indent(line)
            join_next = False
        at_start = mode == "plain"  # the next non-blank character begins a node
        indicator = False  # the last character was `:` `-` `?` that becomes an indicator if whitespace follows
        in_token = False   # inside a !tag or &anchor
        block_cand = False
        while i < n:
            c = line[i]
            if mode == "dq":
                i += 1
                if c == '"':
                    mode, at_start = "plain", False
                elif c != "\\":
                    out.append(c)
                elif i >= n:
                    join_next = True
                else:
                    e = line[i]
                    width = _HEX_ESCAPES.get(e)
                    digits = line[i + 1: i + 1 + width] if width else ""
                    if e in _SIMPLE_ESCAPES:
                        out.append(_SIMPLE_ESCAPES[e])
                        i += 1
                    elif width and len(digits) == width and set(digits) <= _HEX and int(digits, 16) <= 0x10FFFF:
                        out.append(chr(int(digits, 16)))
                        i += 1 + width
                    else:
                        out.append("\\")
                continue
            if mode == "sq":
                i += 1
                if c != "'":
                    out.append(c)
                elif i < n and line[i] == "'":
                    out.append("'")
                    i += 1
                else:
                    mode, at_start = "plain", False
                continue
            # plain
            if c in " \t":
                if indicator or in_token:
                    at_start = True
                indicator = in_token = False
                out.append(c)
                i += 1
                continue
            if c == "#" and (i == 0 or line[i - 1] in " \t"):
                out.append(line[i:])
                break
            if in_token and not (flow and c in ",]}"):
                out.append(c)
                i += 1
                continue
            in_token = False
            if block_cand and c not in "0123456789+-":
                block_cand = False
            if at_start:
                at_start = indicator = False
                if c in "\"'":
                    mode = "dq" if c == '"' else "sq"
                    i += 1
                    continue
                if c in "!&":
                    in_token = True
                elif c in "[{":
                    flow += 1
                    at_start = True
                elif c in "-?":
                    indicator = True
                elif c in "|>" and not flow:
                    block_cand = True
            elif c == ":":
                indicator = True
            elif flow and c == ",":
                at_start = True
            elif flow and c in "]}":
                flow -= 1
            else:
                indicator = False
            out.append(c)
            i += 1
        if join_next:
            continue
        out.append("\n" if mode == "plain" else " ")
        if mode == "plain" and block_cand:
            block_parent = _indent(line)
    return "".join(out)


def _dynamic_environment(text: str) -> bool:
    """True if an `environment:` key has `${{` in its inline value or in a line of its block. Linear time."""
    lines = text.split("\n")
    i, n = 0, len(lines)
    while i < n:
        m = _ENV_KEY.match(lines[i])
        i += 1
        if not m:
            continue
        if "${{" in m[2]:
            return True
        parent = len(m[1])
        while i < n:
            child = lines[i]
            if child.strip() and _indent(child) <= parent:
                break  # the block ended; the outer loop looks at this line again
            if "${{" in child:
                return True
            i += 1
    return False


def _external_reusable(text: str) -> bool:
    for line in text.split("\n"):
        m = _USES_KEY.match(line)
        if m and "/.github/workflows/" in m[1] and not m[1].startswith("./"):
            return True
    return False

def _show(name: str) -> str:
    return name if name.isprintable() else repr(name)


def _drop_one_newline(s: str) -> str:
    return s[:-1] if s.endswith("\n") else s


_RELEASE_REF = re.compile(r"(?P<repo>[A-Za-z0-9-]+/[A-Za-z0-9._-]+)@v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)")
_USES_PIN = re.compile(r"^\s*uses:\s*(?P<ref>\S+)\s*$", re.MULTILINE)
OlderRelease = Callable[[str], tuple[str, str] | None]


def older_release(action_ref: str, index_url: str | None = None) -> OlderRelease:
    """For doctor: a workflow pinned to an older release of the same action is out of date, not unsafe.

    The returned function takes the default branch's `pr-gate.yml` and, when it pins one older
    `owner/repo@vX.Y.Z` of `action_ref`'s repository, returns the workflow that release's ref
    renders and an "update available" warning. Anything else returns None.
    """
    current = _RELEASE_REF.fullmatch(action_ref)

    def check(text: str) -> tuple[str, str] | None:
        if current is None:
            return None
        pins = {m["ref"] for m in _USES_PIN.finditer(text) if _RELEASE_REF.fullmatch(m["ref"])}
        if len(pins) != 1:
            return None
        pin = _RELEASE_REF.fullmatch(pins.pop())
        assert pin is not None
        version = tuple(int(x) for x in pin["version"].split("."))
        if pin["repo"] != current["repo"] or version >= tuple(int(x) for x in current["version"].split(".")):
            return None
        return (render_workflow(pin.group(0), index_url=index_url),
                f"{WORKFLOW_FILE} is pinned to v{pin['version']}; v{current['version']} is available. "
                f"Re-run prgate init to upgrade")
    return check


def workflow_safe(gh: Gh, info: RepoInfo, expected_workflow: str,
                  older: OlderRelease | None = None) -> WorkflowSafety:
    """The workflow-safety rule, read from the default branch through the contents API. Fails closed on anything unexpected.

    `pr-gate.yml` must equal `expected_workflow` (one trailing newline is ignored), and no other file in
    `.github/workflows/` may contain `prgate-verdict` once lowercased with quotes, backslashes and all whitespace
    removed, checked on the raw text and on the text with every \\x, \\u and \\U escape decoded regardless of
    context. A best-effort YAML scan adds warnings (dynamic `environment:`, external reusable workflow); it
    never refuses and never rescues a refusal."""
    branch = info.default_branch
    warnings: list[str] = []
    try:
        listing = gh.api("GET", _contents_path(info, WORKFLOWS_DIR))
    except GhError as e:
        if e.status == 404:
            return WorkflowSafety(False, f"{WORKFLOW_FILE} is missing on {branch} "
                                         f"(there is no {WORKFLOWS_DIR} directory)")
        return WorkflowSafety(False, f"could not list {WORKFLOWS_DIR} on {branch}: {e.message}")
    except Exception as e:  # noqa: BLE001  fail closed
        return WorkflowSafety(False, f"could not list {WORKFLOWS_DIR} on {branch} ({type(e).__name__})")
    if not isinstance(listing, list):
        return WorkflowSafety(False, f"{WORKFLOWS_DIR} on {branch} is not a directory listing")
    if len(listing) >= _LISTING_CAP:
        return WorkflowSafety(False, f"{WORKFLOWS_DIR} on {branch} has {_LISTING_CAP} or more entries, the most the "
                                     "contents API lists, so prgate cannot be sure it saw every workflow")
    entries: list[tuple[str, str]] = []
    for item in listing:
        name = item.get("name") if isinstance(item, dict) else None
        kind = item.get("type") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name or "/" in name or name in (".", "..") or not isinstance(kind, str):
            return WorkflowSafety(False, f"{WORKFLOWS_DIR} on {branch} lists an entry prgate cannot read")
        entries.append((name, kind))
    if not any(name == WORKFLOW_NAME and kind != "dir" for name, kind in entries):
        return WorkflowSafety(False, f"{WORKFLOW_FILE} is missing on {branch}")

    for name, kind in sorted(entries):
        if kind == "dir":
            continue  # GitHub Actions only runs workflow files directly in .github/workflows
        path = f"{WORKFLOWS_DIR}/{name}"
        try:
            text = _decode(gh.api("GET", _contents_path(info, path)))
        except GhError as e:
            return WorkflowSafety(False, f"could not read {_show(path)} on {branch}: {e.message}")
        except _Undecodable as e:
            return WorkflowSafety(False, f"could not read {_show(path)} on {branch}: {e}")
        except Exception as e:  # noqa: BLE001  fail closed
            return WorkflowSafety(False, f"could not read {_show(path)} on {branch} ({type(e).__name__})")
        if name == WORKFLOW_NAME:
            if _drop_one_newline(text) != _drop_one_newline(expected_workflow):
                outdated = older(text) if older is not None else None
                if outdated is None or _drop_one_newline(text) != _drop_one_newline(outdated[0]):
                    return WorkflowSafety(False, f"{WORKFLOW_FILE} on {branch} differs from what prgate init "
                                                 "renders (only a single trailing newline is ignored)")
                warnings.append(outdated[1])
        else:
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            if any(ENV_VERDICT in _squashed(t) for t in (text, _decode_escapes_anywhere(text))):
                return WorkflowSafety(False, f"{_show(path)} on {branch} mentions {ENV_VERDICT}; only "
                                             f"{WORKFLOW_FILE} may use the gate's environment")
            decoded = _decode_yaml_scalars(text)  # for the warnings only
            if _dynamic_environment(text) or _dynamic_environment(decoded):
                warnings.append(f"{_show(path)} sets its environment with an expression (${{{{ }}}}); check it can "
                                f"never be {ENV_VERDICT}")
            if _external_reusable(text) or _external_reusable(decoded):
                warnings.append(f"{_show(path)} calls a reusable workflow from another repository; check that "
                                f"workflow never uses {ENV_VERDICT}")
    return WorkflowSafety(True, f"{WORKFLOW_FILE} matches what prgate init renders and no other workflow mentions "
                                f"{ENV_VERDICT}", tuple(warnings))
