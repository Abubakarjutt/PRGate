"""Fact checks: dependencies a PR newly declares, and imports it newly adds.

Only a *newly declared* dependency that PyPI says does not exist is PROOF. A new import that is
not stdlib, local or declared is a SUSPICION whether or not PyPI knows the name, because an
import name need not equal its package name. Imports are never looked up.
Nothing here runs PR code: manifests and sources are read from git objects and parsed.
"""
from __future__ import annotations

import http.client
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from ..classify import classify
from ..diff import git_output
from ..models import ChangeType, CheckResult, FileChange, Finding, RunStatus, Severity
from ..plugins.base import LanguagePlugin
from ..plugins.python_manifests import Manifests, read_manifests

CHECK = "facts"
PYPI_URL = "https://pypi.org/pypi/{}/json"
PYPI_SIMPLE_URL = "https://pypi.org/simple/{}/"
MAX_LOOKUPS = 50
LOOKUP_TIMEOUT = 10.0
YOUNG_DAYS = 30
_MAX_BODY = 20_000_000
_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")  # PEP 508 package name
_REQUIREMENTS = re.compile(r"requirements[A-Za-z0-9._-]*\.txt")
_MANIFESTS = {"pyproject.toml", "setup.cfg", "setup.py"}
_PY_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError, UnicodeDecodeError)

# name, seconds to wait -> (exists, age in days of the first release); None means "could not tell"
Registry = Callable[[str, float], tuple[bool | None, int | None]]


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# --- the registry -------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a normalised name never redirects; refuse to follow
        return None


def _age_days(body: bytes) -> int | None:
    try:
        releases = json.loads(body).get("releases", {})
        stamps = [datetime.fromisoformat(f["upload_time_iso_8601"])
                  for files in releases.values() for f in files]
        return max(0, (datetime.now(timezone.utc) - min(stamps)).days)
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def _get(url: str, agent: str, limit: float, *, want_body: bool) -> tuple[int | None, bytes | None]:
    """GET `url`, finishing before the monotonic time `limit`. (status, body); (None, None) when
    the request failed, timed out or ran over. The body is capped, and only read when wanted."""
    request = urllib.request.Request(url, headers={"User-Agent": agent, "Accept": "application/json"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        left = limit - time.monotonic()
        if left <= 0:
            return None, None
        try:
            response = opener.open(request, timeout=left)
        except urllib.error.HTTPError as e:
            e.close()
            return e.code, None
        with response:
            body = b""
            while want_body:
                if time.monotonic() > limit:
                    return None, None
                chunk = response.read1(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > _MAX_BODY:
                    return response.status, None
            return response.status, body if want_body else None
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
        return None, None  # timeouts and network errors are OSError subclasses


def pypi_registry(name: str, timeout: float) -> tuple[bool | None, int | None]:
    """Ask PyPI whether a package exists, within `timeout` seconds in all.

    Sends the package name and a generic User-Agent only. The JSON API 404s for a project that
    exists but has no releases, so a 404 there is confirmed against the simple index.
    """
    if not _NAME.fullmatch(name):
        return None, None
    try:
        agent = f"prgate/{metadata.version('prgate')}"
    except metadata.PackageNotFoundError:
        agent = "prgate/0"
    limit = time.monotonic() + timeout
    quoted = urllib.parse.quote(name, safe="")
    status, body = _get(PYPI_URL.format(quoted), agent, limit, want_body=True)
    if status == 200:
        return True, (_age_days(body) if body is not None else None)
    if status != 404:
        return None, None  # 429, 5xx, a redirect, a timeout, a network error: unknown
    status, _ = _get(PYPI_SIMPLE_URL.format(quoted), agent, limit, want_body=False)
    return {200: True, 404: False}.get(status), None


# --- judging ------------------------------------------------------------------------------------

def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise subprocess.TimeoutExpired("registry", 0)
    return min(LOOKUP_TIMEOUT, left)


def judge(new_deps: Mapping[str, str | None], new_imports: Iterable[tuple[str, str]],
          registry: Registry, deadline: float, *, can_prove: bool = True,
          own: frozenset[str] = frozenset()) -> CheckResult:
    """Findings for newly declared dependencies (name -> manifest) and undeclared new imports.

    With `can_prove` false a 404 is only a SUSPICION: the set of new dependencies is not certain.
    A 404 on one of the project's `own` names is a SUSPICION too: pip and uv resolve a project's
    own name, with or without extras or a version, to the project itself.
    """
    findings = [Finding(CHECK, Severity.SUSPICION, f"new import of {name} is not declared", path=path,
                        question=f"Which package provides {name}? It isn't declared.")
                for path, name in sorted(set(new_imports))]

    def stopped(status: RunStatus, detail: str) -> CheckResult:
        return CheckResult(CHECK, status, tuple(findings), detail)

    valid = []
    for name in sorted(new_deps):
        if _NAME.fullmatch(name):
            valid.append(name)
        else:
            findings.append(Finding(CHECK, Severity.SUSPICION, "a declared dependency has an invalid name",
                                    path=new_deps[name], question="Is this dependency name a mistake?"))
    if len(valid) > MAX_LOOKUPS:
        return stopped(RunStatus.COULD_NOT_RUN,
                       f"more than {MAX_LOOKUPS} new dependencies, too many to check against PyPI")
    for name in valid:
        try:
            exists, age = registry(name, _remaining(deadline))
        except subprocess.TimeoutExpired:
            return stopped(RunStatus.TIMED_OUT, "stage 1 deadline reached")
        if exists is None:
            return stopped(RunStatus.COULD_NOT_RUN, "PyPI could not be reached or refused the request")
        if not exists:
            message = f"dependency not on PyPI: {name}"
            if name in own:
                findings.append(Finding(CHECK, Severity.SUSPICION, message, path=new_deps[name],
                                        question=f"{name} is this project's own name. Does it refer to the "
                                                 "project itself?"))
            elif can_prove:
                findings.append(Finding(CHECK, Severity.PROOF, message, path=new_deps[name]))
            else:
                findings.append(Finding(CHECK, Severity.SUSPICION, message, path=new_deps[name],
                                        question="This repo declares dependencies in a way prgate cannot "
                                                 "fully read. Is this package real?"))
        elif age is not None and age < YOUNG_DAYS:
            findings.append(Finding(CHECK, Severity.SUSPICION,
                                    f"dependency {name} was first published {age} days ago",
                                    path=new_deps[name], question="Is this the package you meant to add?"))
    return CheckResult(CHECK, RunStatus.RAN, tuple(findings))


# --- reading git --------------------------------------------------------------------------------

def _manifests(repo: Path, rev: str, deadline: float) -> tuple[Manifests, list[str]]:
    """What the root manifests of `rev` declare, and the manifest names that are not regular files.

    Regular files are copied (under plain names) to a scratch directory and read there.
    Subdirectories are not followed; a symlink or submodule is reported, never read.
    """
    out = git_output(repo, "ls-tree", "-z", rev, deadline=deadline)
    regular: list[str] = []
    unread: list[str] = []
    for entry in out.split(b"\0"):
        meta, _, raw = entry.partition(b"\t")
        name = raw.decode("utf-8", "surrogateescape")
        if not (name in _MANIFESTS or _REQUIREMENTS.fullmatch(name)):
            continue
        (regular if meta.split(b" ")[:2] in ([b"100644", b"blob"], [b"100755", b"blob"]) else unread).append(name)
    with tempfile.TemporaryDirectory() as tmp:
        for name in regular:
            (Path(tmp) / name).write_bytes(git_output(repo, "show", f"{rev}:{name}", deadline=deadline))
        return read_manifests(Path(tmp)), unread


_INDEX_FILES = {"uv.toml", "pip.conf", "pip.ini", "poetry.toml", "pdm.toml"}
_NESTED_MANIFESTS = {"setup.py", "setup.cfg", "pyproject.toml"}
# Files that install Python packages in ways the manifest reader does not parse.
_OTHER_DEP_FILES = {"pipfile", "tox.ini", "environment.yml", "environment.yaml", "pixi.toml", "noxfile.py"}
# A mention of a package index in a file that may install the project's dependencies.
_INDEX_HINT = rb"index[-_]url|extra[-_]index|find[-_]links|uv_index|pip_index|--index\b"
_MAX_HINT_FILES = 500


def _is_unread(path: str) -> bool:
    """Whether a path is a Python dependency or index file that the manifest reader does not parse.

    An explicit list: lock files and other languages' manifests do not count. A root manifest
    whose name differs from a parsed one only in case is not parsed, so it counts.
    """
    parts = path.lower().split("/")
    name = parts[-1]
    if "/" not in path and (path in _MANIFESTS or _REQUIREMENTS.fullmatch(path)):
        return False  # a root manifest the reader parses
    if "/" not in path and name in _MANIFESTS:
        return True  # PyProject.toml, Setup.py: a manifest the reader never opened
    if name in _INDEX_FILES or name in _OTHER_DEP_FILES:
        return True
    if "/" in path and name in _NESTED_MANIFESTS:
        return True
    return name.endswith((".txt", ".in")) and (
        "requirements" in name or name.startswith("constraints")
        or "requirements" in parts[:-1] or "deps" in parts[:-1])


def _may_set_an_index(path: str) -> bool:
    """Whether a path is CI, build or environment config that may point pip at another index."""
    if path == "pyproject.toml" or _REQUIREMENTS.fullmatch(path):
        return False  # parsed: their index settings are read exactly, pypi.org included
    lower = path.lower()
    name = lower.rsplit("/", 1)[-1]
    return (lower.startswith((".github/workflows/", ".circleci/", ".gitlab/"))
            or name in {".gitlab-ci.yml", "azure-pipelines.yml", "makefile", "tox.ini", "noxfile.py",
                        "setup.cfg", "pyproject.toml", "pip.conf", "pip.ini"}
            or name.startswith("dockerfile") or name.endswith(".dockerfile")
            or (name.endswith((".txt", ".in")) and "requirements" in name))


def _index_unsure(repo: Path, rev: str, deadline: float) -> bool:
    """Whether `rev` may install from somewhere other than PyPI in a way the reader cannot see.

    True when it has dependency or index files the manifest reader does not parse, or when CI,
    build or environment config mentions a package index (PIP_INDEX_URL in a workflow, say).
    An index set only outside the repository, such as an organisation's CI secret, stays unseen.
    """
    out = git_output(repo, "ls-tree", "-r", "-z", "--name-only", rev, deadline=deadline)
    paths = [raw.decode("utf-8", "surrogateescape") for raw in out.split(b"\0") if raw]
    if any(_is_unread(p) for p in paths):
        return True
    hinted = [p for p in paths if _may_set_an_index(p)]
    if len(hinted) > _MAX_HINT_FILES:
        return True  # too many to read: assume the worst
    if not hinted:
        return False
    try:
        git_output(repo, "grep", "-I", "-i", "-q", "-E", _INDEX_HINT.decode(), rev, "--", *hinted,
                   deadline=deadline)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return False  # no match
        raise
    return True


def _touches_manifest(changes: tuple[FileChange, ...]) -> bool:
    def is_manifest(path: str | None) -> bool:
        return path is not None and (path in _MANIFESTS or bool(_REQUIREMENTS.fullmatch(path)))
    return any(is_manifest(c.path) or is_manifest(c.old_path) for c in changes)


def _imports_of(repo: Path, rev: str, path: str, plugin: LanguagePlugin, deadline: float) -> frozenset[str]:
    return plugin.imports(git_output(repo, "show", f"{rev}:{path}", deadline=deadline).decode("utf-8"))


def facts_check(repo: Path, changes: tuple[FileChange, ...], base: str, head: str,
                plugin_for: Callable[[str], LanguagePlugin | None], registry: Registry,
                deadline: float) -> CheckResult:
    def not_run(detail: str) -> CheckResult:
        return CheckResult(CHECK, RunStatus.COULD_NOT_RUN, (), detail)

    candidates: list[tuple[str, str]] = []  # (path, import name) added by the PR
    for change in changes:
        plugin = plugin_for(change.path)
        if plugin is None or change.status == "D" \
                or classify(replace(change, binary=False)) not in (ChangeType.CODE, ChangeType.TEST):
            continue
        if change.binary:
            return not_run("code file is marked binary, so it cannot be read")
        try:
            now = _imports_of(repo, head, change.path, plugin, deadline)
        except _PY_ERRORS as e:
            return not_run(f"a changed file could not be parsed ({type(e).__name__})")
        before: frozenset[str] = frozenset()
        if change.status not in ("A", "C"):
            try:
                before = _imports_of(repo, base, change.old_path or change.path, plugin, deadline)
            except (*_PY_ERRORS, subprocess.CalledProcessError):
                pass  # an unreadable old file proves nothing was there, so every import counts as new
        candidates += [(change.path, n) for n in now - before]

    touched = _touches_manifest(changes)
    if not candidates and not touched:
        return CheckResult(CHECK, RunStatus.RAN)
    try:
        head_info, head_unread = _manifests(repo, head, deadline)
        base_info, base_unread = _manifests(repo, base, deadline) if touched else (Manifests(), [])
    except ValueError as e:  # a manifest that cannot be read must not hide new dependencies
        return not_run(f"a dependency manifest could not be read: {e}")
    if head_unread:
        return not_run("a dependency manifest is a symlink or submodule, so it cannot be read")

    entries: dict[str, frozenset[str]] = {}

    def listing(directory: str) -> frozenset[str]:
        if directory not in entries:
            args = ("ls-tree", "-z", "--name-only", head) + (("--", directory + "/") if directory else ())
            raw = git_output(repo, *args, deadline=deadline).split(b"\0")
            entries[directory] = frozenset(Path(e.decode("utf-8", "surrogateescape")).name for e in raw if e)
        return entries[directory]

    def is_local(path: str, name: str) -> bool:
        folder = path.rpartition("/")[0]
        return any(name in listing(d) or f"{name}.py" in listing(d) for d in ("", "src", folder))

    undeclared = [(p, n) for p, n in candidates
                  if n not in sys.stdlib_module_names and _norm(n) not in head_info.deps and not is_local(p, n)]

    notes: list[Finding] = []
    changed = {c.path for c in changes}
    for file in sorted(head_info.indirect & changed):
        notes.append(Finding(CHECK, Severity.SUSPICION, f"Dependencies are declared indirectly in {file}; "
                             "prgate could not check them.", path=file,
                             question="Do the dependencies this file pulls in all exist?"))
    for (name, file), kind in sorted(head_info.direct.items() - base_info.direct.items()):
        notes.append(Finding(CHECK, Severity.SUSPICION, f"{name} is installed from {kind}, not PyPI. Is that intended?",
                             path=file))
    for file, option, _ in sorted(head_info.indexes - base_info.indexes):
        notes.append(Finding(CHECK, Severity.SUSPICION,
                             f"package index setting {option} was added in {file}. Is that intended?", path=file))

    # A 404 is proof only if the new-dependency set is certain and PyPI is the only index.
    can_prove = not (base_unread or base_info.indirect or head_info.indirect or head_info.indexes
                     or head_info.unknown_name or base_info.unknown_name
                     or head_info.env_tools or base_info.env_tools
                     or (touched and (_index_unsure(repo, base, deadline) or _index_unsure(repo, head, deadline))))
    plain = {name for name, _ in head_info.plain}  # a name given a non-PyPI source everywhere is not looked up
    new_deps = {n: f for n, f in head_info.deps.items()
                if n not in base_info.deps and n in plain} if touched else {}
    result = judge(new_deps, undeclared, registry, deadline, can_prove=can_prove,
                   own=frozenset(head_info.own | base_info.own))
    return replace(result, findings=(*notes, *result.findings))
