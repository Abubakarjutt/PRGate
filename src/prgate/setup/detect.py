"""Guess the project's language and test setup from root files only. Never runs or imports project code."""
from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from prgate.setup.gh import Gh, GhError

PYTHON_IMAGE = "python:3.12-slim"
PYTHON_INSTALL = "pip install --target /work/.deps /work pytest"
PYTHON_JUNIT = "/work/.prgate/junit.xml"
PYTHON_TEST = f"PYTHONPATH=/work/.deps python -m pytest -q -p no:cacheprovider --junitxml={PYTHON_JUNIT}"
_ALL_FIELDS = ("language", "image", "install_command", "test_command", "junit_path")


@dataclass(frozen=True)
class ProjectGuess:
    language: str | None
    image: str | None
    install_command: str | None
    test_command: str | None
    junit_path: str | None
    unsure: tuple[str, ...]  # field names the engineer must be asked about


_MAX_MANIFEST_BYTES = 1_048_576
_YES, _NO, _UNSURE = "yes", "no", "unsure"
_PARSE_ERRORS = (OSError, ValueError, RecursionError, MemoryError)  # ValueError covers decode and JSON/TOML errors


def _read(path: Path) -> tuple[bool, str | None]:
    """(present, text). text is None when the file is absent or unreadable: a symlink, a non-file,
    longer than 1 MiB, or not UTF-8. A symlink is never followed."""
    if not os.path.lexists(path):
        return False, None
    if path.is_symlink() or not path.is_file():
        return True, None
    try:
        with open(path, "rb") as f:
            raw = f.read(_MAX_MANIFEST_BYTES + 1)
        if len(raw) > _MAX_MANIFEST_BYTES:
            return True, None
        return True, raw.decode("utf-8")
    except _PARSE_ERRORS:
        return True, None


def _is_python(root: Path) -> str:
    unreadable = False
    found = False
    for name in ("setup.py", "setup.cfg"):  # presence only, never read
        present = _presence(root / name)
        found |= present == _YES
        unreadable |= present == _UNSURE
    present, text = _read(root / "pyproject.toml")
    if present:
        try:
            if text is None:
                raise ValueError
            tomllib.loads(text)
            found = True
        except _PARSE_ERRORS:
            unreadable = True
    return _YES if found else _UNSURE if unreadable else _NO


def _presence(path: Path) -> str:
    if not os.path.lexists(path):
        return _NO
    if path.is_symlink() or not path.is_file():
        return _UNSURE
    return _YES


def _is_typescript(root: Path) -> str:
    unreadable = False
    found = False
    state = _presence(root / "tsconfig.json")
    found |= state == _YES
    unreadable |= state == _UNSURE
    present, text = _read(root / "package.json")
    if present:
        try:
            if text is None:
                raise ValueError
            data = json.loads(text)
            if isinstance(data, dict):
                found |= any(isinstance(data.get(k), dict) and "typescript" in data[k]
                             for k in ("dependencies", "devDependencies"))
        except _PARSE_ERRORS:
            unreadable = True
    return _YES if found else _UNSURE if unreadable else _NO


def detect_project(root: Path) -> ProjectGuess:
    python = _is_python(root)
    typescript = _is_typescript(root)
    if python == _YES and typescript == _NO:
        return ProjectGuess("python", PYTHON_IMAGE, PYTHON_INSTALL, PYTHON_TEST, PYTHON_JUNIT, ())
    if typescript == _YES and python == _NO:
        # Lockfile and test-script rules are not implemented in this release.
        return ProjectGuess("typescript", None, None, None, None, _ALL_FIELDS[1:])
    return ProjectGuess(None, None, None, None, None, _ALL_FIELDS)


def suggest_ci_checks(gh: Gh, repo: str, branch: str, commits: int = 10) -> tuple[str, ...]:
    """Check names present on every one of the last `commits` commits of `branch`, minus pr-gate."""
    commits = max(1, min(commits, 100))
    try:
        listed = gh.api("GET", f"repos/{repo}/commits?sha={quote(branch, safe='')}&per_page={commits}")
        shas = [c["sha"] for c in listed][:commits] if isinstance(listed, list) else []
        if not shas:
            return ()
        common: set[str] | None = None
        for sha in shas:
            data = gh.api("GET", f"repos/{repo}/commits/{sha}/check-runs?per_page=100")
            names = {r["name"] for r in data["check_runs"]}
            common = names if common is None else common & names
    except (GhError, KeyError, TypeError):
        return ()
    return tuple(sorted((common or set()) - {"pr-gate"}))
