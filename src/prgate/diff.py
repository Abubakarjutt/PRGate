from __future__ import annotations

import functools
import re
import subprocess
import time
from pathlib import Path

from .models import FileChange

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


GIT_TIMEOUT = 60


class DiffError(RuntimeError):
    """The diff could not be read reliably; the PR must go to a person."""


def git_timeout(deadline: float | None) -> float:
    """Per-call git timeout: the usual limit, cut down to the time left before `deadline`
    (a time.monotonic() value). Raises TimeoutExpired when none is left."""
    if deadline is None:
        return GIT_TIMEOUT
    left = deadline - time.monotonic()
    if left <= 0:
        raise subprocess.TimeoutExpired("git", 0)
    return min(GIT_TIMEOUT, left)


EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


@functools.cache
def _attr_source_args() -> tuple[str, ...]:
    """Make git ignore the PR's .gitattributes (binary, diff drivers, textconv), where supported."""
    try:
        out = subprocess.run(["git", "--version"], capture_output=True, timeout=GIT_TIMEOUT).stdout.decode()
        major, minor = (int(x) for x in re.search(r"(\d+)\.(\d+)", out).groups())
    except (OSError, subprocess.SubprocessError, AttributeError, ValueError):
        return ()
    return (f"--attr-source={EMPTY_TREE}",) if (major, minor) >= (2, 40) else ()


def git_output(repo: Path, *args: str, deadline: float | None = None) -> bytes:
    """Run git read-only with attributes neutralised; returns stdout."""
    return subprocess.run(
        ["git", "--literal-pathspecs", *_attr_source_args(),
         "-c", "core.attributesFile=/dev/null", "-c", "core.quotepath=off", *args],
        cwd=repo, check=True, capture_output=True, timeout=git_timeout(deadline),
    ).stdout


def _path(raw: bytes) -> str:
    return raw.decode("utf-8", errors="surrogateescape")


_DIFF_ARGS = ("diff", "--find-renames", "--no-ext-diff", "--no-textconv", "--no-color")


def _raw(repo: Path, base: str, head: str, deadline: float | None) -> list[tuple[str, str | None, str]]:
    """(status, old_path, path) per changed file; old_path only for renames/copies."""
    parts = git_output(repo, *_DIFF_ARGS, "-z", "--raw", base, head, "--", deadline=deadline).split(b"\0")
    out: list[tuple[str, str | None, str]] = []
    i = 0
    while i < len(parts) and parts[i]:
        if not parts[i].startswith(b":"):
            raise DiffError("unexpected git diff --raw output")
        code = parts[i].split()[-1][:1].decode()
        if code in ("R", "C"):
            out.append((code, _path(parts[i + 1]), _path(parts[i + 2])))
            i += 3
        else:
            out.append((code, None, _path(parts[i + 1])))
            i += 2
    return out


def _binary_flags(repo: Path, base: str, head: str, deadline: float | None) -> list[tuple[str, bool]]:
    """(path, is_binary) per file, in the same order as --raw."""
    parts = git_output(repo, *_DIFF_ARGS, "-z", "--numstat", base, head, "--", deadline=deadline).split(b"\0")
    out: list[tuple[str, bool]] = []
    i = 0
    while i < len(parts) and parts[i]:
        added, removed, path = parts[i].split(b"\t", 2)
        if path == b"":  # rename: old and new path follow as separate fields
            path = parts[i + 2]
            i += 3
        else:
            i += 1
        out.append((_path(path), added == b"-" and removed == b"-"))
    return out


def _sections(repo: Path, base: str, head: str, deadline: float | None) -> list[tuple[tuple[tuple[int, str], ...], int]]:
    """(added, removed_count) per file, from ONE patch, in --raw order."""
    patch = git_output(repo, *_DIFF_ARGS, "--unified=0", "--patch", base, head, "--", deadline=deadline)
    sections: list[tuple[list[tuple[int, str]], int]] = []
    line = 0
    in_hunk = False
    for raw in patch.split(b"\n"):
        if raw.startswith(b"diff --git "):
            sections.append(([], 0))
            in_hunk = False
            continue
        text = raw.decode("utf-8", errors="replace")
        m = _HUNK.match(text)
        if m:
            line = int(m.group(1))
            in_hunk = True
        elif not in_hunk or not sections:
            continue
        elif text.startswith("+"):
            sections[-1][0].append((line, text[1:].rstrip("\r")))
            line += 1
        elif text.startswith("-"):
            sections[-1] = (sections[-1][0], sections[-1][1] + 1)
    return [(tuple(a), r) for a, r in sections]


def parse_diff(repo: Path, base: str, head: str, deadline: float | None = None) -> tuple[FileChange, ...]:
    """Parse base..head with three git calls in total, whatever the file count.

    `deadline` is a time.monotonic() value; each git call gets the time left as its timeout.
    Raises DiffError (or subprocess errors) when files cannot be attributed.
    """
    entries = _raw(repo, base, head, deadline)
    flags = _binary_flags(repo, base, head, deadline)
    sections = _sections(repo, base, head, deadline)
    if not (len(entries) == len(flags) == len(sections)):
        raise DiffError("could not attribute diff hunks to files")
    changes = []
    for (status, old_path, path), (flag_path, binary), (added, removed) in zip(entries, flags, sections):
        if flag_path != path:
            raise DiffError("diff outputs disagree about file order")
        if binary:
            added, removed = (), 0
        changes.append(FileChange(path, old_path, status, added, removed, binary))
    return tuple(changes)
