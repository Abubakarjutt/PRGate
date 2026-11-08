"""Stage 1: cheap checks that only read git objects and parse text. No PR code ever runs."""
from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from .checks import facts, rollout, secrets
from .checks import integrity as integrity_check
from .checks.integrity import TestRecord
from .classify import CODE_EXT, classify
from .config import Config
from .diff import git_output, parse_diff
from .models import ChangeType, CheckResult, FileChange, Finding, RunStatus
from .plugins import get_plugin
from .plugins.base import ENVIRONMENT_SNIFFING, LanguagePlugin, TestFacts

CHECK_NAMES = ("secrets", "rollout", "test_integrity", ENVIRONMENT_SNIFFING, facts.CHECK)


class _Unreadable(Exception):
    """A test file could not be read or parsed, so integrity cannot be judged."""


def _not_run(name: str, status: RunStatus, detail: str) -> CheckResult:
    return CheckResult(name, status, (), detail)


def _all(status: RunStatus, detail: str) -> tuple[CheckResult, ...]:
    return tuple(_not_run(n, status, detail) for n in CHECK_NAMES)


def _guarded(name: str, deadline: float, fn: Callable[[], CheckResult]) -> CheckResult:
    """Run one check; a crash or timeout becomes a result that routes to a person."""
    if time.monotonic() >= deadline:
        return _not_run(name, RunStatus.TIMED_OUT, "stage 1 deadline reached")
    try:
        return fn()
    except subprocess.TimeoutExpired:
        return _not_run(name, RunStatus.TIMED_OUT, "git call timed out")
    except _Unreadable as e:
        return _not_run(name, RunStatus.COULD_NOT_RUN, str(e))
    except Exception as e:  # a check must never take the run down
        return _not_run(name, RunStatus.COULD_NOT_RUN, f"check crashed: {type(e).__name__}")


def _records(repo: Path, rev: str, path: str, plugin: LanguagePlugin,
             deadline: float) -> tuple[dict[str, TestRecord], TestFacts, dict[str, str]]:
    try:
        source = git_output(repo, "show", f"{rev}:{path}", deadline=deadline).decode("utf-8")
        facts = plugin.test_facts(source)
        hashes = plugin.symbols(source)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        raise
    except Exception as e:
        raise _Unreadable(f"a test file could not be read or parsed ({type(e).__name__})") from e
    records = {f"{path}::{name}": TestRecord(f"{path}::{name}", asserts, name in facts.skipped,
                                             hashes.get(facts.defined_at.get(name, name), ""),
                                             name in facts.maybe_skipped, name in facts.asserts_unsure)
               for name, asserts in facts.tests.items()}
    return records, facts, hashes


def _environment_sniffing(repo: Path, head: str, changes: tuple[FileChange, ...],
                          plugin: LanguagePlugin | None, deadline: float) -> CheckResult:
    """Ask the plug-in about the head source of every changed code and test file."""
    findings: list[Finding] = []

    def stopped(status: RunStatus, detail: str) -> CheckResult:  # keep what was already found
        return CheckResult(ENVIRONMENT_SNIFFING, status, tuple(findings), detail)

    for change in changes:
        kind = classify(replace(change, binary=False))
        if change.status == "D" or kind not in (ChangeType.CODE, ChangeType.TEST):
            continue
        path = change.path
        handler = _plugin_for(path, plugin)
        if handler is None:
            if "." + path.rsplit(".", 1)[-1].lower() in CODE_EXT:
                return stopped(RunStatus.COULD_NOT_RUN, "no language plug-in for a changed code file")
            continue
        if change.binary:
            shown = path.encode("utf-8", "backslashreplace").decode()
            return stopped(RunStatus.COULD_NOT_RUN,
                           f"code file is marked binary, so it cannot be read: {shown}")
        try:
            source = git_output(repo, "show", f"{head}:{path}", deadline=deadline).decode("utf-8")
            found = handler.sniffing(source, is_test=kind == ChangeType.TEST)
        except subprocess.TimeoutExpired:
            return stopped(RunStatus.TIMED_OUT, "git call timed out")
        except subprocess.CalledProcessError:
            return stopped(RunStatus.COULD_NOT_RUN, "git could not read a changed file")
        except Exception as e:
            return stopped(RunStatus.COULD_NOT_RUN,
                           f"a changed file could not be read or parsed ({type(e).__name__})")
        findings.extend(replace(f, path=path) for f in found)
    return CheckResult(ENVIRONMENT_SNIFFING, RunStatus.RAN, tuple(findings))


def _test_files(change: FileChange) -> tuple[str | None, str | None]:
    """(base path, head path) to read when this change touches a test file."""
    base_path = change.old_path if change.status == "R" else change.path
    head_path = change.path
    if change.status == "A" or change.status == "C":
        base_path = None
    if change.status == "D":
        head_path = None
    is_test = any(classify(replace(change, path=p, binary=False)) == ChangeType.TEST
                  for p in (change.path, base_path) if p is not None)
    if is_test and change.binary:
        shown = change.path.encode("utf-8", "backslashreplace").decode()
        raise _Unreadable(f"test file is marked binary, so it cannot be compared: {shown}")
    return (base_path, head_path) if is_test else (None, None)


def _plugin_for(path: str, plugin: LanguagePlugin | None) -> LanguagePlugin | None:
    if plugin is None:
        return get_plugin(path)
    return plugin if plugin.handles(path) else None


def _test_integrity(repo: Path, base: str, head: str, changes: tuple[FileChange, ...],
                    plugin: LanguagePlugin | None, deadline: float) -> CheckResult:
    before: dict[str, TestRecord] = {}
    after: dict[str, TestRecord] = {}
    head_hashes: set[str] = set()
    opaque: set[str] = set()
    renamed: dict[str, str] = {}
    for change in changes:
        base_path, head_path = _test_files(change)
        if base_path is not None and head_path is not None and base_path != head_path:
            renamed[base_path] = head_path
        for rev, path, into in ((base, base_path, before), (head, head_path, after)):
            if path is None:
                continue
            handler = _plugin_for(path, plugin)
            if handler is None:
                if "." + path.rsplit(".", 1)[-1].lower() in CODE_EXT:
                    return _not_run("test_integrity", RunStatus.COULD_NOT_RUN,
                                    "no language plug-in for a test file")
                continue
            records, facts, hashes = _records(repo, rev, path, handler, deadline)
            into.update(records)
            if into is after:
                # Definitions pytest does not collect as these tests, where a test body may now live.
                head_hashes.update(h for k, h in hashes.items() if h and k not in facts.tests)
                if facts.opaque:
                    opaque.add(path)
    return integrity_check.integrity(before, after, head_hashes=frozenset(head_hashes),
                                     opaque=frozenset(opaque), renamed=renamed)


def run_stage1(repo: Path, base: str, head: str, config: Config, deadline_s: float, *,
               plugin: LanguagePlugin | None = None,
               registry: facts.Registry | None = None) -> tuple[CheckResult, ...]:
    """Run the stage 1 checks within `deadline_s` seconds of wall time.

    `plugin` overrides the plug-in registry and `registry` the PyPI lookup (both used in tests).
    A failure, crash or timeout gives COULD_NOT_RUN or TIMED_OUT for the check, never a pass.
    """
    deadline = time.monotonic() + deadline_s
    if deadline_s <= 0:
        return _all(RunStatus.TIMED_OUT, "stage 1 deadline reached")
    try:
        changes = parse_diff(repo, base, head, deadline)
    except subprocess.TimeoutExpired:
        return _all(RunStatus.TIMED_OUT, "reading the diff timed out")
    except Exception as e:  # malformed git output must not crash the run either
        return _all(RunStatus.COULD_NOT_RUN, f"could not read the diff ({type(e).__name__})")
    def read_head_blob(path: str) -> bytes:
        return git_output(repo, "cat-file", "blob", f"{head}:{path}", deadline=deadline)

    return (
        _guarded("secrets", deadline, lambda: secrets.scan(changes, read_head_blob)),
        _guarded("rollout", deadline, lambda: rollout.rollout_check(changes)),
        _guarded("test_integrity", deadline,
                 lambda: _test_integrity(repo, base, head, changes, plugin, deadline)),
        _guarded(ENVIRONMENT_SNIFFING, deadline,
                 lambda: _environment_sniffing(repo, head, changes, plugin, deadline)),
        _guarded(facts.CHECK, deadline,
                 lambda: facts.facts_check(repo, changes, base, head, lambda p: _plugin_for(p, plugin),
                                           registry or facts.pypi_registry, deadline)),
    )
