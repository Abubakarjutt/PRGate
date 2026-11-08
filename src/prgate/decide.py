"""Decision engine: pure function from evidence and config to a verdict. No I/O."""
from __future__ import annotations

import re
from dataclasses import replace
from functools import lru_cache

from .classify import classify
from .config import Config
from .models import ChangeType, Evidence, Outcome, RunStatus, Severity, Verdict
from .plugins.base import ENVIRONMENT_SNIFFING

REQUIRED_CODE_CHECKS = ("secrets", "test_integrity", ENVIRONMENT_SNIFFING, "facts",
                        "old_new_tests", "canaries", "mutation", "behaviour")

_CODE_TYPES = {ChangeType.CODE, ChangeType.TEST}
_MAX_NAMED = 3


@lru_cache(maxsize=256)
def _glob_re(pattern: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z", re.IGNORECASE)


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    """Glob match on the full path; a pattern with no slash also matches the file name."""
    name = path.rsplit("/", 1)[-1]
    for p in patterns:
        rx = _glob_re(p)
        if rx.match(path) or ("/" not in p and rx.match(name)):
            return True
    return False


def _named(paths: list[str]) -> str:
    shown = ", ".join(paths[:_MAX_NAMED])
    return shown + (f" and {len(paths) - _MAX_NAMED} more" if len(paths) > _MAX_NAMED else "")


def decide(evidence: Evidence, config: Config) -> Verdict:
    findings = tuple(f for c in evidence.checks for f in c.findings)

    def verdict(outcome, reasons, question=None, would_clear=False) -> Verdict:
        return Verdict(outcome, evidence.head_sha, tuple(reasons), question, findings, would_clear)

    proofs = [f for f in findings if f.severity == Severity.PROOF]
    if proofs:
        return verdict(Outcome.BLOCKED, [f"{f.check}: {f.message}" for f in proofs])

    changes = evidence.changes
    paths = [c.path for c in changes]
    person: list[str] = []

    def to_person(reasons, would_clear=False) -> Verdict:
        subject = _named(paths) if paths else "this pull request"
        question = f"Please review {subject}: " + "; ".join(reasons) + "."
        return verdict(Outcome.PERSON, reasons, question, would_clear)

    if not config.valid:
        return to_person(["the policy config is invalid, so nothing can clear"
                          + (f" ({'; '.join(config.errors)})" if config.errors else "")])
    if not changes:
        return to_person(["the diff is empty, so there is nothing to clear"])

    types = [classify(c) for c in changes]
    # A rename is judged on both sides: the old path's type must not be one that never clears.
    old_types = [classify(replace(c, path=c.old_path)) if c.old_path is not None else t
                 for c, t in zip(changes, types)]
    eligible = _CODE_TYPES | {ChangeType.DOCS}
    never = sorted({paths[i] for i in range(len(changes))
                    if types[i] not in eligible or old_types[i] not in eligible})
    if never:
        person.append(f"change type never clears automatically: {_named(never)}")

    human = [c.path for c in changes
             if _matches(c.path, config.always_human)
             or (c.old_path is not None and _matches(c.old_path, config.always_human))]
    if human:
        person.append(f"touches an always-human path: {_named(human)}")

    for f in findings:
        if f.severity == Severity.SUSPICION:
            person.append(f.question or f"{f.check}: {f.message}")

    # A change with docs on either side must pass the docs gate on both of its paths.
    docs_idx = [i for i in range(len(changes))
                if ChangeType.DOCS in (types[i], old_types[i])]
    docs_paths = [paths[i] for i in docs_idx]
    off_list = [p for i in docs_idx for p in (paths[i], changes[i].old_path)
                if p is not None and not _matches(p, config.docs_allowlist)]
    if off_list:
        person.append(f"docs outside the allowlist: {_named(off_list)}")

    has_code = any(t in _CODE_TYPES for t in types + old_types)
    by_name = {c.name: c for c in evidence.checks}
    required = REQUIRED_CODE_CHECKS if has_code else ("secrets",)  # every clear needs the secrets scan
    for name in required:
        c = by_name.get(name)
        if c is None:
            person.append(f"required check {name} did not run")
        elif c.status != RunStatus.RAN:
            person.append(f"required check {name} {c.status.value.replace('_', ' ')}")
    if has_code and evidence.ci_passed is not True:
        person.append("CI has not passed" if evidence.ci_passed is False else "CI result is unknown")
    if has_code and not evidence.has_llm:
        person.append("no model key, so the behaviour check could not run")

    if person:
        return to_person(person)

    # Every requirement is met. Clearing still depends on the switches.
    if has_code and not config.clear_code:
        return to_person(["code clearing is off; this change would have cleared"], would_clear=True)
    if docs_paths and not config.clear_docs:
        return to_person(["docs clearing is off; this change would have cleared"], would_clear=True)
    reasons = ["all requirements met"]
    return verdict(Outcome.CLEARED, reasons, None, True)
