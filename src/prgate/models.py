from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Outcome(StrEnum):
    BLOCKED = "blocked"
    PERSON = "person"
    CLEARED = "cleared"


class ChangeType(StrEnum):
    CODE = "code"
    TEST = "test"
    TEST_INFRA = "test_infra"
    MIGRATION = "migration"
    CONFIG = "config"
    DEPENDENCY = "dependency"
    DOCS = "docs"
    AGENT_INSTRUCTIONS = "agent_instructions"
    CI = "ci"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    PROOF = "proof"
    SUSPICION = "suspicion"
    INFO = "info"


class RunStatus(StrEnum):
    RAN = "ran"
    COULD_NOT_RUN = "could_not_run"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True)
class FileChange:
    path: str
    old_path: str | None
    status: str
    added: tuple[tuple[int, str], ...]
    removed_count: int
    binary: bool


@dataclass(frozen=True)
class Finding:
    check: str
    severity: Severity
    message: str
    path: str | None = None
    line: int | None = None
    question: str | None = None


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: RunStatus
    findings: tuple[Finding, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class Evidence:
    base_sha: str
    head_sha: str
    changes: tuple[FileChange, ...]
    checks: tuple[CheckResult, ...]
    ci_passed: bool | None
    has_llm: bool
    additive: bool | None


@dataclass(frozen=True)
class Verdict:
    outcome: Outcome
    head_sha: str
    reasons: tuple[str, ...]
    question: str | None
    findings: tuple[Finding, ...]
    would_clear: bool
    explanation: str | None = None
