"""Config changes need a rollout plan: a marker such as canary or maxUnavailable."""
from __future__ import annotations

from collections.abc import Iterable

from ..classify import classify
from ..models import ChangeType, CheckResult, FileChange, Finding, RunStatus, Severity

CHECK = "rollout"
MARKERS = ("canary", "rollout", "maxunavailable", "percent", "stage")


def rollout_check(changes: Iterable[FileChange]) -> CheckResult:
    findings = []
    for change in changes:
        if not change.added or classify(change) != ChangeType.CONFIG:
            continue
        text = "\n".join(line for _, line in change.added).lower()
        if not any(marker in text for marker in MARKERS):
            findings.append(Finding(
                CHECK, Severity.SUSPICION, "config change without a rollout marker",
                change.path, change.added[0][0],
                question="How will this config change be rolled out (canary, staged, percentage)?"))
    return CheckResult(CHECK, RunStatus.RAN, tuple(findings))
