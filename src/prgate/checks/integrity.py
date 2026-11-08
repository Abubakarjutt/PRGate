"""Test integrity: tests that vanish, lose assertions or get skipped."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ..models import CheckResult, Finding, RunStatus, Severity

CHECK = "test_integrity"


@dataclass(frozen=True)
class TestRecord:
    __test__ = False  # not a pytest class

    key: str  # "<path>::<qualified name>"
    asserts: int
    skipped: bool
    body_hash: str
    maybe_skipped: bool = False
    asserts_unsure: bool = False  # the count may miss checks made in helpers or fixtures


def _last_name(key: str) -> str:
    return key.rsplit("::", 1)[-1].rsplit(".", 1)[-1]


def _path_of(key: str) -> str:
    return key.rsplit("::", 1)[0]


def _find_move(key: str, base: TestRecord, new: dict[str, TestRecord]) -> tuple[TestRecord, bool] | None:
    """The new head test this base test became, and whether its body is unchanged."""
    if base.body_hash:
        same = [r for k, r in sorted(new.items()) if r.body_hash == base.body_hash]
        if same:
            return same[0], True
    named = [r for k, r in sorted(new.items()) if _last_name(k) == _last_name(key)]
    return (named[0], False) if named else None


def _may_skip(key: str) -> Finding:
    return Finding(CHECK, Severity.SUSPICION, f"test may now be skipped: {key}", _path_of(key),
                   question=f"Is {key} skipped under a condition on purpose?")


def _unmatched(key: str, base: TestRecord, new: dict[str, TestRecord], head_hashes: frozenset[str],
               opaque: frozenset[str], renamed: Mapping[str, str]) -> Finding:
    """A base test with no head test to match: deleted (proof) only when nothing could explain it."""
    path = renamed.get(_path_of(key), _path_of(key))
    replacements = sorted(k for k in new if _path_of(k) == path)
    if replacements:  # renamed and changed in one go, as a parametrize merge does
        shown = ", ".join(replacements[:5]) + (", ..." if len(replacements) > 5 else "")
        return Finding(CHECK, Severity.SUSPICION, f"test removed or replaced: {key}", path,
                       question=f"Was {key} replaced by {shown}?")
    if base.body_hash and base.body_hash in head_hashes:
        return Finding(CHECK, Severity.SUSPICION, f"test may have moved: {key}", path,
                       question=f"The body of {key} is still defined in a changed test file. Is it still run?")
    if path in opaque:
        return Finding(CHECK, Severity.SUSPICION, f"test may have been deleted: {key}", path,
                       question=f"{path} makes or inherits tests in ways prgate cannot follow. "
                                f"Does {key} still run?")
    return Finding(CHECK, Severity.PROOF, f"test deleted: {key}", _path_of(key))


def integrity(base: dict[str, TestRecord], head: dict[str, TestRecord], *,
              head_hashes: frozenset[str] = frozenset(), opaque: frozenset[str] = frozenset(),
              renamed: Mapping[str, str] | None = None) -> CheckResult:
    """Compare the tests of the changed test files before and after the PR.

    `head_hashes` holds the body hash of every definition in the head versions of those files,
    test or not; `opaque` names head files whose tests the plug-in cannot fully follow; and
    `renamed` maps a renamed file's base path to its head path.
    """
    findings: list[Finding] = []
    new = {k: r for k, r in head.items() if k not in base}
    unmatched: list[str] = []

    for key in sorted(k for k in base if k not in head):
        found = _find_move(key, base[key], new)
        if found is None:
            unmatched.append(key)
            continue
        moved, unchanged = found
        del new[moved.key]
        if unchanged:
            findings.append(Finding(CHECK, Severity.INFO, f"test moved: {key} to {moved.key}",
                                    _path_of(moved.key)))
            if moved.skipped and not base[key].skipped:
                findings.append(Finding(CHECK, Severity.PROOF, f"test now skipped: {moved.key}",
                                        _path_of(moved.key)))
            elif moved.maybe_skipped and not (base[key].skipped or base[key].maybe_skipped):
                findings.append(_may_skip(moved.key))
        else:
            findings.append(Finding(
                CHECK, Severity.SUSPICION, f"test moved and changed: {key} to {moved.key}",
                _path_of(moved.key),
                question=f"Was {key} moved to {moved.key} on purpose? Its body changed."))
    # Only after every move is matched: what is still new may have replaced what is still gone.
    findings.extend(_unmatched(key, base[key], new, head_hashes, opaque, renamed or {}) for key in unmatched)

    for key in sorted(k for k in base if k in head):
        before, after = base[key], head[key]
        path = _path_of(key)
        if after.asserts == 0 and before.asserts > 0:
            if after.asserts_unsure:
                findings.append(Finding(
                    CHECK, Severity.SUSPICION, f"asserts may have been removed: {key}", path,
                    question=f"{key} has no assert left that prgate can see. "
                             "Do the helpers or fixtures it uses still check the result?"))
            else:
                findings.append(Finding(CHECK, Severity.PROOF, f"asserts removed: {key}", path))
        elif after.asserts < before.asserts:
            findings.append(Finding(
                CHECK, Severity.SUSPICION, f"fewer asserts: {key} ({before.asserts} to {after.asserts})",
                path, question=f"Why does {key} check less than before?"))
        if after.skipped and not before.skipped:
            findings.append(Finding(CHECK, Severity.PROOF, f"test now skipped: {key}", path))
        elif after.maybe_skipped and not (before.skipped or before.maybe_skipped):
            findings.append(_may_skip(key))
    return CheckResult(CHECK, RunStatus.RAN, tuple(findings))
