from dataclasses import replace

import pytest

from prgate.config import Config
from prgate.decide import REQUIRED_CODE_CHECKS, decide
from prgate.models import (CheckResult, ChangeType, Evidence, FileChange, Finding, Outcome,
                           RunStatus, Severity)

HEAD = "a" * 40


def cfg(**kw) -> Config:
    return Config(**kw)


def fc(path, old_path=None) -> FileChange:
    return FileChange(path, old_path, "M" if old_path is None else "R", ((1, "x"),), 0, False)


def evidence(changes, checks, ci=True, llm=True) -> Evidence:
    return Evidence("b" * 40, HEAD, tuple(changes), tuple(checks), ci, llm, None)


def ran(names):
    return [CheckResult(n, RunStatus.RAN) for n in names]


def clean_code() -> Evidence:
    return evidence([fc("src/a.py")], ran(REQUIRED_CODE_CHECKS))


def code_change(path, old_path=None) -> Evidence:
    return evidence([fc(path, old_path)], ran(REQUIRED_CODE_CHECKS))


def only_tests_change() -> Evidence:
    return evidence([fc("tests/test_a.py")], ran(REQUIRED_CODE_CHECKS))


def docs(path) -> Evidence:
    return evidence([fc(path)], ran(("secrets",)))


def stage1_only_ran():
    return ran(("secrets", "test_integrity", "environment_sniffing", "facts"))


def with_finding(ev, severity):
    f = Finding("secrets", severity, "something", "src/a.py", 1)
    checks = (CheckResult("secrets", RunStatus.RAN, (f,)),) + tuple(c for c in ev.checks if c.name != "secrets")
    return replace(ev, checks=checks)


def without_check(ev, name):
    return replace(ev, checks=tuple(c for c in ev.checks if c.name != name))


def with_status(ev, name, status):
    return replace(ev, checks=tuple(replace(c, status=status) if c.name == name else c for c in ev.checks))


_PATHS = {ChangeType.AGENT_INSTRUCTIONS: "CLAUDE.md", ChangeType.CI: ".gitlab-ci.yml",
          ChangeType.TEST_INFRA: "conftest.py", ChangeType.MIGRATION: "db/migrations/1.sql",
          ChangeType.CONFIG: "infra/main.tf", ChangeType.DEPENDENCY: "package.json",
          ChangeType.UNKNOWN: "blob.bin"}


def add_file(ev, kind):
    return replace(ev, changes=ev.changes + (fc(_PATHS[kind]),))


def test_all_six_conditions_clear():
    assert decide(clean_code(), cfg(clear_code=True)).outcome == Outcome.CLEARED


def test_verdict_is_bound_to_head_sha():
    assert decide(clean_code(), cfg(clear_code=True)).head_sha == HEAD


def test_any_proof_blocks():
    assert decide(with_finding(clean_code(), Severity.PROOF), cfg(clear_code=True)).outcome == Outcome.BLOCKED


@pytest.mark.parametrize("name", REQUIRED_CODE_CHECKS)
def test_missing_or_failed_check_goes_to_person(name):
    for ev in (without_check(clean_code(), name), with_status(clean_code(), name, RunStatus.TIMED_OUT)):
        v = decide(ev, cfg(clear_code=True))
        assert v.outcome == Outcome.PERSON and v.question


def test_suspicion_goes_to_person():
    assert decide(with_finding(clean_code(), Severity.SUSPICION), cfg(clear_code=True)).outcome == Outcome.PERSON


@pytest.mark.parametrize("ci", [False, None])
def test_ci_must_have_passed(ci):
    assert decide(replace(clean_code(), ci_passed=ci), cfg(clear_code=True)).outcome == Outcome.PERSON


def test_no_key_cannot_clear_code():
    assert decide(replace(clean_code(), has_llm=False), cfg(clear_code=True)).outcome == Outcome.PERSON


def test_clearing_off_reports_would_clear():
    v = decide(clean_code(), cfg(clear_code=False))
    assert v.outcome == Outcome.PERSON and v.would_clear and v.question


def test_rename_out_of_always_human_goes_to_person():
    ev = code_change(path="misc/login.py", old_path="auth/login.py")
    assert decide(ev, cfg(clear_code=True)).outcome == Outcome.PERSON


def test_docs_under_always_human_path_never_clear():
    v = decide(docs("src/auth/README.md"), cfg(clear_docs=True, docs_allowlist=("**",)))
    assert v.outcome == Outcome.PERSON and v.question


def test_docs_rename_out_of_always_human_path_never_clears():
    ev = evidence([fc("notes/README.md", "src/auth/README.md")], [])
    assert decide(ev, cfg(clear_docs=True, docs_allowlist=("**",))).outcome == Outcome.PERSON


@pytest.mark.parametrize("kind", [ChangeType.AGENT_INSTRUCTIONS, ChangeType.CI, ChangeType.TEST_INFRA,
                                  ChangeType.MIGRATION, ChangeType.CONFIG, ChangeType.DEPENDENCY, ChangeType.UNKNOWN])
def test_never_clearing_types_go_to_person_even_with_clean_code(kind):
    assert decide(add_file(clean_code(), kind), cfg(clear_code=True, clear_docs=True)).outcome == Outcome.PERSON


def test_docs_clear_only_on_allowlist():
    assert decide(docs("README.md"), cfg(clear_docs=True)).outcome == Outcome.CLEARED
    assert decide(docs("notes/x.rst"), cfg(clear_docs=True, docs_allowlist=("*.md",))).outcome == Outcome.PERSON


def test_docs_do_not_clear_when_clear_docs_off():
    v = decide(docs("README.md"), cfg(clear_docs=False))
    assert v.outcome == Outcome.PERSON and v.would_clear


def test_invalid_config_never_clears():
    assert decide(clean_code(), cfg(clear_code=True, valid=False)).outcome == Outcome.PERSON


def test_empty_diff_goes_to_person():
    assert decide(replace(clean_code(), changes=()), cfg(clear_code=True)).outcome == Outcome.PERSON


def test_only_tests_change_change_needs_the_same_evidence():
    assert decide(without_check(only_tests_change(), "mutation"), cfg(clear_code=True)).outcome == Outcome.PERSON


def test_first_release_code_change_goes_to_person_with_a_question():
    ev = replace(code_change(path="src/a.py"), has_llm=False, checks=tuple(stage1_only_ran()))
    v = decide(ev, cfg(clear_code=False, clear_docs=True))
    assert v.outcome == Outcome.PERSON and v.question and "src/a.py" in v.question


def test_first_release_docs_clear():
    assert decide(docs("README.md"), cfg(clear_docs=True)).outcome == Outcome.CLEARED


@pytest.mark.parametrize("old,new", [("CLAUDE.md", "docs/notes.md"), (".prgate.toml", "docs/x.md")])
def test_rename_into_docs_from_never_clearing_type_goes_to_person(old, new):
    ev = evidence([fc(new, old)], ran(("secrets",)))
    v = decide(ev, cfg(clear_docs=True, docs_allowlist=("**",)))
    assert v.outcome == Outcome.PERSON and v.question


@pytest.mark.parametrize("old,new", [("docs/notes.md", "CLAUDE.md"), ("docs/x.md", ".prgate.toml")])
def test_rename_out_of_docs_into_never_clearing_type_goes_to_person(old, new):
    ev = evidence([fc(new, old)], ran(("secrets",)))
    assert decide(ev, cfg(clear_docs=True, docs_allowlist=("**",))).outcome == Outcome.PERSON


def test_docs_rename_between_docs_clears():
    ev = evidence([fc("docs/b.md", "docs/a.md")], ran(("secrets",)))
    assert decide(ev, cfg(clear_docs=True)).outcome == Outcome.CLEARED


@pytest.mark.parametrize("status", [None, RunStatus.COULD_NOT_RUN, RunStatus.TIMED_OUT])
def test_docs_only_clear_requires_secrets_check_ran(status):
    checks = [] if status is None else [CheckResult("secrets", status)]
    v = decide(evidence([fc("README.md")], checks), cfg(clear_docs=True))
    assert v.outcome == Outcome.PERSON and v.question and "secrets" in v.question


def test_docs_only_clear_does_not_need_ci():
    ev = replace(docs("README.md"), ci_passed=None, has_llm=False)
    assert decide(ev, cfg(clear_docs=True)).outcome == Outcome.CLEARED


def test_rename_code_to_docs_needs_code_evidence():
    ev = evidence([fc("docs/a.md", "src/a.py")], ran(("secrets",)))
    assert decide(ev, cfg(clear_code=True, clear_docs=True)).outcome == Outcome.PERSON


def _mixed_rename():
    return evidence([fc("src/a.py", "docs/a.md")], ran(REQUIRED_CODE_CHECKS))


def test_docs_to_code_rename_needs_clear_docs():
    assert decide(_mixed_rename(), cfg(clear_code=True, clear_docs=False)).outcome == Outcome.PERSON


def test_docs_to_code_rename_needs_old_path_on_allowlist():
    v = decide(_mixed_rename(), cfg(clear_code=True, clear_docs=True, docs_allowlist=("other/**",)))
    assert v.outcome == Outcome.PERSON


def test_code_to_docs_rename_needs_both_paths_on_allowlist():
    ev = evidence([fc("docs/a.md", "src/a.py")], ran(REQUIRED_CODE_CHECKS))
    v = decide(ev, cfg(clear_code=True, clear_docs=True, docs_allowlist=("docs/**",)))
    assert v.outcome == Outcome.PERSON


def test_mixed_rename_clears_when_both_gates_satisfied():
    v = decide(_mixed_rename(), cfg(clear_code=True, clear_docs=True, docs_allowlist=("**",)))
    assert v.outcome == Outcome.CLEARED
