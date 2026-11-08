import json

import pytest

from prgate.commands import Command
from prgate.conclude import ArtifactError, build_verdict, conclusion, dump_stage1, load_stage1
from prgate.config import Config
from prgate.models import CheckResult, FileChange, Finding, Outcome, RunStatus, Severity, Verdict

B = "b" * 40
H = "a" * 40
STAGE1 = ("secrets", "rollout", "test_integrity", "environment_sniffing", "facts")


def _v(outcome):
    return Verdict(outcome, H, ("why",), None, (), False)


def cleared():
    return _v(Outcome.CLEARED)


def person():
    return _v(Outcome.PERSON)


def blocked():
    return _v(Outcome.BLOCKED)


def override(sha, reason):
    return Command("override", sha, reason)


def change(path="README.md", **kw):
    return FileChange(path, kw.get("old_path"), kw.get("status", "M"), kw.get("added", ((1, "x"),)), 0, False)


def ran(*extra):
    return tuple(CheckResult(n, RunStatus.RAN) for n in STAGE1) + tuple(extra)


def artifact(changes=(change(),), checks=None, base=B, head=H, diff_ok=True):
    return dump_stage1(base, head, base, changes, ran() if checks is None else checks, diff_ok).encode()


def test_conclusion_is_always_neutral():
    for v in (cleared(), person(), blocked()):
        for g in (None, override(H, "ok")):
            assert conclusion(v, g, "silent") == "neutral"
            assert conclusion(v, g, "enforce") == "neutral"


def test_artifact_round_trips_changes_and_checks_without_line_content():
    f = Finding("facts", Severity.SUSPICION, "odd", "a.py", 3, "why?")
    checks = ran(CheckResult("extra", RunStatus.TIMED_OUT, (f,), "slow"))
    a = load_stage1(artifact(changes=(change("a.py", added=((1, "secret line"),)),
                                      change("b.py", old_path="c.py", status="R")), checks=checks))
    assert a.base_sha == B and a.head_sha == H and a.diff_ok
    assert [c.path for c in a.changes] == ["a.py", "b.py"] and a.changes[1].old_path == "c.py"
    assert all(c.added == () for c in a.changes)
    assert a.checks == checks


def test_artifact_with_lone_surrogates_is_ascii_and_round_trips():
    path = "dir/\udcff\udc80name.py"
    f = Finding("secrets", Severity.SUSPICION, "msg \udcfe", path, 1)
    raw = artifact(changes=(change(path),), checks=ran(CheckResult("x", RunStatus.RAN, (f,))))
    raw.decode("ascii")
    a = load_stage1(raw)
    assert a.changes[0].path == path and a.checks[-1].findings[0].message == "msg \udcfe"


@pytest.mark.parametrize("raw", [
    b"", b"not json", b"[]", b"null", b'{"version": 1}', b"\xff\xfe",
    json.dumps({"version": 2}).encode(),
    b"[" * 100000,
])
def test_malformed_artifact_is_refused(raw):
    with pytest.raises(ArtifactError):
        load_stage1(raw)


def _mutate(fn):
    d = json.loads(artifact())
    fn(d)
    return json.dumps(d).encode()


@pytest.mark.parametrize("fn", [
    lambda d: d.update(head_sha="xyz"),
    lambda d: d.update(base_sha=None),
    lambda d: d.update(diff_ok="yes"),
    lambda d: d.update(changes={}),
    lambda d: d["changes"][0].update(path=3),
    lambda d: d["changes"][0].update(binary="no"),
    lambda d: d["changes"][0].update(status="Z"),
    lambda d: d["checks"][0].update(status="passed"),
    lambda d: d["checks"][0].update(findings=[{"check": "x"}]),
    lambda d: d["checks"][0].update(findings=[{"check": "x", "severity": "proof", "message": "m",
                                               "path": None, "line": "1", "question": None}]),
    lambda d: d["checks"][0].update(findings=[{"check": "x", "severity": "proof", "message": "m",
                                               "path": None, "line": True, "question": None}]),
    lambda d: d.update(extra=1),
    lambda d: d["checks"].append("secrets"),
])
def test_wrongly_shaped_artifact_is_refused(fn):
    with pytest.raises(ArtifactError):
        load_stage1(_mutate(fn))


def test_missing_artifact_gives_person():
    v, checks = build_verdict(None, B, H, Config())
    assert v.outcome == Outcome.PERSON and v.head_sha == H and checks == ()
    assert "missing" in v.reasons[0]


def test_malformed_artifact_gives_person():
    v, _ = build_verdict(b"{", B, H, Config())
    assert v.outcome == Outcome.PERSON and v.head_sha == H


def test_proof_in_a_malformed_artifact_cannot_block():
    d = json.loads(artifact(checks=ran(CheckResult("x", RunStatus.RAN, (
        Finding("secrets", Severity.PROOF, "m"),)))))
    d["changes"][0]["binary"] = "maybe"
    v, _ = build_verdict(json.dumps(d).encode(), B, H, Config())
    assert v.outcome == Outcome.PERSON


def test_artifact_for_another_head_gives_person_on_the_event_head():
    v, _ = build_verdict(artifact(head="c" * 40), B, H, Config())
    assert v.outcome == Outcome.PERSON and v.head_sha == H and "different commit" in v.reasons[0]


def test_artifact_for_another_base_gives_person():
    docs = (change("docs/a.md"),)
    assert build_verdict(artifact(changes=docs), B, H, Config(clear_docs=True))[0].outcome == Outcome.CLEARED
    v, _ = build_verdict(artifact(changes=docs, base="c" * 40), B, H, Config(clear_docs=True))
    assert v.outcome == Outcome.PERSON and "different commit" in v.reasons[0]


def test_unreadable_diff_gives_person_with_the_reason():
    v, _ = build_verdict(artifact(changes=(), diff_ok=False), B, H, Config())
    assert v.outcome == Outcome.PERSON and "diff could not be read" in v.reasons[0]


def test_proof_in_a_valid_artifact_blocks():
    f = Finding("test_integrity", Severity.PROOF, "test deleted: t.py::test_x", "t.py", 1)
    checks = tuple(CheckResult(n, RunStatus.RAN, (f,) if n == "test_integrity" else ()) for n in STAGE1)
    v, out = build_verdict(artifact(changes=(change("tests/t.py", status="D"),), checks=checks), B, H, Config())
    assert v.outcome == Outcome.BLOCKED and v.head_sha == H and out == checks


def test_docs_change_follows_the_policy():
    raw = artifact(changes=(change("docs/a.md"),))
    assert build_verdict(raw, B, H, Config())[0].outcome == Outcome.PERSON
    assert build_verdict(raw, B, H, Config(clear_docs=True))[0].outcome == Outcome.CLEARED


def test_could_not_run_check_goes_to_a_person():
    checks = tuple(CheckResult(n, RunStatus.COULD_NOT_RUN if n == "secrets" else RunStatus.RAN)
                   for n in STAGE1)
    v, _ = build_verdict(artifact(changes=(change("docs/a.md"),), checks=checks), B, H, Config(clear_docs=True))
    assert v.outcome == Outcome.PERSON
