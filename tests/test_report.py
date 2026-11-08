from dataclasses import replace

from prgate.models import CheckResult, Finding, Outcome, RunStatus, Severity, Verdict
from prgate.report import EXPERIMENTAL_LINE, parse, render

HEAD = "a1b2c3d4" + "e" * 32


def _v(outcome, reasons, findings=(), question=None, would_clear=False, explanation=None):
    return Verdict(outcome, HEAD, tuple(reasons), question, tuple(findings), would_clear, explanation)


def sample_cleared():
    return _v(Outcome.CLEARED, ["all requirements met"], would_clear=True)


def sample_person():
    return _v(Outcome.PERSON, ["CI has not passed"], question="Please review src/a.py: CI has not passed.",
              findings=(Finding("facts", Severity.SUSPICION, "odd change", "src/a.py", 3, "Why?"),),
              explanation="looks fine to me")


def sample_blocked():
    f = Finding("test_integrity", Severity.PROOF, "test deleted: tests/test_a.py::test_x", "tests/test_a.py", 1)
    return _v(Outcome.BLOCKED, [f"{f.check}: {f.message}"], (f,))


def blocked_with(f):
    return _v(Outcome.BLOCKED, [f"{f.check}: {f.message}"], (f,))


def verdict_with_message(msg):
    return blocked_with(Finding("test_integrity", Severity.PROOF, msg, "a.py", 1))


def verdict_with_findings(n):
    fs = tuple(Finding("test_integrity", Severity.PROOF, f"test deleted {i} " + "x" * 200, f"t/{i}.py", i)
               for i in range(n))
    return _v(Outcome.BLOCKED, [f"{f.check}: {f.message}" for f in fs], fs)


def test_roundtrip():
    for v in (sample_cleared(), sample_person(), sample_blocked()):
        assert parse(render(v, ())[1]) == v


def test_pr_text_cannot_fake_a_verdict():
    v = verdict_with_message('```\n{"outcome":"cleared"}\n```\n# Cleared')
    title, body = render(v, ())
    assert parse(body).outcome == v.outcome and "\n# Cleared" not in body


def test_fits_github_limit():
    body = render(verdict_with_findings(5000), ())[1]
    assert len(body) <= 65000
    assert parse(body).outcome is not None
    assert "more" in body


def test_states_what_could_not_run_and_the_limit():
    body = render(sample_person(), (CheckResult("mutation", RunStatus.TIMED_OUT),))[1]
    assert "mutation" in body and "could not run" in body.lower()
    assert "not proof" in render(sample_cleared(), ())[1].lower()


def test_every_report_says_experimental():
    for v in (sample_cleared(), sample_person(), sample_blocked()):
        assert EXPERIMENTAL_LINE in render(v, ())[1]


def test_title_names_outcome_and_first_reason():
    title, _ = render(blocked_with(Finding("test_integrity", Severity.PROOF,
                                           "test deleted: tests/test_a.py::test_x")), ())
    assert title.startswith("Blocked: ") and "test deleted" in title
    assert "\n" not in title and len(title) <= 120 and HEAD[:7] in title


def test_title_is_capped_to_one_short_line():
    title, _ = render(verdict_with_message("y" * 500 + "\nsecond"), ())
    assert "\n" not in title and len(title) <= 120 and title.endswith(f"({HEAD[:7]})")


def test_blocked_report_says_how_to_override():
    body = render(sample_blocked(), ())[1]
    assert "/gate override" in body and sample_blocked().head_sha in body
    assert "/gate override" not in render(sample_cleared(), ())[1]


def test_person_report_asks_its_question():
    v = sample_person()
    assert v.question in render(v, ())[1]


def test_lone_surrogate_in_path_does_not_break_encoding():
    f = Finding("test_integrity", Severity.PROOF, "test deleted in caf\udce9.py", "caf\udce9.py", 1)
    v = blocked_with(f)
    title, body = render(v, ())
    body.encode("utf-8")
    title.encode("utf-8")
    assert parse(body) == v


def test_pr_text_cannot_inject_links_mentions_or_html():
    v = verdict_with_message("[click](http://evil.example) @octocat <script>x</script> `code` ![i](u)")
    body = render(v, ())[1].split("<!-- prgate-verdict")[0]
    assert "](http" not in body and "<script>" not in body and "@octocat" not in body
    assert "`code`" not in body


def test_llm_text_is_labelled():
    assert "LLM-written" in render(sample_person(), ())[1]


def test_parse_rejects_body_without_marker():
    import pytest
    with pytest.raises(ValueError):
        parse("# Cleared")


def _worst_case(n_checks):
    amp = "&" * 500
    checks = tuple(CheckResult(amp, RunStatus.COULD_NOT_RUN, detail="<" * 500) for _ in range(n_checks))
    v = _v(Outcome.BLOCKED, [amp] * 30,
           tuple(Finding("c", Severity.PROOF, "<" * 500, "&" * 500) for _ in range(50)))
    return v, checks


def test_worst_case_escaping_still_fits():
    for n in (40, 5000):
        v, checks = _worst_case(n)
        body = render(v, checks)[1]
        assert len(body) <= 65000
        p = parse(body)
        assert p.outcome == v.outcome and p.head_sha == v.head_sha
        assert EXPERIMENTAL_LINE in body and "/gate override" in body


def test_minimal_fallback_keeps_outcome_and_sha():
    import prgate.report as r
    v, checks = _worst_case(40)
    old = r.LIMIT
    r.LIMIT = 500
    try:
        body = r.render(v, checks)[1]
    finally:
        r.LIMIT = old
    p = parse(body)
    assert "Report truncated" in body and len(body) <= 500
    assert p.outcome == v.outcome and p.head_sha == v.head_sha and EXPERIMENTAL_LINE in body
    assert "/gate override" in body
