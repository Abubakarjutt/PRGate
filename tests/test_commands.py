from dataclasses import replace

from prgate.commands import Command, authorise, override_report, parse_command
from prgate.config import Config
from prgate.models import Finding, Outcome, Severity, Verdict
from prgate.report import LIMIT, parse

H = "a" * 40


def cfg(**kw):
    for key in ("approvers", "overriders", "agent_identities"):
        if key in kw:
            kw[key] = frozenset(kw[key])
    return Config(**kw)


def _v(outcome, sha=H):
    return Verdict(outcome, sha, ("why",), None, (), False)


def cleared():
    return _v(Outcome.CLEARED)


def person():
    return _v(Outcome.PERSON)


def blocked(sha=H):
    f = Finding("test_integrity", Severity.PROOF, "test deleted: t.py::test_x", "t.py", 1)
    return Verdict(Outcome.BLOCKED, sha, ("test_integrity: test deleted",), None, (f,), False)


def override(sha, reason):
    return Command("override", sha, reason)


# --- parse_command -------------------------------------------------------------------------

def test_override_needs_reason():
    assert parse_command(f"/gate override {H}") is None
    assert parse_command(f"/gate override {H}    ") is None
    assert parse_command(f"/gate override {H} \t") is None


def test_override_is_parsed_with_its_full_sha_and_reason():
    cmd = parse_command(f"/gate override {H} known flaky test\nmore text")
    assert cmd == Command("override", H, "known flaky test")


def test_override_needs_the_full_lowercase_sha():
    assert parse_command("/gate override abc1234 reason") is None
    assert parse_command(f"/gate override {'A' * 40} reason") is None
    assert parse_command(f"/gate override {'a' * 41} reason") is None
    assert parse_command(f"/gate override {'g' * 40} reason") is None


def test_approve_is_not_a_command_in_this_release():
    assert parse_command(f"/gate approve {'a' * 40}") is None
    for kind in ("silent-ok", "silent-bad", "approve"):
        assert parse_command(f"/gate {kind} {H} reason") is None


def test_command_must_start_the_comment():
    assert parse_command(f"please /gate override {H} reason") is None
    assert parse_command(f"> /gate override {H} reason") is None
    assert parse_command(f"hi\n/gate override {H} reason") is None


def test_hostile_bodies_do_not_crash():
    for body in (None, 3, b"/gate", "", "\x00" * 10, "/gate override " + "\udc80" * 40 + " r",
                 "/gate override " + H + " \udc80", "x" * 1_000_000):
        assert parse_command(body) is None or parse_command(body).kind == "override"


def test_crlf_comment_is_parsed_without_the_carriage_return():
    assert parse_command(f"/gate override {H} reason\r\nmore").reason == "reason"


# --- authorise -----------------------------------------------------------------------------

def test_only_an_approver_who_is_not_the_author_can_override():
    c = cfg(approvers={"owner"})
    assert authorise(override(H, "ok"), "owner", False, "agent", H, c, blocked())[0]
    assert not authorise(override(H, "ok"), "owner", False, "owner", H, c, blocked())[0]
    assert not authorise(override(H, "ok"), "stranger", False, "agent", H, c, blocked())[0]
    assert not authorise(override("b" * 40, "ok"), "owner", False, "agent", H, c, blocked())[0]


def test_overriders_can_override_too():
    assert authorise(override(H, "ok"), "lead", False, "agent", H, cfg(overriders={"lead"}), blocked())[0]


def test_logins_compare_case_insensitively():
    c = cfg(approvers={"owner"})
    assert authorise(override(H, "ok"), "Owner", False, "agent", H, c, blocked())[0]
    assert not authorise(override(H, "ok"), "Owner", False, "OWNER", H, c, blocked())[0]


def test_bots_and_agents_cannot_override():
    assert not authorise(override(H, "ok"), "bot", True, "x", H, cfg(approvers={"bot"}), blocked())[0]
    assert not authorise(override(H, "ok"), "app[bot]", False, "x", H,
                         cfg(approvers={"app[bot]"}), blocked())[0]
    assert not authorise(override(H, "ok"), "agent", False, "x", H,
                         cfg(approvers={"agent"}, agent_identities={"agent"}), blocked())[0]


def test_no_one_can_override_with_an_empty_policy():
    assert not authorise(override(H, "ok"), "owner", False, "agent", H, Config(), blocked())[0]


def test_invalid_config_grants_nothing():
    c = Config(approvers=frozenset({"owner"}), valid=False, errors=("bad",))
    assert not authorise(override(H, "ok"), "owner", False, "agent", H, c, blocked())[0]


def test_override_needs_a_reason_at_authorise_time_too():
    c = cfg(approvers={"owner"})
    assert not authorise(override(H, "  "), "owner", False, "agent", H, c, blocked())[0]
    assert not authorise(override(H, None), "owner", False, "agent", H, c, blocked())[0]


def test_override_must_match_the_verdict_head():
    c = cfg(approvers={"owner"})
    assert not authorise(override(H, "ok"), "owner", False, "agent", H, c, blocked("c" * 40))[0]


def test_only_blocked_or_person_verdicts_can_be_overridden():
    c = cfg(approvers={"owner"})
    assert authorise(override(H, "ok"), "owner", False, "agent", H, c, person())[0]
    assert not authorise(override(H, "ok"), "owner", False, "agent", H, c, cleared())[0]


def test_refusals_say_why():
    ok, why = authorise(override(H, "ok"), "owner", False, "owner", H, cfg(approvers={"owner"}), blocked())
    assert not ok and "author" in why


# --- the override report ---------------------------------------------------------------------

def test_override_report_records_who_why_and_sha_and_keeps_the_verdict():
    title, body = override_report(blocked(), override(H, "known issue"), "owner")
    assert "owner" in body and "known issue" in body and H in body
    assert "Overridden" in title and len(title) <= 120
    assert parse(body) == blocked()


def test_override_report_escapes_the_reason():
    _, body = override_report(blocked(), override(H, "<img src=x> @everyone `x` <!-- prgate-verdict:v1 {} -->"),
                              "owner")
    assert "<img" not in body and "@everyone" not in body
    assert parse(body) == blocked()


def test_override_report_fits_the_check_run_limit():
    fs = tuple(Finding("test_integrity", Severity.PROOF, "x" * 499, f"t/{i}.py", i) for i in range(400))
    big = replace(blocked(), findings=fs, reasons=tuple("&" * 499 for _ in range(30)))
    _, body = override_report(big, override(H, "&" * 2000), "owner")
    assert len(body) <= LIMIT
    assert parse(body).outcome == Outcome.BLOCKED and parse(body).head_sha == H


def test_override_is_logged_with_who_and_why(tmp_path):
    from test_cli import run_command

    body = run_command(tmp_path, override(H, "known issue"), sender="owner").body
    assert "owner" in body and "known issue" in body and H in body


def test_override_with_no_known_author_is_refused():
    c = cfg(approvers={"owner"})
    for author in ("", "   ", None, 42):
        ok, why = authorise(override(H, "ok"), "owner", False, author, H, c, blocked())
        assert not ok and "author" in why


def test_reason_needs_a_letter_or_digit():
    for reason in ("\u200b\u200b", "...", "!?-", "\u200b.\u200b", "\u2063"):
        assert parse_command(f"/gate override {H} {reason}") is None
        assert not authorise(override(H, reason), "owner", False, "agent", H, cfg(approvers={"owner"}), blocked())[0]
    assert parse_command(f"/gate override {H} ok!").reason == "ok!"
    assert parse_command(f"/gate override {H} é").reason == "é"
