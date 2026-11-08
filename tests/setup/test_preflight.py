import pytest

from prgate.setup.gh import GhError
from prgate.setup.preflight import parse_remote, preflight
from tests.setup.fakes import FakeGh


def test_free_private_repo_is_refused_without_writes():
    gh = FakeGh(private=True, plan="free")
    p = preflight(gh, "o/r")
    assert not p.ok and any("public" in x and "upgrade" in x.lower() for x in p.problems)
    assert gh.writes == []


def test_unknown_plan_on_private_repo_is_refused():
    p = preflight(FakeGh(private=True, plan=None, protection_probe=403), "o/r")
    assert not p.ok and any("public" in x and "upgrade" in x.lower() for x in p.problems)


def test_unknown_plan_private_probe_unexpected_error_is_refused():
    assert not preflight(FakeGh(private=True, plan=None, protection_probe=500), "o/r").ok


def test_unknown_plan_private_probe_supported_is_ok():
    assert preflight(FakeGh(private=True, plan=None, protection_probe=404), "o/r").ok
    assert preflight(FakeGh(private=True, plan=None, protection_probe=200), "o/r").ok


def test_failing_org_plan_lookup_falls_through_to_probe():
    refused = preflight(FakeGh(private=True, owner_is_org=True, org_plan_error=403, protection_probe=403), "o/r")
    assert not refused.ok and any("upgrade" in x.lower() for x in refused.problems)
    assert preflight(FakeGh(private=True, owner_is_org=True, org_plan_error=403, protection_probe=404), "o/r").ok


def test_org_membership_lookup_failure_is_named_and_fails_closed():
    p = preflight(FakeGh(owner_is_org=True, org_membership_error=403), "o/r")
    text = " ".join(p.problems)
    assert not p.ok and "could not confirm your role in" in text and "gh auth refresh -s read:org" in text
    assert "only an organization owner" not in text


def test_pending_org_admin_is_refused_with_invitation_hint():
    p = preflight(FakeGh(owner_is_org=True, org_role="admin", org_state="pending"), "o/r")
    assert not p.ok and "invitation" in " ".join(p.problems).lower()


def test_repo_from_remote(tmp_path):
    import subprocess
    from prgate.setup.preflight import repo_from_remote
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    with pytest.raises(ValueError):
        repo_from_remote(tmp_path)
    subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin", "git@github.com:o/r.git"], check=True)
    assert repo_from_remote(tmp_path) == "o/r"


@pytest.mark.parametrize("plan", ["pro", "team", "enterprise"])
def test_paid_private_is_ok(plan):
    assert preflight(FakeGh(private=True, plan=plan), "o/r").ok


def test_public_free_is_ok():
    assert preflight(FakeGh(private=False, plan="free"), "o/r").ok


def test_happy_path_is_read_only():
    gh = FakeGh()
    p = preflight(gh, "o/r")
    assert p.ok and p.repo is not None and p.repo.full_name == "o/r" and gh.writes == []


def test_fully_set_up_passes():
    assert preflight(FakeGh.fully_set_up(), "o/r").ok


def test_missing_gh_names_the_fix():
    p = preflight(FakeGh(), "o/r", which=lambda _: None)
    assert not p.ok and "cli.github.com" in p.problems[0]


def test_not_admin_is_refused():
    assert not preflight(FakeGh(permissions={"admin": False, "push": True}), "o/r").ok


def test_missing_workflow_scope_names_refresh_command():
    p = preflight(FakeGh(scopes={"repo"}), "o/r")
    assert not p.ok and "gh auth refresh -s workflow" in " ".join(p.problems)


def test_unknown_scopes_warn_but_continue():
    p = preflight(FakeGh(scopes=None), "o/r")
    assert p.ok and p.warnings


def test_org_repo_where_user_cannot_create_apps_prints_owner_steps():
    p = preflight(FakeGh(owner_is_org=True, org_role="member"), "o/r")
    assert not p.ok and "organization owner" in " ".join(p.problems).lower()


def test_org_admin_is_ok_and_marks_org():
    p = preflight(FakeGh(owner_is_org=True, org_role="admin"), "o/r")
    assert p.ok and p.repo.owner_is_org


def test_problems_are_collected_not_short_circuited():
    gh = FakeGh(private=True, plan="free", scopes={"repo"}, permissions={"admin": False})
    p = preflight(gh, "o/r")
    assert len(p.problems) >= 3 and gh.writes == []


def test_unreadable_repo_is_refused():
    p = preflight(FakeGh(repo="x/y"), "o/r")
    assert not p.ok and p.repo is None


def test_malformed_repo_info_is_refused():
    gh = FakeGh()
    gh.info.pop("owner")
    assert not preflight(gh, "o/r").ok


def test_scopes_lookup_failure_warns():
    class Boom(FakeGh):
        def scopes(self):
            raise GhError(None, "nope")
    p = preflight(Boom(), "o/r")
    assert p.ok and p.warnings


def test_remote_parsing():
    assert parse_remote("git@github.com:o/r.git") == "o/r"
    assert parse_remote("https://github.com/o/r") == "o/r"
    assert parse_remote("https://github.com/o/r.git/") == "o/r"
    assert parse_remote("ssh://git@github.com/o/r.git") == "o/r"
    assert parse_remote("https://GitHub.com/o/r") == "o/r"
    assert parse_remote("git@github.com:org/.github.git") == "org/.github"  # an org's .github repo
    assert parse_remote("https://github.com/o/.dotfiles") == "o/.dotfiles"
    for bad in ["https://example.com/o/r", "https://github.com/o/.git", "https://github.com/../r",
                "https://github.com/o/r.git.git", "https://github.com/./r", "https://github.com/.o/r",
                "https://github.com/o/..", "https://github.com/o/."]:
        with pytest.raises(ValueError):
            parse_remote(bad)
