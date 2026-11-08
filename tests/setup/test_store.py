import pytest

from prgate.setup.gh import GhError, redact_secret
from prgate.setup.preflight import RepoInfo
from prgate.setup.store import ENV_VERDICT, SetupAborted, SECRET_APP_ID, SECRET_APP_KEY, ensure_environment, store_secret
from tests.setup.fakes import FakeGh


def info(default_branch: str = "main") -> RepoInfo:
    return RepoInfo(full_name="o/r", owner="o", owner_id=7, owner_is_org=False, repo_id=100,
                    private=False, default_branch=default_branch, plan="free")


def test_names():
    assert ENV_VERDICT == "prgate-verdict"
    assert (SECRET_APP_ID, SECRET_APP_KEY) == ("PRGATE_APP_ID", "PRGATE_APP_KEY")


def test_environment_allows_only_default_branch():
    gh = FakeGh(default_branch="main")
    ensure_environment(gh, info(), ENV_VERDICT); ensure_environment(gh, info(), ENV_VERDICT)
    assert gh.environments[ENV_VERDICT]["branch_policies"] == ["main"]


def test_environment_put_restricts_to_custom_branch_policies():
    gh = FakeGh()
    ensure_environment(gh, info(), ENV_VERDICT)
    assert gh.environments[ENV_VERDICT]["deployment_branch_policy"] == {"protected_branches": False,
                                                                        "custom_branch_policies": True}


def test_environment_removes_other_policies_and_duplicates():
    gh = FakeGh(environments={ENV_VERDICT: {"branch_policies": ["dev", "main", "release/*", "main"]}})
    ensure_environment(gh, info(), ENV_VERDICT)
    assert gh.environments[ENV_VERDICT]["branch_policies"] == ["main"]
    assert not any(m == "POST" for m, _ in gh.writes)  # "main" was already there


def test_environment_adds_the_missing_default_branch():
    gh = FakeGh(default_branch="trunk", environments={ENV_VERDICT: {"branch_policies": ["main"]}})
    ensure_environment(gh, info("trunk"), ENV_VERDICT)
    assert gh.environments[ENV_VERDICT]["branch_policies"] == ["trunk"]


def test_environment_handles_more_than_one_page_of_policies():
    gh = FakeGh(environments={ENV_VERDICT: {"branch_policies": [f"b{i}" for i in range(150)]}})
    ensure_environment(gh, info(), ENV_VERDICT)
    assert gh.environments[ENV_VERDICT]["branch_policies"] == ["main"]


def test_environment_on_fully_set_up_repo_changes_no_policy():
    gh = FakeGh.fully_set_up()
    ensure_environment(gh, info(), ENV_VERDICT)
    assert gh.environments[ENV_VERDICT]["branch_policies"] == ["main"]
    assert [w for w in gh.writes if "deployment-branch-policies" in w[1]] == []


def test_secret_is_stored_without_the_value_in_the_log():
    gh = FakeGh()
    store_secret(gh, info(), ENV_VERDICT, SECRET_APP_KEY, "KEY-VALUE")
    assert SECRET_APP_KEY in gh.secrets[ENV_VERDICT]
    assert not any("KEY-VALUE" in part for w in gh.writes for part in w)


def test_secret_never_printed_even_on_failure(capsys):
    gh = FakeGh(fail_secret=True)
    with pytest.raises(GhError) as e:
        store_secret(gh, info(), ENV_VERDICT, "PRGATE_APP_KEY", "KEY-VALUE")
    out = capsys.readouterr()
    assert "KEY-VALUE" not in out.out + out.err
    assert "KEY-VALUE" not in str(e.value) and "KEY-VALUE" not in e.value.message
    assert e.value.__cause__ is None and e.value.__context__ is None
    assert e.value.status == 500


def test_secret_failure_of_another_kind_is_a_gh_error_without_the_value():
    class Boom:
        def set_env_secret(self, repo, env, name, value):
            raise RuntimeError(f"broke on {value}")

    with pytest.raises(GhError) as e:
        store_secret(Boom(), info(), ENV_VERDICT, SECRET_APP_KEY, "KEY-VALUE")
    assert "KEY-VALUE" not in str(e.value) and e.value.__context__ is None


def test_multiline_secret_lines_are_scrubbed_from_errors():
    pem = "-----BEGIN KEY-----\nAAAABBBBCCCCDDDD\n-----END KEY-----\n"

    class Echo:
        def set_env_secret(self, repo, env, name, value):
            raise GhError(400, "bad line: AAAABBBBCCCCDDDD (HTTP 400)")

    with pytest.raises(GhError) as e:
        store_secret(Echo(), info(), ENV_VERDICT, SECRET_APP_KEY, pem)
    assert "AAAABBBBCCCCDDDD" not in e.value.message and e.value.status == 400


@pytest.mark.parametrize("name", ["", "lower", "GITHUB_TOKEN", "A-B", "1ABC"])
def test_bad_secret_names_are_refused(name):
    with pytest.raises(ValueError):
        store_secret(FakeGh(), info(), ENV_VERDICT, name, "v")


@pytest.mark.parametrize("branch", ["rel*", "a?b", "x[1]", "x]", "{a,b}", "a}"])
def test_glob_characters_in_the_default_branch_are_refused(branch):
    gh = FakeGh(default_branch=branch)
    with pytest.raises(SetupAborted) as e:
        ensure_environment(gh, info(branch), ENV_VERDICT)
    assert "can't be used safely in a branch policy" in str(e.value) and branch in str(e.value)
    assert gh.writes == []


def test_a_policy_created_concurrently_is_accepted_after_a_re_list():
    gh = FakeGh(policy_race=True)
    ensure_environment(gh, info(), ENV_VERDICT)
    assert gh.environments[ENV_VERDICT]["branch_policies"] == ["main"]


def test_a_422_on_the_policy_post_without_the_policy_is_an_error():
    gh = FakeGh(fail_once={("POST", f"repos/o/r/environments/{ENV_VERDICT}/deployment-branch-policies"): 422})
    with pytest.raises(GhError):
        ensure_environment(gh, info(), ENV_VERDICT)


def test_fake_rejects_a_duplicate_policy():
    gh = FakeGh(environments={ENV_VERDICT: {"branch_policies": ["main"]}})
    with pytest.raises(GhError) as e:
        gh.api("POST", f"repos/o/r/environments/{ENV_VERDICT}/deployment-branch-policies", {"name": "main"})
    assert e.value.status == 422


def test_shared_redaction_helper():
    pem = "-----BEGIN KEY-----\nAAAABBBBCCCCDDDD\nshort\n-----END KEY-----\n"
    out = redact_secret(f"x {pem} y AAAABBBBCCCCDDDD short", pem)
    assert "AAAABBBBCCCCDDDD" not in out and pem not in out and "short" in out
    assert redact_secret("nothing", "") == "nothing"
