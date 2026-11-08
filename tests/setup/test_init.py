import subprocess
from pathlib import Path

import pytest

import prgate
from prgate.cli import main
from prgate.setup.files import WORKFLOW_FILE, render_workflow
from prgate.setup.gh import GhError
from prgate.setup.inspect import STEPS, inspect
from prgate.setup.preflight import RepoInfo
from prgate.setup.run import init as _init
from prgate.setup.selftest import BRANCH_PREFIX, run_selftest
from prgate.setup.state import LocalState, state_dir
from tests.setup.fakes import FakeGh, ScriptedPrompter

REF = f"Abubakarjutt/PRGate@v{prgate.__version__}"
SELFTEST_PATHS = ("repos/o/r/git/", "repos/o/r/pulls")
KEY_PUT = ("PUT", "secret/prgate-verdict/PRGATE_APP_KEY")


def init(gh, root, prompter, **kw):
    """`init` with the fake's stand-in browser, so the App manifest flow runs without a real one."""
    kw.setdefault("open_browser", gh.browse)
    kw.setdefault("which", lambda _: "/usr/bin/gh")
    return _init(gh, root, prompter, **kw)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "remote", "add", "origin", "https://github.com/o/r.git")
    for name, text in files.items():
        (root / name).write_text(text)
    return root


def py_repo(tmp_path: Path) -> Path:
    return _repo(tmp_path, {"pyproject.toml": '[project]\nname = "x"\n'})


def ts_repo(tmp_path: Path) -> Path:
    return _repo(tmp_path, {"package.json": '{"devDependencies": {"typescript": "5.0.0"}}', "tsconfig.json": "{}"})


def happy_answers(continue_non_python: bool = True) -> ScriptedPrompter:
    return ScriptedPrompter({"CI checks": "", "Approvers": "owner", "Continue": continue_non_python})


def all_ok() -> list[tuple[str, bool]]:
    return [(s, True) for s in STEPS if s not in ("preflight", "selftest")]


def info() -> RepoInfo:
    return RepoInfo(full_name="o/r", owner="owner", owner_id=7, owner_is_org=False, repo_id=100,
                    private=False, default_branch="main", plan="free")


# --- init --------------------------------------------------------------------------------------------

def test_init_end_to_end_on_fake(tmp_path):
    gh = FakeGh()
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 0
    found = inspect(gh, gh_info(gh), LocalState.load("o/r", tmp_path), render_workflow(REF))
    assert [(f.step, f.ok) for f in found] == all_ok()
    assert gh.secrets["prgate-verdict"] == {"PRGATE_APP_ID", "PRGATE_APP_KEY"}
    assert gh.contents[WORKFLOW_FILE] == render_workflow(REF)
    assert gh.open_prs == [] and not any(b.startswith(BRANCH_PREFIX) for b in gh.branches)


def gh_info(gh: FakeGh) -> RepoInfo:
    from prgate.setup.preflight import preflight
    return preflight(gh, "o/r").repo


def test_second_init_changes_nothing(tmp_path):
    gh = FakeGh()
    init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path)
    before, main_before, apps = len(gh.writes), gh.refs["heads/main"], len(gh.apps)
    assert init(gh, tmp_path / "repo", happy_answers(), home=tmp_path) == 0
    assert [w for w in gh.writes[before:] if not w[1].startswith(SELFTEST_PATHS)] == []
    assert gh.refs["heads/main"] == main_before and len(gh.apps) == apps


def test_lost_key_after_app_creation_reports_delete_link_and_rerun_creates_fresh(tmp_path):
    gh = FakeGh(fail_once={KEY_PUT: 500})
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 1
    slug = next(iter(gh.apps))
    assert any(f"https://github.com/settings/apps/{slug}" in s for s in p.said)
    again = FakeGh.resume(gh)
    assert init(again, tmp_path / "repo", happy_answers(), home=tmp_path) == 0
    assert len(again.apps) == 2


def test_free_private_init_changes_nothing(tmp_path):
    gh = FakeGh(private=True, plan="free")
    assert init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path) == 1 and gh.writes == []


def test_files_and_workflow_check_come_before_the_app(tmp_path):
    gh = FakeGh(); init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path)
    paths = [p for _, p in gh.writes]
    first_app = next(i for i, p in enumerate(paths) if "app-manifests" in p)
    first_file = next(i for i, p in enumerate(paths) if "/git/" in p or "/contents/" in p)
    assert first_file < first_app


def test_app_key_is_stored_at_once_in_an_environment_already_limited_to_the_default_branch(tmp_path):
    gh = FakeGh(); init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path)
    kinds = [(m, p) for m, p in gh.writes]
    conv = next(i for i, (m, p) in enumerate(kinds) if "app-manifests" in p)
    env = next(i for i, (m, p) in enumerate(kinds) if p.endswith("/deployment-branch-policies"))
    secrets = [i for i, (m, p) in enumerate(kinds) if m == "SECRET"]
    assert env < conv and secrets == [conv + 1, conv + 2]


def test_unsafe_workflow_means_no_app_and_exit_1(tmp_path):
    gh = FakeGh(contents={".github/workflows/x.yml": "environment: prgate-verdict"})
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 1 and gh.apps == {}
    assert "prgate-verdict" not in gh.environments and any("x.yml" in s for s in p.said)


def test_workflow_warnings_are_printed_and_init_goes_on(tmp_path):
    gh = FakeGh(contents={".github/workflows/deploy.yml": "jobs:\n  d:\n    environment: ${{ inputs.env }}\n"})
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 0
    assert any("deploy.yml" in s and "expression" in s for s in p.said)


def test_protected_branch_pr_not_merged_exits_0_without_app(tmp_path):
    gh = FakeGh(protected=True, merge_after_s=None)
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path, merge_wait_s=1) == 0 and gh.apps == {}
    assert any("re-run prgate init" in s for s in p.said)
    assert any("merge the prgate setup PR, then re-run prgate init" in s for s in p.said)


def test_protected_branch_pr_merged_in_time_goes_on(tmp_path):
    gh = FakeGh(protected=True, merge_after_s=0)
    assert init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path, merge_wait_s=5) == 0
    assert len(gh.apps) == 1 and gh.contents[WORKFLOW_FILE] == render_workflow(REF)


def test_non_python_repo_warns_and_stops_by_default(tmp_path):
    p = happy_answers(continue_non_python=False)
    gh = FakeGh()
    assert init(gh, ts_repo(tmp_path), p, home=tmp_path) == 1
    assert any("Python tests only" in s for s in p.said)
    assert any("prgate 0.x checks Python tests only; secrets and change types are still checked" in s for s in p.said)
    assert gh.writes == []


def test_summary_says_experimental(tmp_path):
    p = happy_answers(); init(FakeGh(), py_repo(tmp_path), p, home=tmp_path)
    assert any("experimental and report-only" in s for s in p.said)
    summary = next(s for s in p.said if "Setup steps:" in s)
    assert summary.splitlines()[0] == f"prgate {prgate.__version__} is experimental and report-only."
    for step in STEPS:
        assert any(line.strip().startswith(f"{step}:") for line in summary.splitlines())


def test_summary_marks_steps_already_set_on_a_second_run(tmp_path):
    gh = FakeGh(); init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path)
    p = happy_answers(); init(gh, tmp_path / "repo", p, home=tmp_path)
    summary = next(s for s in p.said if "Setup steps:" in s)
    assert "gate_app: already set" in summary and "files: already set" in summary


def test_no_secret_in_any_output(tmp_path, capsys):
    gh = FakeGh()
    p = happy_answers()
    init(gh, py_repo(tmp_path), p, home=tmp_path)
    lost = FakeGh(fail_secret=True)  # its error message echoes the value, as a careless CLI might
    q = happy_answers()
    other = tmp_path / "b"
    other.mkdir()
    assert init(lost, py_repo(other), q, home=other) == 1
    out = capsys.readouterr()
    text = out.out + out.err + "\n".join(p.said + q.said)
    assert FakeGh.PEM_MARK not in text and "BEGIN RSA" not in text
    for f in (tmp_path / ".config").rglob("*"):
        if f.is_file():
            assert "BEGIN" not in f.read_text()


@pytest.mark.parametrize("stop", [KeyboardInterrupt, EOFError])
def test_ctrl_c_or_ctrl_d_names_the_step_and_says_rerun(tmp_path, stop):
    class Stops(ScriptedPrompter):
        def ask(self, q, default=None):
            raise stop()
    p = Stops({})
    assert init(FakeGh(), py_repo(tmp_path), p, home=tmp_path) == 130
    assert any("re-run prgate init to continue" in s for s in p.said)


def test_ctrl_c_while_storing_the_key_gives_the_delete_link(tmp_path):
    gh = FakeGh()

    def interrupted(*a):
        raise KeyboardInterrupt
    gh.set_env_secret = interrupted
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 130
    slug = next(iter(gh.apps))
    assert any(f"settings/apps/{slug}" in s for s in p.said) and any("re-run prgate init" in s for s in p.said)


def test_local_state_holds_no_secrets_and_is_private(tmp_path):
    gh = FakeGh(); init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path)
    d = state_dir("o/r", tmp_path)
    f = d / "state.json"
    assert oct(d.stat().st_mode & 0o777) == "0o700" and oct(f.stat().st_mode & 0o777) == "0o600"
    assert "BEGIN" not in f.read_text() and FakeGh.PEM_MARK not in f.read_text()
    assert LocalState.load("o/r", tmp_path).gate_app_slug in gh.apps


def test_dev_options_render_into_the_workflow(tmp_path):
    gh = FakeGh()
    ref, url = "o2/prgate@" + "a" * 40, "https://test.pypi.org/simple/"
    assert init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path, action_ref=ref, index_url=url) == 0
    wf = gh.contents[WORKFLOW_FILE]
    assert wf == render_workflow(ref, index_url=url) and wf.count(f"index-url: {url}") == 2


# --- self-test --------------------------------------------------------------------------------------

def test_selftest_requires_check_from_the_gate_app():
    gh = FakeGh(check_on_selftest={"name": "pr-gate", "app_id": 999})
    f = run_selftest(gh, info(), gate_app_id=42, timeout_s=1, poll_s=0.1)
    assert not f.ok and f.step == "selftest" and "another App" in f.detail


def test_selftest_passes_on_a_neutral_check_from_the_gate_app_and_cleans_up():
    gh = FakeGh(check_on_selftest={"name": "pr-gate", "app_id": 42})
    assert run_selftest(gh, info(), gate_app_id=42, timeout_s=1).ok
    assert gh.open_prs == [] and not any(b.startswith(BRANCH_PREFIX) for b in gh.branches)
    assert gh.blob_paths == ["prgate-selftest.txt"]


def test_selftest_refuses_a_conclusion_other_than_neutral():
    gh = FakeGh(check_on_selftest={"name": "pr-gate", "app_id": 42, "conclusion": "success"})
    assert not run_selftest(gh, info(), gate_app_id=42, timeout_s=1, poll_s=0.1).ok


def test_selftest_cleans_up_on_timeout():
    gh = FakeGh(check_on_selftest=None)
    assert not run_selftest(gh, info(), 42, timeout_s=1, poll_s=0.1).ok
    assert gh.open_prs == [] and not any(b.startswith(BRANCH_PREFIX) for b in gh.branches)


# --- CLI ---------------------------------------------------------------------------------------------

def test_dev_options_need_the_env_var(monkeypatch, capsys):
    monkeypatch.delenv("PRGATE_DEV", raising=False)
    assert main(["init", "--index-url", "https://test.pypi.org/simple/"]) == 2
    assert main(["init", "--action-ref", "o/r@v1"], gh=FakeGh()) == 2
    assert main(["doctor", "--action-ref", "o/r@v1"], gh=FakeGh()) == 2
    assert "development option; set PRGATE_DEV=1" in capsys.readouterr().err


def test_dev_options_are_hidden_from_help(capsys):
    for cmd in ("init", "doctor"):
        assert main([cmd, "--help"]) == 0
        out = capsys.readouterr().out
        assert "--action-ref" not in out and "--index-url" not in out and "--prgate-source" not in out


def test_prgate_source_does_not_exist():
    assert main(["init", "--prgate-source", "x"], env={"PRGATE_DEV": "1"}, gh=FakeGh()) == 2


def test_dev_option_with_a_bad_value_exits_2(capsys):
    assert main(["init", "--index-url", "http://plain.example/"], env={"PRGATE_DEV": "1"}, gh=FakeGh()) == 2


def test_cli_init_and_doctor_use_the_injected_gh_and_prompter(tmp_path, monkeypatch):
    root = py_repo(tmp_path)
    monkeypatch.chdir(root)
    monkeypatch.setenv("HOME", str(tmp_path))
    free = FakeGh(private=True, plan="free")
    p = happy_answers()
    assert main(["init"], env={}, gh=free, prompter=p) == 1 and free.writes == []
    assert any("free plan" in s for s in p.said)
    done = FakeGh.fully_set_up()
    q = ScriptedPrompter({})
    assert main(["doctor"], env={}, gh=done, prompter=q) == 0 and done.writes == []
    other = FakeGh.fully_set_up()
    assert main(["doctor", "--action-ref", "o/r@v9"], env={"PRGATE_DEV": "1"}, gh=other, prompter=q) == 1


# --- fix round 1: only an owner-verified gate App is trusted -----------------------------------------

MALLORY = {"login": "mallory", "id": 99, "type": "User"}
REPLACE = "Create a new gate App"


def _secret_writes(gh: FakeGh) -> list:
    return [w for w in gh.writes if w[0] == "SECRET"]


def test_a_single_foreign_prgate_app_is_not_trusted(tmp_path):
    gh = FakeGh()
    gh.add_app("prgate-evil", 66, owner=MALLORY)
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 0
    ours = LocalState.load("o/r", tmp_path)
    assert ours.gate_app_slug != "prgate-evil" and ours.gate_app_slug in gh.apps and len(gh.apps) == 2
    assert not any("prgate-evil" in s for s in p.said)
    summary = next(s for s in p.said if "Setup steps:" in s)
    assert "gate_app: done" in summary and "selftest: passed" in summary


def test_selftest_ignores_the_foreign_apps_check(tmp_path):
    gh = FakeGh(check_on_selftest={"name": "pr-gate", "app_id": 66})
    gh.add_app("prgate-evil", 66, owner=MALLORY)
    assert init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path, selftest_timeout_s=0.2) == 1


def test_two_owned_matches_ask_before_replacing_the_secrets(tmp_path):
    gh = FakeGh.fully_set_up()
    gh.add_app("prgate-r-aaaaaa", 2)
    p = ScriptedPrompter({"CI checks": "", "Approvers": "owner", REPLACE: False})
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 1
    assert _secret_writes(gh) == [] and not any("app-manifests" in w[1] for w in gh.writes)
    assert any("prgate" in s and "prgate-r-aaaaaa" in s for s in p.said)
    assert not any("settings/apps/" in s for s in p.said)


def test_two_owned_matches_replaced_when_the_user_agrees(tmp_path):
    gh = FakeGh.fully_set_up()
    gh.add_app("prgate-r-aaaaaa", 2)
    p = ScriptedPrompter({"CI checks": "", "Approvers": "owner", REPLACE: True})
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 0
    assert len(_secret_writes(gh)) == 2 and len(gh.apps) == 3


def test_no_verified_app_with_secrets_present_asks_before_overwriting(tmp_path):
    gh = FakeGh.fully_set_up()
    gh.apps.clear(); gh.installations.clear()
    p = ScriptedPrompter({"CI checks": "", "Approvers": "owner", REPLACE: False})
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 1
    assert _secret_writes(gh) == [] and gh.apps == {}


def test_local_state_slug_whose_owner_changed_is_not_trusted(tmp_path):
    gh = FakeGh.fully_set_up()
    gh.apps["prgate"]["owner"] = MALLORY
    LocalState(1, "prgate").save("o/r", tmp_path)
    p = ScriptedPrompter({"CI checks": "", "Approvers": "owner", REPLACE: False})
    assert init(gh, py_repo(tmp_path), p, home=tmp_path) == 1
    assert _secret_writes(gh) == [] and not any("settings/apps/prgate" in s for s in p.said)


def test_org_repo_app_must_be_owned_by_the_org(tmp_path):
    gh = FakeGh.fully_set_up(owner_is_org=True)
    assert gh.apps["prgate"]["owner"]["login"] == "o"
    q = ScriptedPrompter({})
    from prgate.setup.run import doctor
    assert doctor(gh, "o/r", q, home=tmp_path, which=lambda _: "gh") == 0
    gh.apps["prgate"]["owner"] = {"login": "owner", "id": 7, "type": "User"}  # the user, not the org
    q = ScriptedPrompter({})
    assert doctor(gh, "o/r", q, home=tmp_path, which=lambda _: "gh") == 1


# --- fix round 1: clean failures ----------------------------------------------------------------------

@pytest.mark.parametrize("browser", ["interrupt", "timeout"])
def test_stopping_during_app_creation_says_where_to_delete_an_app(tmp_path, browser):
    def interrupt(url):
        raise KeyboardInterrupt
    gh = FakeGh()
    p = happy_answers()
    kw = {"open_browser": interrupt} if browser == "interrupt" else {"open_browser": lambda u: True, "app_timeout_s": 0.2}
    rc = init(gh, py_repo(tmp_path), p, home=tmp_path, **kw)
    assert rc == (130 if browser == "interrupt" else 1)
    assert any("https://github.com/settings/apps" in s and "its key was not kept" in s for s in p.said)


def test_a_bad_config_value_stops_with_one_line_not_a_traceback(tmp_path):
    p = ScriptedPrompter({"CI checks": "bad\ud800", "Approvers": "owner"})
    assert init(FakeGh(), py_repo(tmp_path), p, home=tmp_path) == 1
    assert any("stopped at step files" in s and "Unicode" in s for s in p.said)


def test_setup_pr_closed_without_merging_stops_waiting(tmp_path):
    import time
    gh = FakeGh(protected=True, close_setup_pr=True)
    p = happy_answers()
    start = time.monotonic()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path, merge_wait_s=60) == 1
    assert time.monotonic() - start < 15 and gh.apps == {}
    assert any("closed without" in s for s in p.said)


def test_selftest_deletes_the_branch_name_it_tried_even_when_the_ref_post_fails():
    gh = FakeGh(fail_once={("POST", "repos/o/r/git/refs"): 502})
    f = run_selftest(gh, info(), 42, timeout_s=0.2, poll_s=0.1)
    assert not f.ok and "by hand" not in f.detail
    assert any(m == "DELETE" and BRANCH_PREFIX in p for m, p in gh.writes)


def test_selftest_says_what_is_left_when_interrupted():
    gh = FakeGh(check_on_selftest=None)
    real = gh.api

    def api(method, path, body=None):
        if method == "GET" and "check-runs" in path:
            raise KeyboardInterrupt
        if method == "PATCH" and "/pulls/" in path:
            raise GhError(500, "boom (HTTP 500)")
        return real(method, path, body)
    gh.api = api
    said: list[str] = []
    with pytest.raises(KeyboardInterrupt):
        run_selftest(gh, info(), 42, timeout_s=1, poll_s=0.1, say=said.append)
    assert any("close PR #1" in s for s in said)


def test_merge_wait_survives_a_transient_read_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("prgate.setup.run._MERGE_POLL_S", 0.01)
    gh = FakeGh(protected=True, close_setup_pr=True, fail_once={("GET", "repos/o/r/pulls/1"): 502})
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path, merge_wait_s=30) == 1
    assert ("GET", "repos/o/r/pulls/1") not in gh.fail_once  # the failure happened and was retried
    assert any("closed without" in s for s in p.said)


def test_merge_wait_gives_up_at_the_deadline_when_reads_keep_failing(tmp_path, monkeypatch):
    monkeypatch.setattr("prgate.setup.run._MERGE_POLL_S", 0.01)
    gh = FakeGh(protected=True, merge_after_s=None)
    real = gh.api

    def flaky(method, path, *a, **k):
        if method == "GET" and path.startswith("repos/o/r/pulls/"):
            raise GhError(503, "unavailable")
        return real(method, path, *a, **k)
    monkeypatch.setattr(gh, "api", flaky)
    p = happy_answers()
    assert init(gh, py_repo(tmp_path), p, home=tmp_path, merge_wait_s=0.5) == 0 and gh.apps == {}
    assert any("merge the prgate setup PR, then re-run prgate init" in s for s in p.said)


def test_new_app_hint_warns_about_other_repositories(tmp_path):
    gh = FakeGh()
    init(gh, py_repo(tmp_path), happy_answers(), home=tmp_path)
    gh.secrets["prgate-verdict"] = {"PRGATE_APP_ID"}
    p = happy_answers()
    init(gh, tmp_path / "repo", p, home=tmp_path)
    assert any("unless another repository uses it" in s for s in p.said)


def test_summary_speaks_to_strangers_about_enforce_mode(tmp_path):
    p = happy_answers()
    init(FakeGh(), py_repo(tmp_path), p, home=tmp_path)
    text = "\n".join(p.said)
    assert "in a later release" in text and "after the proof" not in text
