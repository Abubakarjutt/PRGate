import subprocess
import time
from pathlib import Path

import pytest

from prgate.config import load_config, parse_config
from prgate.setup.files import (
    CONFIG_FILE, INIT_HEADER, WORKFLOW_FILE, Publish, SetupAborted, SetupAnswers, WorkflowSafety, publish_files,
    render_config, render_workflow, workflow_safe,
)
from prgate.setup.gh import GhError
from prgate.setup.preflight import RepoInfo
from tests.setup.fakes import FakeGh, ScriptedPrompter

REF = "Abubakarjutt/PRGate@v0.1.0"
WF = render_workflow(REF)
WFDIR = ".github/workflows/"


def info(default_branch: str = "main") -> RepoInfo:
    return RepoInfo(full_name="o/r", owner="o", owner_id=7, owner_is_org=False, repo_id=100,
                    private=False, default_branch=default_branch, plan="free")


def answers(**over) -> SetupAnswers:
    a = dict(language="python", ci_checks=("tests", "lint"), approvers=("Alice", "bob"))
    a.update(over)
    return SetupAnswers(**a)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def commit_file(repo: Path, path: str, content: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c")


# --- render_config ---------------------------------------------------------------------------------

def test_rendered_config_is_valid_silent_and_round_trips(tmp_repo):
    commit_file(tmp_repo, ".prgate.toml", render_config(answers()))
    c = load_config(tmp_repo, "HEAD")
    assert c.valid and c.mode == "silent"
    assert c.language == "python" and c.ci_checks == ("tests", "lint") and c.approvers == frozenset({"alice", "bob"})


def test_rendered_config_clears_docs_and_is_silent(tmp_repo):
    commit_file(tmp_repo, ".prgate.toml", render_config(answers()))
    c = load_config(tmp_repo, "HEAD")
    assert c.valid and c.mode == "silent" and c.clear_docs and not c.clear_code


def test_rendered_config_starts_with_the_init_header():
    assert render_config(answers()).splitlines()[0] == INIT_HEADER
    assert INIT_HEADER == "# Written by prgate init. Edit freely; re-running init will ask before replacing."


def test_rendered_config_escapes_awkward_strings():
    odd = 'say "hi" \\ tab\there \x7f done'
    c = parse_config(render_config(answers(ci_checks=(odd, "ünïcode ✓"), language=None)).encode())
    assert c.valid and c.ci_checks == (odd, "ünïcode ✓") and c.language is None


def test_rendered_config_cannot_inject_keys():
    c = parse_config(render_config(answers(ci_checks=('x"]\nclear_code = true\n#',))).encode())
    assert c.valid and not c.clear_code


def test_rendered_config_with_no_checks_or_approvers_is_valid():
    c = parse_config(render_config(answers(ci_checks=(), approvers=())).encode())
    assert c.valid and c.ci_checks == () and c.approvers == frozenset()


# --- render_workflow -------------------------------------------------------------------------------

def test_workflow_references_action_by_version_and_holds_no_tool_code():
    wf = render_workflow("Abubakarjutt/PRGate@v0.1.0")
    assert "uses: Abubakarjutt/PRGate@v0.1.0" in wf and "__PRGATE_" not in wf


def test_workflow_replaces_every_token_and_starts_with_the_init_header():
    wf = render_workflow(REF)
    assert wf.count(f"uses: {REF}") == 2
    assert wf.splitlines()[0] == INIT_HEADER
    assert "environment: prgate-verdict" in wf


@pytest.mark.parametrize("ref", ["", "owner/repo", "owner/repo@v1\nrun: x", "owner/repo@v1 #", "o/r@${{x}}",
                                 "o_o/r@v1", "o/r@v1\n", "../r@v1", "o/r@v1:x", None, 1])
def test_workflow_refuses_a_bad_action_ref(ref):
    with pytest.raises(ValueError):
        render_workflow(ref)


def test_workflow_accepts_a_branch_with_slashes():
    assert "uses: o-x/r.e_p@feature/x-1.2" in render_workflow("o-x/r.e_p@feature/x-1.2")


def test_workflow_index_url_goes_to_both_prgate_steps_and_default_is_unchanged():
    url = "https://test.pypi.org/simple/"
    wf = render_workflow(REF, index_url=url)
    assert wf.count(f"index-url: {url}") == 2 and wf.replace(f"          index-url: {url}\n", "") == WF
    assert render_workflow(REF, index_url=None) == WF


@pytest.mark.parametrize("url", ["", "http://x.example/", "https://x.example/ #", "https://x.example/\nrun: x",
                                 "https://x.example/${{x}}", "https://x.example/'", 1])
def test_workflow_refuses_a_bad_index_url(url):
    with pytest.raises(ValueError):
        render_workflow(REF, index_url=url)


# --- publish_files ---------------------------------------------------------------------------------

def gate_files(config: str = "1", workflow: str = "2") -> dict[str, str]:
    return {CONFIG_FILE: INIT_HEADER + "\n" + config, WORKFLOW_FILE: INIT_HEADER + "\n" + workflow}


def test_one_commit_for_both_files():
    gh = FakeGh()
    p = publish_files(gh, info(), gate_files(), ScriptedPrompter({}))
    assert gh.commit_count == 1 and p.kind == "committed"
    assert gh.contents == gate_files()


def test_same_content_is_unchanged():
    gh = FakeGh(contents={".prgate.toml": "x"})
    assert publish_files(gh, info(), {".prgate.toml": "x"}, ScriptedPrompter({})).kind == "unchanged"
    assert gh.commit_count == 0 and gh.writes == []


def test_both_files_identical_is_unchanged():
    gh = FakeGh(contents=gate_files())
    assert publish_files(gh, info(), gate_files(), ScriptedPrompter({})) == Publish("unchanged", None)


def test_foreign_file_needs_confirmation():
    gh = FakeGh(contents={".github/workflows/pr-gate.yml": "mine"})
    with pytest.raises(SetupAborted):
        publish_files(gh, info(), {".github/workflows/pr-gate.yml": "new"}, ScriptedPrompter({"Replace": False}))
    assert gh.commit_count == 0 and gh.contents[WORKFLOW_FILE] == "mine"


def test_foreign_file_shows_a_diff_and_is_replaced_on_yes():
    gh = FakeGh(contents={WORKFLOW_FILE: "mine\n"})
    p = ScriptedPrompter({"Replace": True})
    publish_files(gh, info(), {WORKFLOW_FILE: "new\n"}, p)
    shown = "\n".join(p.said)
    assert "-mine" in shown and "+new" in shown
    assert gh.contents[WORKFLOW_FILE] == "new\n" and gh.commit_count == 1


def test_init_written_file_with_changes_asks_and_is_replaced_on_yes():
    gh = FakeGh(contents=gate_files(config="old"))
    p = ScriptedPrompter({"Replace": True})
    publish_files(gh, info(), gate_files(config="new"), p)
    assert gh.contents[CONFIG_FILE].endswith("new") and gh.commit_count == 1
    assert any("-old" in s and "+new" in s for s in p.said)


def test_init_written_file_with_changes_is_kept_on_no():
    gh = FakeGh(contents=gate_files(config="old"))
    with pytest.raises(SetupAborted):
        publish_files(gh, info(), gate_files(config="new"), ScriptedPrompter({"Replace": False}))
    assert gh.commit_count == 0 and gh.contents[CONFIG_FILE].endswith("old")


def test_identical_content_asks_nothing_and_writes_nothing():
    gh = FakeGh(contents=gate_files())
    p = ScriptedPrompter({})  # any question raises
    assert publish_files(gh, info(), gate_files(), p).kind == "unchanged"
    assert gh.commit_count == 0 and gh.writes == [] and p.said == []


def test_a_trailing_newline_difference_asks_nothing_and_writes_nothing():
    on_github = {k: v + "\n" for k, v in gate_files().items()}
    gh = FakeGh(contents=on_github)
    p = ScriptedPrompter({})  # any question raises
    assert publish_files(gh, info(), gate_files(), p).kind == "unchanged"
    assert gh.commit_count == 0 and gh.writes == [] and p.said == []


def test_a_gate_file_that_is_not_text_asks_instead_of_crashing():
    gh = FakeGh(contents={WORKFLOW_FILE: b"\xff\xfe not utf-8"})
    p = ScriptedPrompter({"Replace": False})
    with pytest.raises(SetupAborted):
        publish_files(gh, info(), {WORKFLOW_FILE: "new\n"}, p)
    assert any("cannot be shown as text" in s for s in p.said)
    assert gh.commit_count == 0


def test_file_without_header_still_asks():
    gh = FakeGh(contents={CONFIG_FILE: "mine\n"})
    with pytest.raises(SetupAborted):
        publish_files(gh, info(), gate_files(), ScriptedPrompter({"Replace": False}))
    assert gh.contents[CONFIG_FILE] == "mine\n"


def test_only_changed_files_go_into_the_commit():
    gh = FakeGh(contents=gate_files())
    publish_files(gh, info(), gate_files(workflow="changed"), ScriptedPrompter({"Replace": True}))
    assert gh.blob_paths == [WORKFLOW_FILE]


def test_protected_branch_gets_a_pr():
    p = publish_files(FakeGh(protected=True), info(), {".prgate.toml": "1"}, ScriptedPrompter({}))
    assert p.kind == "pr" and p.url


def test_protected_branch_pr_targets_default_branch_and_leaves_it_alone():
    gh = FakeGh(protected=True)
    p = publish_files(gh, info(), gate_files(), ScriptedPrompter({}))
    assert gh.contents == {}
    assert gh.prs[0]["head"] == "prgate-setup" and gh.prs[0]["base"] == "main" and p.url == gh.prs[0]["html_url"]
    assert gh.refs["heads/prgate-setup"] != "0" * 40


FOREIGN = "f" * 40


def foreign_branch(**kw) -> FakeGh:
    gh = FakeGh(protected=True, commits={FOREIGN: {"tree": None, "parents": ["0" * 40], "message": "my work"}}, **kw)
    gh.refs["heads/prgate-setup"] = FOREIGN
    return gh


def test_setup_branch_with_foreign_commits_aborts_and_is_untouched():
    gh = foreign_branch()
    with pytest.raises(SetupAborted):
        publish_files(gh, info(), gate_files(), ScriptedPrompter({"Replace branch prgate-setup": False}))
    assert gh.refs["heads/prgate-setup"] == FOREIGN and gh.prs == []


def test_setup_branch_with_foreign_commits_is_replaced_when_confirmed():
    gh = foreign_branch()
    p = ScriptedPrompter({"Replace branch prgate-setup? It has commits prgate did not make.": True})
    assert publish_files(gh, info(), gate_files(), p).kind == "pr"
    assert gh.refs["heads/prgate-setup"] != FOREIGN


def test_setup_branch_with_a_merge_commit_is_foreign():
    gh = FakeGh(protected=True, commits={FOREIGN: {"tree": None, "parents": ["0" * 40, "1" * 40],
                                                   "message": "Set up prgate (experimental, report-only PR gate)"}})
    gh.refs["heads/prgate-setup"] = FOREIGN
    with pytest.raises(SetupAborted):
        publish_files(gh, info(), gate_files(), ScriptedPrompter({"Replace branch": False}))


def test_setup_branch_with_prgate_commit_is_updated_without_asking():
    gh = FakeGh(protected=True)
    publish_files(gh, info(), gate_files(), ScriptedPrompter({}))
    first = gh.refs["heads/prgate-setup"]
    publish_files(gh, info(), gate_files(config="again"), ScriptedPrompter({}))  # no answers: a prompt would raise
    assert gh.refs["heads/prgate-setup"] != first


def test_rerun_with_an_open_pr_reuses_it():
    gh = FakeGh(protected=True)
    first = publish_files(gh, info(), gate_files(), ScriptedPrompter({}))
    second = publish_files(gh, info(), gate_files(config="again"), ScriptedPrompter({}))
    assert len(gh.prs) == 1 and first.url == second.url


@pytest.mark.parametrize("status,msg", [(409, "conflict"), (422, "x"), (403, "Protected branch update failed")])
def test_protection_refusals_are_recognised(status, msg):
    gh = FakeGh(protected=(status, msg))
    assert publish_files(gh, info(), gate_files(), ScriptedPrompter({})).kind == "pr"


def test_other_ref_failures_are_raised():
    gh = FakeGh(protected=(500, "server error"))
    with pytest.raises(GhError):
        publish_files(gh, info(), gate_files(), ScriptedPrompter({}))


@pytest.mark.parametrize("files", [{"a": "1"}, {".github/workflows/other.yml": "x"}, {"../.prgate.toml": "x"}, {},
                                   {CONFIG_FILE: b"bytes"}])
def test_only_the_two_gate_files_can_be_published(files):
    gh = FakeGh()
    with pytest.raises(ValueError):
        publish_files(gh, info(), files, ScriptedPrompter({}))
    assert gh.writes == []


def test_a_rerun_with_changed_answers_asks_before_replacing():
    gh = FakeGh(contents={CONFIG_FILE: render_config(answers()), WORKFLOW_FILE: render_workflow("o/r@v0.0.1")})
    p = publish_files(gh, info(), {CONFIG_FILE: render_config(answers(language="go")), WORKFLOW_FILE: WF},
                      ScriptedPrompter({"Replace": True}))
    assert p.kind == "committed"


def test_fully_set_up_repo_is_unchanged():
    gh = FakeGh.fully_set_up()
    files = {CONFIG_FILE: gh.contents[CONFIG_FILE], WORKFLOW_FILE: gh.contents[WORKFLOW_FILE]}
    assert publish_files(gh, info(), files, ScriptedPrompter({})).kind == "unchanged"


# --- workflow_safe ---------------------------------------------------------------------------------

def test_existing_ci_workflows_are_fine():
    gh = FakeGh(contents={".github/workflows/pr-gate.yml": WF, ".github/workflows/ci.yml": "on: push"})
    assert workflow_safe(gh, info(), WF)[0]


def test_other_workflow_using_the_verdict_environment_is_refused():
    gh = FakeGh(contents={".github/workflows/pr-gate.yml": WF, ".github/workflows/x.yml": "environment: prgate-verdict"})
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and "x.yml" in why


def test_modified_gate_workflow_is_refused():
    gh = FakeGh(contents={".github/workflows/pr-gate.yml": WF + "\n# changed"})
    assert not workflow_safe(gh, info(), WF)[0]


def test_missing_gate_workflow_is_refused():
    ok, why = workflow_safe(FakeGh(contents={WFDIR + "ci.yml": "on: push"}), info(), WF)[:2]
    assert not ok and "pr-gate.yml" in why


def test_no_workflows_directory_is_refused():
    ok, why = workflow_safe(FakeGh(), info(), WF)[:2]
    assert not ok and "pr-gate.yml" in why


def test_a_trailing_newline_difference_is_tolerated():
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF.rstrip("\n")})
    assert workflow_safe(gh, info(), WF)[0]
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF + "\n"})
    ok, _ = workflow_safe(gh, info(), WF)[:2]
    assert not ok  # only one trailing newline is normalised


@pytest.mark.parametrize("name", ["x.yaml", "notes.txt", "README", "x.YML"])
def test_any_other_file_naming_the_environment_is_refused(name):
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + name: "jobs:\n  a:\n    environment: PRGATE-Verdict\n"})
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and name in why


def test_listing_failure_fails_closed():
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF},
                fail_once={("GET", "repos/o/r/contents/.github/workflows?ref=main"): 500})
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and why


def test_file_read_failure_fails_closed_and_names_the_file():
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "ci.yml": "on: push"},
                fail_once={("GET", "repos/o/r/contents/.github/workflows/ci.yml?ref=main"): 502})
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and "ci.yml" in why


def test_undecodable_file_fails_closed():
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "big.yml": "x"}, undecodable={WFDIR + "big.yml"})
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and "big.yml" in why


def test_non_utf8_file_fails_closed():
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "bin.yml": b"\xff\xfeprgate"})
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and "bin.yml" in why


def test_a_capped_listing_fails_closed():
    many = {f"{WFDIR}w{i}.yml": "on: push" for i in range(1000)}
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, **many})
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and "1000" in why


def test_subdirectories_are_not_workflows_and_are_skipped():
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "sub/x.yml": "environment: prgate-verdict"})
    assert workflow_safe(gh, info(), WF)[0]


def test_reads_the_default_branch():
    gh = FakeGh(default_branch="trunk", contents={WFDIR + "pr-gate.yml": WF})
    assert workflow_safe(gh, info("trunk"), WF)[0]
    assert any("ref=trunk" in p for p in gh.reads)


def test_fully_set_up_repo_is_workflow_safe():
    gh = FakeGh.fully_set_up()
    assert workflow_safe(gh, info(), gh.contents[WORKFLOW_FILE])[0]


# --- fix round 1 -----------------------------------------------------------------------------------

def test_default_branch_update_is_never_forced():
    gh = FakeGh()
    publish_files(gh, info(), gate_files(), ScriptedPrompter({}))
    assert gh.default_ref_bodies and all(b["force"] is False for b in gh.default_ref_bodies)


def test_fake_refuses_a_forced_default_branch_update():
    gh = FakeGh()
    with pytest.raises(GhError):
        gh.api("PATCH", "repos/o/r/git/refs/heads/main", {"sha": "a" * 40, "force": True})


@pytest.mark.parametrize("status", [409, 404])
def test_empty_repo_is_a_clear_abort(status):
    gh = FakeGh(empty=status)
    with pytest.raises(SetupAborted) as e:
        publish_files(gh, info(), gate_files(), ScriptedPrompter({}))
    msg = str(e.value)
    assert "push an initial commit first, then re-run prgate init" in msg
    if status == 404:
        assert "or its default branch is missing" in msg
    else:
        assert msg == "the repository has no commits yet; push an initial commit first, then re-run prgate init"


def test_fake_empty_true_means_409():
    with pytest.raises(GhError) as e:
        FakeGh(empty=True).api("GET", "repos/o/r/git/ref/heads/main")
    assert e.value.status == 409


def test_pr_created_concurrently_is_reused():
    gh = FakeGh(protected=True, pr_race=True)
    p = publish_files(gh, info(), gate_files(), ScriptedPrompter({}))
    assert p.kind == "pr" and len(gh.prs) == 1 and p.url == gh.prs[0]["html_url"]


def test_pr_post_422_with_no_pr_found_is_an_error():
    gh = FakeGh(protected=True, fail_once={("POST", "repos/o/r/pulls"): 422})
    with pytest.raises(GhError):
        publish_files(gh, info(), gate_files(), ScriptedPrompter({}))


def test_pr_reply_without_url_is_an_error():
    gh = FakeGh(protected=True, pr_without_url=True)
    with pytest.raises(GhError):
        publish_files(gh, info(), gate_files(), ScriptedPrompter({}))


def test_listed_open_pr_without_url_is_an_error():
    gh = FakeGh(protected=True, prs=[{"number": 1, "head": "prgate-setup", "base": "main", "state": "open"}])
    with pytest.raises(GhError):
        publish_files(gh, info(), gate_files(), ScriptedPrompter({}))


VARIANTS = [
    'environment: "prgate-\\\n  verdict"',
    "environment: prgate - verdict",
    "environment: 'prgate-verdict'",
    'environment: "PRGATE-VERDICT"',
    "environment:\n  name: Prgate-Verdict\n",
    'environment: "PRGATE-\\\n    VERDICT"',
]


@pytest.mark.parametrize("text", VARIANTS)
def test_disguised_environment_names_are_refused(text):
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "x.yml": text})
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and "x.yml" in why


def test_line_continuation_variant_is_really_split():
    assert "prgate-verdict" not in VARIANTS[0] and "\n" in VARIANTS[0]


def test_result_is_a_named_tuple():
    r = workflow_safe(FakeGh(contents={WFDIR + "pr-gate.yml": WF}), info(), WF)
    assert isinstance(r, WorkflowSafety) and isinstance(r, tuple)
    assert r.ok and r[0] is r.ok and r.warnings == ()
    ok, reason, warnings = r
    assert reason == r.reason


@pytest.mark.parametrize("text", ["jobs:\n  d:\n    environment: ${{ matrix.env }}\n",
                                  "jobs:\n  d:\n    environment:\n      name: ${{ inputs.target }}\n"])
def test_dynamic_environment_is_a_warning_not_a_refusal(text):
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "deploy.yml": text})
    r = workflow_safe(gh, info(), WF)
    assert r.ok and len(r.warnings) == 1 and "deploy.yml" in r.warnings[0]


@pytest.mark.parametrize("uses,warned", [
    ("uses: other/repo/.github/workflows/build.yml@v1", True),
    ("  - uses: 'other/repo/.github/workflows/b.yml@main'", True),
    ("uses: ./.github/workflows/local.yml", False),
    ("uses: actions/checkout@v4", False),
])
def test_external_reusable_workflow_is_a_warning(uses, warned):
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "ci.yml": f"jobs:\n  b:\n    {uses}\n"})
    r = workflow_safe(gh, info(), WF)
    assert r.ok
    assert (len(r.warnings) == 1 and "ci.yml" in r.warnings[0]) if warned else r.warnings == ()


def test_warnings_do_not_rescue_a_refusal():
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "a.yml": "environment: ${{ x }}",
                          WFDIR + "b.yml": "environment: prgate-verdict"})
    assert not workflow_safe(gh, info(), WF).ok


def test_the_gate_workflow_itself_gives_no_warning():
    r = workflow_safe(FakeGh(contents={WFDIR + "pr-gate.yml": WF}), info(), WF)
    assert r.warnings == ()


@pytest.mark.parametrize("kind", ["symlink", "submodule"])
def test_symlink_and_submodule_entries_are_refused(kind):
    gh = FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "odd.yml": "on: push"},
                entry_types={WFDIR + "odd.yml": kind})
    assert any(e["type"] == kind for e in gh.api("GET", "repos/o/r/contents/.github/workflows?ref=main"))
    ok, why = workflow_safe(gh, info(), WF)[:2]
    assert not ok and "odd.yml" in why


# --- fix round 2 -----------------------------------------------------------------------------------

def _other(text: str) -> FakeGh:
    return FakeGh(contents={WFDIR + "pr-gate.yml": WF, WFDIR + "x.yml": text})


def test_dynamic_env_scan_is_linear_time():
    text = "jobs:\n  d:\n    environment:\n" + "".join(f"        k{i}: v\n" for i in range(5000))
    start = time.perf_counter()
    r = workflow_safe(_other(text), info(), WF)
    assert time.perf_counter() - start < 1.0
    assert r.ok and r.warnings == ()


def test_many_environment_keys_stay_linear():
    text = "".join("    environment:\n      name: prod\n" for _ in range(3000)) + "x: '" + " " * 20000 + "'\n"
    start = time.perf_counter()
    assert workflow_safe(_other(text), info(), WF).ok
    assert time.perf_counter() - start < 1.0


def test_uses_scan_is_linear_time():
    text = " " * 100000 + "\n" + "-" * 100000 + "\n"
    start = time.perf_counter()
    workflow_safe(_other(text), info(), WF)
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize("text", [
    r'environment: "prgate\x2dverdict"',
    r'environment: "\x70rgate-verdict"',
    r'environment: "prgate\u002dverdict"',
    r'environment: "prgate\U0000002dverdict"',
    r'jobs: {d: {environment: "\x50RGATE\x2DVERDICT"}}',
    'environment: "prgate\\\n  -verdict"',
    "environment: 'prgate''-verdict'",
    r'environment: "prgate\x2d\x76erdict"',
])
def test_yaml_escapes_are_decoded_before_matching(text):
    ok, why = workflow_safe(_other(text), info(), WF)[:2]
    assert not ok and "x.yml" in why


@pytest.mark.parametrize("text", [
    'jobs:\n  t:\n    steps:\n      - run: echo "\\d+" | grep x\n',
    "jobs:\n  t:\n    steps:\n      - run: |\n          grep \"\\d\" f\n          echo 'x\n",
    "name: don't panic\n",
    "# a comment with a \"\\q\" in it\non: push\n",
])
def test_backslashes_outside_quoted_scalars_are_left_alone(text):
    assert workflow_safe(_other(text), info(), WF).ok


def test_escaped_expression_gives_the_dynamic_warning():
    r = workflow_safe(_other('jobs:\n  d:\n    environment: "\\x24{{ matrix.env }}"\n'), info(), WF)
    assert r.ok and len(r.warnings) == 1


@pytest.mark.parametrize("text", ["jobs:\r\n  d:\r\n    environment:\r\n      name: ${{ x }}\r\n",
                                  "jobs:\r  d:\r    environment:\r      name: ${{ x }}\r",
                                  "environment:\r\n  name: ${{ x }}"])
def test_crlf_and_cr_are_normalised(text):
    r = workflow_safe(_other(text), info(), WF)
    assert r.ok and len(r.warnings) == 1 and "x.yml" in r.warnings[0]


def test_url_only_dynamic_is_still_flagged_child_lines():
    r = workflow_safe(_other("jobs:\n  d:\n    environment:\n      name: prod\n      url: ${{ steps.d.url }}\n"
                             "    steps: []\n"), info(), WF)
    assert r.ok and len(r.warnings) == 1


def test_dynamic_scan_stops_at_the_end_of_the_block():
    r = workflow_safe(_other("jobs:\n  d:\n    environment:\n      name: prod\n    steps:\n      - run: echo ${{ x }}\n"),
                      info(), WF)
    assert r.ok and r.warnings == ()


PRGATE_MSG = "Set up prgate (experimental, report-only PR gate)"


def test_amended_prgate_commit_on_a_non_ancestor_parent_asks():
    gh = FakeGh(protected=True, commits={FOREIGN: {"tree": None, "parents": ["1" * 40], "message": PRGATE_MSG}})
    gh.refs["heads/prgate-setup"] = FOREIGN
    with pytest.raises(SetupAborted):
        publish_files(gh, info(), gate_files(), ScriptedPrompter({"Replace branch prgate-setup": False}))
    assert gh.refs["heads/prgate-setup"] == FOREIGN


def test_prgate_commit_on_the_current_head_does_not_ask():
    gh = FakeGh(protected=True, commits={FOREIGN: {"tree": None, "parents": ["0" * 40], "message": PRGATE_MSG}})
    gh.refs["heads/prgate-setup"] = FOREIGN
    assert publish_files(gh, info(), gate_files(), ScriptedPrompter({})).kind == "pr"
    assert gh.refs["heads/prgate-setup"] != FOREIGN


def test_prgate_commit_on_an_older_default_head_does_not_ask():
    newer = "2" * 40
    gh = FakeGh(protected=True, commits={FOREIGN: {"tree": None, "parents": ["0" * 40], "message": PRGATE_MSG},
                                         newer: {"tree": None, "parents": ["0" * 40], "message": "later work"}})
    gh.refs["heads/main"] = newer
    gh.refs["heads/prgate-setup"] = FOREIGN
    assert publish_files(gh, info(), gate_files(), ScriptedPrompter({})).kind == "pr"


def test_fake_compare_statuses():
    gh = FakeGh(commits={"a" * 40: {"tree": None, "parents": ["0" * 40], "message": ""}})
    cmp = lambda b, h: gh.api("GET", f"repos/o/r/compare/{b}...{h}")["status"]
    assert cmp("0" * 40, "0" * 40) == "identical"
    assert cmp("0" * 40, "a" * 40) == "ahead"
    assert cmp("a" * 40, "0" * 40) == "behind"
    assert cmp("1" * 40, "a" * 40) == "diverged"


def test_block_scalar_with_a_trailing_comment_is_left_alone():
    text = 'jobs:\n  t:\n    steps:\n      - run: | # shell\n          "\\d" is a regex\n'
    assert workflow_safe(_other(text), info(), WF).ok


# --- round 3: context-free decode for the refusal; the scanner only warns ------------------------

@pytest.mark.parametrize("text", [
    "name: a:'b\nenvironment: \"\\x70rgate-verdict\"\nsteps: [{run: \"echo it's\"}]\n",
    "name: a-'b\nenvironment: \"\\x70rgate-verdict\"\nsteps: [{run: \"echo it's\"}]\n",
    "name: a,'b\nenvironment: \"\\x70rgate-verdict\"\nsteps: [{run: \"echo it's\"}]\n",
    "name: a:\"b\nenvironment: \"\\x70rgate-verdict\"\nsteps: [{run: \"echo it's\"}]\n",
    'environment: &a "\\x70rgate-verdict"\n',
    'x: &a "\\x70rgate-verdict"\njobs:\n  d:\n    environment: *a\n',
    'environment: !!str "\\x70rgate-verdict"\n',
    "jobs:\n  d:\n    steps:\n      - run: !!str |\n          echo it's\n    environment: \"\\x70rgate-verdict\"\n",
    'jobs:\n  d:\n    steps:\n      - run: |\n          echo "\\x70rgate\\u002dverdict"\n',
])
def test_round3_bypasses_are_refused(text):
    ok, why = workflow_safe(_other(text), info(), WF)[:2]
    assert not ok and "x.yml" in why


@pytest.mark.parametrize("text", [
    "jobs:\n  t:\n    steps:\n      - run: echo '{\"re\":\"\\d+\"}' | jq .\n",
    "jobs:\n  t:\n    steps:\n      - run: curl -d '{\"p\":\"C:\\Users\\x\"}'\n",
    'jobs:\n  t:\n    steps:\n      - run: tool -- "C:\\Users\\me"\n',
    "jobs:\n  t:\n    steps:\n      - run: echo key:'it\n",
    'jobs:\n  t:\n    steps:\n      - run: echo first\n          "second \\d line\n',
    'environment: "prgate\\qverdict"\n',
    'name: "\\x2"\n',
    'name: "\\U00110000"\n',
    'name: "never closed\n',
])
def test_round3_former_false_refusals_pass(text):
    r = workflow_safe(_other(text), info(), WF)
    assert r.ok, r.reason


def test_out_of_range_escape_is_left_as_is_and_not_matched():
    assert workflow_safe(_other('environment: "\\U00110070rgate-verdict"\n'), info(), WF).ok


def test_split_expression_across_an_escaped_line_break_warns():
    text = "jobs:\n  d:\n    environment: \"$\\\n      {{ format('{0}', matrix.e) }}\"\n"
    r = workflow_safe(_other(text), info(), WF)
    assert r.ok and len(r.warnings) == 1


def test_tagged_dynamic_environment_warns():
    r = workflow_safe(_other('jobs:\n  d:\n    environment: !!str "\\x24{{ x }}"\n'), info(), WF)
    assert r.ok and len(r.warnings) == 1


def test_plain_scalar_quote_does_not_desync_the_warnings():
    text = "jobs:\n  d:\n    name: a:'b\n    environment: ${{ x }}\n    steps: [{run: \"echo it's\"}]\n"
    r = workflow_safe(_other(text), info(), WF)
    assert r.ok and len(r.warnings) == 1


def test_tagged_block_scalar_content_is_not_scanned_for_quotes():
    text = "jobs:\n  d:\n    steps:\n      - run: !!str |\n          echo it's\n    environment: \"\\x24{{ x }}\"\n"
    r = workflow_safe(_other(text), info(), WF)
    assert r.ok and len(r.warnings) == 1


def test_one_megabyte_adversarial_input_is_fast():
    parts = ['\\x7 "\\u00 \'', '"\\U0000 &a !t ', "a:'b: \"c", "[{,'\"", "\\x" * 3]
    text = ""
    i = 0
    while len(text) < 1_000_000:
        text += parts[i % len(parts)]
        i += 1
        if i % 50 == 0:
            text += "\n" + " " * (i % 17)
    start = time.perf_counter()
    workflow_safe(_other(text), info(), WF)
    one_line = "\\x7" * 333_000 + "'" * 1000
    workflow_safe(_other(one_line), info(), WF)
    assert time.perf_counter() - start < 1.0
