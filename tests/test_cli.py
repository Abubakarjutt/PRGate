import hashlib
import json
import subprocess

import pytest

from fake_api import REPO, SLUG, FakeAPI
from prgate import cli
from prgate.commands import Command
from prgate.conclude import dump_stage1, load_stage1
from prgate.diff import DiffError
from prgate.github import GitHub
from prgate.models import CheckResult, FileChange, Finding, Outcome, RunStatus, Severity, Verdict
from prgate.report import EXPERIMENTAL_LINE, parse, render
from test_diff import add, commit, git
from test_diff import repo  # noqa: F401  (fixture)

TOKEN = "ghs_TESTTOKEN0123456789abcdefTOKEN"
B = "b" * 40
H = "a" * 40
STAGE1 = ("secrets", "rollout", "test_integrity", "environment_sniffing", "facts")
DEFAULT = object()


def sha(name):
    """Readable names in tests ("old", "new") become distinct full SHAs."""
    if len(name) == 40 and all(c in "0123456789abcdef" for c in name):
        return name
    return hashlib.sha1(name.encode()).hexdigest()


def no_network(name, timeout):
    return True, 1000


def env_for(tmp_path, event_name, event, **extra):
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event))
    env = {"GITHUB_EVENT_NAME": event_name, "GITHUB_EVENT_PATH": str(path), "GITHUB_REPOSITORY": REPO,
           "GITHUB_RUN_ATTEMPT": "1", "PRGATE_TOKEN": TOKEN, "PRGATE_APP_SLUG": SLUG}
    env.update(extra)
    return {k: v for k, v in env.items() if v is not None}


def factory(api):
    return lambda token, repo, app_slug: GitHub(token, repo, app_slug=app_slug, opener=api)


def pr_event(base=B, head=H, number=5):
    return {"action": "synchronize", "number": number,
            "pull_request": {"number": number, "base": {"sha": base, "ref": "main"}, "head": {"sha": head}},
            "repository": {"default_branch": "main"}}


def stage1_with(*replacements, changes=None, base=B, head=H):
    by = {c.name: c for c in replacements}
    checks = tuple(by.pop(n, CheckResult(n, RunStatus.RAN)) for n in STAGE1) + tuple(by.values())
    changes = (FileChange("docs/a.md", None, "M", (), 0, False),) if changes is None else changes
    return dump_stage1(base, head, base, changes, checks, True).encode()


def run_verdict(tmp_path, artifacts=DEFAULT, artifact_sha=H, event_sha=H, api=None, config=None, expect=0):
    api = api or FakeAPI()
    if config is not None:
        api.contents[(".prgate.toml", B)] = config.encode()
    art = tmp_path / "prgate-stage1.json"
    if artifacts is DEFAULT:
        artifacts = stage1_with(head=sha(artifact_sha))
    if artifacts is not None:
        art.write_bytes(artifacts)
    env = env_for(tmp_path, "pull_request_target", pr_event(head=sha(event_sha)))
    assert cli.main(["verdict", "--stage1", str(art)], env=env, github=factory(api)) == expect
    posted = api.posted()
    assert len(posted) == 1
    p = posted[0]
    assert p.conclusion == "neutral" and p.head_sha == sha(event_sha) and EXPERIMENTAL_LINE in p.body
    return parse(p.body)


# --- verdict ------------------------------------------------------------------------------

def test_missing_artifacts_produce_person_verdict(tmp_path):
    assert run_verdict(tmp_path, artifacts=None).outcome == Outcome.PERSON


def test_malformed_artifacts_produce_person_verdict(tmp_path):
    for raw in (b"", b"{]", b'{"version": 1}', b"\x00" * 100, b"[" * 100000):
        sub = tmp_path / str(len(list(tmp_path.iterdir())))
        sub.mkdir()
        assert run_verdict(sub, artifacts=raw).outcome == Outcome.PERSON


def test_stale_head_is_not_reported_on_new_sha(tmp_path):
    assert run_verdict(tmp_path, artifact_sha="old", event_sha="new").outcome == Outcome.PERSON


def test_stale_artifact_cannot_clear_even_when_it_would(tmp_path):
    v = run_verdict(tmp_path, artifact_sha="old", event_sha="new", config="clear_docs = true\n")
    assert v.outcome == Outcome.PERSON and "different commit" in v.reasons[0]


def test_github_api_failure_still_posts_a_person_report(tmp_path):
    v = run_verdict(tmp_path, artifacts=stage1_with(CheckResult("facts", RunStatus.COULD_NOT_RUN)))
    assert v.outcome == Outcome.PERSON


def test_config_read_failure_still_posts_a_person_report(tmp_path):
    api = FakeAPI(fail=[("GET", r"/contents/", 502)])
    v = run_verdict(tmp_path, api=api, config='clear_docs = true\n')
    assert v.outcome == Outcome.PERSON and any("config" in r for r in v.reasons)


def test_truncated_config_reply_still_posts_a_person_report(tmp_path):
    import http.client

    class Truncating(FakeAPI):
        def open(self, req, timeout=None):
            resp = super().open(req, timeout)
            if "/contents/" in req.full_url:
                def read(*a):
                    raise http.client.IncompleteRead(b"")
                resp.read = read
            return resp

    v = run_verdict(tmp_path, api=Truncating(), config="clear_docs = true\n")
    assert v.outcome == Outcome.PERSON and any("config" in r for r in v.reasons)


def test_verdict_posts_nothing_for_a_pr_into_another_branch(tmp_path, capsys):
    api = FakeAPI()
    (tmp_path / "a.json").write_bytes(stage1_with())
    event = pr_event()
    event["pull_request"]["base"]["ref"] = "develop"
    env = env_for(tmp_path, "pull_request_target", event)
    assert cli.main(["verdict", "--stage1", str(tmp_path / "a.json")], env=env, github=factory(api)) == 0
    assert api.seen == [] and api.posted() == []
    err = capsys.readouterr().err
    assert len(err.strip().splitlines()) == 1 and "default branch" in err and "develop" not in err


@pytest.mark.parametrize("change", [lambda e: e["repository"].pop("default_branch"),
                                    lambda e: e["pull_request"]["base"].pop("ref"),
                                    lambda e: e["pull_request"]["base"].update(ref=["main"])])
def test_verdict_posts_nothing_without_a_matching_default_branch(tmp_path, change):
    api = FakeAPI()
    event = pr_event()
    change(event)
    env = env_for(tmp_path, "pull_request_target", event)
    assert cli.main(["verdict"], env=env, github=factory(api)) == 0 and api.seen == []


def test_docs_pr_clears_when_the_base_config_allows_it(tmp_path):
    assert run_verdict(tmp_path, config="clear_docs = true\n").outcome == Outcome.CLEARED


def test_docs_pr_goes_to_a_person_by_default(tmp_path):
    v = run_verdict(tmp_path)
    assert v.outcome == Outcome.PERSON and v.would_clear


def test_failure_to_post_exits_non_zero_without_leaking_the_token(tmp_path, capsys):
    api = FakeAPI(fail=[("POST", r"/check-runs", 500)])
    (tmp_path / "a.json").write_bytes(stage1_with())
    env = env_for(tmp_path, "pull_request_target", pr_event())
    assert cli.main(["verdict", "--stage1", str(tmp_path / "a.json")], env=env, github=factory(api)) == 1
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err and "500" in out.err


@pytest.mark.parametrize("bad", ["", "abc", "A" * 40, "a" * 39, "a" * 41, "$(touch pwned)", "--output=x",
                                 "a" * 40 + "\n", None, 12])
def test_hostile_event_head_posts_nothing_and_does_not_crash(tmp_path, bad):
    api = FakeAPI()
    event = pr_event()
    event["pull_request"]["head"]["sha"] = bad
    env = env_for(tmp_path, "pull_request_target", event)
    assert cli.main(["verdict", "--stage1", str(tmp_path / "x.json")], env=env, github=factory(api)) == 2
    assert api.posted() == [] and api.seen == []


def test_hostile_event_base_posts_nothing(tmp_path):
    api = FakeAPI()
    env = env_for(tmp_path, "pull_request_target", pr_event(base="main"))
    assert cli.main(["verdict"], env=env, github=factory(api)) == 2
    assert api.seen == []


@pytest.mark.parametrize("event", ['{"pull_request": 3}', "[]", "not json", '{"pull_request": {"head": []}}'])
def test_hostile_event_payload_does_not_crash(tmp_path, event):
    (tmp_path / "e.json").write_text(event)
    env = env_for(tmp_path, "pull_request_target", {}, GITHUB_EVENT_PATH=str(tmp_path / "e.json"))
    assert cli.main(["verdict"], env=env, github=factory(FakeAPI())) == 2


def test_missing_token_posts_nothing(tmp_path):
    api = FakeAPI()
    env = env_for(tmp_path, "pull_request_target", pr_event(), PRGATE_TOKEN=None)
    assert cli.main(["verdict"], env=env, github=factory(api)) == 2 and api.seen == []


def test_bad_repository_name_posts_nothing(tmp_path):
    env = env_for(tmp_path, "pull_request_target", pr_event(), GITHUB_REPOSITORY="o/r/../x")
    assert cli.main(["verdict"], env=env, github=factory(FakeAPI())) == 2


def test_verdict_refuses_a_comment_event(tmp_path):
    api = FakeAPI()
    env = env_for(tmp_path, "issue_comment", pr_event())
    assert cli.main(["verdict"], env=env, github=factory(api)) == 2 and api.seen == []


def test_verdict_output_names_the_outcome_and_never_the_token(tmp_path, capsys):
    run_verdict(tmp_path)
    out = capsys.readouterr()
    assert "person" in out.out and TOKEN not in out.out + out.err


def test_token_reaches_only_the_api_host(tmp_path):
    api = FakeAPI()
    run_verdict(tmp_path, api=api)
    assert api.seen and all(url.startswith("https://api.github.com/") for _, url, _ in api.seen)
    assert all(h["authorization"] == f"Bearer {TOKEN}" for _, _, h in api.seen)


# --- stage1 -------------------------------------------------------------------------------

def head_of(repo):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()


def test_stage1_then_verdict_blocks_a_deleted_test(repo, tmp_path, monkeypatch):
    add(repo, "tests/test_a.py", "def test_x():\n    assert 1 == 1\n")
    commit(repo)
    base = head_of(repo)
    git(repo, "rm", "-q", "tests/test_a.py")
    commit(repo)
    head = head_of(repo)
    out = tmp_path / "out.json"
    monkeypatch.chdir(repo)
    assert cli.main(["stage1", "--base", base, "--head", head, "--out", str(out)], env={},
                    registry=no_network) == 0
    a = load_stage1(out.read_bytes())
    assert a.head_sha == head and a.base_sha == base and [c.path for c in a.changes] == ["tests/test_a.py"]

    api = FakeAPI()
    env = env_for(tmp_path, "pull_request_target", pr_event(base=base, head=head))
    assert cli.main(["verdict", "--stage1", str(out)], env=env, github=factory(api)) == 0
    [p] = api.posted()
    assert p.head_sha == head and p.conclusion == "neutral" and p.title.startswith("Blocked")
    assert parse(p.body).outcome == Outcome.BLOCKED


def test_stage1_reads_shas_from_the_event_by_default(repo, tmp_path, monkeypatch):
    base = head_of(repo)
    add(repo, "docs/a.md", "x\n")
    commit(repo)
    head = head_of(repo)
    monkeypatch.chdir(repo)
    env = env_for(tmp_path, "pull_request_target", pr_event(base=base, head=head))
    assert cli.main(["stage1"], env=env, registry=no_network) == 0
    a = load_stage1((repo / "prgate-stage1.json").read_bytes())
    assert (a.base_sha, a.head_sha) == (base, head)


def test_stage1_diffs_from_the_merge_base(repo, tmp_path, monkeypatch):
    fork_point = head_of(repo)
    git(repo, "checkout", "-q", "-b", "pr")
    add(repo, "docs/a.md", "x\n")
    commit(repo)
    head = head_of(repo)
    git(repo, "checkout", "-q", "-")
    add(repo, "tests/test_new.py", "def test_y():\n    assert 2 == 2\n")
    commit(repo)
    base = head_of(repo)
    out = tmp_path / "o.json"
    monkeypatch.chdir(repo)
    assert cli.main(["stage1", "--base", base, "--head", head, "--out", str(out)], env={},
                    registry=no_network) == 0
    a = load_stage1(out.read_bytes())
    assert a.diff_base == fork_point and [c.path for c in a.changes] == ["docs/a.md"]
    assert not any(f.severity == Severity.PROOF for c in a.checks for f in c.findings)


@pytest.mark.parametrize("bad", ["HEAD", "a" * 39, "A" * 40, "$(touch pwned)", "--output=/tmp/x", "-q", ""])
def test_stage1_refuses_hostile_shas_and_writes_nothing(repo, tmp_path, monkeypatch, bad):
    out = tmp_path / "o.json"
    monkeypatch.chdir(repo)
    called = []
    monkeypatch.setattr(cli, "run_stage1", lambda *a, **k: called.append(1))
    assert cli.main(["stage1", "--base", bad, "--head", "a" * 40, "--out", str(out)], env={}) == 2
    assert cli.main(["stage1", "--base", "a" * 40, "--head", bad, "--out", str(out)], env={}) == 2
    assert not out.exists() and not called and not (repo / "pwned").exists()


def test_stage1_refuses_a_comment_event(repo, tmp_path, monkeypatch):
    monkeypatch.chdir(repo)
    env = env_for(tmp_path, "issue_comment", pr_event())
    assert cli.main(["stage1"], env=env) == 2


def test_stage1_deadline_fits_inside_the_job_timeout(repo, tmp_path, monkeypatch):
    add(repo, ".prgate.toml", "stage1_s = 100000\n")
    commit(repo)
    base = head_of(repo)
    add(repo, "docs/a.md", "x\n")
    commit(repo)
    seen = []
    monkeypatch.setattr(cli, "run_stage1", lambda repo, b, h, c, d, **k: seen.append(d) or ())
    monkeypatch.chdir(repo)
    assert cli.main(["stage1", "--base", base, "--head", head_of(repo), "--out", str(tmp_path / "o")],
                    env={}) == 0
    assert seen and 0 < seen[0] <= 240


@pytest.mark.parametrize("error", [DiffError("bad"), subprocess.CalledProcessError(1, "git"),
                                   subprocess.TimeoutExpired("git", 1)])
def test_stage1_diff_errors_route_to_a_person(repo, tmp_path, monkeypatch, error):
    base = head_of(repo)
    add(repo, "docs/a.md", "x\n")
    commit(repo)
    head = head_of(repo)

    def boom(*a, **k):
        raise error
    monkeypatch.setattr(cli, "parse_diff", boom)
    monkeypatch.chdir(repo)
    out = tmp_path / "o.json"
    assert cli.main(["stage1", "--base", base, "--head", head, "--out", str(out)], env={},
                    registry=no_network) == 0
    a = load_stage1(out.read_bytes())
    assert not a.diff_ok and [c.name for c in a.checks] == list(STAGE1)
    assert all(c.status == RunStatus.COULD_NOT_RUN for c in a.checks)
    v = run_verdict(tmp_path, artifacts=out.read_bytes().replace(base.encode(), B.encode())
                    .replace(head.encode(), H.encode()))
    assert v.outcome == Outcome.PERSON and "diff could not be read" in v.reasons[0]


def test_stage1_unrelated_histories_route_to_a_person(repo, tmp_path, monkeypatch):
    base = head_of(repo)
    git(repo, "checkout", "-q", "--orphan", "other")
    add(repo, "docs/b.md", "y\n")
    commit(repo)
    head = head_of(repo)
    monkeypatch.chdir(repo)
    out = tmp_path / "o.json"
    assert cli.main(["stage1", "--base", base, "--head", head, "--out", str(out)], env={},
                    registry=no_network) == 0
    assert not load_stage1(out.read_bytes()).diff_ok


def test_stage1_with_surrogate_paths_writes_ascii_json(repo, tmp_path, monkeypatch):
    base = head_of(repo)
    name = b"docs/\xff\xfe.md"
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, input=b"x\n",
                          check=True, capture_output=True).stdout.decode().strip()
    subprocess.run(["git", "update-index", "--add", "--index-info"], cwd=repo, check=True, capture_output=True,
                   input=f"100644 {blob}\t".encode() + name + b"\n")
    git(repo, "commit", "-q", "-m", "c")
    head = head_of(repo)
    monkeypatch.chdir(repo)
    out = tmp_path / "o.json"
    assert cli.main(["stage1", "--base", base, "--head", head, "--out", str(out)], env={},
                    registry=no_network) == 0
    raw = out.read_bytes()
    raw.decode("ascii")
    assert load_stage1(raw).changes[0].path == name.decode("utf-8", "surrogateescape")
    v = run_verdict(tmp_path, artifacts=raw.replace(base.encode(), B.encode()).replace(head.encode(), H.encode()))
    assert v.outcome == Outcome.PERSON


# --- command ------------------------------------------------------------------------------

CONFIG = 'approvers = ["owner"]\n'


def blocked_verdict(head=H):
    f = Finding("test_integrity", Severity.PROOF, "test deleted: t.py::test_x", "t.py", 1)
    return Verdict(Outcome.BLOCKED, head, ("test_integrity: test deleted",), None, (f,), False)


def comment_event(body, sender="owner", number=5, is_bot=False, pull_request=True):
    issue = {"number": number}
    if pull_request:
        issue["pull_request"] = {"url": "x"}
    return {"action": "created", "issue": issue,
            "comment": {"body": body, "user": {"login": sender, "type": "Bot" if is_bot else "User"}},
            "repository": {"default_branch": "main"}}


_NO_USER = object()


def comment_api(head=H, author="agent", state="open", base_ref="main", gate=True, config=CONFIG, user=None):
    api = FakeAPI()
    api.prs[5] = {"number": 5, "state": state, "user": {"login": author} if user is None else user,
                  "head": {"sha": head}, "base": {"sha": B, "ref": base_ref}}
    if user is _NO_USER:
        del api.prs[5]["user"]
    if config is not None:
        api.contents[(".prgate.toml", B)] = config.encode()
    if gate:
        api.add_run(head, render(blocked_verdict(head), ())[1])
    return api


def run_command(tmp_path, cmd, sender="owner", api=None, attempt="1", is_bot=False, body=None, expect=0):
    api = api or comment_api()
    body = body if body is not None else f"/gate {cmd.kind} {cmd.sha} {cmd.reason}"
    env = env_for(tmp_path, "issue_comment", comment_event(body, sender, is_bot=is_bot),
                  GITHUB_RUN_ATTEMPT=attempt)
    assert cli.main(["command"], env=env, github=factory(api)) == expect
    posted = api.posted()
    assert len(posted) <= 1
    return posted[0] if posted else None


def override(sha, reason):
    return Command("override", sha, reason)


def test_override_posts_a_neutral_check_recording_who_why_and_sha(tmp_path):
    p = run_command(tmp_path, override(H, "known issue"))
    assert p.conclusion == "neutral" and p.head_sha == H
    assert "owner" in p.body and "known issue" in p.body and H in p.body and EXPERIMENTAL_LINE in p.body
    assert parse(p.body) == blocked_verdict()


@pytest.mark.parametrize("kw", [
    {"sender": "stranger"},
    {"sender": "agent"},
    {"is_bot": True},
    {"attempt": "2"},
    {"api": comment_api(state="closed")},
    {"api": comment_api(base_ref="develop")},
    {"api": comment_api(gate=False)},
    {"api": comment_api(config=None)},
    {"api": comment_api(config="mode = 'enforce'\napprovers = ['owner']\n")},
    {"api": comment_api(head="c" * 40)},
    {"api": comment_api(author=None)},
    {"api": comment_api(author="")},
    {"api": comment_api(author="   ")},
    {"api": comment_api(author=42)},
    {"api": comment_api(user="agent")},
    {"api": comment_api(user=_NO_USER)},
    {"body": f"/gate override {H} \u200b\u200b"},
    {"body": f"/gate override {H} ...!?"},
])
def test_refused_overrides_post_nothing(tmp_path, kw):
    assert run_command(tmp_path, override(H, "ok"), **kw) is None


def test_override_ignores_gate_checks_from_other_apps(tmp_path):
    api = comment_api(gate=False)
    api.add_run(H, render(blocked_verdict(), ())[1], slug="github-actions")
    assert run_command(tmp_path, override(H, "ok"), api=api) is None


def test_override_never_reads_verdicts_from_comments(tmp_path):
    api = comment_api(gate=False)
    api.comments[5] = [{"body": render(blocked_verdict(), ())[1], "user": {"login": "owner"}}]
    assert run_command(tmp_path, override(H, "ok"), api=api) is None
    assert not any("/comments" in url for _, url, _ in api.seen)


def test_override_with_a_marker_for_another_head_is_refused(tmp_path):
    api = comment_api(gate=False)
    api.add_run(H, render(blocked_verdict("c" * 40), ())[1])
    assert run_command(tmp_path, override(H, "ok"), api=api) is None


def test_override_with_an_unparseable_gate_check_is_refused(tmp_path):
    api = comment_api(gate=False)
    api.add_run(H, "no marker <!-- prgate-verdict:v1 {\"outcome\": 1} -->")
    assert run_command(tmp_path, override(H, "ok"), api=api) is None


def test_the_newest_gate_check_is_the_one_overridden(tmp_path):
    api = comment_api(gate=False)
    api.add_run(H, render(blocked_verdict(), ())[1])
    newer = Verdict(Outcome.CLEARED, H, ("all requirements met",), None, (), True)
    api.add_run(H, render(newer, ())[1])
    assert run_command(tmp_path, override(H, "ok"), api=api) is None  # cleared needs no override


def test_non_commands_post_nothing_and_call_no_api(tmp_path):
    api = comment_api()
    for body in ("thanks!", f"/gate approve {H}", f"/gate override {H}", "/gate override abc reason"):
        assert run_command(tmp_path, None, api=api, body=body) is None
    assert api.seen == []


def test_comment_on_a_plain_issue_is_ignored(tmp_path):
    api = comment_api()
    env = env_for(tmp_path, "issue_comment", comment_event(f"/gate override {H} ok", pull_request=False))
    assert cli.main(["command"], env=env, github=factory(api)) == 0 and api.seen == []


def test_command_mode_runs_no_stage1_and_no_git(tmp_path, monkeypatch):
    def never(*a, **k):
        raise AssertionError("command mode must not run git or stage 1")
    monkeypatch.setattr(cli, "run_stage1", never)
    monkeypatch.setattr(cli, "parse_diff", never)
    monkeypatch.setattr(subprocess, "run", never)
    monkeypatch.setattr(subprocess, "Popen", never)
    assert run_command(tmp_path, override(H, "ok")) is not None


def test_command_refuses_a_pull_request_event(tmp_path):
    api = comment_api()
    env = env_for(tmp_path, "pull_request_target", pr_event())
    assert cli.main(["command"], env=env, github=factory(api)) == 2 and api.seen == []


def test_command_with_a_hostile_pr_head_posts_nothing(tmp_path):
    api = comment_api(head="zz")
    api.prs[5]["head"]["sha"] = "$(id)"
    assert run_command(tmp_path, override(H, "ok"), api=api, expect=2) is None


def test_command_api_failure_does_not_crash_or_leak(tmp_path, capsys):
    api = comment_api()
    api.fail.append(("GET", r"/pulls/", 500))
    assert run_command(tmp_path, override(H, "ok"), api=api, expect=1) is None
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err


def test_refusal_reason_is_printed_without_the_comment_text(tmp_path, capsys):
    run_command(tmp_path, override(H, "::set-output name=x::y"), sender="stranger")
    out = capsys.readouterr().out
    assert "override refused" in out and "::set-output" not in out


def test_unknown_mode_is_a_usage_error(capsys):
    for gone in ("execute", "generate-tests", "silent-status", "approve"):
        assert cli.main([gone], env={}) == 2
    assert cli.main(["--help"], env={}) == 0
    usage = capsys.readouterr().out
    assert "stage1" in usage and "execute" not in usage and "silent" not in usage
