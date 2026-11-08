import json
import subprocess

import pytest

import getpass

from fakes import FakeGh, ScriptedPrompter, UnansweredQuestion
from prgate.cli import main
from prgate.setup import gh as ghmod
from prgate.setup.gh import CliGh, GhError
from prgate.setup.ui import TerminalPrompter


class Calls(list):
    kwargs: list


def record_subprocess(monkeypatch, *, rc=0, stdout="", stderr=""):
    calls = Calls()
    calls.kwargs = []

    def fake_run(argv, input=None, **kw):
        calls.append((list(argv), input))
        calls.kwargs.append(kw)
        return subprocess.CompletedProcess(argv, rc, stdout, stderr)

    monkeypatch.setattr(ghmod.subprocess, "run", fake_run)
    return calls


def test_secret_goes_on_stdin_not_argv(monkeypatch):
    calls = record_subprocess(monkeypatch)
    CliGh().set_env_secret("o/r", "prgate-verdict", "PRGATE_APP_KEY", "s3cr3t")
    argv, stdin = calls[0]
    assert "s3cr3t" not in " ".join(argv) and stdin == "s3cr3t"
    assert argv == ["gh", "secret", "set", "PRGATE_APP_KEY", "--env", "prgate-verdict", "--repo", "o/r"]


def test_secret_failure_does_not_echo_secret(monkeypatch):
    record_subprocess(monkeypatch, rc=1, stderr="bad value s3cr3t (HTTP 422)")
    with pytest.raises(GhError) as e:
        CliGh().set_env_secret("o/r", "env", "N", "s3cr3t")
    assert "s3cr3t" not in e.value.message and "s3cr3t" not in str(e.value)


def test_api_body_goes_on_stdin(monkeypatch):
    calls = record_subprocess(monkeypatch, stdout="{}")
    CliGh().api("POST", "repos/o/r/rulesets", {"name": "prgate"})
    argv, stdin = calls[0]
    assert argv[:4] == ["gh", "api", "-X", "POST"] and json.loads(stdin) == {"name": "prgate"}
    assert "prgate" not in " ".join(argv[4:]).replace("repos/o/r/rulesets", "")


def test_api_error_raises_with_status(monkeypatch):
    record_subprocess(monkeypatch, rc=1, stderr="gh: Not Found (HTTP 404)")
    with pytest.raises(GhError) as e:
        CliGh().api("GET", "repos/o/missing")
    assert e.value.status == 404


def test_api_error_message_excludes_body(monkeypatch):
    record_subprocess(monkeypatch, rc=1, stderr="gh: Validation Failed (HTTP 422)")
    with pytest.raises(GhError) as e:
        CliGh().api("POST", "repos/o/r/x", {"private": "TOPSECRETBODY"})
    assert "TOPSECRETBODY" not in e.value.message and e.value.status == 422


def test_scopes_parsed_from_header(monkeypatch):
    record_subprocess(monkeypatch, stdout="HTTP/2.0 200 OK\nX-Oauth-Scopes: repo, workflow\n\n{}")
    assert CliGh().scopes() == frozenset({"repo", "workflow"})


def test_scopes_unknown_without_header(monkeypatch):
    record_subprocess(monkeypatch, stdout="HTTP/2.0 200 OK\n\n{}")
    assert CliGh().scopes() is None


def test_missing_gh_is_a_gh_error(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(ghmod.subprocess, "run", boom)
    with pytest.raises(GhError):
        CliGh().login()


def test_cli_lists_setup_commands(capsys):
    rc = main(["--help"])
    out = capsys.readouterr().out
    assert rc == 0 and "init" in out and "doctor" in out and "agent-token" not in out


def test_fake_gh_records_writes_and_resumes():
    gh = FakeGh(fail_once={("PUT", "repos/o/r/environments/e"): 500})
    with pytest.raises(GhError):
        gh.api("PUT", "repos/o/r/environments/e")
    again = FakeGh.resume(gh)
    again.api("PUT", "repos/o/r/environments/e")
    again.set_env_secret("o/r", "e", "N", "v")
    assert ("PUT", "repos/o/r/environments/e") in again.writes
    again.set_env_secret("o/r", "e", "N2", "s3cr3t-value-xyz")
    assert again.writes and not any("s3cr3t-value-xyz" in part for w in again.writes for part in w)
    assert FakeGh.fully_set_up().secrets["prgate-verdict"]


def test_scripted_prompter_raises_on_unknown_question():
    p = ScriptedPrompter({"name": "x"})
    assert p.ask("App name?") == "x"
    with pytest.raises(UnansweredQuestion):
        p.confirm("Continue?", False)


def test_status_parsed_from_non_api_form(monkeypatch):
    record_subprocess(monkeypatch, rc=1, stderr="HTTP 403: Resource not accessible (https://api.github.com/repos/o/r)")
    with pytest.raises(GhError) as e:
        CliGh().login()
    assert e.value.status == 403


def test_status_parsed_from_api_form(monkeypatch):
    record_subprocess(monkeypatch, rc=1, stderr="gh: Forbidden (HTTP 403)")
    with pytest.raises(GhError) as e:
        CliGh().login()
    assert e.value.status == 403


def test_multiline_secret_lines_are_redacted(monkeypatch):
    pem = "-----BEGIN KEY-----\nABCDEFGHIJKLMNOP\nQRSTUVWXYZ012345\n-----END KEY-----"
    record_subprocess(monkeypatch, rc=1, stderr="bad: ABCDEFGHIJKLMNOP\nthen QRSTUVWXYZ012345\n(HTTP 422)")
    with pytest.raises(GhError) as e:
        CliGh().set_env_secret("o/r", "env", "N", pem)
    assert "ABCDEFGHIJKLMNOP" not in e.value.message and "QRSTUVWXYZ012345" not in e.value.message


def test_no_stdin_uses_devnull(monkeypatch):
    calls = record_subprocess(monkeypatch, stdout="{}")
    CliGh().api("GET", "user")
    assert calls.kwargs[0].get("stdin") is subprocess.DEVNULL


def test_secret_prompt_uses_getpass(monkeypatch):
    def no_input(*a, **k):
        raise AssertionError("input() must not be used for secrets")

    monkeypatch.setattr("builtins.input", no_input)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "hidden")
    assert TerminalPrompter().secret("Key") == "hidden"


def test_empty_scopes_header_is_empty_set_missing_is_none(monkeypatch):
    record_subprocess(monkeypatch, stdout="HTTP/2.0 200 OK\nX-OAuth-Scopes: \n\n{}")
    assert CliGh().scopes() == frozenset()
    record_subprocess(monkeypatch, stdout="HTTP/2.0 200 OK\n\n{}")
    assert CliGh().scopes() is None
