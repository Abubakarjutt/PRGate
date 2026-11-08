"""prgate command line: `stage1`, `verdict` and `command`, as run by the gate workflow.

Trust boundaries:
- `stage1` runs in a job with no secrets. It reads git objects of the base checkout and the
  fetched PR head, and writes a JSON artifact. It never runs PR code.
- `verdict` and `command` hold the App token (env PRGATE_TOKEN only). They never touch git or
  PR files; `verdict` reads the artifact as data and `command` reads the gate App's own check.
- Nothing taken from the event or the PR is printed, except SHAs after validation.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from . import __version__, setup
from .checks import facts
from .commands import authorise, override_report, parse_command
from .conclude import MAX_ARTIFACT, build_verdict, conclusion, dump_stage1
from .config import CONFIG_PATH, Config, load_config, parse_config
from .diff import DiffError, git_output, parse_diff
from .github import GitHub, GitHubError, valid_repo, valid_sha
from .models import CheckResult, RunStatus
from .report import parse, render
from .stage1 import CHECK_NAMES, run_stage1

ARTIFACT = "prgate-stage1.json"
STAGE1_MAX_S = 240  # the stage1 job has timeout-minutes: 5; leave room for setup and upload
PR_EVENT = "pull_request_target"
COMMENT_EVENT = "issue_comment"
_MAX_EVENT = 25 * 1024 * 1024

Factory = Callable[[str, str, "str | None"], Any]


def _say(msg: str) -> None:
    print(f"prgate: {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"prgate: {msg}", file=sys.stderr, flush=True)


def _get(d: object, *keys: str) -> object:
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def _event(env: Mapping[str, str]) -> dict | None:
    path = env.get("GITHUB_EVENT_PATH")
    if not path:
        _warn("GITHUB_EVENT_PATH is not set")
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read(_MAX_EVENT + 1)
        data = json.loads(raw) if len(raw) <= _MAX_EVENT else None
    except (OSError, ValueError, RecursionError):
        data = None
    if not isinstance(data, dict):
        _warn("the event payload could not be read")
        return None
    return data


def _event_name_is(env: Mapping[str, str], want: str, mode: str, *, optional: bool = False) -> bool:
    name = env.get("GITHUB_EVENT_NAME")
    if (optional and name is None) or name == want:
        return True
    _warn(f"`prgate {mode}` runs only on {want} events")
    return False


def _client(env: Mapping[str, str], factory: Factory | None) -> Any:
    token = env.get("PRGATE_TOKEN")
    repo = env.get("GITHUB_REPOSITORY")
    if not token:
        _warn("PRGATE_TOKEN is not set")
        return None
    if not valid_repo(repo):
        _warn("GITHUB_REPOSITORY is not owner/name")
        return None
    make = factory or (lambda t, r, s: GitHub(t, r, app_slug=s))
    try:
        return make(token, repo, env.get("PRGATE_APP_SLUG") or None)
    except ValueError as e:
        _warn(str(e))
        return None


# --- stage1 ---------------------------------------------------------------------------------

def _merge_base(repo: Path, base: str, head: str, deadline: float) -> str:
    out = git_output(repo, "merge-base", base, head, deadline=deadline).decode("ascii", "replace").strip()
    if not valid_sha(out):
        raise DiffError("git merge-base gave no single commit")
    return out


def _stage1(args: argparse.Namespace, env: Mapping[str, str], registry: facts.Registry | None) -> int:
    if not _event_name_is(env, PR_EVENT, "stage1", optional=True):
        return 2
    base, head = args.base, args.head
    if base is None or head is None:
        event = _event(env)
        if event is None:
            return 2
        base = base if base is not None else _get(event, "pull_request", "base", "sha")
        head = head if head is not None else _get(event, "pull_request", "head", "sha")
    if not (valid_sha(base) and valid_sha(head)):
        _warn("base and head must be full 40-character lowercase commit SHAs; nothing was written")
        return 2

    repo = Path.cwd()
    started = time.monotonic()
    config = load_config(repo, base)
    deadline = started + min(config.stage1_s, STAGE1_MAX_S)
    diff_base: str | None = None
    changes: tuple = ()
    checks: tuple = ()
    diff_ok = False
    try:
        diff_base = _merge_base(repo, base, head, deadline)
        changes = parse_diff(repo, diff_base, head, deadline)
        diff_ok = True
    except (DiffError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        _warn(f"could not read the diff ({type(e).__name__}); the PR goes to a person")
        detail = f"the diff could not be read ({type(e).__name__})"
        checks = tuple(CheckResult(name, RunStatus.COULD_NOT_RUN, (), detail) for name in CHECK_NAMES)
    if diff_ok:
        checks = run_stage1(repo, diff_base, head, config, max(deadline - time.monotonic(), 0.0),
                            registry=registry)
    out = Path(args.out or ARTIFACT)
    out.write_text(dump_stage1(base, head, diff_base, changes, checks, diff_ok), encoding="ascii")
    _say(f"stage 1 wrote {len(changes)} changed file(s) and {len(checks)} check result(s) for {head}")
    return 0


# --- verdict --------------------------------------------------------------------------------

def _read_artifact(path: Path) -> bytes | None:
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_ARTIFACT + 1)
    except FileNotFoundError:
        return None
    except OSError:
        return b""  # present but unreadable: treated as malformed
    return raw if len(raw) <= MAX_ARTIFACT else b""


def _config_at(gh: Any, base: str) -> Config:
    try:
        return parse_config(gh.file(CONFIG_PATH, base))
    except GitHubError as e:
        _warn(f"{e}; the policy config is treated as invalid")
        return Config(valid=False, errors=("the policy config could not be read from GitHub",))


def _verdict(args: argparse.Namespace, env: Mapping[str, str], factory: Factory | None) -> int:
    if not _event_name_is(env, PR_EVENT, "verdict"):
        return 2
    event = _event(env)
    if event is None:
        return 2
    base = _get(event, "pull_request", "base", "sha")
    head = _get(event, "pull_request", "head", "sha")
    if not (valid_sha(base) and valid_sha(head)):
        _warn("the event's base or head is not a full commit SHA; nothing was posted")
        return 2
    base_ref = _get(event, "pull_request", "base", "ref")
    default_branch = _get(event, "repository", "default_branch")
    if not isinstance(default_branch, str) or not default_branch or base_ref != default_branch:
        _warn("the PR is not based on the default branch; prgate reports only on PRs into it")
        return 0
    gh = _client(env, factory)
    if gh is None:
        return 2
    config = _config_at(gh, base)
    verdict, checks = build_verdict(_read_artifact(Path(args.stage1 or ARTIFACT)), base, head, config)
    title, body = render(verdict, checks)
    try:
        gh.create_check(head, conclusion(verdict, None, config.mode), title, body)
    except GitHubError as e:
        _warn(f"could not post the report: {e}")
        return 1
    _say(f"posted {verdict.outcome.value} on {head}")
    return 0


# --- command --------------------------------------------------------------------------------

def _command(env: Mapping[str, str], factory: Factory | None) -> int:
    if not _event_name_is(env, COMMENT_EVENT, "command"):
        return 2
    event = _event(env)
    if event is None:
        return 2
    if _get(event, "action") != "created" or not isinstance(_get(event, "issue", "pull_request"), dict):
        _say("not a new pull request comment; nothing to do")
        return 0
    cmd = parse_command(_get(event, "comment", "body"))
    if cmd is None:
        _say("the comment is not a gate command; nothing to do")
        return 0
    number = _get(event, "issue", "number")
    sender = _get(event, "comment", "user", "login")
    default_branch = _get(event, "repository", "default_branch")
    if type(number) is not int or number <= 0 or not isinstance(sender, str) or not sender:
        _warn("the comment event is missing its PR number or sender")
        return 2
    is_bot = _get(event, "comment", "user", "type") == "Bot"
    gh = _client(env, factory)
    if gh is None:
        return 2

    def refuse(why: str) -> int:
        _say(f"override refused: {why}")
        return 0

    try:
        pr = gh.pr(number)
        head, base = _get(pr, "head", "sha"), _get(pr, "base", "sha")
        if not (valid_sha(head) and valid_sha(base)):
            _warn("the PR's head or base is not a full commit SHA; nothing was posted")
            return 2
        if env.get("GITHUB_RUN_ATTEMPT") != "1":
            return refuse("a re-run cannot override; comment again instead")
        if _get(pr, "state") != "open":
            return refuse("the PR is not open")
        base_ref = _get(pr, "base", "ref")
        if not isinstance(default_branch, str) or base_ref != default_branch:
            return refuse("the PR is not based on the default branch")
        config = _config_at(gh, base)
        check = gh.latest_check(head)
        if check is None:
            return refuse("this App has posted no pr-gate report on the current head")
        try:
            verdict = parse(check["output"]["summary"])
        except Exception:
            return refuse("the gate's report on the current head cannot be read")
        author = _get(pr, "user", "login")
        ok, why = authorise(cmd, sender, is_bot, author if isinstance(author, str) else None, head, config,
                            verdict)
        if not ok:
            return refuse(why)
        title, body = override_report(verdict, cmd, sender)
        gh.create_check(head, conclusion(verdict, cmd, config.mode), title, body)
    except GitHubError as e:
        _warn(f"{e}; nothing was posted")
        return 1
    _say(f"override recorded on {head}")
    return 0


# --- entry point ----------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prgate", description="Experimental, report-only PR gate.")
    p.add_argument("--version", action="version", version=f"prgate {__version__}")
    sub = p.add_subparsers(dest="mode", required=True)
    s1 = sub.add_parser("stage1", help="read the PR as git objects and write the stage 1 artifact")
    s1.add_argument("--base", help="base commit SHA (default: from the event)")
    s1.add_argument("--head", help="head commit SHA (default: from the event)")
    s1.add_argument("--out", help=f"artifact path (default: {ARTIFACT})")
    v = sub.add_parser("verdict", help="decide from the stage 1 artifact and post the pr-gate check")
    v.add_argument("--stage1", help=f"artifact path (default: {ARTIFACT})")
    sub.add_parser("command", help="handle a /gate override comment")
    init = sub.add_parser("init", help="set up prgate in this repository (experimental, report-only)")
    doctor = sub.add_parser("doctor", help="check that this repository's prgate setup is complete")
    for s in (init, doctor):  # development only: hidden, and refused unless PRGATE_DEV=1
        s.add_argument("--action-ref", help=argparse.SUPPRESS)
        s.add_argument("--index-url", help=argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None, *, env: Mapping[str, str] | None = None,
         github: Factory | None = None, registry: facts.Registry | None = None,
         gh: Any = None, prompter: Any = None) -> int:
    """`github` and `registry` replace the GitHub client and the PyPI lookup; `gh` and `prompter` replace the
    gh CLI and the terminal for `init` and `doctor` (tests only)."""
    env = os.environ if env is None else env
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2
    if args.mode == "stage1":
        return _stage1(args, env, registry)
    if args.mode == "verdict":
        return _verdict(args, env, github)
    if args.mode == "init":
        return setup.init(args, env, gh=gh, prompter=prompter)
    if args.mode == "doctor":
        return setup.doctor(args, env, gh=gh, prompter=prompter)
    return _command(env, github)


if __name__ == "__main__":
    sys.exit(main())
