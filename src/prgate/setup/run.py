"""`prgate init` and `prgate doctor`. Experimental and report-only: no ruleset, no required check.

`init` publishes the gate files and checks the workflow-safety rule before any GitHub App exists,
then creates the App and stores its id and key at once in `prgate-verdict`. No secret is ever
printed, logged or put in argv: the key lives only in `AppCreds` and reaches `gh` on stdin.
"""
from __future__ import annotations

import re
import shutil
import time
import webbrowser
from pathlib import Path
from typing import Callable

from prgate import __version__
from prgate.setup.apps import (
    app_name, apps_settings_url, create_app, ensure_installed, gate_manifest, is_installed, settings_url,
)
from prgate.setup.detect import detect_project, suggest_ci_checks
from prgate.setup.files import (
    CONFIG_FILE, WORKFLOW_FILE, SetupAnswers, files_on_default, older_release, publish_files, render_config, render_workflow,
    workflow_safe,
)
from prgate.setup.gh import Gh, GhError
from prgate.setup.inspect import APP_PREFIX, STEPS, GateApp, SetupFinding, find_gate_app, inspect, missing_secrets
from prgate.setup.preflight import RepoInfo, preflight, repo_from_remote
from prgate.setup.selftest import run_selftest
from prgate.setup.state import LocalState
from prgate.setup.store import (
    ENV_VERDICT, SECRET_APP_ID, SECRET_APP_KEY, SetupAborted, ensure_environment, environment_ok, store_secret,
)
from prgate.setup.ui import Prompter

DEFAULT_ACTION_REF = f"Abubakarjutt/PRGate@v{__version__}"
NON_PYTHON = "prgate 0.x checks Python tests only; secrets and change types are still checked"
RERUN = "re-run prgate init to continue"
MERGE_FIRST = "merge the prgate setup PR, then re-run prgate init"
INTERRUPTED = 130

REPLACE_SECRETS = f"Create a new gate App and replace the App ID and key stored in {ENV_VERDICT}?"
_PR_NUMBER = re.compile(r"/pull/([0-9]+)$")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_MERGE_POLL_S = 10.0
_ASKS = 3

Which = Callable[[str], "str | None"]


def headline() -> str:
    return f"prgate {__version__} is experimental and report-only."


class _Progress:
    def __init__(self) -> None:
        self.step = STEPS[0]
        self.status = {s: "skipped" for s in STEPS}

    def at(self, step: str) -> None:
        self.step = step

    def mark(self, step: str, done: bool) -> None:
        self.status[step] = "done" if done else "already set"


def _split(answer: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,\s]+", answer or "") if p.strip()]


def _ask_ci(gh: Gh, info: RepoInfo, prompter: Prompter) -> tuple[str, ...]:
    suggested = suggest_ci_checks(gh, info.full_name, info.default_branch)
    if suggested:
        prompter.say(f"These checks ran on each of the last commits of {info.default_branch}: {', '.join(suggested)}")
    answer = prompter.ask("CI checks the report should list, comma-separated (empty for none)", ", ".join(suggested))
    return tuple(dict.fromkeys(p.strip() for p in (answer or "").split(",") if p.strip()))


def _ask_approvers(gh: Gh, prompter: Prompter) -> tuple[str, ...]:
    me = gh.login()
    for _ in range(_ASKS):
        names = _split(prompter.ask("Approvers who may override the gate, comma-separated GitHub logins", me)) or [me]
        bad = [n for n in names if not _LOGIN.fullmatch(n)]
        if not bad:
            return tuple(dict.fromkeys(names))
        prompter.say(f"not a GitHub login: {', '.join(repr(b) for b in bad)}")
    raise SetupAborted("no valid approvers were given")


def _wait_for_merge(gh: Gh, info: RepoInfo, files: dict[str, str], pr_url: str | None, wait_s: float) -> str:
    """"merged" once the files are on the default branch, "closed" if the PR closes without them, else "timeout"."""
    m = _PR_NUMBER.search(pr_url or "")
    deadline = time.monotonic() + wait_s
    while True:
        try:
            if files_on_default(gh, info, files):
                return "merged"
            if m:
                pr = gh.api("GET", f"repos/{info.full_name}/pulls/{m[1]}")
                if isinstance(pr, dict) and pr.get("state") == "closed" and not files_on_default(gh, info, files):
                    return "closed"
        except GhError:
            pass  # one failed read (a 5xx, a network blip) is retried until the deadline
        if time.monotonic() >= deadline:
            return "timeout"
        time.sleep(max(0.0, min(_MERGE_POLL_S, deadline - time.monotonic())))


def _summary(progress: _Progress, selftest: SetupFinding | None) -> str:
    lines = [headline(), "", "Setup steps:"]
    for step in STEPS:
        status = progress.status[step]
        if step == "selftest" and selftest is not None:
            status = "passed" if selftest.ok else f"failed: {selftest.detail}. Fix: {selftest.fix}"
        lines.append(f"  {step}: {status}")
    lines += ["", "The pr-gate check always concludes neutral, so it never blocks a merge. This release has no "
                  "enforce mode; one may come in a later release.",
              "Run `prgate doctor` at any time to check the setup."]
    return "\n".join(lines)


def _gate_app(gh: Gh, info: RepoInfo, repo: str, prompter: Prompter, home: Path, progress: _Progress,
              browser: Callable[[str], bool], app_timeout_s: float) -> GateApp | None:
    """The gate App with its id and key stored. A new App is created when either is missing. None: stop (said)."""
    state = LocalState.load(repo, home)
    lookup = find_gate_app(gh, info, state)
    app = lookup.app
    missing = missing_secrets(gh, info)
    if app is not None and not missing:
        progress.mark("gate_app", False)
        progress.mark("secrets", False)
        if state != LocalState(app.app_id, app.slug):
            _save_state(LocalState(app.app_id, app.slug), repo, home, prompter)
        return app
    if lookup.ambiguous or (app is None and not missing):
        if lookup.ambiguous:
            prompter.say(f"Several prgate Apps owned by {info.owner} are installed on {info.full_name} "
                         f"({', '.join(lookup.ambiguous)}), and prgate cannot tell which one holds the stored key.")
        else:
            prompter.say(f"{ENV_VERDICT} already holds an App ID and key, but no prgate App owned by {info.owner} "
                         "that prgate can confirm is installed on this repository.")
        if not prompter.confirm(REPLACE_SECRETS, False):
            named = ", ".join(lookup.ambiguous) or "none found"
            raise SetupAborted(f"left the stored App ID and key as they are (candidate Apps: {named})")
    if app is not None:  # owner-verified, so this hint never points at someone else's App
        prompter.say(f"The gate App {app.slug} has no stored key in {ENV_VERDICT}, and GitHub shows a key only once, "
                     f"so prgate creates a new App. Delete {app.slug} at {settings_url(info, app.slug)} "
                     "unless another repository uses it")
    name = app_name(APP_PREFIX, info.full_name.split("/", 1)[1])
    leftover = (f"If you created an App on GitHub, delete it at {apps_settings_url(info)}; its key was not kept.")
    try:
        creds = create_app(gh, info, lambda url: gate_manifest(info, name, url), prompter, open_browser=browser,
                           timeout_s=app_timeout_s)
    except (GhError, KeyboardInterrupt, EOFError):
        prompter.say(leftover)
        raise
    progress.mark("gate_app", True)
    progress.at("secrets")
    lost = (f"The App {creds.slug} was created but its key could not be stored, and GitHub shows a key only once. "
            f"Delete the App at {settings_url(info, creds.slug)}, then re-run prgate init.")
    try:  # at once: GitHub never shows this key again
        store_secret(gh, info, ENV_VERDICT, SECRET_APP_ID, str(creds.app_id))
        store_secret(gh, info, ENV_VERDICT, SECRET_APP_KEY, creds.pem)
    except GhError as e:  # store_secret's message never holds the value
        prompter.say(e.message)
        prompter.say(lost)
        return None
    except (KeyboardInterrupt, EOFError):
        prompter.say(lost)
        raise
    progress.mark("secrets", True)
    _save_state(LocalState(creds.app_id, creds.slug), repo, home, prompter)
    return GateApp(creds.slug, creds.app_id)


def _save_state(state: LocalState, repo: str, home: Path, prompter: Prompter) -> None:
    try:
        state.save(repo, home)
    except OSError as e:
        prompter.say(f"warning: could not save prgate's local state ({type(e).__name__}); doctor will find the App "
                     "by its installation")


def _init(gh: Gh, root: Path, prompter: Prompter, home: Path, action_ref: str, index_url: str | None,
          merge_wait_s: float, browser: Callable[[str], bool], app_timeout_s: float, selftest_timeout_s: float,
          which: Which, progress: _Progress) -> int:
    say = prompter.say
    say(headline())
    try:
        repo = repo_from_remote(root)
    except ValueError as e:
        say(f"prgate init: {e}")
        return 1
    workflow = render_workflow(action_ref, index_url=index_url)
    pf = preflight(gh, repo, which)
    for w in pf.warnings:
        say(f"warning: {w}")
    if not pf.ok or pf.repo is None:
        for p in pf.problems:
            say(f"cannot set up prgate: {p}")
        return 1
    info = pf.repo
    progress.mark("preflight", True)

    guess = detect_project(root)
    if guess.language != "python":
        say(f"warning: {NON_PYTHON}")
        if not prompter.confirm("Continue setting up prgate anyway?", False):
            say("stopped; nothing was changed")
            return 1
    answers = SetupAnswers(guess.language, _ask_ci(gh, info, prompter), _ask_approvers(gh, prompter))

    progress.at("files")
    files = {CONFIG_FILE: render_config(answers), WORKFLOW_FILE: workflow}
    published = publish_files(gh, info, files, prompter)
    if published.kind == "pr":
        say(f"{info.default_branch} is protected, so prgate opened a pull request: {published.url}")
        say(f"Waiting up to {max(1, round(merge_wait_s / 60))} minute(s) for it to be merged.")
        merged = _wait_for_merge(gh, info, files, published.url, merge_wait_s)
        if merged == "closed":
            say("the prgate setup PR was closed without merging the gate files; re-run prgate init to open it again")
            return 1
        if merged == "timeout":
            say(MERGE_FIRST)
            return 0
    progress.mark("files", published.kind != "unchanged")

    progress.at("workflow_safe")
    safety = workflow_safe(gh, info, workflow)
    for w in safety.warnings:
        say(f"warning: {w}")
    if not safety.ok:
        say(f"prgate init stopped before creating the GitHub App: {safety.reason}")
        return 1
    progress.mark("workflow_safe", True)

    progress.at("environment")  # before the key exists, so it is never stored where another branch could reach it
    env_was_ok = environment_ok(gh, info, ENV_VERDICT)
    if not env_was_ok:
        ensure_environment(gh, info, ENV_VERDICT)

    progress.at("gate_app")
    app = _gate_app(gh, info, repo, prompter, home, progress, browser, app_timeout_s)
    if app is None:
        return 1

    progress.at("gate_installed")
    was_installed = is_installed(gh, app.slug, info.repo_id)
    if not was_installed:
        ensure_installed(gh, info, app.slug, prompter, open_browser=browser)
    progress.mark("gate_installed", not was_installed)

    progress.at("environment")
    if not environment_ok(gh, info, ENV_VERDICT):
        raise SetupAborted(f"environment {ENV_VERDICT} is not limited to {info.default_branch}")
    progress.mark("environment", not env_was_ok)

    progress.at("selftest")
    say("Opening a self-test PR and waiting for the pr-gate report.")
    selftest = run_selftest(gh, info, app.app_id, timeout_s=selftest_timeout_s, say=say)
    progress.status["selftest"] = "done" if selftest.ok else "failed"
    say(_summary(progress, selftest))
    return 0 if selftest.ok else 1


def init(gh: Gh, root: Path, prompter: Prompter, home: Path, action_ref: str = DEFAULT_ACTION_REF, *,
         index_url: str | None = None, merge_wait_s: float = 900, open_browser: Callable[[str], bool] | None = None,
         app_timeout_s: float = 600, selftest_timeout_s: float = 600, which: Which | None = None) -> int:
    """Set up prgate for the repo at `root`, doing only the steps that are not already done."""
    progress = _Progress()
    try:
        return _init(gh, Path(root), prompter, Path(home), action_ref, index_url, merge_wait_s,
                     open_browser or webbrowser.open, app_timeout_s, selftest_timeout_s, which or shutil.which,
                     progress)
    except (KeyboardInterrupt, EOFError):
        prompter.say(f"setup stopped at step {progress.step}; {RERUN}")
        return INTERRUPTED
    except SetupAborted as e:
        prompter.say(f"prgate init stopped at step {progress.step}: {e}")
        return 1
    except GhError as e:  # gh's stderr only, never a request body or a secret
        prompter.say(f"prgate init stopped at step {progress.step}: {e.message}")
        return 1
    except ValueError as e:  # a value prgate cannot write safely (config or file checks); never a secret
        prompter.say(f"prgate init stopped at step {progress.step}: {e}")
        return 1


def doctor(gh: Gh, repo: str, prompter: Prompter, home: Path, action_ref: str = DEFAULT_ACTION_REF, *,
           index_url: str | None = None, which: Which | None = None) -> int:
    """Check every setup step, read-only. 0 when all are ok, else 1; one line per step, with a fix when not ok."""
    say = prompter.say
    try:
        say(headline())
        workflow = render_workflow(action_ref, index_url=index_url)
        pf = preflight(gh, repo, which or shutil.which)
        for w in pf.warnings:
            say(f"warning: {w}")
        findings = [SetupFinding("preflight", pf.ok, "the repository and your access are fine" if pf.ok
                                 else "; ".join(pf.problems), "" if pf.ok else "fix the problems above, then run prgate doctor")]
        if pf.repo is not None:
            findings += inspect(gh, pf.repo, LocalState.load(repo, home), workflow,
                                older_release(action_ref, index_url=index_url))
    except (KeyboardInterrupt, EOFError):
        say("doctor stopped")
        return INTERRUPTED
    except GhError as e:
        say(f"prgate doctor could not finish: {e.message}")
        return 1
    for f in findings:
        say(f"{f.step}: ok, {f.detail}" if f.ok else f"{f.step}: NOT OK, {f.detail}. Fix: {f.fix}")
        for w in f.warnings:
            say(f"warning: {w}")
    ok = all(f.ok for f in findings) and pf.repo is not None
    say("All setup steps are in place." if ok else "Some setup steps need attention; see the fixes above.")
    return 0 if ok else 1
