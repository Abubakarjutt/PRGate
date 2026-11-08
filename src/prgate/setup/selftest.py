"""The self-test: a throwaway PR that must get a neutral `pr-gate` report from the gate App, then is cleaned up."""
from __future__ import annotations

import secrets
import time
from dataclasses import replace
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from prgate.setup.gh import Gh, GhError
from prgate.setup.inspect import SetupFinding
from prgate.setup.preflight import RepoInfo

SELFTEST_FILE = "prgate-selftest.txt"
BRANCH_PREFIX = "prgate-selftest-"
CHECK = "pr-gate"
_POLL_S = 5.0
_TITLE = "prgate self-test (experimental, report-only)"
_TEXT = ("prgate self-test. This file is not code, so prgate sends the PR to a person.\n"
         "prgate init closes this PR and deletes its branch when the test ends.\n")
_BODY = ("`prgate init` opened this PR to check that the `pr-gate` report arrives. It closes the PR and deletes "
         "its branch by itself. prgate is experimental and report-only: the check always concludes `neutral`.\n")
_FIX = "open the Actions tab and look at the pr-gate run, then run prgate doctor"


def _sha(data: Any, *keys: str) -> str:
    v = data
    for k in keys:
        v = v.get(k) if isinstance(v, dict) else None
    if not isinstance(v, str) or len(v) not in (40, 64):
        raise GhError(None, f"GitHub returned an unexpected reply (no {'.'.join(keys)})")
    return v


class _Opened:
    def __init__(self) -> None:
        self.branch: str | None = None
        self.pr: int | None = None


def _open(gh: Gh, info: RepoInfo, opened: _Opened) -> str:
    r = info.full_name
    base = _sha(gh.api("GET", f"repos/{r}/git/ref/heads/{quote(info.default_branch, safe='/')}"), "object", "sha")
    tree = _sha(gh.api("GET", f"repos/{r}/git/commits/{base}"), "tree", "sha")
    blob = _sha(gh.api("POST", f"repos/{r}/git/blobs", {"content": _TEXT, "encoding": "utf-8"}), "sha")
    new_tree = _sha(gh.api("POST", f"repos/{r}/git/trees", {"base_tree": tree, "tree": [
        {"path": SELFTEST_FILE, "mode": "100644", "type": "blob", "sha": blob}]}), "sha")
    head = _sha(gh.api("POST", f"repos/{r}/git/commits", {"message": _TITLE, "tree": new_tree, "parents": [base]}), "sha")
    opened.branch = f"{BRANCH_PREFIX}{secrets.token_hex(4)}"  # before the POST: a reply lost after creation still gets cleaned up
    gh.api("POST", f"repos/{r}/git/refs", {"ref": f"refs/heads/{opened.branch}", "sha": head})
    branch = opened.branch
    pr = gh.api("POST", f"repos/{r}/pulls", {"title": _TITLE, "head": branch, "base": info.default_branch, "body": _BODY})
    number = pr.get("number") if isinstance(pr, dict) else None
    if type(number) is not int:
        raise GhError(None, "GitHub returned a pull request without a number")
    opened.pr = number
    return head


def _wait(gh: Gh, info: RepoInfo, head: str, gate_app_id: int, timeout_s: float, poll_s: float) -> SetupFinding:
    deadline = time.monotonic() + timeout_s
    foreign: set[object] = set()
    while True:
        try:
            data = gh.api("GET", f"repos/{info.full_name}/commits/{head}/check-runs?check_name={CHECK}&per_page=100")
            runs = data.get("check_runs") if isinstance(data, dict) else None
        except GhError:
            runs = None  # transient: try again until the deadline
        for run in runs if isinstance(runs, list) else ():
            if not isinstance(run, dict) or run.get("name") != CHECK or run.get("head_sha") != head:
                continue
            app = run.get("app")
            app_id = app.get("id") if isinstance(app, dict) else None
            if app_id != gate_app_id:
                foreign.add(app_id)
                continue
            if run.get("status") != "completed":
                continue
            if run.get("conclusion") == "neutral":
                return SetupFinding("selftest", True, f"the gate App posted a neutral {CHECK} report on the self-test PR", "")
            return SetupFinding("selftest", False, f"the gate App's {CHECK} report concluded {run.get('conclusion')!r}, "
                                                   "not neutral", _FIX)
        if time.monotonic() >= deadline:
            break
        time.sleep(max(0.0, min(poll_s, deadline - time.monotonic())))
    if foreign:
        return SetupFinding("selftest", False, f"a {CHECK} check came only from another App, not the gate App "
                                               f"(id {gate_app_id})", _FIX)
    return SetupFinding("selftest", False, f"no {CHECK} report from the gate App within {int(timeout_s)} s", _FIX)


def _clean_up(gh: Gh, info: RepoInfo, opened: _Opened) -> list[str]:
    left: list[str] = []
    if opened.pr is not None:
        try:
            gh.api("PATCH", f"repos/{info.full_name}/pulls/{opened.pr}", {"state": "closed"})
        except GhError:
            left.append(f"close PR #{opened.pr}")
    if opened.branch is not None:
        try:
            gh.api("DELETE", f"repos/{info.full_name}/git/refs/heads/{opened.branch}")
        except GhError as e:
            if e.status not in (404, 422):  # 404/422: the branch was never created, so nothing is left
                left.append(f"delete branch {opened.branch}")
    return left


def run_selftest(gh: Gh, info: RepoInfo, gate_app_id: int, timeout_s: float = 600, poll_s: float = _POLL_S,
                 say: Callable[[str], None] | None = None) -> SetupFinding:
    """Open a PR adding `prgate-selftest.txt` and wait for a neutral `pr-gate` from the gate App on its head.

    The PR is closed and its branch deleted however the test ends, Ctrl-C included. If an exception ends the
    test and something could not be cleaned up, `say` is told what is left."""
    opened = _Opened()
    finished = False
    try:
        try:
            head = _open(gh, info, opened)
        except GhError as e:
            finding = SetupFinding("selftest", False, f"could not open the self-test PR: {e.message}", _FIX)
        else:
            finding = _wait(gh, info, head, gate_app_id, timeout_s, poll_s)
        finished = True
    finally:
        left = _clean_up(gh, info, opened)
        if left and not finished and say is not None:
            say(f"the self-test stopped early and prgate could not {' or '.join(left)}; please do it by hand")
    if left:
        finding = replace(finding, detail=f"{finding.detail}; prgate could not {' or '.join(left)}, please do it by hand")
    return finding
