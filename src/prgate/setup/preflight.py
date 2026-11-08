"""Read-only checks `prgate init` runs before it changes anything. GET requests only; fails closed."""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

from prgate.setup.gh import Gh, GhError

_PAID = frozenset({"pro", "team", "enterprise"})
_REMOTE = re.compile(r"^(?:git@github\.com:|(?:https?|ssh)://(?:[^@/]+@)?github\.com[:/])([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
                     re.IGNORECASE)
_GH_MISSING = "the gh CLI is not installed; install it from https://cli.github.com and run `gh auth login`"


@dataclass(frozen=True)
class RepoInfo:
    full_name: str
    owner: str
    owner_id: int
    owner_is_org: bool
    repo_id: int
    private: bool
    default_branch: str
    plan: str | None


@dataclass(frozen=True)
class Preflight:
    ok: bool
    problems: tuple[str, ...]
    warnings: tuple[str, ...]
    repo: RepoInfo | None


def parse_remote(url: str) -> str:
    m = _REMOTE.match(url.strip())
    if not m:
        raise ValueError("not a GitHub remote URL (expected git@github.com:OWNER/REPO or https://github.com/OWNER/REPO)")
    owner, repo = m[1], m[2]
    # An owner never starts with a dot; a repository may (an organization's `.github`), but is never `.` or `..`.
    if owner.startswith(".") or repo in (".", "..") or any(p.lower().endswith(".git") for p in (owner, repo)):
        raise ValueError("not a valid GitHub OWNER/REPO in the remote URL")
    return f"{m[1]}/{m[2]}"


def repo_from_remote(root: Path) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(root), "remote", "get-url", "origin"], capture_output=True, text=True, timeout=30,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("could not run git to read the origin remote") from None
    if proc.returncode != 0:
        raise ValueError("this directory has no git remote named origin")
    return parse_remote(proc.stdout)


def _plan_name(data: object) -> str | None:
    plan = data.get("plan") if isinstance(data, dict) else None
    name = plan.get("name") if isinstance(plan, dict) else None
    return name.lower() if isinstance(name, str) and name else None


def _get(gh: Gh, path: str) -> Any:
    return gh.api("GET", path)


def preflight(gh: Gh, repo: str, which: Callable[[str], str | None] | None = None) -> Preflight:
    if (which or shutil.which)("gh") is None:
        return Preflight(False, (_GH_MISSING,), (), None)
    problems: list[str] = []
    warnings: list[str] = []
    try:
        data = _get(gh, f"repos/{repo}")
        owner = data["owner"]
        info = RepoInfo(
            full_name=str(data["full_name"]), owner=str(owner["login"]), owner_id=int(owner["id"]),
            owner_is_org=owner["type"] == "Organization", repo_id=int(data["id"]),
            private=bool(data["private"]), default_branch=str(data["default_branch"]), plan=None,
        )
        perms = data.get("permissions") if isinstance(data, dict) else None
    except GhError as e:
        return Preflight(False, (f"cannot read {repo}: {e.message}",), (), None)
    except (KeyError, TypeError, ValueError, AttributeError):
        return Preflight(False, (f"GitHub returned an unexpected answer for {repo}; refusing to continue",), (), None)

    if not (isinstance(perms, dict) and perms.get("admin") is True):
        problems.append(f"you need admin access to {repo} (the Environment and secret are admin-only)")

    try:
        scopes = gh.scopes()
    except GhError:
        scopes = None
    if scopes is None:
        warnings.append("could not read the token's scopes; if init fails on the workflow file, run `gh auth refresh -s workflow`")
    elif "workflow" not in scopes:
        problems.append("your gh token lacks the workflow scope; run `gh auth refresh -s workflow` and try again")

    if info.owner_is_org:
        role = state = None
        try:
            m = _get(gh, f"user/memberships/orgs/{info.owner}")
            if isinstance(m, dict):
                role, state = m.get("role"), m.get("state")
        except GhError as e:
            problems.append(f"could not confirm your role in {info.owner} ({e.message}); run `gh auth refresh -s read:org` and retry")
            role = "unknown"
        if role == "admin" and state != "active":
            problems.append(f"your owner membership in {info.owner} is not active; accept the organization invitation and retry")
        elif role != "admin" and role != "unknown":
            problems.append(f"{info.owner} is an organization and only an organization owner can create its GitHub App; "
                            f"ask an organization owner to run `prgate init` or to make you an owner")

    plan: str | None = None
    if info.private:
        try:
            if info.owner_is_org:
                plan = _plan_name(_get(gh, f"orgs/{info.owner}"))
            elif info.owner.lower() == gh.login().lower():
                plan = _plan_name(_get(gh, "user"))
        except GhError:
            plan = None
        if plan in _PAID:
            pass
        elif plan == "free":
            problems.append("private repositories on the free plan cannot use this: make the repository public or upgrade the plan")
        else:
            refusal = _probe_protection(gh, repo, info.default_branch)
            if refusal:
                problems.append(refusal)
    info = replace(info, plan=plan)
    return Preflight(not problems, tuple(problems), tuple(warnings), info)


def _probe_protection(gh: Gh, repo: str, branch: str) -> str:
    """'' when branch protection is supported (so the plan is paid); otherwise the refusal."""
    try:
        gh.api("GET", f"repos/{repo}/branches/{branch}/protection")
        return ""
    except GhError as e:
        if e.status == 404 and "not protected" in e.message.lower():
            return ""
        if e.status == 403 and "upgrade" in e.message.lower():
            return "private repositories on the free plan cannot use this: make the repository public or upgrade the plan"
        return "could not confirm the plan supports a private repository; refusing (make the repository public or upgrade the plan)"
