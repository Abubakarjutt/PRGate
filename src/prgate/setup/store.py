"""The `prgate-verdict` environment and the App secrets stored in it. A secret value is never printed, logged or raised."""
from __future__ import annotations

import re
from urllib.parse import quote

from prgate.setup.gh import Gh, GhError, redact_secret
from prgate.setup.preflight import RepoInfo

ENV_VERDICT = "prgate-verdict"
SECRET_APP_ID = "PRGATE_APP_ID"
SECRET_APP_KEY = "PRGATE_APP_KEY"

_GLOB = frozenset("*?[]{}")


class SetupAborted(Exception):
    """`init` stops: a step it needs cannot be done safely, or the person declined it. Nothing more is changed."""


_BRANCH_ONLY = {"protected_branches": False, "custom_branch_policies": True}
_SECRET_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_PAGE = 100
_MAX_PAGES = 50


def _policies_path(info: RepoInfo, env: str) -> str:
    return f"repos/{info.full_name}/environments/{quote(env, safe='')}/deployment-branch-policies"


def _list_policies(gh: Gh, info: RepoInfo, env: str) -> list[dict]:
    out: list[dict] = []
    for page in range(1, _MAX_PAGES + 1):
        data = gh.api("GET", f"{_policies_path(info, env)}?per_page={_PAGE}&page={page}")
        items = data.get("branch_policies") if isinstance(data, dict) else None
        total = data.get("total_count") if isinstance(data, dict) else None
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            raise GhError(None, f"GitHub returned an unexpected branch policy list for environment {env}")
        out.extend(items)
        if len(items) < _PAGE or (isinstance(total, int) and len(out) >= total):
            return out
    raise GhError(None, f"environment {env} has too many branch policies to list")


def _is_default(policy: dict, branch: str) -> bool:
    return policy.get("name") == branch and policy.get("type", "branch") == "branch"


def ensure_environment(gh: Gh, info: RepoInfo, name: str) -> None:
    """Create or update `name` so only the default branch may deploy to it. Idempotent."""
    branch = info.default_branch
    if _GLOB & set(branch):
        raise SetupAborted(f"the default branch name {branch!r} can't be used safely in a branch policy, because "
                           "GitHub reads * ? [ ] { } in it as a pattern that could match other branches")
    gh.api("PUT", f"repos/{info.full_name}/environments/{quote(name, safe='')}",
           {"deployment_branch_policy": dict(_BRANCH_ONLY)})
    keep: dict | None = None
    for policy in _list_policies(gh, info, name):
        if keep is None and _is_default(policy, branch):
            keep = policy
            continue
        pid = policy.get("id")
        if type(pid) is not int:
            raise GhError(None, f"environment {name} has a branch policy without an id")
        gh.api("DELETE", f"{_policies_path(info, name)}/{pid}")
    if keep is None:
        try:
            gh.api("POST", _policies_path(info, name), {"name": branch, "type": "branch"})
        except GhError as e:
            if e.status != 422:  # 422: it already exists (made concurrently); the re-list below verifies
                raise
    after = _list_policies(gh, info, name)
    if len(after) != 1 or not _is_default(after[0], branch):
        raise GhError(None, f"environment {name} does not allow exactly the branch {branch}")


def environment_ok(gh: Gh, info: RepoInfo, name: str) -> bool:
    """True when environment `name` exists and only the default branch may deploy to it. Read-only."""
    if _GLOB & set(info.default_branch):
        return False
    try:
        env = gh.api("GET", f"repos/{info.full_name}/environments/{quote(name, safe='')}")
    except GhError as e:
        if e.status == 404:
            return False
        raise
    policy = env.get("deployment_branch_policy") if isinstance(env, dict) else None
    if not isinstance(policy, dict) or {k: policy.get(k) for k in _BRANCH_ONLY} != _BRANCH_ONLY:
        return False
    policies = _list_policies(gh, info, name)
    return len(policies) == 1 and _is_default(policies[0], info.default_branch)


def secret_names(gh: Gh, info: RepoInfo, env: str) -> frozenset[str] | None:
    """Names of the secrets in environment `env` (never values), or None when the environment does not exist."""
    names: set[str] = set()
    for page in range(1, _MAX_PAGES + 1):
        try:
            data = gh.api("GET", f"repos/{info.full_name}/environments/{quote(env, safe='')}/secrets?per_page={_PAGE}&page={page}")
        except GhError as e:
            if e.status == 404 and page == 1:
                return None
            raise
        items = data.get("secrets") if isinstance(data, dict) else None
        if not isinstance(items, list):
            raise GhError(None, f"GitHub returned an unexpected secret list for environment {env}")
        names.update(i["name"] for i in items if isinstance(i, dict) and isinstance(i.get("name"), str))
        if len(items) < _PAGE:
            return frozenset(names)
    raise GhError(None, f"environment {env} has too many secrets to list")


def store_secret(gh: Gh, info: RepoInfo, env: str, name: str, value: str) -> None:
    """Store `value` as environment secret `name`. On failure, a GhError that never contains the value."""
    if not isinstance(name, str) or not _SECRET_NAME.fullmatch(name) or name.startswith("GITHUB_"):
        raise ValueError(f"not a valid secret name: {name!r}")
    where = f"could not store secret {name} in environment {env}"
    failure: tuple[int | None, str] | None = None
    try:
        gh.set_env_secret(info.full_name, env, name, value)
    except GhError as e:
        detail = redact_secret(str(e.message), value) if isinstance(value, str) else "(details withheld)"
        failure = (e.status, f"{where}: {detail}")
    except Exception as e:  # noqa: BLE001  any other failure must not carry the value out
        failure = (None, f"{where} ({type(e).__name__})")
    if failure is not None:
        # Raised outside the except block, so neither __cause__ nor __context__ holds the original error.
        raise GhError(*failure)
