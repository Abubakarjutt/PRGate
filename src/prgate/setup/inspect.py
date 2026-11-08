"""Read-only inspection of a repository's prgate setup, shared by `prgate doctor` and `prgate init`."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

from prgate.config import parse_config
from prgate.setup.apps import installed_app_slugs, is_installed
from prgate.setup.files import CONFIG_FILE, OlderRelease, read_default, workflow_safe
from prgate.setup.gh import Gh, GhError
from prgate.setup.preflight import RepoInfo
from prgate.setup.state import LocalState
from prgate.setup.store import ENV_VERDICT, SECRET_APP_ID, SECRET_APP_KEY, environment_ok, secret_names

STEPS = ("preflight", "files", "workflow_safe", "gate_app", "gate_installed", "environment", "secrets", "selftest")
RUN_INIT = "run prgate init"
APP_PREFIX = "prgate"
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,99}")


@dataclass(frozen=True)
class SetupFinding:
    """One setup step's state. Deliberately not `models.Finding`."""
    step: str
    ok: bool
    detail: str
    fix: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class GateApp:
    slug: str
    app_id: int


@dataclass(frozen=True)
class GateLookup:
    """`app`: the one owner-verified gate App, or None. `ambiguous`: owner-verified prgate Apps when there are several."""
    app: GateApp | None
    ambiguous: tuple[str, ...] = ()


def verified_app(gh: Gh, info: RepoInfo, slug: str) -> GateApp | None:
    """The App `slug` if it exists and is owned by the account `create_app` registers it under: the repo's owner
    (the organization for an organization repo), matched exactly by id and login. Otherwise None."""
    try:
        data = gh.api("GET", f"apps/{quote(slug, safe='')}")
    except GhError as e:
        if e.status == 404:
            return None
        raise
    owner = data.get("owner") if isinstance(data, dict) else None
    app_id = data.get("id") if isinstance(data, dict) else None
    if not (isinstance(owner, dict) and type(owner.get("id")) is int and owner["id"] == info.owner_id
            and isinstance(owner.get("login"), str) and owner["login"].lower() == info.owner.lower()
            and data.get("slug") == slug and type(app_id) is int and app_id > 0):
        return None
    return GateApp(slug, app_id)


def find_gate_app(gh: Gh, info: RepoInfo, state: LocalState) -> GateLookup:
    """The gate App: the slug in local state, else the one prgate App installed on the repo. Either must pass
    `verified_app`; a slug can be re-registered by someone else, and anyone can name an App `prgate-...`."""
    if state.gate_app_slug and _SLUG.fullmatch(state.gate_app_slug):
        app = verified_app(gh, info, state.gate_app_slug)
        if app is not None:
            return GateLookup(app)
    named = [s for s in installed_app_slugs(gh, info.repo_id) if s == APP_PREFIX or s.startswith(f"{APP_PREFIX}-")]
    ours = [a for a in (verified_app(gh, info, s) for s in named) if a is not None]
    if len(ours) == 1:
        return GateLookup(ours[0])
    return GateLookup(None, tuple(a.slug for a in ours))


def missing_secrets(gh: Gh, info: RepoInfo) -> tuple[str, ...]:
    names = secret_names(gh, info, ENV_VERDICT) or frozenset()
    return tuple(n for n in (SECRET_APP_ID, SECRET_APP_KEY) if n not in names)


def _files(gh: Gh, info: RepoInfo) -> SetupFinding:
    exists, text = read_default(gh, info, CONFIG_FILE)
    where = f"{CONFIG_FILE} on {info.default_branch}"
    if not exists:
        return SetupFinding("files", False, f"{where} is missing", RUN_INIT)
    config = parse_config(text.encode("utf-8")) if text is not None else None
    if config is None or not config.valid:
        why = "; ".join(config.errors) if config is not None else "it cannot be read as text"
        return SetupFinding("files", False, f"{where} is not a valid config ({why})",
                            f"fix {CONFIG_FILE}, or delete it and {RUN_INIT}")
    return SetupFinding("files", True, f"{where} is a valid config", "")


def inspect(gh: Gh, info: RepoInfo, state: LocalState, expected_workflow: str,
            older: OlderRelease | None = None) -> list[SetupFinding]:
    """Every step from `files` to `secrets`, in STEPS order. GET requests only; secrets are checked by name.

    With `older`, a workflow pinned to an older prgate release is ok with an update warning.
    """
    out = [_files(gh, info)]
    safety = workflow_safe(gh, info, expected_workflow, older)
    out.append(SetupFinding("workflow_safe", safety.ok, safety.reason,
                            "" if safety.ok else f"fix the workflow named above, then {RUN_INIT}", safety.warnings))

    lookup = find_gate_app(gh, info, state)
    app = lookup.app
    if app is None:
        if lookup.ambiguous:
            detail = f"several prgate Apps owned by {info.owner} are installed ({', '.join(lookup.ambiguous)})"
        elif state.gate_app_slug:
            detail = f"the gate App {state.gate_app_slug} does not exist or is not owned by {info.owner}"
        else:
            detail = f"no prgate gate App owned by {info.owner} is installed on {info.full_name}"
        out.append(SetupFinding("gate_app", False, detail, f"{RUN_INIT} (it asks before making a new App)"))
        out.append(SetupFinding("gate_installed", False, "there is no gate App to install", RUN_INIT))
    else:
        out.append(SetupFinding("gate_app", True, f"the gate App is {app.slug} (id {app.app_id})", ""))
        if is_installed(gh, app.slug, info.repo_id):
            out.append(SetupFinding("gate_installed", True, f"{app.slug} is installed on {info.full_name}", ""))
        else:
            out.append(SetupFinding("gate_installed", False, f"{app.slug} is not installed on {info.full_name}",
                                    f"install it at https://github.com/apps/{app.slug}/installations/new, or {RUN_INIT}"))

    if environment_ok(gh, info, ENV_VERDICT):
        out.append(SetupFinding("environment", True,
                                f"environment {ENV_VERDICT} exists and only {info.default_branch} may use it", ""))
    else:
        out.append(SetupFinding("environment", False, f"environment {ENV_VERDICT} is missing or not limited to "
                                                      f"{info.default_branch}", RUN_INIT))
    missing = missing_secrets(gh, info)
    if missing:
        out.append(SetupFinding("secrets", False, f"environment {ENV_VERDICT} lacks {', '.join(missing)}",
                                f"{RUN_INIT} (a lost key means a new App)"))
    else:
        out.append(SetupFinding("secrets", True, f"{SECRET_APP_ID} and {SECRET_APP_KEY} are stored in {ENV_VERDICT}", ""))
    return out
