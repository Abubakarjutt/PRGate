"""Setup commands (`prgate init`, `prgate doctor`): the CLI entry points. The steps live in `prgate.setup.run`."""
from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

DEV_OPTIONS = ("action_ref", "index_url")


def _warn(msg: str) -> None:
    print(f"prgate: {msg}", file=sys.stderr, flush=True)


def _options(args: Any, env: Mapping[str, str]) -> tuple[str, str | None] | None:
    """(action_ref, index_url), or None after saying why the hidden development options are refused."""
    from prgate.setup.files import render_workflow
    from prgate.setup.run import DEFAULT_ACTION_REF

    if any(getattr(args, k, None) is not None for k in DEV_OPTIONS) and env.get("PRGATE_DEV") != "1":
        _warn("development option; set PRGATE_DEV=1")
        return None
    action_ref = args.action_ref if args.action_ref is not None else DEFAULT_ACTION_REF
    try:
        render_workflow(action_ref, index_url=args.index_url)
    except ValueError as e:
        _warn(str(e))
        return None
    return action_ref, args.index_url


def _tools(gh: Any, prompter: Any) -> tuple[Any, Any]:
    from prgate.setup.gh import CliGh
    from prgate.setup.ui import TerminalPrompter

    return (gh if gh is not None else CliGh()), (prompter if prompter is not None else TerminalPrompter())


def init(args: Any, env: Mapping[str, str], *, gh: Any = None, prompter: Any = None) -> int:
    from prgate.setup import run

    opts = _options(args, env)
    if opts is None:
        return 2
    gh, prompter = _tools(gh, prompter)
    return run.init(gh, Path.cwd(), prompter, Path.home(), opts[0], index_url=opts[1])


def doctor(args: Any, env: Mapping[str, str], *, gh: Any = None, prompter: Any = None) -> int:
    from prgate.setup import run
    from prgate.setup.preflight import repo_from_remote

    opts = _options(args, env)
    if opts is None:
        return 2
    try:
        repo = repo_from_remote(Path.cwd())
    except ValueError as e:
        _warn(str(e))
        return 1
    gh, prompter = _tools(gh, prompter)
    return run.doctor(gh, repo, prompter, Path.home(), opts[0], index_url=opts[1])
