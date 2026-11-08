"""The `gh` CLI as a narrow interface. Request bodies and secrets reach `gh` on stdin only."""
from __future__ import annotations

import json
import re
import subprocess
from typing import Any, Protocol

_HTTP = re.compile(r"\(HTTP (\d{3})\)|\bHTTP (\d{3}):")
_MAX_MESSAGE = 500


class GhError(Exception):
    """A failed `gh` call. `message` is gh's stderr only: never the request body or a secret."""

    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class Gh(Protocol):
    def api(self, method: str, path: str, body: dict | None = None) -> Any: ...
    def set_env_secret(self, repo: str, env: str, name: str, value: str) -> None: ...
    def login(self) -> str: ...
    def scopes(self) -> frozenset[str] | None:
        """Token scopes, or None when unknown (for example a fine-grained token)."""
        ...


def redact_secret(text: str, secret: str) -> str:
    """`text` with `secret`, and each of its lines of 8 or more characters, replaced by `[redacted]`."""
    if not secret:
        return text
    pieces = {secret} | {p for p in (secret.strip(), *(ln.strip() for ln in secret.splitlines())) if len(p) >= 8}
    for piece in sorted(pieces, key=len, reverse=True):
        text = text.replace(piece, "[redacted]")
    return text


def _run(argv: list[str], stdin: str | None, redact: str | None = None) -> str:
    try:
        extra = {"stdin": subprocess.DEVNULL} if stdin is None else {}
        proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=120, **extra)
    except FileNotFoundError:
        raise GhError(None, "the gh CLI is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise GhError(None, "gh timed out") from None
    except OSError as e:
        raise GhError(None, f"gh could not run ({type(e).__name__})") from None
    if proc.returncode != 0:
        text = (proc.stderr or "").strip()
        if redact:
            text = redact_secret(text, redact)
        m = _HTTP.search(text)
        raise GhError(int(m.group(1) or m.group(2)) if m else None, text[:_MAX_MESSAGE] or f"gh exited {proc.returncode}")
    return proc.stdout or ""


class CliGh:
    def api(self, method: str, path: str, body: dict | None = None) -> Any:
        argv = ["gh", "api", "-X", method.upper(), path]
        stdin = None
        if body is not None:
            argv += ["--input", "-"]
            stdin = json.dumps(body)
        out = _run(argv, stdin).strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except ValueError:
            raise GhError(None, "gh returned a response that is not JSON") from None

    def set_env_secret(self, repo: str, env: str, name: str, value: str) -> None:
        _run(["gh", "secret", "set", name, "--env", env, "--repo", repo], value, redact=value)

    def login(self) -> str:
        data = self.api("GET", "user")
        login = data.get("login") if isinstance(data, dict) else None
        if not isinstance(login, str) or not login:
            raise GhError(None, "gh did not report a login")
        return login

    def scopes(self) -> frozenset[str] | None:
        for line in _run(["gh", "api", "-i", "user"], None).splitlines():
            name, sep, value = line.partition(":")
            if sep and name.strip().lower() == "x-oauth-scopes":
                return frozenset(s.strip() for s in value.split(",") if s.strip())
        return None
