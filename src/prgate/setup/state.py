"""What `prgate init` remembers on this machine: the gate App's id and slug. Never a secret."""
from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

_REPO = re.compile(r"([A-Za-z0-9_-][A-Za-z0-9_.-]*)/([A-Za-z0-9_-][A-Za-z0-9_.-]*)")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,99}")
_MAX_STATE = 64 * 1024


def _dir(repo: str, home: Path) -> Path:
    m = _REPO.fullmatch(repo) if isinstance(repo, str) else None
    if not m:
        raise ValueError("not an OWNER/REPO name")
    return Path(home) / ".config" / "prgate" / f"{m[1]}__{m[2]}"


def state_dir(repo: str, home: Path | None = None) -> Path:
    """`~/.config/prgate/<owner>__<repo>/`, created with mode 0700."""
    d = _dir(repo, Path.home() if home is None else home)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


@dataclass(frozen=True)
class LocalState:
    gate_app_id: int | None = None
    gate_app_slug: str | None = None

    @classmethod
    def load(cls, repo: str, home: Path | None = None) -> "LocalState":
        """The saved state, or an empty one when there is none or it cannot be read. Creates nothing."""
        path = _dir(repo, Path.home() if home is None else home) / "state.json"
        try:
            with open(path, "rb") as f:
                raw = f.read(_MAX_STATE + 1)
            data = json.loads(raw) if len(raw) <= _MAX_STATE else None
        except (OSError, ValueError, RecursionError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        app_id, slug = data.get("gate_app_id"), data.get("gate_app_slug")
        if type(app_id) is not int or app_id <= 0 or not isinstance(slug, str) or not _SLUG.fullmatch(slug):
            return cls()
        return cls(app_id, slug)

    def save(self, repo: str, home: Path | None = None) -> None:
        d = state_dir(repo, home)
        tmp = d / f".state.{secrets.token_hex(4)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"gate_app_id": self.gate_app_id, "gate_app_slug": self.gate_app_slug}, f)
            os.replace(tmp, d / "state.json")
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
