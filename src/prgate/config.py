"""Policy config, read from the BASE commit only (never the working tree or the PR head)."""
from __future__ import annotations

import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_PATH = ".prgate.toml"
ENFORCE_ERROR = "enforce mode arrives after the proof; this release is report-only"
CLEAR_CODE_ERROR = "code clearing arrives in a later release"

DEFAULT_ALWAYS_HUMAN = ("**/auth/**", "**/payments/**", "**/migrations/**", ".github/**", CONFIG_PATH)
DEFAULT_DOCS_ALLOWLIST = ("docs/**", "README*", "CHANGELOG*")


@dataclass(frozen=True)
class Config:
    mode: str = "silent"
    always_human: tuple[str, ...] = DEFAULT_ALWAYS_HUMAN
    docs_allowlist: tuple[str, ...] = DEFAULT_DOCS_ALLOWLIST
    clear_docs: bool = False
    clear_code: bool = False
    approvers: frozenset[str] = frozenset()
    overriders: frozenset[str] = frozenset()
    agent_identities: frozenset[str] = frozenset()
    ci_checks: tuple[str, ...] = ()
    language: str | None = None
    image: str | None = None
    install_command: str | None = None
    test_command: str | None = None
    junit_path: str | None = None
    stage1_s: int = 120
    stage2_s: int = 900
    max_mutants: int = 60
    max_llm_calls: int = 2
    valid: bool = True
    errors: tuple[str, ...] = ()


_BOOLS = ("clear_docs", "clear_code")
_INTS = ("stage1_s", "stage2_s", "max_mutants", "max_llm_calls")
_STRS = ("language", "image", "install_command", "test_command", "junit_path")
_LISTS = ("always_human", "docs_allowlist", "ci_checks")
_LOGINS = ("approvers", "overriders", "agent_identities")
_KNOWN = {"mode", *_BOOLS, *_INTS, *_STRS, *_LISTS, *_LOGINS}


def _invalid(*errors: str) -> Config:
    """Safe defaults, nothing can clear."""
    return Config(valid=False, errors=tuple(errors))


def _read_base(repo: Path, base_sha: str) -> tuple[bytes | None, str | None]:
    """Return (content, None); (None, None) if the file is absent; (None, error) if base is unusable."""
    def run(*args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(["git", *args], cwd=repo, capture_output=True)

    try:
        if run("rev-parse", "--verify", "--quiet", f"{base_sha}^{{commit}}").returncode != 0:
            return None, f"cannot resolve base commit {base_sha!r}"
        if run("cat-file", "-e", f"{base_sha}:{CONFIG_PATH}").returncode != 0:
            return None, None
        shown = run("show", f"{base_sha}:{CONFIG_PATH}")
    except OSError as e:
        return None, f"cannot run git: {e}"
    if shown.returncode != 0:
        return None, f"cannot read {CONFIG_PATH} at {base_sha}"
    return shown.stdout, None


def load_config(repo: Path, base_sha: str) -> Config:
    raw, problem = _read_base(repo, base_sha)
    if problem:
        return _invalid(problem)
    return parse_config(raw)


def parse_config(raw: bytes | None) -> Config:
    """Config from the raw bytes of the base commit's .prgate.toml; None means the file is absent."""
    if raw is None:
        return Config()
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as e:
        return _invalid(f"{CONFIG_PATH} is not valid UTF-8: {e}")
    except tomllib.TOMLDecodeError as e:
        return _invalid(f"{CONFIG_PATH} is not valid TOML: {e}")
    except RecursionError:
        return _invalid(f"{CONFIG_PATH} is nested too deeply to parse")

    errors: list[str] = []
    values: dict[str, object] = {}

    for key in sorted(set(data) - _KNOWN):
        errors.append(f"unknown key: {key}")

    mode = data.get("mode", "silent")
    if mode == "enforce":
        errors.append(ENFORCE_ERROR)
    elif mode != "silent":
        errors.append(f"mode must be \"silent\", got {mode!r}")

    for key in _BOOLS:
        if key in data:
            if isinstance(data[key], bool):
                values[key] = data[key]
            else:
                errors.append(f"{key} must be true or false")
    if values.get("clear_code"):
        errors.append(CLEAR_CODE_ERROR)

    for key in _INTS:
        if key in data:
            v = data[key]
            if type(v) is int and v > 0:
                values[key] = v
            else:
                errors.append(f"{key} must be a positive integer")

    for key in _STRS:
        if key in data:
            if isinstance(data[key], str):
                values[key] = data[key]
            else:
                errors.append(f"{key} must be a string")

    for key in (*_LISTS, *_LOGINS):
        if key in data:
            v = data[key]
            if isinstance(v, list) and all(isinstance(i, str) for i in v):
                if key in _LOGINS:
                    values[key] = frozenset(i.lower() for i in v)
                else:
                    values[key] = tuple(v)
            else:
                errors.append(f"{key} must be a list of strings")

    if errors:
        return _invalid(*errors)

    # Union with the defaults: a config can add always-human paths but never drop one.
    user = tuple(values.pop("always_human", ()))  # type: ignore[arg-type]
    human = DEFAULT_ALWAYS_HUMAN + tuple(p for p in user if p not in DEFAULT_ALWAYS_HUMAN)
    return Config(mode="silent", always_human=human, **values)  # type: ignore[arg-type]
