"""Python dependency manifests, read as text. Nothing here imports or runs the code it reads.

Reads requirements*.txt, pyproject.toml, setup.cfg and setup.py directly under one directory and
reports what they declare, plus what this reader cannot see through: indirection (includes,
dynamic values), direct references (URL, git, path) and package index settings.
"""
from __future__ import annotations

import ast
import configparser
import json
import re
import shlex
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

_SPEC_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_AT_URL = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*(\S+)")
_EXTRAS_ONLY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\s*\[[^\]]*\]")  # `name[extra]`: no version, no URL
_ARCHIVE = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2")
_PARSE_ERRORS = (ValueError, SyntaxError, RecursionError, MemoryError, AttributeError, TypeError,
                 configparser.Error)  # ValueError covers bad TOML and bad UTF-8

# pip's requirements-file options: long name -> (short name, takes a value, kind)
_OPTIONS = {
    "--requirement": ("-r", True, "include"), "--constraint": ("-c", True, "include"),
    "--editable": ("-e", True, "include"),
    "--index-url": ("-i", True, "index"), "--extra-index-url": (None, True, "index"),
    "--find-links": ("-f", True, "index"), "--trusted-host": (None, True, "index"),
    "--no-index": (None, False, "index"),
    "--no-binary": (None, True, "other"), "--only-binary": (None, True, "other"),
    "--prefer-binary": (None, False, "other"), "--require-hashes": (None, False, "other"),
    "--pre": (None, False, "other"), "--use-feature": (None, True, "other"),
    "--config-settings": ("-C", True, "other"), "--always-unzip": ("-Z", False, "other"),
    "--global-option": (None, True, "other"), "--install-option": (None, True, "other"),
    "--hash": (None, True, "other"),
}
_SHORT_BY_LETTER = {short[1]: long for long, (short, _, _) in _OPTIONS.items() if short}
_PYPI_OK = {"--index-url", "--extra-index-url"}


def _normalise(name: str) -> str:
    """PEP 503 name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Manifests:
    deps: dict[str, str] = field(default_factory=dict)      # normalised name -> first manifest declaring it
    plain: set[tuple[str, str]] = field(default_factory=set)    # (name, file) declared as a PyPI name
    direct: dict[tuple[str, str], str] = field(default_factory=dict)  # (name, file) -> non-PyPI source
    indirect: set[str] = field(default_factory=set)         # files declaring deps we cannot see
    indexes: set[tuple[str, str, str]] = field(default_factory=set)  # (file, option, fingerprint)
    own: set[str] = field(default_factory=set)              # the project's own names
    self_refs: set[tuple[str, str]] = field(default_factory=set)  # (name, file) given as `name[extra]` only
    unknown_name: bool = False                              # the project's own name is not a literal
    env_tools: bool = False                                 # hatch environments may install from any index

    def spec(self, text: str, file: str) -> None:
        """Record one requirement string such as `Flask>=1`, `pkg @ git+https://...` or `./vendor/x`."""
        text = text.strip()
        if m := _AT_URL.match(text):
            name = _normalise(m.group(1))
            url = m.group(2).lower()
            self.deps.setdefault(name, file)
            self.direct[name, file] = ("a git repository" if url.startswith(("git+", "git:"))
                                       else "a local path" if url.startswith("file:") else "a URL")
            return
        head = text.split(";", 1)[0].strip()
        if not head or "/" in head or "\\" in head or head.startswith(".") \
                or head.lower().endswith(_ARCHIVE) or not (m := _SPEC_NAME.match(head)):
            self.indirect.add(file)  # a path or URL line has no name we can trust
            return
        name = _normalise(m.group())
        self.deps.setdefault(name, file)
        self.plain.add((name, file))
        if not file.startswith("requirements") and _EXTRAS_ONLY.fullmatch(head):
            self.self_refs.add((name, file))

    def index(self, file: str, option: str, value: object, *, pypi_ok: bool = False) -> None:
        """Record a package index setting. With `pypi_ok`, pypi.org itself is not worth noting."""
        url = value.get("url") if isinstance(value, dict) else value
        if pypi_ok and isinstance(url, str) and urlsplit(url).hostname == "pypi.org":
            return
        self.indexes.add((file, option, json.dumps(value, sort_keys=True, default=str)))


def _resolve(option: str) -> str | None:
    """A long option by exact name or unique prefix, as optparse does; None if unknown or ambiguous."""
    if option in _OPTIONS:
        return option
    hits = [name for name in _OPTIONS if name.startswith(option)]
    return hits[0] if len(hits) == 1 else None


def _option_tokens(tokens: list[str], file: str, out: Manifests) -> None:
    """Every option on a requirements line. Anything not understood counts as indirection."""
    i = 0
    while i < len(tokens):
        token = tokens[i]
        i += 1
        value: str | None = None
        if token.startswith("--"):
            name, eq, attached = token.partition("=")
            long = _resolve(name)
            value = attached if eq else None
        elif token[1:2] in _SHORT_BY_LETTER and token[:1] == "-":
            long = _SHORT_BY_LETTER[token[1]]
            value = token[2:] or None
        else:
            long = None
        if long is None:
            out.indirect.add(file)
            continue
        takes_value, kind = _OPTIONS[long][1:]
        if not takes_value and value:  # e.g. `-Zx` or `--pre=1`: not an option pip would read this way
            out.indirect.add(file)
            continue
        if takes_value and value is None:
            if i >= len(tokens):
                out.indirect.add(file)
                break
            value, i = tokens[i], i + 1
        if kind == "include":
            out.indirect.add(file)
        elif kind == "index":
            out.index(file, long, value if takes_value else True, pypi_ok=long in _PYPI_OK)


def _requirements(text: str, file: str, out: Manifests) -> None:
    for line in re.sub(r"\\\r?\n", " ", text).splitlines():
        line = re.sub(r"(^|\s)#.*", "", line).strip()
        if not line:
            continue
        # A requirement may be followed by per-requirement options (--hash=...); read them all.
        spec, options = _split_options(line)
        if spec:
            out.spec(spec, file)
        if options:
            try:
                tokens = shlex.split(options)
            except ValueError:
                out.indirect.add(file)
                continue
            _option_tokens(tokens, file, out)


def _split_options(line: str) -> tuple[str, str]:
    """(requirement, options) of one requirements line."""
    if line.startswith("-"):
        return "", line
    m = re.search(r"\s+(?=--?[A-Za-z])", line)
    return (line[:m.start()], line[m.end():]) if m else (line, "")


_SOURCE_KEYS = (("git", "a git repository"), ("path", "a local path"), ("url", "a URL"),
                ("workspace", "a workspace member"), ("index", "a non-PyPI index"),
                ("source", "a non-PyPI index"))


def _source_kind(table: object, *, any_table: bool = False) -> str | None:
    """Where a dependency table says it comes from, if not PyPI. With `any_table` (uv sources) a
    table of any shape replaces the PyPI source, so an unrecognised one still counts."""
    if isinstance(table, list):
        kinds = [_source_kind(t, any_table=any_table) for t in table]
        return next((k for k in kinds if k), None)
    if isinstance(table, dict):
        for key, kind in _SOURCE_KEYS:
            if key in table:
                return kind
        return "a custom source" if any_table and table else None
    return None


def _table(parent: dict, key: str) -> dict:
    """`parent[key]` as a table; a value of another shape cannot be read, so it raises."""
    value = parent.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"{key} is not a table")
    return value


def _list(value: object, key: str) -> list:
    """A dependency group must be a list: a string would be read one letter at a time."""
    if not isinstance(value, list):
        raise ValueError(f"{key} is not a list")
    return value


def _pyproject(text: str, file: str, out: Manifests) -> None:
    data = tomllib.loads(text)
    project = _table(data, "project")
    tool = _table(data, "tool")
    poetry, uv, pdm = _table(tool, "poetry"), _table(tool, "uv"), _table(tool, "pdm")
    for name in (project.get("name"), poetry.get("name")):
        if isinstance(name, str):
            out.own.add(_normalise(name))
    if {"dependencies", "optional-dependencies"} & set(_list(project.get("dynamic", []), "dynamic")):
        out.indirect.add(file)
    if "name" in project.get("dynamic", []):
        out.unknown_name = True
    if "envs" in _table(tool, "hatch"):
        out.env_tools = True
    groups = [_list(project.get("dependencies", []), "dependencies"),
              *(_list(v, "optional-dependencies") for v in _table(project, "optional-dependencies").values()),
              *(_list(v, "dependency-groups") for v in _table(data, "dependency-groups").values()),
              *(_list(v, "dev-dependencies") for v in _table(pdm, "dev-dependencies").values()),
              _list(uv.get("dev-dependencies", []), "dev-dependencies")]
    for group in groups:
        for s in group:
            if isinstance(s, str):
                out.spec(s, file)
    tables = [_table(poetry, "dependencies"), _table(poetry, "dev-dependencies"),
              *(_table(_table(_table(poetry, "group"), g), "dependencies") for g in _table(poetry, "group"))]
    for table in tables:
        for key, value in table.items():
            if key.lower() == "python":
                continue
            name = _normalise(key)
            out.deps.setdefault(name, file)
            if kind := _source_kind(value):
                out.direct[name, file] = kind
            else:
                out.plain.add((name, file))
    for key, value in _table(uv, "sources").items():  # a uv source replaces where the name comes from
        if kind := _source_kind(value, any_table=True):
            name = _normalise(key)
            out.plain.discard((name, file))
            out.deps.setdefault(name, file)
            out.direct[name, file] = kind
    entries = [(where, e) for where, value in (("tool.poetry.source", poetry.get("source")),
                                               ("tool.uv.index", uv.get("index")),
                                               ("tool.pdm.source", pdm.get("source"))) for e in value or []
               if not (isinstance(e, dict) and "url" not in e and str(e.get("name", "")).lower() == "pypi")]
    for where, entry in entries:  # pypi.org may be ignored only as the sole index
        out.index(file, where, entry, pypi_ok=len(entries) == 1)
    for scope, table in (("tool.uv", uv), ("tool.uv.pip", uv.get("pip", {}))):
        for key in ("index-url", "extra-index-url", "find-links", "no-index"):
            if table.get(key):
                out.index(file, f"{scope}.{key}", table[key], pypi_ok=key.endswith("index-url"))


def _cfg(text: str, file: str, out: Manifests) -> None:
    cfg = configparser.ConfigParser(interpolation=None, strict=False)
    cfg.read_string(text)
    if name := cfg.get("metadata", "name", fallback="").strip():
        out.own.add(_normalise(name))
    values = [cfg.get("options", "install_requires", fallback="")]
    if cfg.has_section("options.extras_require"):
        values += [v for _, v in cfg.items("options.extras_require")]
    for value in values:
        if value.strip().startswith(("file:", "attr:")):
            out.indirect.add(file)
            continue
        for line in value.splitlines():
            if line.strip():
                out.spec(line, file)


def _literal_specs(node: ast.expr | None, file: str, out: Manifests) -> None:
    """Specs from a list or tuple of string literals; anything else is indirection, never guessed."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        out.indirect.add(file)
        return
    for e in node.elts:
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            out.spec(e.value, file)
        else:
            out.indirect.add(file)


def _dotted_tail(node: ast.expr) -> str:
    return node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else ""


def _setup_py(text: str, file: str, out: Manifests) -> None:
    found = False
    for node in ast.walk(ast.parse(text)):
        if not (isinstance(node, ast.Call) and _dotted_tail(node.func) == "setup"):
            continue
        found = True
        for kw in node.keywords:
            if kw.arg is None:
                out.indirect.add(file)  # setup(**options): any key may be set
            elif kw.arg == "name":
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    out.own.add(_normalise(kw.value.value))
                else:
                    out.unknown_name = True
            elif kw.arg == "install_requires":
                _literal_specs(kw.value, file, out)
            elif kw.arg == "extras_require":
                if isinstance(kw.value, ast.Dict) and None not in kw.value.keys:
                    for value in kw.value.values:
                        _literal_specs(value, file, out)
                else:
                    out.indirect.add(file)
    if not found:
        out.indirect.add(file)  # no recognisable setup(...) call, e.g. an aliased setup


_READERS = {"txt": _requirements, "toml": _pyproject, "cfg": _cfg, "py": _setup_py}


def read_manifests(repo: Path) -> Manifests:
    """What the manifests directly under `repo` declare. Raises ValueError when one cannot be read.

    A self-reference that names only extras (`myproject[extra]`) is not a dependency, so it is dropped.
    """
    out = Manifests()
    for path in (*sorted(repo.glob("requirements*.txt")), repo / "pyproject.toml",
                 repo / "setup.cfg", repo / "setup.py"):
        if not path.is_file():
            continue
        try:
            _READERS[path.name.rsplit(".", 1)[-1]](path.read_text("utf-8"), path.name, out)
        except _PARSE_ERRORS as e:
            raise ValueError(f"{path.name} could not be parsed ({type(e).__name__})") from e
    for name, file in out.self_refs:  # `myproject[extra]` in the project's own metadata is not a dependency
        if name in out.own:
            out.plain.discard((name, file))
            if not any(k[0] == name for k in (*out.plain, *out.direct)):
                out.deps.pop(name, None)
    return out
