"""Build prgate's wheel reproducibly and pin its sha256 in action-requirements.txt.

    python release/hash_release.py <version>            # owner, at release time: rewrite the pin
    python release/hash_release.py --check <version>    # release workflow: the wheel must be the pinned one

The wheel is built from the committed state of its inputs (HEAD), never the working tree, with the
exact tools in release/build-requirements.txt installed by hash into a fresh venv, a fixed umask and
normalised file modes, and SOURCE_DATE_EPOCH set to the time of the last commit that touched an input.
action-requirements.txt and action.yml are not inputs, so committing the new pin leaves the hash alone.
Exit 1 means refused; nothing is written then.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "action-requirements.txt"
BUILD_REQUIREMENTS = ROOT / "release" / "build-requirements.txt"
PLACEHOLDER = "0" * 64
# Everything the wheel is built from. Nothing else in the repo can change its bytes.
WHEEL_INPUTS = ("src", "pyproject.toml", "setup.py", "README.md", "LICENSE")

# git archive must emit the committed bytes: no line-ending conversion from the caller's config,
# and no attribute that substitutes, converts, filters or drops content on export.
ARCHIVE_CONFIG = ("-c", "core.autocrlf=false", "-c", "core.eol=lf")
REWRITING_ATTRIBUTES = frozenset({"export-subst", "export-ignore", "eol", "text", "crlf", "ident", "filter",
                                  "working-tree-encoding"})

_PIN = re.compile(r"prgate==(?P<version>\S+) --hash=sha256:(?P<digest>[0-9a-f]{64})")
_VERSION = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)


class Refused(Exception):
    pass


def _git(*args: str) -> str:
    r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise Refused(f"git {' '.join(args[:2])} failed: {r.stderr.strip()}")
    return r.stdout


def _inputs(worktree: bool = False) -> list[str]:
    """The inputs that exist: tracked, plus untracked-but-not-ignored with `worktree` (LICENSE may not exist yet)."""
    extra = ("--others", "--exclude-standard") if worktree else ()
    tracked = set(_git("ls-files", "-z", "--cached", *extra, "--", *WHEEL_INPUTS).split("\0")) - {""}
    found = [p for p in WHEEL_INPUTS if any(t == p or t.startswith(p + "/") for t in tracked)]
    if "src" not in found or "pyproject.toml" not in found:
        raise Refused("src/ and pyproject.toml must be committed")
    return found


def committed_version() -> str:
    m = _VERSION.search(_git("show", "HEAD:src/prgate/__init__.py"))
    if not m:
        raise Refused("no __version__ in the committed src/prgate/__init__.py")
    return m.group(1)


def source_date_epoch() -> str:
    epoch = _git("log", "-1", "--format=%ct", "HEAD", "--", *WHEEL_INPUTS).strip()
    if not epoch.isdigit():
        raise Refused("no commit touches the wheel inputs (a shallow clone needs fetch-depth: 0)")
    return epoch


def check_committed() -> None:
    dirty = _git("status", "--porcelain", "--untracked-files=no", "--", *WHEEL_INPUTS)
    if dirty.strip():
        raise Refused("uncommitted changes to the wheel inputs; commit them first:\n" + dirty)


def refuse_rewriting_attributes(check_attr_output: str) -> None:
    """`git check-attr -a` lines are `<path>: <attr>: <value>`; any set rewriting attribute is refused."""
    for line in check_attr_output.splitlines():
        path, _, rest = line.partition(": ")
        attr, _, value = rest.partition(": ")
        if attr in REWRITING_ATTRIBUTES and value != "unset":
            raise Refused(f"{path} has git attribute `{attr}: {value}`, which changes archived bytes; remove it")


def check_attributes() -> None:
    """Attributes on the committed inputs (in-tree .gitattributes at HEAD, .git/info/attributes, core.attributesFile)."""
    files = [p for p in _git("ls-tree", "-r", "-z", "--name-only", "HEAD", "--", *_inputs()).split("\0") if p]
    out = subprocess.run(["git", "-C", str(ROOT), *ARCHIVE_CONFIG, "check-attr", "--source=HEAD", "-a", "--stdin", "-z"],
                         input="\0".join(files), capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise Refused(f"git check-attr failed: {out.stderr.strip()}")
    fields = out.stdout.split("\0")
    refuse_rewriting_attributes("".join(f"{a}: {b}: {c}\n" for a, b, c in zip(*[iter(fields)] * 3)))


def _normalise(tree: Path, epoch: int) -> None:
    for path in sorted(tree.rglob("*"), reverse=True):
        if path.is_symlink():
            raise Refused(f"symlink in the wheel inputs: {path.relative_to(tree)}")
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
        os.utime(path, (epoch, epoch))


def stage_head(dest: Path) -> None:
    """The committed inputs at HEAD, as plain files with normalised modes."""
    check_attributes()
    archive = subprocess.run(["git", "-C", str(ROOT), *ARCHIVE_CONFIG, "archive", "--format=tar", "HEAD", "--",
                              *_inputs()],
                             capture_output=True, check=True).stdout
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    _normalise(dest, int(source_date_epoch()))


def stage_worktree(dest: Path) -> None:
    """The working-tree inputs (tracked and untracked-but-not-ignored). For tests during development."""
    listed = _git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--",
                  *_inputs(worktree=True)).split("\0")
    for rel in sorted({p for p in listed if p}):
        src = ROOT / rel
        if src.is_file() and "__pycache__" not in src.parts:
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest / rel)
    _normalise(dest, int(source_date_epoch()))


def build_tools(workdir: Path) -> str:
    """A fresh venv holding exactly release/build-requirements.txt; returns its python."""
    env_dir = workdir / "build-venv"
    venv.create(env_dir, with_pip=True, clear=True)
    python = str(env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    subprocess.run([python, "-I", "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
                    "--no-input", "--require-hashes", "--no-deps", "--only-binary=:all:",
                    "-r", str(BUILD_REQUIREMENTS)], check=True)
    return python


def build_wheel(tree: Path, outdir: Path, python: str, epoch: str) -> Path:
    """`python -m build --wheel` on `tree`, deterministic: fixed SOURCE_DATE_EPOCH and umask."""
    outdir.mkdir(parents=True, exist_ok=True)
    fresh = Path(tempfile.mkdtemp(prefix="wheel-", dir=outdir))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "SETUPTOOLS_", "PYTHON"))}
    env.update(SOURCE_DATE_EPOCH=epoch, PYTHONHASHSEED="0", LC_ALL="C.UTF-8")
    old = os.umask(0o022)
    try:
        subprocess.run([python, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(fresh), str(tree)],
                       env=env, check=True, stdout=subprocess.DEVNULL)
    finally:
        os.umask(old)
    made = sorted(fresh.iterdir())
    if len(made) != 1 or made[0].suffix != ".whl":
        raise Refused(f"expected one wheel from the build, found {[m.name for m in made]}")
    wheel = Path(shutil.move(made[0], outdir / made[0].name))
    fresh.rmdir()
    return wheel


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_atomically(path: Path, text: str) -> None:
    """Write via a temp file in the same directory and os.replace, so the pin is never half-written."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def rewrite_requirements(text: str, version: str, digest: str) -> str:
    """The pin line replaced; comment lines kept as they are."""
    _pinned(text)
    lines = text.splitlines()
    pins = [i for i, ln in enumerate(lines) if ln.strip() and not ln.lstrip().startswith("#")]
    lines[pins[0]] = f"prgate=={version} --hash=sha256:{digest}"
    return "\n".join(lines) + "\n"


def _pinned(text: str) -> re.Match:
    pins = [_PIN.fullmatch(ln.strip()) for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if len(pins) != 1 or pins[0] is None:
        raise Refused("action-requirements.txt must hold exactly one `prgate==<v> --hash=sha256:<hex>` line")
    return pins[0]


def verify_pin(text: str, version: str, digest: str) -> None:
    pin = _pinned(text)
    if pin["digest"] == PLACEHOLDER:
        raise Refused("action-requirements.txt still holds the placeholder hash; run release/hash_release.py")
    if pin["version"] != version:
        raise Refused(f"action-requirements.txt pins prgate=={pin['version']}, not {version}")
    if pin["digest"] != digest:
        raise Refused(f"the built wheel's sha256 is {digest}, but action-requirements.txt pins {pin['digest']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("version", help="the version being released; must equal prgate.__version__")
    parser.add_argument("--check", action="store_true",
                        help="build and verify against action-requirements.txt instead of rewriting it")
    parser.add_argument("--outdir", type=Path, help="keep the wheel here (default: a temporary directory)")
    args = parser.parse_args(argv)
    try:
        committed = committed_version()
        if args.version != committed:
            raise Refused(f"version {args.version} does not match __version__ = {committed!r} at HEAD")
        if args.check:
            # Fail fast on the placeholder or a wrong version, before spending a build.
            pinned = REQUIREMENTS.read_text(encoding="utf-8")
            verify_pin(pinned, args.version, _pinned(pinned)["digest"])
        check_committed()
        epoch = source_date_epoch()
        with tempfile.TemporaryDirectory(prefix="prgate-release-") as tmp:
            work = Path(tmp)
            stage_head(work / "src")
            python = build_tools(work)
            outdir = args.outdir.resolve() if args.outdir else work / "dist"
            wheel = build_wheel(work / "src", outdir, python, epoch)
            if wheel.name != f"prgate-{args.version}-py3-none-any.whl":
                raise Refused(f"built {wheel.name}, not a wheel for prgate {args.version}")
            digest = sha256(wheel)
            text = REQUIREMENTS.read_text(encoding="utf-8")
            if args.check:
                verify_pin(text, args.version, digest)
            else:
                write_atomically(REQUIREMENTS, rewrite_requirements(text, args.version, digest))
    except Refused as e:
        print(f"hash_release: {e}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print(f"hash_release: {e}", file=sys.stderr)
        return 1
    print(f"SOURCE_DATE_EPOCH={epoch}")
    print(f"{wheel.name} sha256:{digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
