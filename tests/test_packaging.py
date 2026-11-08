"""Packaging, version consistency and the release workflow."""
import hashlib
import os
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

import prgate
from prgate.setup.files import render_workflow

ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = "0" * 64


def _release_workflow() -> str:
    # The workflow may sit in release/ or in .github/workflows/; either is accepted.
    for rel in ("release/release.yml", ".github/workflows/release.yml"):
        if (ROOT / rel).is_file():
            return (ROOT / rel).read_text(encoding="utf-8")
    pytest.fail("no release workflow at release/release.yml or .github/workflows/release.yml")


def _hash_release():
    from release import hash_release
    return hash_release


# --- versions ---------------------------------------------------------------------------------------

def test_versions_agree():
    v = prgate.__version__
    reqs = (ROOT / "action-requirements.txt").read_text(encoding="utf-8")
    assert re.search(rf"^prgate=={re.escape(v)} --hash=sha256:[0-9a-f]{{64}}$", reqs, re.MULTILINE)
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "--require-hashes" in action and "action-requirements.txt" in action
    assert render_workflow(f"Abubakarjutt/PRGate@v{v}").count(f"@v{v}") >= 1


def _release_tag() -> str | None:
    """The tag being released, or None. A branch named like `v2-work` is not a tag."""
    if os.environ.get("GITHUB_REF_TYPE") == "tag" and os.environ.get("GITHUB_REF_NAME", "").startswith("v"):
        return os.environ["GITHUB_REF_NAME"]
    return None


def test_release_tag_is_only_a_tag(monkeypatch):
    monkeypatch.setenv("GITHUB_REF_NAME", "v2-work")
    monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
    assert _release_tag() is None
    monkeypatch.delenv("GITHUB_REF_TYPE")
    assert _release_tag() is None
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    assert _release_tag() == "v2-work"


def test_tag_matches_version():
    tag = _release_tag()
    if tag:
        assert tag == f"v{prgate.__version__}"


def test_placeholder_hash_never_reaches_a_tag():
    reqs = (ROOT / "action-requirements.txt").read_text(encoding="utf-8")
    if _release_tag():
        assert PLACEHOLDER not in reqs, "action-requirements.txt still holds the placeholder hash"


def test_pyproject_metadata():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["build-system"] == {"requires": ["setuptools>=77"], "build-backend": "setuptools.build_meta"}
    project = meta["project"]
    assert "version" not in project and project["dynamic"] == ["version"]
    assert meta["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "prgate.__version__"}
    assert project["license"] == "MIT" and project["readme"] == "README.md"
    assert "experimental, report-only" in project["description"]
    assert "Development Status :: 3 - Alpha" in project["classifiers"]
    assert project["urls"]["Source"] == "https://github.com/Abubakarjutt/PRGate"
    assert project["dependencies"] == []
    assert project["scripts"] == {"prgate": "prgate.cli:main"}
    assert "templates/*.yml" in meta["tool"]["setuptools"]["package-data"]["prgate"]


# --- the wheel --------------------------------------------------------------------------------------

def _build(tmp_path: Path, name: str, umask: int) -> Path:
    """Stage and build with `umask` in force for both, as a careless caller would leave it."""
    hr = _hash_release()
    tree = tmp_path / f"{name}-src"
    old = os.umask(umask)
    try:
        hr.stage_worktree(tree)
        wheel = hr.build_wheel(tree, tmp_path / f"{name}-dist", sys.executable, hr.source_date_epoch())
        assert os.umask(umask) == umask, "build_wheel must restore the caller's umask"
        return wheel
    finally:
        os.umask(old)


def test_wheel_contains_template_and_only_the_package(tmp_path):
    pytest.importorskip("build")
    wheel = _build(tmp_path, "a", 0o022)
    assert wheel.name == f"prgate-{prgate.__version__}-py3-none-any.whl"
    names = zipfile.ZipFile(wheel).namelist()
    assert "prgate/templates/pr-gate.yml" in names
    assert "prgate/cli.py" in names and "prgate/setup/files.py" in names
    # Nothing outside the package directories, and no sandbox module.
    assert not any(n.startswith(("proof/", "research_notes/", "reports/")) or n.endswith("sandbox.py") for n in names)
    assert not any(n.endswith(("action.yml", "action-requirements.txt")) for n in names)
    dist_info = f"prgate-{prgate.__version__}.dist-info/"
    assert all(n.startswith(("prgate/", dist_info)) for n in names), names
    metadata = zipfile.ZipFile(wheel).read(dist_info + "METADATA").decode()
    assert "Requires-Dist" not in metadata and "experimental, report-only" in metadata


def test_staging_and_build_ignore_the_callers_umask(tmp_path):
    """Under umask 077 the staged copies start as 0600; staging normalises them and build_wheel forces
    umask 022 for setuptools' own dist-info files, so the wheel is byte-identical to a umask-022 build."""
    pytest.importorskip("build")
    first = _build(tmp_path, "a", 0o022)
    second = _build(tmp_path, "b", 0o077)
    assert hashlib.sha256(first.read_bytes()).hexdigest() == hashlib.sha256(second.read_bytes()).hexdigest()
    modes = {i.filename: i.external_attr >> 16 for i in zipfile.ZipFile(second).infolist()}
    assert modes["prgate/cli.py"] == 0o100644 and modes[f"prgate-{prgate.__version__}.dist-info/METADATA"] == 0o100644


# --- the hash script --------------------------------------------------------------------------------

def test_hash_script_refuses_a_version_that_is_not_dunder_version():
    before = (ROOT / "action-requirements.txt").read_bytes()
    r = subprocess.run([sys.executable, str(ROOT / "release/hash_release.py"), "9.9.9"],
                       cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 1 and "__version__" in r.stderr
    assert (ROOT / "action-requirements.txt").read_bytes() == before


def test_pin_is_written_atomically(tmp_path, monkeypatch):
    hr = _hash_release()
    target = tmp_path / "action-requirements.txt"
    target.write_text("old\n")
    hr.write_atomically(target, "new\n")
    assert target.read_text() == "new\n" and sorted(p.name for p in tmp_path.iterdir()) == [target.name]

    def boom(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(hr.os, "replace", boom)
    with pytest.raises(OSError):
        hr.write_atomically(target, "half\n")
    assert target.read_text() == "new\n" and sorted(p.name for p in tmp_path.iterdir()) == [target.name]


@pytest.mark.parametrize("line", [
    "src/prgate/cli.py: export-subst: set",
    "src/prgate/cli.py: eol: lf",
    "README.md: text: auto",
    "pyproject.toml: crlf: set",
    "src/prgate/a.py: filter: lfs",
    "src/prgate/a.py: ident: set",
    "src/prgate/a.py: working-tree-encoding: UTF-16",
    "src/prgate/a.py: export-ignore: set",
])
def test_attributes_that_rewrite_archived_bytes_are_refused(line):
    hr = _hash_release()
    with pytest.raises(hr.Refused):
        hr.refuse_rewriting_attributes(line + "\n")


def test_harmless_or_unset_attributes_pass():
    hr = _hash_release()
    hr.refuse_rewriting_attributes("")
    hr.refuse_rewriting_attributes("src/prgate/cli.py: linguist-language: Python\nREADME.md: text: unset\n")
    hr.check_attributes()  # this repo's committed inputs carry none


def test_archive_ignores_the_callers_eol_config():
    hr = _hash_release()
    assert hr.ARCHIVE_CONFIG == ("-c", "core.autocrlf=false", "-c", "core.eol=lf")


def test_rewrite_keeps_the_comment_and_pins_the_hash():
    hr = _hash_release()
    text = "# a comment that stays\nprgate==0.0.1 --hash=sha256:" + PLACEHOLDER + "\n"
    out = hr.rewrite_requirements(text, "0.0.1", "ab" * 32)
    assert out == "# a comment that stays\nprgate==0.0.1 --hash=sha256:" + "ab" * 32 + "\n"
    with pytest.raises(hr.Refused):
        hr.rewrite_requirements("# nothing pinned\n", "0.0.1", "ab" * 32)


def test_verify_pin_refuses_placeholder_wrong_version_and_wrong_hash():
    hr = _hash_release()
    good = "# c\nprgate==0.0.1 --hash=sha256:" + "ab" * 32 + "\n"
    hr.verify_pin(good, "0.0.1", "ab" * 32)
    for text, version, digest in [
        ("# c\nprgate==0.0.1 --hash=sha256:" + PLACEHOLDER + "\n", "0.0.1", PLACEHOLDER),
        (good, "0.0.2", "ab" * 32),
        (good, "0.0.1", "cd" * 32),
    ]:
        with pytest.raises(hr.Refused):
            hr.verify_pin(text, version, digest)


def test_build_requirements_are_exact_and_hashed():
    lines = [ln for ln in (ROOT / "release/build-requirements.txt").read_text().splitlines()
             if ln.strip() and not ln.startswith("#")]
    names = {ln.split("==")[0] for ln in lines}
    assert {"build", "setuptools"} <= names
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][^ ]* --hash=sha256:[0-9a-f]{64}", ln) for ln in lines), lines


# --- the release workflow ---------------------------------------------------------------------------

def test_release_workflow_has_no_token_and_pins_publish_action():
    wf = _release_workflow()
    assert "id-token: write" in wf and "password:" not in wf and "PYPI_TOKEN" not in wf
    assert "secrets." not in wf and "api-token" not in wf.lower()
    assert re.search(r"pypa/gh-action-pypi-publish@[0-9a-f]{40}", wf)


def test_release_workflow_pins_every_action_and_reads_only_by_default():
    wf = _release_workflow()
    uses = re.findall(r"uses:\s*(\S+)", wf)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses
    assert re.search(r"^permissions:\n  contents: read$", wf, re.MULTILINE)


def test_release_workflow_builds_checks_and_publishes_only_the_pinned_wheel():
    wf = _release_workflow()
    assert re.search(r"^on:\n  push:\n    tags:\n      - \"v\*\"$", wf, re.MULTILINE)
    assert "environment: pypi" in wf
    assert "release/hash_release.py --check" in wf and "build-requirements.txt" in wf
    assert "fetch-depth: 0" in wf
    assert "sha256:0{64}' action-requirements.txt" in wf  # explicit placeholder refusal
    assert "tests/test_packaging.py" in wf
    assert "upload-artifact@" in wf and "download-artifact@" in wf
    assert "repository-url: https://test.pypi.org/legacy/" in wf
    assert "startsWith(github.ref_name, 'v0.0.')" in wf
