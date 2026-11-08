import http.server
import json
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from prgate.checks import facts
from prgate.checks.facts import facts_check, judge, pypi_registry
from prgate.diff import parse_diff
from prgate.models import RunStatus, Severity
from prgate.plugins.python import PythonPlugin
from test_diff import add, commit
from test_diff import repo  # noqa: F401  (fixture)


class Fake:
    """A registry that records what it was asked and never touches the network."""

    def __init__(self, table=None):
        self.table = table or {}
        self.calls = []

    def __call__(self, name, timeout):
        self.calls.append(name)
        return self.table.get(name, (True, 900))


def run(repo, head, base=None, registry=None, deadline=120):
    """Commit `base` files, then `head` files, and run the fact check on the second commit."""
    if base:
        for path, text in base.items():
            add(repo, path, text)
        commit(repo, "pre")
    for path, text in head.items():
        add(repo, path, text)
    commit(repo, "head")
    changes = parse_diff(repo, "HEAD~1", "HEAD")
    plugin = PythonPlugin()
    return facts_check(repo, changes, "HEAD~1", "HEAD",
                       lambda p: plugin if plugin.handles(p) else None,
                       registry or Fake(), time.monotonic() + deadline)


def undeclared(r):
    return [f for f in r.findings if "isn't declared" in (f.question or "")]


# --- newly declared dependencies ---------------------------------------------------------------

def test_proof_names_the_manifest(repo):
    r = run(repo, {"requirements.txt": "fakepkg-xyz\n"}, registry=Fake({"fakepkg-xyz": (False, None)}))
    assert r.findings[0].path == "requirements.txt"


def test_new_declared_dependency_missing_from_pypi_is_proof(repo):
    r = run(repo, {"requirements.txt": "fakepkg-xyz\n"}, registry=Fake({"fakepkg-xyz": (False, None)}))
    assert r.status == RunStatus.RAN and len(r.findings) == 1
    f = r.findings[0]
    assert f.severity == Severity.PROOF and f.message == "dependency not on PyPI: fakepkg-xyz"


@pytest.mark.parametrize("path, text", [
    ("pyproject.toml", '[project]\nname = "a"\ndependencies = ["fakepkg-xyz>=1"]\n'),
    ("setup.cfg", "[options]\ninstall_requires =\n    fakepkg-xyz\n"),
    ("setup.py", "from setuptools import setup\nsetup(install_requires=['fakepkg-xyz'])\n"),
    ("requirements-dev.txt", "fakepkg-xyz==1\n"),
])
def test_each_manifest_format_yields_proof(repo, path, text):
    r = run(repo, {path: text}, registry=Fake({"fakepkg-xyz": (False, None)}))
    assert [f.severity for f in r.findings] == [Severity.PROOF]


def test_dependency_already_declared_at_base_is_not_looked_up(repo):
    reg = Fake({"old": (False, None)})
    r = run(repo, {"requirements.txt": "old\nnew\n"}, base={"requirements.txt": "old\n"}, registry=reg)
    assert reg.calls == ["new"] and not r.findings


def test_removed_or_unchanged_dependencies_are_not_looked_up(repo):
    reg = Fake()
    run(repo, {"requirements.txt": "a\n", "x.txt": "1"}, base={"requirements.txt": "a\nb\n"}, registry=reg)
    assert reg.calls == []


def test_dependency_names_compare_normalised(repo):
    reg = Fake()
    run(repo, {"requirements.txt": "My_Pkg\n"}, base={"requirements.txt": "my-pkg\n"}, registry=reg)
    assert reg.calls == []


def test_manifests_outside_the_root_are_ignored(repo):
    reg = Fake()
    run(repo, {"sub/requirements.txt": "nested\n", "sub/pyproject.toml": "[["}, registry=reg)
    assert reg.calls == []


def test_symlinked_manifest_at_head_is_could_not_run(repo):
    (repo / "requirements.txt").symlink_to("/etc/hosts")
    commit(repo, "link")
    reg = Fake()
    r = run(repo, {"pyproject.toml": "[project]\n"}, registry=reg)
    assert r.status == RunStatus.COULD_NOT_RUN and "symlink" in r.detail and reg.calls == []


def test_young_package_is_flagged(repo):
    r = run(repo, {"requirements.txt": "x\n"}, registry=Fake({"x": (True, 3)}))
    assert [f.severity for f in r.findings] == [Severity.SUSPICION] and "3 days" in r.findings[0].message


def test_old_package_is_fine(repo):
    assert not run(repo, {"requirements.txt": "x\n"}, registry=Fake({"x": (True, 30)})).findings


@pytest.mark.parametrize("answer", [(None, None), (None, 12)])
def test_registry_down_or_rate_limited_is_could_not_run(repo, answer):
    r = run(repo, {"requirements.txt": "x\n"}, registry=Fake({"x": answer}))
    assert r.status == RunStatus.COULD_NOT_RUN and "PyPI" in r.detail


def test_unreachable_registry_keeps_findings_already_made(repo):
    reg = Fake({"a-gone": (False, None), "b-down": (None, None)})
    r = run(repo, {"requirements.txt": "a-gone\nb-down\n"}, registry=reg)
    assert r.status == RunStatus.COULD_NOT_RUN and [f.severity for f in r.findings] == [Severity.PROOF]


def test_more_than_fifty_new_dependencies_is_could_not_run_without_lookups(repo):
    reg = Fake()
    r = run(repo, {"requirements.txt": "".join(f"pkg{i}\n" for i in range(51))}, registry=reg)
    assert r.status == RunStatus.COULD_NOT_RUN and "50" in r.detail and reg.calls == []


def test_exactly_fifty_is_looked_up(repo):
    reg = Fake()
    r = run(repo, {"requirements.txt": "".join(f"pkg{i}\n" for i in range(50))}, registry=reg)
    assert r.status == RunStatus.RAN and len(reg.calls) == 50


@pytest.mark.parametrize("path, text", [
    ("pyproject.toml", "[[["), ("setup.cfg", "[x\n"), ("setup.py", "setup(["),
])
def test_unparseable_head_manifest_is_could_not_run(repo, path, text):
    r = run(repo, {path: text})
    assert r.status == RunStatus.COULD_NOT_RUN and path in r.detail


def test_unparseable_base_manifest_is_could_not_run(repo):
    r = run(repo, {"pyproject.toml": '[project]\ndependencies = ["a"]\n'}, base={"pyproject.toml": "[[["})
    assert r.status == RunStatus.COULD_NOT_RUN


def test_invalid_package_name_is_suspicion_and_not_looked_up():
    reg = Fake()
    r = judge({"bad name": None, "-x": None}, [], reg, time.monotonic() + 60)
    assert reg.calls == [] and len(r.findings) == 2
    assert all(f.severity == Severity.SUSPICION for f in r.findings)


def test_deadline_in_judge_is_timed_out_and_keeps_findings():
    r = judge({"x": "requirements.txt"}, [("a.py", "fakepkg")], Fake(), time.monotonic() - 1)
    assert r.status == RunStatus.TIMED_OUT and len(r.findings) == 1


def test_expired_deadline_raises_timeout(repo):
    with pytest.raises(subprocess.TimeoutExpired):
        run(repo, {"requirements.txt": "x\n"}, deadline=-1)


# --- uncertainty: a 404 is proof only for a plain PyPI name in a certain, PyPI-only repo ---------

GONE = {"ghost": (False, None)}


def sev(r):
    return [f.severity for f in r.findings]


@pytest.mark.parametrize("path, text", [
    ("requirements.txt", "-r base.txt\nghost\n"),
    ("requirements.txt", "--constraint c.txt\nghost\n"),
    ("requirements.txt", "-e .\nghost\n"),
    ("setup.cfg", "[options]\ninstall_requires = file: r.txt\n"),
    ("setup.cfg", "[options]\ninstall_requires = attr: pkg.deps\n"),
    ("pyproject.toml", '[project]\nname="a"\ndynamic = ["dependencies"]\ndependencies = ["ghost"]\n'),
    ("setup.py", "setup(install_requires=['ghost', read()])\n"),
    ("setup.py", "setup(install_requires=REQS)\n"),
    ("setup.py", "setup(**opts)\n"),
])
def test_indirection_in_a_touched_manifest_is_flagged(repo, path, text):
    r = run(repo, {path: text, **({"requirements.txt": "ghost\n"} if path != "requirements.txt" else {})},
            registry=Fake(GONE))
    msgs = [f.message for f in r.findings]
    assert f"Dependencies are declared indirectly in {path}; prgate could not check them." in msgs
    assert Severity.PROOF not in sev(r)


def test_indirection_at_base_makes_a_404_only_suspicion(repo):
    r = run(repo, {"requirements.txt": "-r other.txt\nghost\n"},
            base={"requirements.txt": "-r other.txt\n"}, registry=Fake(GONE))
    assert Severity.PROOF not in sev(r)
    assert "dependency not on PyPI: ghost" in [f.message for f in r.findings]


def test_symlinked_base_manifest_makes_a_404_only_suspicion(repo):
    (repo / "pyproject.toml").symlink_to("/etc/hosts")
    commit(repo, "link")
    (repo / "pyproject.toml").unlink()  # the PR removes it, so head can be read but base was not
    r = run(repo, {"requirements.txt": "ghost\n"}, registry=Fake(GONE))
    assert sev(r) == [Severity.SUSPICION] and "not on PyPI" in r.findings[0].message


@pytest.mark.parametrize("line, kind", [
    ("ghost @ https://example.com/ghost.whl", "a URL"),
    ("ghost @ git+https://example.com/ghost.git", "a git repository"),
    ("ghost @ file:///opt/ghost", "a local path"),
])
def test_direct_references_are_not_looked_up(repo, line, kind):
    reg = Fake(GONE)
    r = run(repo, {"requirements.txt": line + "\n"}, registry=reg)
    assert reg.calls == [] and [f.message for f in r.findings] == [
        f"ghost is installed from {kind}, not PyPI. Is that intended?"]


def test_poetry_git_and_path_tables_are_direct(repo):
    reg = Fake(GONE)
    r = run(repo, {"pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.12"\n'
                   'ghost = {git = "https://example.com/g.git"}\nlocal = {path = "../l"}\n'
                   'real = "^1"\n'}, registry=reg)
    assert reg.calls == ["real"]
    assert sorted(f.message for f in r.findings) == [
        "ghost is installed from a git repository, not PyPI. Is that intended?",
        "local is installed from a local path, not PyPI. Is that intended?"]


@pytest.mark.parametrize("line", ["./vendor/pkg", "vendor/pkg", "dist/pkg-1.0-py3-none-any.whl",
                                  "pkg-1.0.tar.gz", "git+https://example.com/g.git#egg=ghost",
                                  "https://example.com/ghost.zip"])
def test_path_like_lines_never_become_a_name(repo, line):
    reg = Fake(GONE)
    r = run(repo, {"requirements.txt": line + "\n"}, registry=reg)
    assert reg.calls == [] and Severity.PROOF not in sev(r)
    assert r.findings and "indirectly in requirements.txt" in r.findings[0].message


def test_already_present_direct_reference_is_not_new(repo):
    r = run(repo, {"requirements.txt": "ghost @ https://e.com/g.whl\n", "x.txt": "1"},
            base={"requirements.txt": "ghost @ https://e.com/g.whl\n"})
    assert not r.findings


@pytest.mark.parametrize("path, text, option", [
    ("requirements.txt", "--extra-index-url https://user:secret@idx.example/simple\nghost\n",
     "--extra-index-url"),
    ("requirements.txt", "-i https://idx.example/simple\nghost\n", "-i"),
    ("requirements.txt", "--find-links ./wheels\nghost\n", "--find-links"),
    ("pyproject.toml", '[[tool.poetry.source]]\nname="p"\nurl="https://idx.example/s"\n'
     '[tool.poetry.dependencies]\nghost="1"\n', "tool.poetry.source"),
    ("pyproject.toml", '[[tool.uv.index]]\nname="p"\nurl="https://idx.example/s"\n'
     '[project]\ndependencies=["ghost"]\n', "tool.uv.index"),
    ("pyproject.toml", '[tool.uv]\nindex-url="https://idx.example/s"\n'
     '[project]\ndependencies=["ghost"]\n', "tool.uv.index-url"),
    ("pyproject.toml", '[[tool.pdm.source]]\nname="p"\nurl="https://idx.example/s"\n'
     '[project]\ndependencies=["ghost"]\n', "tool.pdm.source"),
])
def test_new_index_option_is_suspicion_and_downgrades_a_404(repo, path, text, option):
    r = run(repo, {path: text}, registry=Fake(GONE))
    assert Severity.PROOF not in sev(r)
    msgs = [f.message for f in r.findings]
    assert any(option in m and "was added" in m for m in msgs)
    assert any("not on PyPI: ghost" in m for m in msgs)
    assert "secret" not in repr(r)


def test_pypi_as_the_index_is_not_a_non_pypi_index(repo):
    r = run(repo, {"requirements.txt": "--index-url https://pypi.org/simple\nghost\n"}, registry=Fake(GONE))
    assert sev(r) == [Severity.PROOF]


def test_existing_index_at_base_still_downgrades_a_404_without_a_new_finding(repo):
    r = run(repo, {"requirements.txt": "-i https://idx.example/s\nghost\n"},
            base={"requirements.txt": "-i https://idx.example/s\n"}, registry=Fake(GONE))
    assert sev(r) == [Severity.SUSPICION] and "not on PyPI" in r.findings[0].message


def test_directory_names_starting_with_a_dash_are_listed_safely(repo):
    r = run(repo, {"-dir/a.py": "import fakepkg\n"})
    assert r.status == RunStatus.RAN and len(undeclared(r)) == 1


# --- round 2: more ways a 404 is not proof ----------------------------------------------------

PYP = '[project]\nname = "app"\ndependencies = ["ghost"]\n'


@pytest.mark.parametrize("source, kind", [
    ("{workspace = true}", "a workspace member"),
    ("{index = \"private\"}", "a non-PyPI index"),
    ("{git = \"https://example.com/g.git\"}", "a git repository"),
    ("{something = 1}", "a custom source"),
    ("[{path = \"../g\", marker = \"sys_platform == 'linux'\"}]", "a local path"),
])
def test_uv_sources_make_a_name_direct(repo, source, kind):
    reg = Fake(GONE)
    r = run(repo, {"pyproject.toml": PYP + f"[tool.uv.sources]\nghost = {source}\n"}, registry=reg)
    assert reg.calls == [] and f"ghost is installed from {kind}, not PyPI. Is that intended?" in \
        [f.message for f in r.findings]


@pytest.mark.parametrize("path, text", [
    ("pyproject.toml", '[project]\nname = "Ghost_Lib"\n[project.optional-dependencies]\nall = ["ghost-lib[x]"]\n'),
    ("setup.py", "setup(name='ghost.lib', install_requires=['ghost-lib[x]'])\n"),
    ("setup.cfg", "[metadata]\nname = ghost-lib\n[options]\ninstall_requires = ghost_lib[x]\n"),
])
def test_a_projects_own_name_is_not_a_dependency(repo, path, text):
    reg = Fake({"ghost-lib": (False, None)})
    assert not run(repo, {path: text}, registry=reg).findings and reg.calls == []


UNREAD = ["requirements/dev.txt", "requirements-dev.in", "constraints.txt", "Pipfile", "uv.toml",
          "pip.conf", "pip.ini", "poetry.toml", "pdm.toml", "sub/pyproject.toml", "sub/pip.conf",
          "sub/setup.py", "sub/setup.cfg", "sub/requirements.txt", "sub/constraints-dev.in"]


@pytest.mark.parametrize("where", ["base", "head"])
@pytest.mark.parametrize("unread", UNREAD)
def test_dependency_files_the_reader_skips_make_a_404_only_suspicion(repo, where, unread):
    files = {"requirements.txt": "ghost\n"}
    if where == "head":
        r = run(repo, {**files, unread: "x\n"}, registry=Fake(GONE))
    else:
        r = run(repo, files, base={unread: "x\n"}, registry=Fake(GONE))
    assert sev(r) and Severity.PROOF not in sev(r)
    assert "dependency not on PyPI: ghost" in [f.message for f in r.findings]


def test_aliased_setup_call_counts_as_indirect(repo):
    r = run(repo, {"setup.py": "from setuptools import setup as s\ns(install_requires=['ghost'])\n"},
            registry=Fake(GONE))
    assert Severity.PROOF not in sev(r)
    assert "Dependencies are declared indirectly in setup.py; prgate could not check them." in \
        [f.message for f in r.findings]


def test_pdm_dev_dependencies_are_read(repo):
    r = run(repo, {"pyproject.toml": '[project]\nname="a"\n[tool.pdm.dev-dependencies]\ntest = ["ghost"]\n'},
            registry=Fake(GONE))
    assert sev(r) == [Severity.PROOF]


@pytest.mark.parametrize("line, option", [
    ("-r base.txt --extra-index-url https://x.example/s", "--extra-index-url"),
    ("--index-url https://a.example/s --extra-index-url https://b.example/s", "--extra-index-url"),
    ('--extra-index-url "https://x.example/s"', "--extra-index-url"),
    ("-r a.txt -ihttps://x.example/s", "--index-url"),
    ("--no-index -f ./wheels", "--find-links"),
    ("--trusted-host=x.example", "--trusted-host"),
])
def test_every_token_of_a_requirements_option_line_is_read(repo, line, option):
    r = run(repo, {"requirements.txt": line + "\nghost\n"}, registry=Fake(GONE))
    assert Severity.PROOF not in sev(r)
    assert any(option in f.message and "was added" in f.message for f in r.findings)
    assert "x.example" not in repr(r)


def test_requirement_followed_by_options_is_still_a_requirement(repo):
    reg = Fake(GONE)
    r = run(repo, {"requirements.txt": "ghost==1 --hash=sha256:abc --hash sha256:def\n"}, registry=reg)
    assert reg.calls == ["ghost"] and sev(r) == [Severity.PROOF]


@pytest.mark.parametrize("line, option", [
    ("--extra-index https://x.example/s", "--extra-index-url"),
    ("--extra https://x.example/s", "--extra-index-url"),
    ("--find https://x.example/s", "--find-links"),
    ("--no-ind", "--no-index"),
])
def test_long_options_resolve_by_unique_prefix(repo, line, option):
    r = run(repo, {"requirements.txt": line + "\nghost\n"}, registry=Fake(GONE))
    assert Severity.PROOF not in sev(r)
    assert any(option in f.message and "was added" in f.message for f in r.findings)


@pytest.mark.parametrize("line", ["--no- x", "--bogus x", "-Q x", "--index-url", "--extra-index-url 'unclosed"])
def test_unknown_ambiguous_or_broken_options_count_as_indirection(repo, line):
    r = run(repo, {"requirements.txt": line + "\nghost\n"}, registry=Fake(GONE))
    assert Severity.PROOF not in sev(r)
    assert "Dependencies are declared indirectly in requirements.txt; prgate could not check them." in \
        [f.message for f in r.findings]


@pytest.mark.parametrize("section, option", [
    ('[tool.uv]\nfind-links = ["./w"]\n', "tool.uv.find-links"),
    ("[tool.uv]\nno-index = true\n", "tool.uv.no-index"),
    ('[tool.uv.pip]\nindex-url = "https://x.example/s"\n', "tool.uv.pip.index-url"),
    ('[tool.uv.pip]\nextra-index-url = ["https://x.example/s"]\n', "tool.uv.pip.extra-index-url"),
    ('[tool.uv.pip]\nfind-links = ["./w"]\n', "tool.uv.pip.find-links"),
    ("[tool.uv.pip]\nno-index = true\n", "tool.uv.pip.no-index"),
])
def test_more_uv_index_keys(repo, section, option):
    r = run(repo, {"pyproject.toml": PYP + section}, registry=Fake(GONE))
    assert Severity.PROOF not in sev(r) and any(option in f.message for f in r.findings)


def test_pypi_source_table_is_ignored_only_as_the_sole_index(repo):
    pypi = '[[tool.uv.index]]\nname = "pypi"\nurl = "https://pypi.org/simple"\n'
    assert sev(run(repo, {"pyproject.toml": PYP + pypi}, registry=Fake(GONE))) == [Severity.PROOF]


def test_pypi_source_table_beside_another_index_blocks_proof(repo):
    pypi = '[[tool.uv.index]]\nurl = "https://pypi.org/simple"\n'
    r = run(repo, {"pyproject.toml": PYP + pypi + pypi}, registry=Fake(GONE))
    assert Severity.PROOF not in sev(r)


def test_a_name_declared_plainly_anywhere_is_still_looked_up(repo):
    reg = Fake(GONE)
    r = run(repo, {"requirements.txt": "ghost\n", "pyproject.toml": "[project]\ndependencies=['ghost @ https://e.com/g.whl']\n"},
            registry=reg)
    assert reg.calls == ["ghost"]
    assert "dependency not on PyPI: ghost" in [f.message for f in r.findings]


def test_a_name_direct_in_every_manifest_is_not_looked_up(repo):
    reg = Fake(GONE)
    r = run(repo, {"requirements.txt": "ghost @ https://e.com/g.whl\n",
                   "pyproject.toml": "[project]\ndependencies=['ghost @ git+https://e.com/g.git']\n"}, registry=reg)
    assert reg.calls == [] and len(r.findings) == 2


# --- round 3 ------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["package.json", "uv.lock", "poetry.lock", "Pipfile.lock", "package-lock.json",
                                  "pnpm-lock.yaml", "yarn.lock", "Cargo.toml", "go.mod", "Gemfile",
                                  "web/package.json"])
def test_lock_files_and_other_languages_manifests_do_not_block_proof(repo, path):
    r = run(repo, {"requirements.txt": "ghost\n", path: "x\n"}, base={path: "x\n"}, registry=Fake(GONE))
    assert sev(r) == [Severity.PROOF]


def test_own_name_with_a_version_or_url_is_still_a_dependency(repo):
    reg = Fake({"ghost-lib": (False, None)})
    r = run(repo, {"setup.py": "setup(name='ghost-lib', install_requires=['ghost-lib>=1'])\n"}, registry=reg)
    assert reg.calls == ["ghost-lib"]
    reg = Fake({"ghost-lib": (False, None)})
    run(repo, {"pyproject.toml": '[project]\nname="ghost-lib"\ndependencies=["ghost-lib @ https://e.com/g.whl"]\n'},
        registry=reg)
    assert reg.calls == []  # direct, not looked up, and its entry is kept


def test_own_name_extras_are_not_filtered_out_of_requirements_files(repo):
    reg = Fake({"ghost-lib": (False, None)})
    run(repo, {"requirements.txt": "ghost-lib[x]\n", "setup.py": "setup(name='ghost-lib')\n"}, registry=reg)
    assert reg.calls == ["ghost-lib"]


def test_own_name_extras_never_remove_a_direct_entry(repo):
    r = run(repo, {"pyproject.toml": '[project]\nname="ghost-lib"\ndependencies=["ghost-lib @ https://e.com/g.whl",'
                   '"ghost-lib[x]"]\n'}, registry=Fake({"ghost-lib": (False, None)}))
    assert "ghost-lib is installed from a URL, not PyPI. Is that intended?" in [f.message for f in r.findings]


@pytest.mark.parametrize("line", ["-Zx", "-Z=1", "--pre=1", "--no-index=yes", "--requirement"])
def test_options_the_parser_cannot_read_as_written_are_indirect(repo, line):
    r = run(repo, {"requirements.txt": line + "\nghost\n"}, registry=Fake(GONE))
    assert Severity.PROOF not in sev(r)
    assert "Dependencies are declared indirectly in requirements.txt; prgate could not check them." in \
        [f.message for f in r.findings]


@pytest.mark.parametrize("path, text", [
    ("setup.py", "NAME = 'x'\nsetup(name=NAME, install_requires=['ghost'])\n"),
    ("setup.py", "setup(name=get_name(), install_requires=['ghost'])\n"),
    ("pyproject.toml", '[project]\ndynamic = ["name"]\ndependencies = ["ghost"]\n'),
])
def test_unknown_project_name_blocks_proof(repo, path, text):
    r = run(repo, {path: text}, registry=Fake(GONE))
    assert sev(r) == [Severity.SUSPICION] and "not on PyPI" in r.findings[0].message


def test_literal_project_name_still_allows_proof(repo):
    r = run(repo, {"setup.py": "setup(name='app', install_requires=['ghost'])\n"}, registry=Fake(GONE))
    assert sev(r) == [Severity.PROOF]


def test_uv_dev_dependencies_are_read(repo):
    r = run(repo, {"pyproject.toml": '[project]\nname="a"\n[tool.uv]\ndev-dependencies = ["ghost"]\n'},
            registry=Fake(GONE))
    assert sev(r) == [Severity.PROOF]


# --- new imports ---------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["yaml", "fakepkg"])
def test_undeclared_import_is_never_proof_and_never_looked_up(repo, name):
    reg = Fake({name: (False, None)})
    r = run(repo, {"app/a.py": f"import {name}\n"}, registry=reg)
    assert reg.calls == [] and r.status == RunStatus.RAN
    assert [f.severity for f in r.findings] == [Severity.SUSPICION]
    f = r.findings[0]
    assert f.path == "app/a.py" and f.question == f"Which package provides {name}? It isn't declared."


def test_stdlib_local_and_declared_imports_are_ignored(repo):
    r = run(repo, {
        "app/a.py": "import json, sys\nimport mylocal, pkg, srcpkg, sibling\nimport my_dep\nfrom . import x\n",
        "mylocal.py": "", "pkg/__init__.py": "", "src/srcpkg/__init__.py": "", "app/sibling.py": "",
        "requirements.txt": "My-Dep\n",
    })
    assert not r.findings


def test_test_files_are_checked_too(repo):
    r = run(repo, {"tests/test_a.py": "import fakepkg\n"})
    assert [f.path for f in undeclared(r)] == ["tests/test_a.py"]


def test_import_already_in_base_file_is_not_new(repo):
    r = run(repo, {"app/a.py": "import fakepkg\nimport newone\n"}, base={"app/a.py": "import fakepkg\n"})
    assert [f.message for f in r.findings] == ["new import of newone is not declared"]


def test_renamed_file_compares_against_its_old_path(repo):
    body = "import fakepkg\n" + "".join(f"x{i} = {i}\n" for i in range(30))
    add(repo, "app/old.py", body)
    commit(repo, "add")
    subprocess.run(["git", "mv", "app/old.py", "app/new.py"], cwd=repo, check=True)
    commit(repo, "rename")
    plugin = PythonPlugin()
    changes = parse_diff(repo, "HEAD~1", "HEAD")
    r = facts_check(repo, changes, "HEAD~1", "HEAD", lambda p: plugin if plugin.handles(p) else None,
                    Fake(), time.monotonic() + 60)
    assert not r.findings


def test_import_declared_in_the_same_pr_is_declared(repo):
    assert not run(repo, {"app/a.py": "import fakepkg\n", "requirements.txt": "fakepkg\n"}).findings


def test_non_code_changes_need_nothing(repo):
    reg = Fake()
    r = run(repo, {"docs/a.md": "import fakepkg\n"}, registry=reg)
    assert r.status == RunStatus.RAN and not r.findings and reg.calls == []


def test_unparseable_new_python_file_is_could_not_run(repo):
    assert run(repo, {"app/a.py": "def (\n"}).status == RunStatus.COULD_NOT_RUN


def test_unparseable_base_python_file_counts_every_head_import_as_new(repo):
    r = run(repo, {"app/a.py": "import fakepkg\n"}, base={"app/a.py": "def (\n"})
    assert len(undeclared(r)) == 1


# --- the real PyPI lookup, against a local server -----------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        type(self).seen.append((self.path, self.headers.get("User-Agent")))
        parts = self.path.strip("/").split("/")
        simple = parts[0] == "simple"
        name = parts[1] if simple else parts[0]
        stamp = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        body = json.dumps({"releases": {"1": [{"upload_time_iso_8601": stamp}],
                                        "0": [{"upload_time_iso_8601": "2999-01-01T00:00:00Z"}]}})
        table = {"ok": (200, body), "garbled": (200, "not json"), "missing": (404, "{}"),
                 "limited": (429, ""), "broken": (503, ""), "moved": (301, ""),
                 "norelease": (404, "{}"), "simplebroken": (404, "{}"), "drip": (200, "x" * 40)}
        if simple:
            table = {"missing": (404, ""), "norelease": (200, "<html></html>"), "simplebroken": (503, "")}
        code, payload = table[name]
        self.send_response(code)
        if code == 301:
            self.send_header("Location", "http://127.0.0.1:1/x")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            for ch in payload:
                self.wfile.write(ch.encode())
                self.wfile.flush()
                if name == "drip":
                    time.sleep(0.15)
        except OSError:
            pass

    def log_message(self, *a):
        pass


@pytest.fixture
def pypi(monkeypatch):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=lambda: server.serve_forever(0.01), daemon=True).start()
    _Handler.seen = []
    root = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setattr(facts, "PYPI_URL", root + "/{}/json")
    monkeypatch.setattr(facts, "PYPI_SIMPLE_URL", root + "/simple/{}/")
    yield server
    server.shutdown()
    server.server_close()


def test_real_lookup_200_has_an_age_from_the_first_release(pypi):
    exists, age = pypi_registry("ok", 5)
    assert exists is True and age == 10


@pytest.mark.parametrize("name, expected", [
    ("missing", (False, None)), ("limited", (None, None)), ("broken", (None, None)),
    ("garbled", (True, None)), ("moved", (None, None)),
    ("norelease", (True, None)), ("simplebroken", (None, None)),
])
def test_real_lookup_status_mapping(pypi, name, expected):
    assert pypi_registry(name, 5) == expected


def test_real_lookup_sends_only_a_generic_user_agent(pypi):
    pypi_registry("ok", 5)
    (path, agent), = _Handler.seen
    assert path == "/ok/json" and agent.startswith("prgate/") and "@" not in agent


def test_real_lookup_network_error_is_unknown(monkeypatch):
    monkeypatch.setattr(facts, "PYPI_URL", "http://127.0.0.1:1/{}/json")  # nothing listens here
    assert pypi_registry("x", 2) == (None, None)


def test_real_lookup_refuses_an_invalid_name_without_a_request(pypi):
    assert pypi_registry("a/../b", 5) == (None, None) and _Handler.seen == []


def test_real_lookup_confirms_a_404_against_the_simple_index(pypi):
    pypi_registry("missing", 5)
    assert [p for p, _ in _Handler.seen] == ["/missing/json", "/simple/missing/"]
    assert all(a.startswith("prgate/") for _, a in _Handler.seen)


def test_real_lookup_stops_a_slowly_dripped_body_at_its_limit(pypi):
    start = time.monotonic()
    assert pypi_registry("drip", 0.5) == (None, None)
    assert time.monotonic() - start < 2  # the full body would take 6 s


# --- final review: private indexes and own-name edges (I6, I7) ----------------------------------

ACME = {"acme-internal": (False, None)}
ACME_PYP = '[project]\nname = "app"\ndependencies = ["acme-internal"]\n'


@pytest.mark.parametrize("files", [
    pytest.param({"test-requirements.txt": "-i https://pkgs.acme.internal/simple\nx\n"}, id="test-requirements"),
    pytest.param({"tox.ini": "[testenv]\nsetenv = PIP_INDEX_URL=https://pkgs.acme.internal/simple\n"}, id="tox"),
    pytest.param({".github/workflows/ci.yml": "env:\n  PIP_INDEX_URL: ${{ secrets.IDX }}\n"}, id="workflow"),
    pytest.param({"Makefile": "install:\n\tpip install --extra-index-url $(IDX) .\n"}, id="makefile"),
    pytest.param({"Dockerfile": "RUN pip install --index-url https://pkgs.acme.internal/simple .\n"},
                 id="dockerfile"),
    pytest.param({"deps/ci.txt": "x\n"}, id="deps-dir"),
    pytest.param({"environment.yml": "dependencies:\n  - pip\n"}, id="environment"),
    pytest.param({"pixi.toml": "[project]\n"}, id="pixi"),
    pytest.param({"noxfile.py": "import nox\n"}, id="noxfile"),
])
def test_private_index_hints_make_a_404_only_suspicion(repo, files):
    r = run(repo, {"pyproject.toml": ACME_PYP}, base=files, registry=Fake(ACME))
    assert sev(r) == [Severity.SUSPICION], r.findings


def test_hatch_env_vars_make_a_404_only_suspicion(repo):
    pyp = ACME_PYP + '[tool.hatch.envs.default.env-vars]\nPIP_INDEX_URL = "https://pkgs.acme.internal/simple"\n'
    r = run(repo, {"pyproject.toml": pyp}, registry=Fake(ACME))
    assert Severity.PROOF not in sev(r) and sev(r)


def test_index_mention_in_unrelated_docs_still_allows_proof(repo):
    r = run(repo, {"requirements.txt": "ghost\n"}, base={"docs/install.md": "pip install --index-url X\n"},
            registry=Fake(GONE))
    assert sev(r) == [Severity.PROOF]


@pytest.mark.parametrize("text", [
    '[project]\nname = "acme-tools"\n[project.optional-dependencies]\nall = ["acme-tools[cli]>=1"]\n',
    '[project]\nname = "acme-tools"\n[dependency-groups]\ndev = ["acme-tools"]\n',
])
def test_a_404_on_the_projects_own_name_is_only_suspicion(repo, text):
    r = run(repo, {"pyproject.toml": text}, registry=Fake({"acme-tools": (False, None)}))
    assert sev(r) == [Severity.SUSPICION]


@pytest.mark.parametrize("text", [
    '[project]\nname = "a"\n[tool.uv]\ndev-dependencies = "pytest"\n',
    '[project]\nname = "a"\n[dependency-groups]\ndev = "pytest"\n',
    '[project]\nname = "a"\n[project.optional-dependencies]\ndev = "pytest"\n',
    '[project]\nname = "a"\ndependencies = "pytest"\n',
    '[project]\nname = "a"\noptional-dependencies = ["pytest"]\n',
    '[project]\nname = "a"\n[tool.pdm]\ndev-dependencies = ["pytest"]\n',
    '[project]\nname = "a"\n[tool.poetry]\ndependencies = ["pytest"]\n',
])
def test_a_group_of_the_wrong_shape_is_could_not_run_not_letters(repo, text):
    reg = Fake({c: (False, None) for c in "pytes"})
    r = run(repo, {"pyproject.toml": text}, registry=reg)
    assert r.status == RunStatus.COULD_NOT_RUN and reg.calls == []


@pytest.mark.parametrize("name", ["PyProject.toml", "Setup.cfg", "Setup.py"])
def test_root_manifest_in_another_case_makes_a_404_only_suspicion(repo, name):
    r = run(repo, {"requirements.txt": "ghost\n"}, base={name: "[x]\n"}, registry=Fake(GONE))
    assert sev(r) == [Severity.SUSPICION]
