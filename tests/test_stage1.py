import subprocess

import pytest

from prgate.config import Config
from prgate.models import FileChange, RunStatus, Severity
from prgate.plugins.python import PythonPlugin
from prgate.stage1 import run_stage1
from test_diff import add, commit, git
from test_diff import repo  # noqa: F401  (fixture)
from test_secrets import AWS

NAMES = ("secrets", "rollout", "test_integrity", "environment_sniffing", "facts")


def cfg():
    return Config()


def by_name(results, name):
    return next(c for c in results if c.name == name)


def no_network(name, timeout):
    return True, 1000  # every package "exists"; tests never reach PyPI


def run(repo, deadline=120, **kw):
    kw.setdefault("registry", no_network)
    return run_stage1(repo, "HEAD~1", "HEAD", cfg(), deadline, plugin=PythonPlugin(), **kw)


def commit_file(repo, path, content):
    add(repo, path, content)
    commit(repo)


def test_stage1_returns_the_named_checks(repo):
    commit_file(repo, "app/a.py", "x = 1\n")
    results = run(repo)
    assert tuple(c.name for c in results) == NAMES
    assert all(c.status == RunStatus.RAN and not c.findings for c in results)


def test_secret_in_the_diff_is_found(repo):
    commit_file(repo, "app/a.py", f'k = "{AWS}"\n')
    f = by_name(run(repo), "secrets").findings[0]
    assert f.severity == Severity.PROOF and f.path == "app/a.py" and f.line == 1


def test_stage1_timeout_is_timed_out_not_a_crash(repo):
    commit_file(repo, "app/a.py", "x = 1\n")
    results = run(repo, deadline=0)
    assert [c.name for c in results] == list(NAMES)
    assert all(c.status == RunStatus.TIMED_OUT for c in results)


def test_git_timeout_is_timed_out(repo, monkeypatch):
    commit_file(repo, "app/a.py", "x = 1\n")

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("git", 1)
    monkeypatch.setattr("prgate.diff.subprocess.run", slow)
    assert all(c.status == RunStatus.TIMED_OUT for c in run(repo))


def test_unreadable_diff_is_could_not_run_for_every_check(repo):
    results = run_stage1(repo, "HEAD~1", "nonexistent", cfg(), 120, plugin=PythonPlugin(), registry=no_network)
    assert all(c.status == RunStatus.COULD_NOT_RUN for c in results)


def test_a_crashing_check_becomes_could_not_run(repo, monkeypatch):
    commit_file(repo, "app/a.py", "x = 1\n")

    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr("prgate.checks.secrets.scan", boom)
    results = run(repo)
    assert by_name(results, "secrets").status == RunStatus.COULD_NOT_RUN
    assert by_name(results, "rollout").status == RunStatus.RAN


def test_remaining_time_is_passed_to_git(repo, monkeypatch):
    commit_file(repo, "app/a.py", "x = 1\n")
    seen = []
    real = subprocess.run

    def spy(*a, **k):
        seen.append(k.get("timeout"))
        return real(*a, **k)
    monkeypatch.setattr("prgate.diff.subprocess.run", spy)
    run(repo, deadline=5)
    assert seen and all(t is not None and t <= 5 for t in seen)


def test_deleted_test_file_is_proof(repo):
    commit_file(repo, "tests/test_a.py", "def test_x():\n    assert 1\n")
    git(repo, "rm", "-q", "tests/test_a.py")
    commit(repo)
    r = by_name(run(repo), "test_integrity")
    assert r.status == RunStatus.RAN and r.findings[0].severity == Severity.PROOF


def test_test_loses_its_assert_is_proof(repo):
    commit_file(repo, "tests/test_a.py", "def test_x():\n    assert 1\n")
    commit_file(repo, "tests/test_a.py", "def test_x():\n    pass\n")
    r = by_name(run(repo), "test_integrity")
    assert r.findings[0].message == "asserts removed: tests/test_a.py::test_x"


def test_unparseable_test_file_at_head_is_could_not_run_not_deleted(repo):
    commit_file(repo, "tests/test_a.py", "def test_x():\n    assert 1\n")
    commit_file(repo, "tests/test_a.py", "def test_x(:\n")
    r = by_name(run(repo), "test_integrity")
    assert r.status == RunStatus.COULD_NOT_RUN and not r.findings


def test_test_file_moved_in_the_same_pr_is_not_deleted(repo):
    commit_file(repo, "tests/test_a.py", "def test_x():\n    assert 1\n")
    (repo / "tests/unit").mkdir()
    git(repo, "mv", "tests/test_a.py", "tests/unit/test_a.py")
    commit(repo)
    r = by_name(run(repo), "test_integrity")
    assert r.status == RunStatus.RAN and r.findings and all(f.severity == Severity.INFO for f in r.findings)


def test_test_file_moved_out_of_tests_is_still_compared(repo):
    commit_file(repo, "tests/test_a.py", "def test_x():\n    assert 1\n")
    (repo / "src").mkdir()
    git(repo, "mv", "tests/test_a.py", "src/helpers_a.py")
    commit(repo)
    r = by_name(run(repo), "test_integrity")
    assert r.status == RunStatus.RAN
    assert all(f.severity == Severity.INFO for f in r.findings)


def test_added_test_file_is_quiet(repo):
    commit_file(repo, "tests/test_a.py", "def test_x():\n    assert 1\n")
    r = by_name(run(repo), "test_integrity")
    assert r.status == RunStatus.RAN and not r.findings


def test_test_code_file_without_a_plugin_is_could_not_run(repo):
    commit_file(repo, "tests/a.test.js", "test('x', () => {})\n")
    r = by_name(run(repo), "test_integrity")
    assert r.status == RunStatus.COULD_NOT_RUN


def test_test_data_file_needs_no_plugin(repo):
    commit_file(repo, "tests/data.json", "{}\n")
    assert by_name(run(repo), "test_integrity").status == RunStatus.RAN


def test_non_utf8_test_file_is_could_not_run(repo):
    commit_file(repo, "tests/test_a.py", b"def test_x():\n    assert '\xff'\n")
    assert by_name(run(repo), "test_integrity").status == RunStatus.COULD_NOT_RUN


def test_plugin_exception_is_could_not_run(repo):
    class Bad(PythonPlugin):
        def test_facts(self, source):
            raise RuntimeError("x")
    commit_file(repo, "tests/test_a.py", "def test_x():\n    assert 1\n")
    r = run_stage1(repo, "HEAD~1", "HEAD", cfg(), 120, plugin=Bad(), registry=no_network)
    assert by_name(r, "test_integrity").status == RunStatus.COULD_NOT_RUN


def test_surrogate_path_does_not_crash(repo, monkeypatch):
    path = "tests/test_\udcff.py"  # the filesystem may refuse such a name, so fake the diff
    change = FileChange(path, None, "M", ((1, "x = 1"),), 0, False)
    monkeypatch.setattr("prgate.stage1.parse_diff", lambda *a, **k: (change,))
    results = run(repo)
    assert [c.name for c in results] == list(NAMES)
    assert by_name(results, "secrets").status == RunStatus.RAN
    assert by_name(results, "test_integrity").status == RunStatus.COULD_NOT_RUN


def test_gitattributes_binary_cannot_hide_a_secret(repo):
    add(repo, ".gitattributes", "secret.txt binary\n")
    add(repo, "secret.txt", f"token = {AWS}\n")
    commit(repo)
    f = by_name(run(repo), "secrets").findings[0]
    assert f.severity == Severity.PROOF and f.path == "secret.txt"


def test_real_binary_file_is_scanned_through_its_blob(repo):
    commit_file(repo, "blob.dat", b"\x00\x01" + AWS.encode() + b"\n")
    f = by_name(run(repo), "secrets").findings[0]
    assert f.severity == Severity.PROOF and f.line == 1


def test_unreadable_blob_makes_secrets_could_not_run(repo, monkeypatch):
    commit_file(repo, "blob.dat", b"\x00\x01")

    def broken(*a, **k):
        raise subprocess.CalledProcessError(1, "git")
    monkeypatch.setattr("prgate.stage1.git_output", broken)
    r = by_name(run(repo), "secrets")
    assert r.status == RunStatus.COULD_NOT_RUN and not r.findings


def test_binary_test_file_is_could_not_run_and_named(repo):
    commit_file(repo, "tests/test_a.py", "def test_x():\n    assert 1\n")
    add(repo, ".gitattributes", "")
    commit_file(repo, "tests/test_a.py", b"\x00\x01def test_x(): pass\n")
    r = by_name(run(repo), "test_integrity")
    assert r.status == RunStatus.COULD_NOT_RUN and "tests/test_a.py" in r.detail


def test_malformed_diff_output_is_could_not_run(repo, monkeypatch):
    def broken(*a, **k):
        raise IndexError("x")
    monkeypatch.setattr("prgate.stage1.parse_diff", broken)
    assert all(c.status == RunStatus.COULD_NOT_RUN for c in run(repo))


def test_environment_sniffing_in_a_new_file_is_suspicion(repo):
    commit_file(repo, "app/a.py", 'import os\nif os.environ.get("CI"):\n    pass\n')
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.RAN
    assert [(f.severity, f.path, f.line) for f in r.findings] == [(Severity.SUSPICION, "app/a.py", 2)]


def test_pytest_import_alone_in_a_test_file_is_quiet(repo):
    commit_file(repo, "tests/test_a.py", "import pytest\nfrom pytest import raises\n\ndef test_x():\n    assert 1\n")
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.RAN and not r.findings


def test_environment_read_in_a_test_file_is_suspicion(repo):
    commit_file(repo, "tests/test_a.py",
                "import pytest\nimport os\n\ndef test_x():\n    assert os.environ.get('CI')\n")
    f = by_name(run(repo), "environment_sniffing").findings
    assert [(x.severity, x.path, x.line) for x in f] == [(Severity.SUSPICION, "tests/test_a.py", 5)]


def test_import_pytest_in_code_is_still_suspicion(repo):
    commit_file(repo, "app/a.py", "import pytest\n")
    assert by_name(run(repo), "environment_sniffing").findings


def test_git_failure_keeps_earlier_findings(repo, monkeypatch):
    add(repo, "app/a.py", "import os\nos._exit(0)\n")
    add(repo, "app/b.py", "x = 1\n")
    commit(repo)
    import prgate.stage1 as st
    real = st.git_output

    def flaky(r, *a, **k):
        if a[0] == "show" and a[1].endswith("app/b.py"):
            raise subprocess.TimeoutExpired("git", 1)
        return real(r, *a, **k)
    monkeypatch.setattr(st, "git_output", flaky)
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.TIMED_OUT and [f.path for f in r.findings] == ["app/a.py"]


def test_findings_survive_a_later_file_failing(repo):
    add(repo, "app/a.py", "import os\nos._exit(0)\n")
    add(repo, "app/b.py", "def f(:\n")
    commit(repo)
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.COULD_NOT_RUN and [f.path for f in r.findings] == ["app/a.py"]


def test_clean_pr_has_no_sniffing_findings(repo):
    commit_file(repo, "app/a.py", "x = 1\n")
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.RAN and not r.findings


def test_deleted_file_is_not_sniffed(repo):
    commit_file(repo, "app/a.py", "import os\nos._exit(0)\n")
    git(repo, "rm", "-q", "app/a.py")
    commit(repo)
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.RAN and not r.findings


def test_unparseable_code_file_makes_sniffing_could_not_run(repo):
    commit_file(repo, "app/a.py", "def f(:\n")
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.COULD_NOT_RUN and not r.findings


def test_code_file_without_a_plugin_makes_sniffing_could_not_run(repo):
    commit_file(repo, "app/a.js", "let x = 1\n")
    assert by_name(run(repo), "environment_sniffing").status == RunStatus.COULD_NOT_RUN


def test_docs_and_data_files_are_not_sniffed(repo):
    commit_file(repo, "README.md", "os.environ['CI']\n")
    commit_file(repo, "tests/data.json", "{}\n")
    assert by_name(run(repo), "environment_sniffing").status == RunStatus.RAN


def test_binary_flagged_python_file_makes_sniffing_could_not_run(repo):
    commit_file(repo, "app/a.py", b"\x00\x01import os\nos._exit(0)\n")
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.COULD_NOT_RUN and "app/a.py" in r.detail


def test_sniffing_with_a_surrogate_path_does_not_crash(repo, monkeypatch):
    change = FileChange("app/\udcff.py", None, "M", ((1, "x = 1"),), 0, False)
    monkeypatch.setattr("prgate.stage1.parse_diff", lambda *a, **k: (change,))
    assert by_name(run(repo), "environment_sniffing").status == RunStatus.COULD_NOT_RUN


def test_sniffing_plugin_crash_is_could_not_run(repo):
    class Bad(PythonPlugin):
        def sniffing(self, source, **kw):
            raise RuntimeError("x")
    commit_file(repo, "app/a.py", "x = 1\n")
    r = run_stage1(repo, "HEAD~1", "HEAD", cfg(), 120, plugin=Bad(), registry=no_network)
    assert by_name(r, "environment_sniffing").status == RunStatus.COULD_NOT_RUN


def test_called_process_error_keeps_earlier_findings(repo, monkeypatch):
    add(repo, "app/a.py", "import os\nos._exit(0)\n")
    add(repo, "app/b.py", "x = 1\n")
    commit(repo)
    import prgate.stage1 as st
    real = st.git_output

    def failing(r, *a, **k):
        if a[0] == "show" and a[1].endswith("app/b.py"):
            raise subprocess.CalledProcessError(1, "git")
        return real(r, *a, **k)
    monkeypatch.setattr(st, "git_output", failing)
    r = by_name(run(repo), "environment_sniffing")
    assert r.status == RunStatus.COULD_NOT_RUN and [f.path for f in r.findings] == ["app/a.py"]


def test_missing_dependency_is_proof_through_stage1(repo):
    commit_file(repo, "requirements.txt", "fakepkg-xyz\n")
    r = by_name(run(repo, registry=lambda n, t: (False, None)), "facts")
    assert r.status == RunStatus.RAN and r.findings[0].severity == Severity.PROOF


def test_registry_crash_is_could_not_run_through_stage1(repo):
    commit_file(repo, "requirements.txt", "x\n")

    def boom(name, timeout):
        raise RuntimeError("no")
    assert by_name(run(repo, registry=boom), "facts").status == RunStatus.COULD_NOT_RUN
