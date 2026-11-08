"""Common refactors that must never give a false Blocked: each goes to a person, or stays quiet."""
import pytest

from prgate.models import Severity
from prgate.plugins.python import PythonPlugin
from test_diff import commit, git
from test_diff import repo  # noqa: F401  (fixture)
from test_stage1 import by_name, commit_file, run

PATH = "tests/test_a.py"


def integrity_of(repo, base, head, path=PATH):
    commit_file(repo, path, base)
    commit_file(repo, path, head)
    return by_name(run(repo), "test_integrity")


def proofs(result):
    return [f.message for f in result.findings if f.severity == Severity.PROOF]


# I1: assertion styles the count used to miss.
@pytest.mark.parametrize("head", [
    pytest.param("from pandas.testing import assert_frame_equal\n"
                 "def test_x():\n    assert_frame_equal(df, exp)\n", id="bare-assert-helper"),
    pytest.param("from numpy.testing import assert_allclose\n"
                 "def test_x():\n    assert_allclose(a, b)\n", id="bare-numpy-helper"),
    pytest.param("import pytest\ndef test_x():\n    with pytest.warns(UserWarning):\n        f()\n",
                 id="pytest-warns"),
    pytest.param("import pytest\ndef test_x():\n    with pytest.deprecated_call():\n        f()\n",
                 id="deprecated-call"),
    pytest.param("def _check(x, v):\n    assert x == v\ndef test_x():\n    _check(1, 2)\n",
                 id="local-helper"),
    pytest.param("def _inner(x):\n    assert x\ndef _check(x):\n    _inner(x)\ndef test_x():\n    _check(1)\n",
                 id="local-helper-transitive"),
    pytest.param("class TestC:\n    def _check(self, x):\n        assert x\n    def test_x(self):\n"
                 "        self._check(1)\n", id="local-method-helper", ),
    pytest.param("def _check(x):\n    return x\ndef test_x():\n    _check(1)\n", id="local-helper-no-assert"),
    pytest.param("from tests.helpers import check\ndef test_x():\n    check(1)\n", id="imported-test-helper"),
    pytest.param("def test_x():\n    verify_output(1)\n", id="checking-name"),
    pytest.param("import pytest\ndef test_x():\n    if f() != 1:\n        pytest.fail('bad')\n", id="pytest-fail"),
    pytest.param("def test_x():\n    if f() != 1:\n        raise AssertionError('bad')\n", id="raise"),
    pytest.param("import pytest\n@pytest.fixture\ndef checked():\n    yield\n    assert done()\n"
                 "def test_x(checked):\n    f()\n", id="local-fixture-asserts"),
    pytest.param("def test_x(snapshot_checker):\n    f()\n", id="unknown-fixture"),
])
def test_assertion_styles_are_never_asserts_removed_proof(repo, head):
    r = integrity_of(repo, "def test_x():\n    assert f() == 1\n", head)
    assert not proofs(r), r.findings


def test_class_helper_key_names_test_x():
    src = "class TestC:\n    def _check(self, x):\n        assert x\n    def test_x(self):\n        self._check(1)\n"
    assert PythonPlugin().test_facts(src).tests == {"TestC.test_x": 1}


def test_asserts_really_removed_is_still_proof(repo):
    r = integrity_of(repo, "def test_x():\n    assert f() == 1\n", "def test_x():\n    f()\n")
    assert proofs(r) == [f"asserts removed: {PATH}::test_x"]


def test_asserts_removed_with_builtin_fixture_is_still_proof(repo):
    r = integrity_of(repo, "def test_x(tmp_path):\n    assert f(tmp_path)\n",
                     "def test_x(tmp_path):\n    f(tmp_path)\n")
    assert proofs(r) == [f"asserts removed: {PATH}::test_x"]


# I2: tests wrapped in blocks, nested classes and inherited tests.
@pytest.mark.parametrize("head", [
    pytest.param("import sys\nif sys.platform != 'win32':\n    def test_x():\n        assert 1\n", id="if"),
    pytest.param("import warnings\nwith warnings.catch_warnings():\n    def test_x():\n        assert 1\n",
                 id="with"),
    pytest.param("try:\n    import numpy\nexcept ImportError:\n    pass\nelse:\n    def test_x():\n"
                 "        assert 1\n", id="try-else"),
    pytest.param("try:\n    def test_x():\n        assert 1\nfinally:\n    pass\n", id="try-body"),
])
def test_wrapped_test_is_not_deleted(repo, head):
    r = integrity_of(repo, "def test_x():\n    assert 1\n", head)
    assert not proofs(r), r.findings


def test_with_wrapped_test_is_seen():
    f = PythonPlugin().test_facts("import warnings\nwith warnings.catch_warnings():\n"
                                  "    def test_x():\n        assert 1\n")
    assert f.tests == {"test_x": 1} and not f.skipped


def test_if_wrapped_test_may_be_skipped():
    f = PythonPlugin().test_facts("import sys\nif sys.platform != 'win32':\n    def test_x():\n        assert 1\n")
    assert f.tests == {"test_x": 1} and f.maybe_skipped == {"test_x"}


def test_nested_test_class_is_seen():
    f = PythonPlugin().test_facts("class TestOuter:\n    class TestInner:\n        def test_a(self):\n"
                                  "            assert 1\n")
    assert f.tests == {"TestOuter.TestInner.test_a": 1}


def test_renamed_base_class_with_inheriting_subclass_is_not_deleted(repo):
    base = ("class TestBase:\n    def test_a(self):\n        assert 1\n"
            "class TestImpl(TestBase):\n    pass\n")
    head = ("class Base:\n    def test_a(self):\n        assert 1\n"
            "class TestImpl(Base):\n    pass\n")
    r = integrity_of(repo, base, head)
    assert not proofs(r), r.findings


def test_inherited_tests_are_collected():
    f = PythonPlugin().test_facts("class Base:\n    def test_a(self):\n        assert 1\n"
                                  "class TestImpl(Base):\n    def test_b(self):\n        assert 1\n")
    assert f.tests == {"TestImpl.test_a": 1, "TestImpl.test_b": 1}


def test_unresolvable_base_class_makes_deletion_unsure(repo):
    base = "class TestC:\n    def test_a(self):\n        assert 1\n"
    head = "from helpers import Mixin\nclass TestC(Mixin):\n    pass\n"
    r = integrity_of(repo, base, head)
    assert not proofs(r), r.findings


@pytest.mark.parametrize("head", [
    pytest.param("def _make():\n    def t():\n        assert 1\n    return t\ntest_a = _make()\n", id="assigned"),
    pytest.param("for n in range(2):\n    globals()[f'test_{n}'] = lambda: None\n", id="globals"),
])
def test_dynamically_made_tests_make_deletion_unsure(repo, head):
    r = integrity_of(repo, "def test_a():\n    assert 1\n", head)
    assert not proofs(r), r.findings


def test_plain_deletion_is_still_proof(repo):
    r = integrity_of(repo, "def test_a():\n    assert 1\ndef test_b():\n    assert 1\n",
                     "def test_a():\n    assert 1\n")
    assert proofs(r) == [f"test deleted: {PATH}::test_b"]


# I3: parametrize consolidation (renamed and changed in one PR).
def test_parametrize_consolidation_is_not_deletion(repo):
    base = "def test_add_one():\n    assert add(1) == 2\ndef test_add_two():\n    assert add(2) == 3\n"
    head = ("import pytest\n@pytest.mark.parametrize('x,y', [(1, 2), (2, 3)])\n"
            "def test_add(x, y):\n    assert add(x) == y\n")
    r = integrity_of(repo, base, head)
    assert not proofs(r), r.findings
    sus = [f for f in r.findings if f.severity == Severity.SUSPICION]
    assert len(sus) == 2 and all("test_add" in f.question for f in sus)


def test_rename_and_change_in_a_moved_file_is_not_deletion(repo):
    keep = "".join(f"def test_k{i}():\n    assert k({i})\n" for i in range(8))
    commit_file(repo, "tests/test_a.py", keep + "def test_x():\n    assert f() == 1\n")
    git(repo, "mv", "tests/test_a.py", "tests/test_b.py")
    (repo / "tests/test_b.py").write_text(keep + "def test_y():\n    assert f() == 1\n    assert g()\n")
    commit(repo)
    r = by_name(run(repo), "test_integrity")
    assert not proofs(r), r.findings


# I4: duplicate definitions.
def test_skipped_duplicate_above_a_running_test_is_not_now_skipped(repo):
    base = "def test_a():\n    assert 1\n"
    head = "import pytest\n@pytest.mark.skip\ndef test_a():\n    assert 1\ndef test_a():\n    assert 1\n"
    r = integrity_of(repo, base, head)
    assert not proofs(r), r.findings


def test_running_duplicate_above_a_skipped_one_is_at_most_maybe():
    f = PythonPlugin().test_facts("import pytest\ndef test_a():\n    assert 1\n"
                                  "@pytest.mark.skip\ndef test_a():\n    assert 1\n")
    assert not f.skipped and f.maybe_skipped == {"test_a"}


# Parked 160 (b): `**` in a mark call.
@pytest.mark.parametrize("dec", ["pytest.mark.skipif(True, **{'condition': False})",
                                 "pytest.mark.xfail(run=False, **{'condition': False})"])
def test_double_star_mark_is_maybe(dec):
    f = PythonPlugin().test_facts(f"import pytest\n@{dec}\ndef test_a():\n    assert 1\n")
    assert not f.skipped and f.maybe_skipped == {"test_a"}


# Parked 160 (c): rebinding pytest's names at run time.
@pytest.mark.parametrize("pre", ["pytest.mark.skip = lambda f: f\n", "setattr(pytest.mark, 'skip', id)\n",
                                 "del pytest.mark\n", "import sys\nsys.modules['pytest'] = fake\n",
                                 "globals()['pytest'] = fake\n"])
def test_rebinding_pytest_makes_skip_maybe(pre):
    f = PythonPlugin().test_facts(f"import pytest\n{pre}@pytest.mark.skip\ndef test_a():\n    assert 1\n")
    assert not f.skipped and f.maybe_skipped == {"test_a"}


# Review of I1: helper counting must stay linear, and fail to unsure when it gives up.
def _fan_out(width, levels, leaf):
    lines = []
    for level in range(levels):
        for i in range(width):
            calls = "".join(f"    h{level + 1}_{j}(x)\n" for j in range(width)) if level + 1 < levels else leaf
            lines.append(f"def h{level}_{i}(x):\n{calls}")
    return "".join(lines) + "def test_x():\n" + "".join(f"    h0_{i}(1)\n" for i in range(width))


def test_wide_helper_fan_out_is_fast_and_unsure():
    import time
    start = time.monotonic()
    f = PythonPlugin().test_facts(_fan_out(30, 4, "    return x\n"))
    assert time.monotonic() - start < 2
    assert f.tests["test_x"] == 0 and "test_x" in f.asserts_unsure


def test_wide_helper_fan_out_is_not_asserts_removed(repo):
    r = integrity_of(repo, "def test_x():\n    assert f() == 1\n", _fan_out(30, 4, "    return x\n"))
    assert not proofs(r), r.findings


def test_hitting_the_node_budget_is_unsure(monkeypatch):
    monkeypatch.setattr("prgate.plugins.python._NODE_BUDGET", 50)
    src = "def _h(x):\n" + "    y = x\n" * 60 + "    assert y\ndef test_x():\n    _h(1)\n"
    f = PythonPlugin().test_facts(src)
    assert "test_x" in f.asserts_unsure


def _many_tests(n, last):
    body = "".join(f"def test_{i}():\n" + "".join(f"    assert f({i}) == {k}\n" for k in range(10))
                   for i in range(n))
    return body + "def test_last():\n" + last


def test_the_node_budget_is_per_test_so_late_tests_are_still_counted():
    f = PythonPlugin().test_facts(_many_tests(400, "    assert f() == 1\n"))
    assert f.tests["test_last"] == 1 and "test_last" not in f.asserts_unsure


def test_asserts_removed_from_the_last_test_of_a_large_file_is_still_proof(repo):
    r = integrity_of(repo, _many_tests(400, "    assert f() == 1\n"), _many_tests(400, "    f()\n"))
    assert any("test_last" in m for m in proofs(r)), r.findings


def _diamond(width, depth):
    lines = []
    for level in range(depth - 1, -1, -1):
        bases = ", ".join(f"C{level + 1}_{j}" for j in range(width)) if level + 1 < depth else ""
        for i in range(width):
            lines.append(f"class C{level}_{i}({bases}):\n    def m{level}_{i}(self):\n        assert self\n")
    tops = ", ".join(f"C0_{j}" for j in range(width))
    return "".join(lines) + f"class TestTop({tops}):\n    def test_x(self):\n        self.m{depth - 1}_0()\n"


def test_a_wide_class_diamond_is_fast():
    import time
    start = time.monotonic()
    f = PythonPlugin().test_facts(_diamond(12, 8))
    assert time.monotonic() - start < 2
    assert "TestTop.test_x" in f.tests


def test_running_out_of_budget_on_classes_makes_the_file_opaque(monkeypatch):
    monkeypatch.setattr("prgate.plugins.python._NODE_BUDGET", 20)
    assert PythonPlugin().test_facts(_diamond(4, 4)).opaque
