import pytest

from prgate.models import Severity
from prgate.plugins import get_plugin
from prgate.plugins.python import PythonPlugin

P = PythonPlugin()


def test_registry_returns_the_python_plugin():
    assert isinstance(get_plugin("a/b.py"), PythonPlugin)
    assert get_plugin("a/b.js") is None
    assert get_plugin("a/\udcff.py") is not None  # lone surrogates must not crash


def test_symbols_ignore_comments_and_formatting():
    assert P.symbols("def f():\n  return 1 # x\n") == P.symbols("def f():\n    return 1\n")


def test_symbols_see_body_change_and_methods():
    assert "C.m" in P.symbols("class C:\n def m(self): return 1\n")
    assert P.symbols("def f(): return 1") != P.symbols("def f(): return 2")


def test_test_facts_counts_asserts_and_skips():
    f = P.test_facts("import pytest\n@pytest.mark.skip\ndef test_a():\n assert 1\n assert 2\n")
    assert f.tests == {"test_a": 2} and f.skipped == {"test_a"}


def test_methods_are_keyed_by_class_and_inherit_a_class_skip():
    src = "import pytest\n@pytest.mark.skip\nclass TestC:\n    def test_a(self):\n        assert 1\n"
    f = P.test_facts(src)
    assert f.tests == {"TestC.test_a": 1} and f.skipped == {"TestC.test_a"}


def test_conditional_skip_is_not_a_skip():
    src = "import pytest\n@pytest.mark.skipif(x, reason='')\ndef test_a():\n    assert 1\n"
    assert P.test_facts(src).skipped == frozenset()


def test_non_test_code_is_not_a_test():
    assert P.test_facts("def helper():\n    assert 1\nclass Util:\n    def test_a(self): pass\n").tests == {}


def test_unittest_assert_methods_count():
    src = "class TestC:\n    def test_a(self):\n        self.assertEqual(1, 1)\n"
    assert P.test_facts(src).tests == {"TestC.test_a": 1}


def test_facts_and_symbols_share_keys():
    src = "class TestC:\n    def test_a(self):\n        assert 1\n"
    assert set(P.test_facts(src).tests) <= set(P.symbols(src))


def test_parametrized_test_counts_its_asserts_once():
    src = "import pytest\n@pytest.mark.parametrize('x', [1, 2])\ndef test_a(x):\n    assert x\n"
    assert P.test_facts(src).tests == {"test_a": 1}


@pytest.mark.parametrize("src", ["import pytest", "'pytest' in sys.modules", "os.environ['CI']",
                                 "os._exit(0)", "os.environ['PRGATE_X']", "import _pytest",
                                 "sys.settrace(f)", "os.environ.get('CI')", "os.getenv('GITHUB_ACTIONS')",
                                 "from pytest import raises"])
def test_sniffing_in_changed_source_is_suspicion(src):
    found = P.sniffing(src)
    assert found and found[0].severity == Severity.SUSPICION and found[0].line == 1
    assert found[0].check == "environment_sniffing"


@pytest.mark.parametrize("src", ["import os\nos.environ.get('HOME')\n", "x = 'CI'\n", "import json\n"])
def test_ordinary_source_is_not_sniffing(src):
    assert P.sniffing(src) == ()


def test_syntax_error_raises_for_could_not_run():
    for call in (P.symbols, P.test_facts, P.sniffing, P.imports):
        with pytest.raises(SyntaxError):
            call("def (")


def test_imports_and_deps(tmp_path):
    assert P.imports("import a.b\nfrom c import d\nfrom . import e\n") == {"a", "c"}
    (tmp_path / "requirements.txt").write_text("Flask==3\n# c\n-r other.txt\nMy_Pkg[x]>=1 ; python_version>'3'\n")
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["Requests>=2"]\n')
    assert P.declared_deps(tmp_path) == {"flask", "my-pkg", "requests"}


@pytest.mark.parametrize("name, body", [
    pytest.param("pyproject.toml", "[[[", id="toml"),
    pytest.param("setup.cfg", "[options\ninstall_requires = x\n", id="cfg"),
    pytest.param("setup.py", "setup(install_requires=[", id="syntax"),
    pytest.param("setup.py", "x = " + "[" * 5000, id="too-deep"),
    pytest.param("requirements.txt", b"\xff\xfe\x00bad", id="not-utf8"),
])
def test_unparseable_manifest_raises_not_empty(tmp_path, name, body):
    (tmp_path / name).write_bytes(body if isinstance(body, bytes) else body.encode())
    with pytest.raises(ValueError, match="could not be parsed"):
        P.declared_deps(tmp_path)


def test_setup_cfg_deps(tmp_path):
    (tmp_path / "setup.cfg").write_text(
        "[options]\ninstall_requires =\n    Requests>=2\n    # c\n    pyyaml ; python_version>'3'\n"
        "[options.extras_require]\ndev = pytest\n")
    assert P.declared_deps(tmp_path) == {"requests", "pyyaml", "pytest"}


def test_setup_cfg_file_directive_is_not_a_package(tmp_path):
    (tmp_path / "setup.cfg").write_text("[options]\ninstall_requires = file: requirements.txt\n")
    assert P.declared_deps(tmp_path) == frozenset()


def test_setup_py_deps_are_read_by_ast_never_run(tmp_path):
    (tmp_path / "setup.py").write_text(
        "import os\nos.system('touch ran')\nfrom setuptools import setup\n"
        "setup(name='x', install_requires=['Flask>=1', dep()], extras_require={'t': ['pytest', dep()]})\n")
    assert P.declared_deps(tmp_path) == {"flask", "pytest"}
    assert not (tmp_path / "ran").exists()


def test_setup_py_dynamic_requirements_are_not_guessed(tmp_path):
    (tmp_path / "setup.py").write_text("setup(install_requires=read())\n")
    assert P.declared_deps(tmp_path) == frozenset()


def facts(src):
    return P.test_facts(src)


@pytest.mark.parametrize("head", [
    "import pytest as pt\n@pt.mark.skip\n",
    "from pytest import mark\n@mark.skip\n",
    "from unittest import skip as s\n@s('x')\n",
    "import pytest\n@pytest.mark.skipif(True, reason='')\n",
    "import unittest\n@unittest.skipUnless(False, 'x')\n",
    "import pytest\n@pytest.mark.xfail(run=False)\n",
])
def test_aliased_and_constant_skips_are_skipped(head):
    f = facts(head + "def test_a():\n    assert 1\n")
    assert f.skipped == {"test_a"} and not f.maybe_skipped


@pytest.mark.parametrize("head", [
    "import pytest\n@pytest.mark.skipif(sys.platform == 'win32', reason='')\n",
    "import unittest\n@unittest.skipIf(cond, 'x')\n",
])
def test_conditional_skips_are_maybe_skipped(head):
    f = facts(head + "def test_a():\n    assert 1\n")
    assert f.maybe_skipped == {"test_a"} and not f.skipped


def test_false_condition_is_not_a_skip():
    src = "import pytest\n@pytest.mark.skipif(False, reason='')\ndef test_a(): assert 1\n"
    f = facts(src)
    assert not f.skipped and not f.maybe_skipped


def test_skip_calls_in_the_body():
    src = ("import pytest, unittest\n"
           "def test_a():\n    pytest.skip('x')\n    assert 1\n"
           "def test_b():\n    raise unittest.SkipTest('x')\n"
           "def test_c():\n    raise SkipTest\n"
           "def test_d(x):\n    if x:\n        pytest.skip('x')\n    assert 1\n")
    f = facts(src)
    # test_c raises a bare SkipTest nothing imports, so it may not be unittest's: maybe, not proof.
    assert f.skipped == {"test_a", "test_b"} and f.maybe_skipped == {"test_c", "test_d"}


@pytest.mark.parametrize("mark", ["pytestmark = pytest.mark.skip", "pytestmark = [pytest.mark.skip]",
                                  "pytestmark: list = (pytest.mark.skip,)"])
def test_module_pytestmark_skips_everything(mark):
    f = facts(f"import pytest\n{mark}\ndef test_a(): assert 1\nclass TestC:\n    def test_b(self): assert 1\n")
    assert f.skipped == {"test_a", "TestC.test_b"}


def test_testcase_subclass_is_collected():
    src = "import unittest\nclass Checks(unittest.TestCase):\n    def test_a(self):\n        self.assertTrue(1)\n"
    assert facts(src).tests == {"Checks.test_a": 1}


def test_asserts_in_nested_scopes_do_not_count():
    src = ("def test_a():\n    assert 1\n    def helper():\n        assert 2\n"
           "    f = lambda: (assert_ := 1)\n    class K:\n        def m(self):\n            assert 3\n"
           "    async def g():\n        assert 4\n")
    assert facts(src).tests == {"test_a": 1}


def test_pytest_raises_and_assert_raises_count():
    src = ("import pytest as pt\ndef test_a():\n    with pt.raises(ValueError):\n        f()\n"
           "class TestC:\n    def test_b(self):\n        with self.assertRaises(E):\n            f()\n")
    assert facts(src).tests == {"test_a": 1, "TestC.test_b": 1}


@pytest.mark.parametrize("src", [
    "sys.modules.get('pytest')", "sys.modules['_pytest']", "__import__('pytest')",
    "importlib.import_module('pytest')", "from importlib import import_module\nimport_module('pytest')",
    "from os import environ\nenviron['CI']", "import os as o\no.environ.get('GITHUB_ACTIONS')",
    "from os import getenv\ngetenv('PRGATE_X')",
    "import os\nos.environ[name]", "import os\nos.environ.get(name)", "import os\nos.getenv(k)",
    "import sys as s\ns.settrace(f)", "from os import _exit\n_exit(1)",
])
def test_more_sniffing_forms(src):
    found = P.sniffing(src)
    assert found and found[0].severity == Severity.SUSPICION


def test_string_conditions_are_maybe_not_proof():
    for dec in ("pytest.mark.skipif(\"sys.platform == 'win32'\", reason='')", "unittest.skipIf('x', 'r')",
                "unittest.skipUnless('x', 'r')"):
        f = facts(f"import pytest, unittest\n@{dec}\ndef test_a():\n    assert 1\n")
        assert f.maybe_skipped == {"test_a"} and not f.skipped


@pytest.mark.parametrize("dec,expect", [
    ("pytest.mark.xfail", "maybe"), ("pytest.mark.xfail()", "maybe"),
    ("pytest.mark.xfail(reason='x')", "maybe"), ("pytest.mark.xfail(cond, strict=True)", "maybe"),
    ("pytest.mark.xfail(cond)", "maybe"), ("pytest.mark.xfail(run=False)", "skip"),
    ("pytest.mark.xfail(strict=True)", "maybe"), ("pytest.mark.xfail(True, strict=True)", "maybe"),
    ("pytest.mark.xfail(False)", "none"), ("pytest.mark.xfail(False, strict=True)", "none"),
    ("pytest.mark.xfail(False, run=False)", "none"),
    ("pytest.mark.xfail(condition=False, run=False)", "none"),
    ("pytest.mark.xfail(cond, run=False)", "maybe"),
    ("pytest.mark.xfail(True, run=False)", "skip"),
    ("pytest.mark.xfail(condition=True, run=False)", "skip"),
])
def test_xfail_modes(dec, expect):
    f = facts(f"import pytest\n@{dec}\ndef test_a():\n    assert 1\n")
    got = "skip" if f.skipped else "maybe" if f.maybe_skipped else "none"
    assert got == expect


def test_star_imports_bind_the_names_we_look_for():
    assert P.sniffing("from os import *\ngetenv('CI')")
    assert P.sniffing("from os import *\nenviron['CI']")
    assert P.sniffing("from os import *\n_exit(1)")
    f = facts("from pytest import *\n@mark.skip\ndef test_a(): assert 1\n"
              "@mark.skipif(cond)\ndef test_b(): assert 1\n"
              "def test_c():\n    with raises(E):\n        f()\n")
    # Star-derived names are seen, but never proof.
    assert not f.skipped and f.maybe_skipped == {"test_a", "test_b"} and f.tests["test_c"] == 1
    f = facts("from unittest import *\n@skip('x')\ndef test_a(): pass\n@skipIf(c, 'x')\ndef test_b(): pass\n")
    assert not f.skipped and f.maybe_skipped == {"test_a", "test_b"}


def test_test_files_may_import_pytest_but_nothing_else():
    ok = ["import pytest", "import pytest as pt", "from pytest import raises"]
    assert all(P.sniffing(src, is_test=True) == () for src in ok)
    for src in ["import _pytest", "from _pytest import x", "os.environ.get('CI')", "sys.modules.get('pytest')",
                "__import__('pytest')"]:
        assert P.sniffing(src, is_test=True)
    assert all(P.sniffing(src) for src in ok)


def test_explicit_alias_and_star_import_both_count():
    assert P.sniffing("from os import environ as e\nfrom os import *\nenviron.get('CI')")
    assert P.sniffing("from os import *\nfrom os import environ as e\nenviron.get('CI')")
    assert P.sniffing("from os import environ as e\nfrom os import *\ne.get('CI')")
    f = facts("from pytest import mark as m\nfrom pytest import *\n@mark.skip\ndef test_a(): assert 1\n")
    assert f.maybe_skipped == {"test_a"} and not f.skipped  # `mark` is bound only by the star


def _how(f):
    return "skip" if f.skipped else "maybe" if f.maybe_skipped else "none"


@pytest.mark.parametrize("src,expect", [
    # Ambiguous or star-derived resolution is never proof.
    ("from unittest import *\ndef skip(f): return f\n@skip\ndef test_a(): assert 1\n", "maybe"),
    ("from mylib import skip\nfrom unittest import *\n@skip\ndef test_a(): assert 1\n", "maybe"),
    ("from unittest import *\n@skip('r')\ndef test_a(): assert 1\n", "maybe"),
    ("from unittest import skip\n@skip('r')\ndef test_a(): assert 1\nskip = something\n", "maybe"),
    ("class SkipTest(Exception): pass\ndef test_a():\n    raise SkipTest('x')\n", "maybe"),
    ("from unittest import SkipTest\nclass SkipTest(Exception): pass\ndef test_a():\n    raise SkipTest\n",
     "maybe"),
    ("import pytest\ndef test_a():\n    pytest.skip('x')\npytest = None\n", "maybe"),
    ("@pytest.mark.skip\ndef test_a(): assert 1\n", "maybe"),  # pytest never imported
    ("import pytest\npytestmark = pytest.mark.skip\npytestmark = []\ndef test_a(): assert 1\n", "maybe"),
    # A star import we cannot see into may rebind anything.
    ("from mylib import *\nimport pytest\n@pytest.mark.skip\ndef test_a(): assert 1\n", "maybe"),
    ("from .helpers import *\n@pytest.mark.skip\ndef test_a(): assert 1\n", "maybe"),
    ("from .helpers import *\nimport pytest\n@pytest.mark.skip\ndef test_a(): assert 1\n", "maybe"),
    ("from . import *\nfrom unittest import SkipTest\ndef test_a():\n    raise SkipTest\n", "maybe"),
    # Unambiguous resolution is still proof.
    ("import pytest\n@pytest.mark.skip\ndef test_a(): assert 1\n", "skip"),
    ("from pytest import mark\n@mark.skip\ndef test_a(): assert 1\n", "skip"),
    ("from unittest import skip\nfrom unittest import skip\n@skip('r')\ndef test_a(): assert 1\n", "skip"),
    ("from unittest import SkipTest\ndef test_a():\n    raise SkipTest('x')\n", "skip"),
    ("import pytest\ndef test_a():\n    raise pytest.skip.Exception('x')\n", "skip"),
])
def test_proof_needs_an_unambiguous_name(src, expect):
    assert _how(facts(src)) == expect


@pytest.mark.parametrize("src,expect", [
    # Bindings that disagree (skipIf(False) runs, skipUnless(False) skips) are maybe.
    ("from unittest import skipIf as s\nfrom unittest import skipUnless as s\n@s(False, 'r')\n", "maybe"),
    # Bindings that agree keep their result, capped at maybe.
    ("from unittest import skipIf as s\nfrom unittest import skipUnless as s\n@s(x, 'r')\n", "maybe"),
    ("from unittest import skip as s\nfrom pytest.mark import skip as s\n@s('r')\n", "maybe"),
    ("from mylib import skipIf\nfrom unittest import *\n@skipIf(False, 'r')\n", "none"),
])
def test_ambiguous_bindings_are_judged_under_each(src, expect):
    assert _how(facts(src + "def test_a(): assert 1\n")) == expect


@pytest.mark.parametrize("dec,expect", [
    ("pytest.mark.skipif(False, True, reason='')", "skip"),
    ("pytest.mark.skipif(False, x, reason='')", "maybe"),
    ("pytest.mark.skipif(False, False, reason='')", "none"),
    ("pytest.mark.skipif(True, x, reason='')", "skip"),
    ("pytest.mark.skipif(True, condition=False, reason='')", "none"),
    ("pytest.mark.xfail(False, cond, run=False)", "maybe"),
    ("pytest.mark.xfail(False, True, run=False)", "skip"),
    ("unittest.skipIf(False, True)", "none"),  # unittest reads only the first argument
])
def test_condition_lists(dec, expect):
    assert _how(facts(f"import pytest, unittest\n@{dec}\ndef test_a():\n    assert 1\n")) == expect
