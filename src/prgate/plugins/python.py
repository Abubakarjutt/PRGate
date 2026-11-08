"""Python plug-in. Parses with `ast` only; it never imports or runs the code it reads."""
from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterator
from pathlib import Path

from ..models import Finding, Severity
from .base import ENVIRONMENT_SNIFFING, TestFacts
from .python_manifests import read_manifests

CHECK = ENVIRONMENT_SNIFFING
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
_ENV_KEYS = {"CI", "GITHUB_ACTIONS", "PYTEST_CURRENT_TEST"}
_ENV_PREFIXES = ("PRGATE_", "GITHUB_")
_SNIFFED_MODULES = {"pytest", "_pytest"}


def _dotted(node: ast.expr) -> str:
    """`a.b.c` for a chain of names and attributes, else an empty string."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


# What `from <module> import *` binds that this plug-in looks for.
_STAR_NAMES = {
    "os": {"environ", "getenv", "_exit"},
    "sys": {"modules", "settrace", "setprofile"},
    "importlib": {"import_module", "__import__"},
    "unittest": {"skip", "skipIf", "skipUnless", "SkipTest"},
    "pytest": {"mark", "skip", "raises", "xfail"},
}


def _aliases(tree: ast.AST) -> dict[str, set[str]]:
    """Local name -> every dotted name it may be bound to by an import.

    `pt` -> `pytest`, `mark` -> `pytest.mark`. A star import from a module a check cares about
    binds all of that module's names we look for. A name bound twice counts as both.
    """
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out.setdefault(a.asname or a.name.split(".")[0], set()).add(
                    a.name if a.asname else a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                if a.name != "*":
                    out.setdefault(a.asname or a.name, set()).add(f"{node.module}.{a.name}")
                else:
                    for bound in _STAR_NAMES.get(node.module, ()):
                        out.setdefault(bound, set()).add(f"{node.module}.{bound}")
    return out


def _bound_names(node: ast.AST) -> Iterator[str]:
    """Every local name this node binds, in whatever scope."""
    if isinstance(node, ast.Import):
        for a in node.names:
            yield a.asname or a.name.split(".")[0]
    elif isinstance(node, ast.ImportFrom):
        for a in node.names:
            if a.name != "*":
                yield a.asname or a.name
            elif node.level == 0 and node.module:
                yield from _STAR_NAMES.get(node.module, ())
    elif isinstance(node, (*_FUNCS, ast.ClassDef)):
        yield node.name
    elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        yield node.id
    elif isinstance(node, ast.arg):
        yield node.arg
    elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar,
                           ast.TypeVar, ast.ParamSpec, ast.TypeVarTuple)) and node.name:
        yield node.name
    elif isinstance(node, ast.MatchMapping) and node.rest:
        yield node.rest


def _sure_aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> the one dotted name it is surely bound to.

    Only a name bound by explicit absolute imports, all to the same target, and bound by nothing
    else anywhere in the file (no star import, def, class, assignment, loop or `with` target).
    """
    targets: dict[str, set[str]] = {}
    unsure: set[str] = set()
    aliases = _aliases(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                targets.setdefault(a.asname or a.name.split(".")[0], set()).add(
                    a.name if a.asname else a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                if a.name != "*":
                    targets.setdefault(a.asname or a.name, set()).add(f"{node.module}.{a.name}")
                elif node.module in _STAR_NAMES:
                    unsure.update(_STAR_NAMES[node.module])
                else:
                    return {}  # a star import we cannot see into may rebind any name
        elif isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            return {}  # relative star import: likewise opaque
        else:
            unsure.update(_bound_names(node))
            rebound = _rebinds(node, aliases)
            if rebound is _ANY:
                return {}
            unsure.update(rebound)
    return {k: next(iter(v)) for k, v in targets.items() if len(v) == 1 and k not in unsure}


_ANY = frozenset({"*"})  # a write that may rebind any name
_NAMESPACE_CALLS = {"globals", "locals", "vars"}


def _root(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _is_sys_modules(node: ast.expr, aliases: dict[str, set[str]]) -> bool:
    head, _, rest = _dotted(node).partition(".")
    return bool(head) and any((f"{h}.{rest}" if rest else h) == "sys.modules"
                              for h in aliases.get(head, {head}))


def _rebinds(node: ast.AST, aliases: dict[str, set[str]]) -> frozenset[str]:
    """Names an attribute write, setattr or namespace write may rebind at run time.

    `pytest.mark.skip = ...`, `del pytest.mark` or `setattr(pytest.mark, ...)` make `pytest` unsure;
    a write through `globals()`, `locals()`, `vars()` or `sys.modules` may rebind anything.
    """
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        root = _root(node.value)
        return frozenset({root}) if root else frozenset()
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        value = node.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in _NAMESPACE_CALLS:
            return _ANY
        if _is_sys_modules(value, aliases):
            return _ANY
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"setattr", "delattr"} and node.args:
            root = _root(node.args[0])
            return frozenset({root}) if root else frozenset()
        if isinstance(func, ast.Attribute) and func.attr in {"update", "setdefault", "__setitem__", "pop"} \
                and (_is_sys_modules(func.value, aliases) or (
                    isinstance(func.value, ast.Call) and isinstance(func.value.func, ast.Name)
                    and func.value.func.id in _NAMESPACE_CALLS)):
            return _ANY
    return frozenset()


class _Names:
    """Resolves a name or attribute chain through the file's import aliases."""

    def __init__(self, tree: ast.AST) -> None:
        self._aliases = _aliases(tree)
        self._sure = _sure_aliases(tree)

    def all(self, node: ast.expr) -> frozenset[str]:
        """Every dotted name this expression may refer to."""
        name = _dotted(node.func if isinstance(node, ast.Call) else node)
        head, _, rest = name.partition(".")
        heads = self._aliases.get(head) or {head}
        return frozenset(f"{h}.{rest}" if rest else h for h in heads)

    def sure(self, node: ast.expr) -> str | None:
        """The one dotted name this expression surely refers to, or None when it is ambiguous."""
        name = _dotted(node.func if isinstance(node, ast.Call) else node)
        head, _, rest = name.partition(".")
        target = self._sure.get(head)
        if target is None:
            return None
        return f"{target}.{rest}" if rest else target

    def matches(self, node: ast.expr, *targets: str | set[str]) -> bool:
        wanted = {t for group in targets for t in ({group} if isinstance(group, str) else group)}
        return not wanted.isdisjoint(self.all(node))


def _flat(body: list[ast.stmt], cond: bool = False) -> Iterator[tuple[ast.stmt, bool]]:
    """The statements of a body, looking through `if`, `with`, `try`, loops and `match`.

    The flag says whether the statement runs only under a condition: in an `if`, a loop, a
    `match` case, an `except` handler or a `try`'s `else`.
    """
    for node in body:
        if isinstance(node, ast.If):
            yield from _flat(node.body, True)
            yield from _flat(node.orelse, True)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            yield from _flat(node.body, cond)
        elif isinstance(node, (ast.Try, ast.TryStar)):
            yield from _flat(node.body, cond)
            for handler in node.handlers:
                yield from _flat(handler.body, True)
            yield from _flat(node.orelse, True)
            yield from _flat(node.finalbody, cond)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            yield from _flat(node.body, True)
            yield from _flat(node.orelse, True)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                yield from _flat(case.body, True)
        else:
            yield node, cond


def _definitions(body: list[ast.stmt], prefix: str = "") -> Iterator[tuple[str, ast.stmt]]:
    """Every function and class, keyed `Class.method` or `outer.inner`, also inside blocks."""
    for node, _ in _flat(body):
        if isinstance(node, (*_FUNCS, ast.ClassDef)):
            name = prefix + node.name
            yield name, node
            yield from _definitions(node.body, name + ".")


def _own_nodes(body: list[ast.stmt]) -> Iterator[ast.AST]:
    """Nodes of a body, not descending into nested functions, classes or lambdas."""
    stack: list[ast.AST] = list(reversed(body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (*_FUNCS, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


_NONE, _MAYBE, _SKIP = 0, 1, 2  # how surely a mark or statement skips a test
_SKIP_MARKS = {"pytest.mark.skip", "unittest.skip", "pytest.mark.skipif", "unittest.skipIf",
               "unittest.skipUnless", "pytest.mark.xfail"}


def _truthy(node: ast.expr | None) -> bool | None:
    """The truth of a bool, int or None constant, else None. A string is code to evaluate."""
    if isinstance(node, ast.Constant) and (node.value is None or isinstance(node.value, (bool, int))):
        return bool(node.value)
    return None


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _conditions(name: str, call: ast.Call | None) -> list[ast.expr]:
    """The conditions a skipif-like or xfail mark tests, gathered the way pytest and unittest do."""
    if call is None:
        return []
    if (kw := _keyword(call, "condition")) is not None:
        return [kw]
    return list(call.args[:1]) if name.startswith("unittest.") else list(call.args)


def _any_truthy(conds: list[ast.expr]) -> bool | None:
    """True when any condition is constant-true, None when any other is unknown, else False."""
    truths = [_truthy(c) for c in conds]
    if any(t is True for t in truths):
        return True
    return None if any(t is None for t in truths) else False


def _mark_level(name: str, call: ast.Call | None) -> int:
    """How surely a decorator or mark that resolves to `name` skips the test."""
    if call is not None and name in _SKIP_MARKS and any(k.arg is None for k in call.keywords):
        return _MAYBE  # `**kwargs` may hold a condition or `run` we cannot see
    if name in {"pytest.mark.skip", "unittest.skip"}:
        return _SKIP
    if name in {"pytest.mark.skipif", "unittest.skipIf", "unittest.skipUnless"}:
        conds = _conditions(name, call)
        truth = _any_truthy(conds) if conds else None  # no condition at all: not provably a skip
        if truth is None:
            return _MAYBE
        if name == "unittest.skipUnless":
            truth = not truth
        return _SKIP if truth else _NONE
    if name == "pytest.mark.xfail":
        # A strict xfail still hides a failing test, so it is no safer than a plain one.
        conds = _conditions(name, call)
        truth = _any_truthy(conds) if conds else True
        if truth is None:
            return _MAYBE
        if truth:
            run_off = call is not None and _truthy(_keyword(call, "run")) is False
            return _SKIP if run_off else _MAYBE
    return _NONE


def _mark_skip(expr: ast.expr, names: _Names) -> int:
    """Whether a decorator or mark skips the test: always, maybe, or not.

    Always needs the name to resolve unambiguously. An ambiguous name (star-derived, shadowed or
    bound twice) is judged under each binding: if they disagree it is maybe, if they agree it is
    that result, capped at maybe either way, since it may not be the skip it looks like.
    """
    call = expr if isinstance(expr, ast.Call) else None
    sure = names.sure(expr)
    if sure is not None:
        return _mark_level(sure, call)
    levels = {_mark_level(n, call) for n in names.all(expr)}
    agreed = levels.pop() if len(levels) == 1 else _MAYBE
    return min(_MAYBE, agreed)


def _marks_skip(value: ast.expr, names: _Names) -> int:
    items = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
    return max((_mark_skip(i, names) for i in items), default=_NONE)


def _pytestmark(tree: ast.Module, names: _Names) -> int:
    best = _NONE
    for n in tree.body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytestmark"
                                             for t in n.targets):
            best = max(best, _marks_skip(n.value, names))
        elif isinstance(n, ast.AnnAssign) and n.value is not None and isinstance(n.target, ast.Name) \
                and n.target.id == "pytestmark":
            best = max(best, _marks_skip(n.value, names))
    if best == _SKIP and sum(b == "pytestmark" for node in ast.walk(tree) for b in _bound_names(node)) != 1:
        best = _MAYBE  # rebound somewhere, so the skipping value may not be the one pytest sees
    return best


# What a raise of a skip exception surely resolves to.
_SKIP_RAISES = {"unittest.SkipTest", "unittest.case.SkipTest", "pytest.skip.Exception",
                "_pytest.outcomes.Skipped"}


def _skips_here(node: ast.AST, names: _Names) -> int:
    """A pytest.skip(...) call or a raise of SkipTest: surely, maybe (ambiguous name), or not."""
    if isinstance(node, ast.Call):
        target: ast.expr = node
        wanted = {"pytest.skip"}
        hit = names.matches(node, wanted)
    elif isinstance(node, ast.Raise) and node.exc is not None:
        target = node.exc
        wanted = _SKIP_RAISES
        hit = any(n in wanted or n.rsplit(".", 1)[-1] == "SkipTest" for n in names.all(node.exc))
    else:
        return _NONE
    if not hit:
        return _NONE
    return _SKIP if names.sure(target) in wanted else _MAYBE


def _body_skip(fn: ast.FunctionDef | ast.AsyncFunctionDef, names: _Names) -> int:
    """Skipping directly in the body is unconditional; skipping deeper (inside an if) is maybe."""
    direct = {id(n.value if isinstance(n, ast.Expr) else n) for n in fn.body}
    best = _NONE
    for n in _own_nodes(fn.body):
        how = _skips_here(n, names)
        best = max(best, how if id(n) in direct else min(how, _MAYBE))
    return best


# Calls that check something as surely as an `assert` does.
_CHECK_CALLS = {"pytest.raises", "pytest.warns", "pytest.deprecated_call", "pytest.fail"}
# A called name with one of these words may be a check prgate cannot see into.
_CHECKY = ("check", "verify", "expect", "validate", "ensure", "compare", "should", "must", "match")
# Module path parts that mark an import as a shared test helper.
_HELPER_MODULES = {"test", "tests", "testing", "conftest", "helpers", "helper", "utils", "util", "support",
                   "fixtures", "testutils", "test_utils", "testlib"}
# pytest's own fixtures: none of them checks anything when the test ends.
_BUILTIN_FIXTURES = {"self", "cls", "tmp_path", "tmpdir", "tmp_path_factory", "tmpdir_factory", "monkeypatch",
                     "capsys", "capsysbinary", "capfd", "capfdbinary", "caplog", "request", "recwarn",
                     "pytestconfig", "record_property", "record_testsuite_property", "record_xml_attribute",
                     "doctest_namespace", "cache"}
# Bases that add no test methods of their own.
_EMPTY_BASES = ("unittest.", "django.test.", "rest_framework.test.", "twisted.trial.unittest.")
_HELPER_DEPTH = 4
_NODE_BUDGET = 20_000  # nodes counted per test, and class work per file; past it, unsure


def _is_test_class(node: ast.ClassDef, names: _Names) -> bool:
    return node.name.startswith("Test") or any(n.endswith("TestCase") for b in node.bases for n in names.all(b))


def _parametrized(fn: ast.FunctionDef | ast.AsyncFunctionDef, names: _Names) -> set[str] | None:
    """Argument names a parametrize mark fills, or None when one cannot be read."""
    out: set[str] = set()
    for dec in fn.decorator_list:
        if isinstance(dec, ast.Call) and names.matches(dec, "pytest.mark.parametrize"):
            first = dec.args[0] if dec.args else _keyword(dec, "argnames")
            if (text := _const_str(first)) is not None:
                out.update(a.strip() for a in text.split(","))
            elif isinstance(first, (ast.List, ast.Tuple)) and all(_const_str(e) is not None for e in first.elts):
                out.update(_const_str(e) for e in first.elts)  # type: ignore[misc]
            else:
                return None
    return out


class _Checks:
    """Counts the checks a test makes, following helpers defined in the same file.

    The count is unsure when the test may check things prgate cannot see: it calls a helper
    from this file that asserts nothing it can see, a helper imported from test support code or
    named like a check, a method its class may inherit from elsewhere, or uses a fixture that is
    not pytest's own. An unsure count of zero is never proof that the asserts were removed.
    """

    def __init__(self, tree: ast.Module, names: _Names, classes: dict[str, ast.ClassDef]) -> None:
        self._names = names
        self._classes = classes
        self._funcs = {n.name: n for n, _ in _flat(tree.body) if isinstance(n, _FUNCS)}
        self._relative = {a.asname or a.name for n in ast.walk(tree)
                          if isinstance(n, ast.ImportFrom) and n.level > 0 for a in n.names}
        self._cache: dict[int, tuple[dict[str, tuple[ast.stmt, ast.ClassDef]], bool]] = {}
        self._helpers: dict[tuple[int, int], tuple[int, bool]] = {}  # each helper is counted once per file
        self._visited = 0  # nodes counted for the current test
        self._spent = False  # whether the current test ran out of budget
        self._class_work = 0  # bases and methods read for the whole file
        self._resolving: set[int] = set()

    def methods(self, cls: ast.ClassDef, depth: int = 0) -> tuple[dict[str, tuple[ast.stmt, ast.ClassDef]], bool]:
        """Every method a class has, inherited ones included, and whether a base is unknown.

        Each class is resolved once per file. A cycle, a chain deeper than 8, or more class work than
        the node budget makes the bases unknown, which never lets a deletion be proof."""
        if id(cls) in self._cache:
            return self._cache[id(cls)]
        if id(cls) in self._resolving:
            return {}, True
        self._resolving.add(id(cls))
        found: dict[str, tuple[ast.stmt, ast.ClassDef]] = {}
        unknown = False
        for base in reversed(cls.bases):
            self._class_work += 1
            if self._class_work > _NODE_BUDGET:
                unknown = True
                break
            local = base.id if isinstance(base, ast.Name) else None
            if local in self._classes and self._classes[local] is not cls and depth < 8:
                inherited, more = self.methods(self._classes[local], depth + 1)
                self._class_work += len(inherited)
                found.update(inherited)
                unknown |= more
            elif not all(n == "object" or n.startswith(_EMPTY_BASES) for n in self._names.all(base)):
                unknown = True
        for node, _ in _flat(cls.body):
            if isinstance(node, _FUNCS):
                found[node.name] = (node, cls)
        self._resolving.discard(id(cls))
        result = found, unknown or bool(cls.keywords)
        self._cache[id(cls)] = result
        return result

    def test(self, fn: ast.FunctionDef | ast.AsyncFunctionDef, owner: ast.ClassDef | None) -> tuple[int, bool]:
        self._visited, self._spent = 0, False  # the budget is per test, so one big file cannot starve the rest
        count, unsure = self._tally(fn, owner, 0, {id(fn)})
        filled = _parametrized(fn, self._names)
        args = fn.args
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            if a.arg in _BUILTIN_FIXTURES or (filled is not None and a.arg in filled):
                continue
            if a.arg in self._funcs:  # a fixture in this file: its checks run with the test
                more, why = self._helper(self._funcs[a.arg], None, 0, {id(fn)})
                count, unsure = count + more, unsure or why
            else:
                unsure = True
        return count, unsure

    def _tally(self, fn: ast.stmt, owner: ast.ClassDef | None, depth: int, seen: set[int]) -> tuple[int, bool]:
        count, unsure = 0, False
        for node in _own_nodes(fn.body):  # type: ignore[attr-defined]
            self._visited += 1
            if self._visited > _NODE_BUDGET:
                self._spent = True
                return count, True  # too much to follow: never proof
            if isinstance(node, ast.Assert):
                count += 1
            elif isinstance(node, ast.Raise):
                if node.exc is not None and any(n.rsplit(".", 1)[-1] == "AssertionError"
                                                for n in self._names.all(node.exc)):
                    count += 1
                else:
                    unsure = True
            elif isinstance(node, ast.Call):
                more, why = self._call(node, owner, depth, seen)
                count, unsure = count + more, unsure or why
        return count, unsure

    def _helper(self, fn: ast.stmt, owner: ast.ClassDef | None, depth: int, seen: set[int]) -> tuple[int, bool]:
        key = (id(fn), id(owner))
        if key in self._helpers:
            return self._helpers[key]
        if depth >= _HELPER_DEPTH or id(fn) in seen:
            return 0, True  # not memoised: a shallower call may still read it in full
        count, unsure = self._tally(fn, owner, depth + 1, seen | {id(fn)})
        result = (count, unsure) if count else (0, True)
        if not self._spent:  # a count cut short by the budget is only this test's
            self._helpers[key] = result
        return result

    def _call(self, node: ast.Call, owner: ast.ClassDef | None, depth: int, seen: set[int]) -> tuple[int, bool]:
        func = node.func
        if self._names.matches(node, _CHECK_CALLS):
            return 1, False
        if isinstance(func, ast.Name):
            last = func.id
        elif isinstance(func, ast.Attribute):
            last = func.attr
        else:
            return 0, True  # calling the result of an expression: cannot tell
        bare = last.lstrip("_").lower()
        if bare.startswith("assert") or (isinstance(func, ast.Attribute) and bare.startswith("fail")):
            return 1, False  # assert_frame_equal(...), self.assertEqual(...), self.fail(...)
        if isinstance(func, ast.Name) and func.id in self._funcs:
            return self._helper(self._funcs[func.id], None, depth, seen)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            holder = func.value.id
            cls = owner if holder in {"self", "cls"} else self._classes.get(holder)
            if cls is not None:
                methods, unknown = self.methods(cls)
                if func.attr in methods:
                    method, where = methods[func.attr]
                    return self._helper(method, where, depth, seen)
                if unknown:
                    return 0, True  # may be a helper inherited from a base we cannot read
        if any(word in bare for word in _CHECKY):
            return 0, True
        if isinstance(func, ast.Name) and func.id in self._relative:
            return 0, True
        if isinstance(func, ast.Name):
            for target in self._names.all(func):
                parts = target.split(".")[:-1]
                if any(p in _HELPER_MODULES or p.startswith("test") or p.endswith("_test") for p in parts):
                    return 0, True
        return 0, False


_ENVIRON = {"os.environ", "environ"}
_ENV_READS = {"os.environ.get", "os.getenv"}
_IMPORTERS = {"__import__", "importlib.import_module", "importlib.__import__"}


def _const_str(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _env_read(node: ast.AST, names: _Names) -> tuple[bool, str | None] | None:
    """(is a read, constant key or None) when a node reads the environment by key."""
    key: ast.expr | None
    if isinstance(node, ast.Subscript) and names.matches(node.value, _ENVIRON):
        key = node.slice
    elif isinstance(node, ast.Call) and names.matches(node, _ENV_READS):
        if not node.args:
            return None
        key = node.args[0]
    elif isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.In) \
            and names.matches(node.comparators[0], _ENVIRON):
        key = node.left
    else:
        return None
    return True, _const_str(key)


def _sniffs(node: ast.AST, names: _Names, is_test: bool) -> str | None:
    """Why this node looks at the environment it runs in, or None.

    A test file importing pytest itself is ordinary, so `is_test` exempts plain `pytest` imports.
    """
    if isinstance(node, ast.Import):
        if any(a.name.split(".")[0] in _SNIFFED_MODULES and not (is_test and a.name == "pytest")
               for a in node.names):
            return "imports pytest"
    elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        if node.level == 0 and module.split(".")[0] in _SNIFFED_MODULES \
                and not (is_test and module == "pytest"):
            return "imports pytest"
    elif isinstance(node, ast.Compare) and _const_str(node.left) in _SNIFFED_MODULES \
            and isinstance(node.ops[0], ast.In) and names.matches(node.comparators[0], "sys.modules"):
        return "checks whether pytest is loaded"
    elif isinstance(node, ast.Subscript) and names.matches(node.value, "sys.modules") \
            and _const_str(node.slice) in _SNIFFED_MODULES:
        return "checks whether pytest is loaded"
    elif isinstance(node, ast.Call):
        first = _const_str(node.args[0]) if node.args else None
        for called in sorted(names.all(node)):
            if called in {"os._exit", "sys.settrace", "sys.setprofile"}:
                return f"calls {called}"
        if names.matches(node, "sys.modules.get", _IMPORTERS) and first in _SNIFFED_MODULES:
            return "looks for pytest"
    read = _env_read(node, names)
    if read is not None:
        key = read[1]
        if key is None:
            return "reads an environment variable by a computed name"
        if key in _ENV_KEYS or key.startswith(_ENV_PREFIXES):
            return f"reads the {key} environment variable"
    return None


_DYNAMIC_CALLS = {"globals", "locals", "vars", "exec", "eval"}
# Values that are plain data, never a callable pytest could collect.
_DATA = (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp,
         ast.JoinedStr, ast.BinOp)


def _dynamic_tests(tree: ast.Module, top: list[tuple[ast.stmt, bool]]) -> bool:
    """Whether the file may make tests in ways prgate cannot follow.

    A `test*` or `Test*` name bound by assignment, a module-level `setattr`, a `load_tests`
    hook, or any use of `globals()`, `locals()`, `vars()`, `exec` or `eval`.
    """
    scopes = [top] + [list(_flat(n.body)) for n, _ in top if isinstance(n, ast.ClassDef)]
    for scope in scopes:
        for node, _ in scope:
            if isinstance(node, _FUNCS) and node.name == "load_tests":
                return True
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value is not None \
                    and not isinstance(node.value, _DATA):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name) and n.id.startswith(("test", "Test")):
                            return True
            for n in ast.walk(node) if not isinstance(node, (*_FUNCS, ast.ClassDef)) else ():
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "setattr":
                    return True
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _DYNAMIC_CALLS
               for n in ast.walk(tree))


class PythonPlugin:
    name = "python"

    def handles(self, path: str) -> bool:
        return path.endswith(".py")

    def symbols(self, source: str) -> dict[str, str]:
        """Qualified name -> hash of the definition without its name, comments or formatting."""
        out: dict[str, str] = {}
        for name, node in _definitions(ast.parse(source).body):
            if isinstance(node, ast.ClassDef):
                shape = ast.Module(node.body, [])
            else:
                shape = ast.Module([ast.Expr(ast.Tuple(list(node.decorator_list), ast.Load())),
                                    ast.Expr(ast.Constant(ast.dump(node.args))), *node.body], [])
            out[name] = hashlib.sha256(ast.dump(shape).encode()).hexdigest()
        return out

    def test_facts(self, source: str) -> TestFacts:
        """`test*` functions, and `test*` methods of `Test*` and `TestCase` classes.

        Tests are found inside `if`, `with`, `try` and loop blocks, in nested `Test*` classes and
        through inheritance from classes in the same file. A test that exists only under a
        condition, or is defined more than once, is at most maybe skipped.
        """
        tree = ast.parse(source)
        names = _Names(tree)
        tests: dict[str, int] = {}
        skipped: set[str] = set()
        maybe: set[str] = set()
        unsure: set[str] = set()
        defined_at: dict[str, str] = {}
        seen: set[str] = set()
        module_mark = _pytestmark(tree, names)
        top = list(_flat(tree.body))
        classes = {n.name: n for n, _ in top if isinstance(n, ast.ClassDef)}
        checks = _Checks(tree, names, classes)
        opaque = _dynamic_tests(tree, top)

        def record(name: str, fn: ast.FunctionDef | ast.AsyncFunctionDef, owner: ast.ClassDef | None,
                   inherited: int, where: str, cond: bool) -> None:
            count, why = checks.test(fn, owner)
            tests[name] = count
            defined_at[name] = where
            skipped.discard(name)
            maybe.discard(name)
            unsure.discard(name)
            how = max(inherited, _body_skip(fn, names),
                      *(_mark_skip(d, names) for d in fn.decorator_list), _NONE)
            if name in seen or cond:  # which definition pytest sees depends on run-time order
                how = _MAYBE
                why = True
            seen.add(name)
            if how == _SKIP:
                skipped.add(name)
            elif how == _MAYBE:
                maybe.add(name)
            if why:
                unsure.add(name)

        def visit_class(cls: ast.ClassDef, qual: str, outer_mark: int, cond: bool, depth: int) -> None:
            nonlocal opaque
            class_mark = max(outer_mark, _NONE, *(_mark_skip(d, names) for d in cls.decorator_list))
            methods, unknown = checks.methods(cls)
            opaque = opaque or unknown
            for mname, (method, where) in sorted(methods.items()):
                if not mname.startswith("test") or not isinstance(method, _FUNCS):
                    continue
                mark = class_mark
                if where is not cls:  # inherited: the base's own marks may or may not apply
                    base_mark = max((_mark_skip(d, names) for d in where.decorator_list), default=_NONE)
                    mark = max(mark, min(base_mark, _MAYBE))
                # `symbols` keys an inherited method by its module-level class, an own one by `qual`.
                record(f"{qual}.{mname}", method, where, mark,
                       f"{qual if where is cls else where.name}.{mname}", cond)
            for inner, inner_cond in _flat(cls.body, cond):
                if isinstance(inner, ast.ClassDef) and inner.name.startswith("Test") and depth < 8:
                    visit_class(inner, f"{qual}.{inner.name}", class_mark, inner_cond, depth + 1)

        for node, cond in top:
            if isinstance(node, _FUNCS) and node.name.startswith("test"):
                record(node.name, node, None, module_mark, node.name, cond)
            elif isinstance(node, ast.ClassDef) and _is_test_class(node, names):
                visit_class(node, node.name, module_mark, cond, 0)
        return TestFacts(tests, frozenset(skipped), frozenset(maybe), frozenset(unsure),
                         defined_at, opaque)

    def sniffing(self, source: str, *, is_test: bool = False) -> tuple[Finding, ...]:
        tree = ast.parse(source)
        names = _Names(tree)
        found = []
        for node in ast.walk(tree):
            why = _sniffs(node, names, is_test)
            if why is not None:
                found.append(Finding(
                    CHECK, Severity.SUSPICION, f"code {why}", line=getattr(node, "lineno", None),
                    question="Does this code behave differently when it detects a test run or CI?"))
        return tuple(sorted(found, key=lambda f: (f.line or 0, f.message)))

    def imports(self, source: str) -> frozenset[str]:
        names: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
        return frozenset(names)

    def declared_deps(self, repo: Path) -> frozenset[str]:
        """Normalised names declared in the manifests directly under `repo`.

        A manifest that cannot be read raises ValueError: silence would hide new dependencies.
        """
        return frozenset(read_manifests(repo).deps)
