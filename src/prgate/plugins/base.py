"""The boundary every language implements. Plug-ins only parse text; they never run PR code."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..models import Finding

ENVIRONMENT_SNIFFING = "environment_sniffing"


@dataclass(frozen=True)
class TestFacts:
    """Per test, keyed by qualified name such as `TestC.test_a` or `test_a`."""
    __test__ = False  # not a pytest class

    tests: dict[str, int]  # assert count
    skipped: frozenset[str]
    maybe_skipped: frozenset[str] = frozenset()  # skipped only under a condition we cannot evaluate
    asserts_unsure: frozenset[str] = frozenset()  # the count may miss checks made out of sight
    defined_at: dict[str, str] = field(default_factory=dict)  # test -> `symbols` key of its body
    opaque: bool = False  # the file may make or inherit tests in ways the plug-in cannot follow


class LanguagePlugin(Protocol):
    name: str

    def handles(self, path: str) -> bool: ...
    def symbols(self, source: str) -> dict[str, str]: ...  # qualified name -> normalised body hash
    def test_facts(self, source: str) -> TestFacts: ...
    def sniffing(self, source: str, *, is_test: bool = False) -> tuple[Finding, ...]: ...
    def imports(self, source: str) -> frozenset[str]: ...
    def declared_deps(self, repo: Path) -> frozenset[str]: ...
