from __future__ import annotations

import re

from .models import ChangeType, FileChange

_AGENT_NAMES = {"claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules",
                "copilot-instructions.md"}
_AGENT_DIRS = {".claude", ".cursor", ".codex", ".gemini"}
_CI_PREFIXES = (".github/workflows/", ".circleci/", ".buildkite/")
_CI_NAMES = {".prgate.toml", ".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", ".travis.yml"}
_TEST_INFRA_NAMES = {"conftest.py", "pytest.ini", "setup.py", "setup.cfg", "tox.ini", "noxfile.py",
                     "makefile", ".coveragerc", "karma.conf.js"}
_TEST_INFRA_RE = re.compile(r"^(jest|vitest|playwright|cypress)\.config\.[a-z]+$")
_DEP_NAMES = {"pyproject.toml", "package.json", "pipfile", "go.mod", "go.sum", "cargo.toml",
              "gemfile", "poetry.lock", "yarn.lock", "pnpm-lock.yaml"}
_DEP_RE = re.compile(r"(^(requirements|constraints).*\.(txt|in)$)|(\.lock$)|(^package-lock\.json$)")
_TEST_RE = re.compile(r"(^test_.*\.py$)|(_test\.(py|go)$)|(\.(test|spec)\.[a-z]+$)")
_TEST_DIRS = {"tests", "test", "__tests__", "spec"}
_CONFIG_EXT = {".tf", ".tfvars", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".json"}
_DOC_EXT = {".md", ".rst", ".txt", ".adoc"}
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt",
             ".rb", ".php", ".cs", ".c", ".h", ".cpp", ".hpp", ".swift", ".vue", ".svelte",
             ".sql", ".sh"}


def classify(change: FileChange) -> ChangeType:
    if change.binary:
        return ChangeType.UNKNOWN
    path = change.path.lower()
    parts = path.split("/")
    name = parts[-1]
    ext = "." + name.rsplit(".", 1)[1] if "." in name else ""

    if name in _AGENT_NAMES or _AGENT_DIRS & set(parts[:-1]):
        return ChangeType.AGENT_INSTRUCTIONS
    if path.startswith(_CI_PREFIXES) or name in _CI_NAMES:
        return ChangeType.CI
    if "migrations" in parts[:-1] or path.startswith("alembic/versions/"):
        return ChangeType.MIGRATION
    if name in _TEST_INFRA_NAMES or _TEST_INFRA_RE.match(name):
        return ChangeType.TEST_INFRA
    if name in _DEP_NAMES or _DEP_RE.search(name) or (
        name.endswith((".txt", ".in")) and "requirements" in parts[:-1]
    ):
        return ChangeType.DEPENDENCY
    if _TEST_DIRS & set(parts[:-1]) or _TEST_RE.search(name):
        return ChangeType.TEST
    if name.startswith(".env") or ext in _CONFIG_EXT:
        return ChangeType.CONFIG
    if name == "cmakelists.txt":
        return ChangeType.CONFIG
    if ext in _DOC_EXT or (parts[0] == "docs" and ext not in CODE_EXT):
        return ChangeType.DOCS
    if ext in CODE_EXT:
        return ChangeType.CODE
    return ChangeType.UNKNOWN
