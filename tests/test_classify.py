import pytest

from prgate.classify import classify
from prgate.models import ChangeType, FileChange


def change(path: str, binary: bool = False) -> FileChange:
    return FileChange(path, None, "M", (), 0, binary)


@pytest.mark.parametrize("path,kind", [
    ("src/a.py", ChangeType.CODE), ("web/a.tsx", ChangeType.CODE),
    ("tests/test_a.py", ChangeType.TEST), ("src/a.test.ts", ChangeType.TEST),
    ("conftest.py", ChangeType.TEST_INFRA), ("pytest.ini", ChangeType.TEST_INFRA),
    ("jest.config.ts", ChangeType.TEST_INFRA), ("vitest.config.ts", ChangeType.TEST_INFRA),
    ("setup.py", ChangeType.TEST_INFRA), ("Makefile", ChangeType.TEST_INFRA),
    ("tests/conftest.py", ChangeType.TEST_INFRA),
    ("pyproject.toml", ChangeType.DEPENDENCY), ("package.json", ChangeType.DEPENDENCY),
    ("uv.lock", ChangeType.DEPENDENCY), ("package-lock.json", ChangeType.DEPENDENCY),
    ("prisma/migrations/1/migration.sql", ChangeType.MIGRATION),
    ("supabase/migrations/1.sql", ChangeType.MIGRATION), ("alembic/versions/1.py", ChangeType.MIGRATION),
    ("infra/main.tf", ChangeType.CONFIG), ("k8s/app.yaml", ChangeType.CONFIG), (".env.example", ChangeType.CONFIG),
    ("README.md", ChangeType.DOCS), ("CLAUDE.md", ChangeType.AGENT_INSTRUCTIONS),
    (".claude/skills/x/SKILL.md", ChangeType.AGENT_INSTRUCTIONS), ("AGENTS.md", ChangeType.AGENT_INSTRUCTIONS),
    (".github/workflows/ci.yml", ChangeType.CI), (".prgate.toml", ChangeType.CI),
    ("blob.bin", ChangeType.UNKNOWN),
])
def test_classify(path, kind):
    assert classify(change(path)) == kind


def test_binary_is_unknown():
    assert classify(change("src/a.py", binary=True)) == ChangeType.UNKNOWN


@pytest.mark.parametrize("path,kind", [
    ("requirements/base.txt", ChangeType.DEPENDENCY),
    ("a/requirements-dev.txt", ChangeType.DEPENDENCY),
    ("constraints.txt", ChangeType.DEPENDENCY),
    ("CMakeLists.txt", ChangeType.CONFIG),
    ("sub/.claude/skills/x/SKILL.md", ChangeType.AGENT_INSTRUCTIONS),
    ("docs/conf.py", ChangeType.CODE),
    ("docs/notes.txt", ChangeType.DOCS),
])
def test_classify_holes(path, kind):
    assert classify(change(path)) == kind
