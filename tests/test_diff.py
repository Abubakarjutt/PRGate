import subprocess
from pathlib import Path

import pytest

from prgate.diff import parse_diff


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    git(tmp_path, "config", "commit.gpgsign", "false")
    add(tmp_path, "README.md", "hello\n")
    commit(tmp_path, "base")
    return tmp_path


def add(repo: Path, path: str, content: str | bytes) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content.encode() if isinstance(content, str) else content)


def commit(repo: Path, msg: str = "c") -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)


def commit_rename(repo: Path, old: str, new: str) -> None:
    add(repo, old, "".join(f"line {i}\n" for i in range(20)))
    commit(repo, "add")
    (repo / new).parent.mkdir(parents=True, exist_ok=True)
    git(repo, "mv", old, new)
    commit(repo, "rename")


def commit_and_parse(repo: Path):
    commit(repo)
    return parse_diff(repo, "HEAD~1", "HEAD")


def one(changes):
    assert len(changes) == 1
    return changes[0]


def test_rename_keeps_old_path(repo):
    commit_rename(repo, "auth/login.py", "misc/login.py")
    change = one(parse_diff(repo, "HEAD~1", "HEAD"))
    assert change.old_path == "auth/login.py"
    assert change.path == "misc/login.py"
    assert change.status == "R"


def test_binary_and_non_utf8_and_spaces(repo):
    add(repo, "a b.png", b"\x00\xff")
    add(repo, "l1.py", "x='é'".encode("latin-1"))
    by = {c.path: c for c in commit_and_parse(repo)}
    assert by["a b.png"].binary and "l1.py" in by
    assert not by["l1.py"].binary
    assert by["l1.py"].added[0][0] == 1
    assert by["a b.png"].added == ()


def test_added_lines_have_new_file_line_numbers(repo):
    add(repo, "m.py", "a\nb\nc\nd\n")
    commit(repo)
    add(repo, "m.py", "a\nB\nc\nd\ne\n")
    change = one(commit_and_parse(repo))
    assert change.added == ((2, "B"), (5, "e"))
    assert change.removed_count == 1
    assert change.status == "M"


def test_deleted_file(repo):
    (repo / "README.md").unlink()
    change = one(commit_and_parse(repo))
    assert change.status == "D" and change.added == () and change.removed_count == 1


def test_non_utf8_filename_keeps_its_hunks(repo):
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, input=b"x = 1\ny = 2\n",
                          check=True, capture_output=True).stdout.decode().strip()
    subprocess.run(["git", "update-index", "--add", "--index-info"], cwd=repo, check=True, capture_output=True,
                   input=f"100644 {blob}\tbad_".encode() + b"\xe9" + b".py\n")
    git(repo, "commit", "-q", "-m", "c")
    change = one(parse_diff(repo, "HEAD~1", "HEAD"))
    assert change.added == ((1, "x = 1"), (2, "y = 2"))
    assert not change.binary


def test_glob_like_filename_is_literal(repo):
    add(repo, "[a-z]*.py", "one\n")
    add(repo, "abc.py", "two\n")
    by = {c.path: c for c in commit_and_parse(repo)}
    assert by["[a-z]*.py"].added == ((1, "one"),)
    assert by["abc.py"].added == ((1, "two"),)


def test_bounded_git_calls_for_many_files(repo, monkeypatch):
    for i in range(300):
        add(repo, f"d/f{i}.py", f"v{i} = {i}\n")
    commit(repo)
    calls = []
    real = subprocess.run

    def counting(*a, **kw):
        calls.append(a)
        return real(*a, **kw)

    monkeypatch.setattr(subprocess, "run", counting)
    changes = parse_diff(repo, "HEAD~1", "HEAD")
    assert len(changes) == 300 and len(calls) <= 3
