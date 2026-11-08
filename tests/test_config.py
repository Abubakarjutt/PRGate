import subprocess
from pathlib import Path

import pytest

from prgate.config import Config, load_config, parse_config


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def commit(repo: Path) -> None:
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "c")


def sha(repo: Path) -> str:
    return git(repo, "rev-parse", "HEAD")


def write_config(repo: Path, text: str) -> None:
    (repo / ".prgate.toml").write_text(text)


@pytest.fixture
def repo_without_config(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.txt").write_text("x")
    commit(tmp_path)
    return tmp_path


@pytest.fixture
def repo(repo_without_config):
    return repo_without_config


def test_defaults_are_safe(repo_without_config):
    c = load_config(repo_without_config, "HEAD")
    assert c.valid and c.mode == "silent" and not c.clear_code and not c.clear_docs
    assert c.stage1_s == 120 and c.stage2_s == 900
    assert c.max_mutants == 60 and c.max_llm_calls == 2
    assert all(p in c.always_human for p in ("**/auth/**", "**/payments/**", "**/migrations/**", ".github/**", ".prgate.toml"))


def test_reads_base_not_pr(repo):
    write_config(repo, 'clear_code = false'); commit(repo)
    base = sha(repo); write_config(repo, 'clear_code = true'); commit(repo)
    assert load_config(repo, base).clear_code is False


def test_reads_base_not_working_tree(repo):
    write_config(repo, 'clear_docs = true')  # uncommitted
    assert load_config(repo, "HEAD").clear_docs is False


def test_malformed_config_is_invalid_and_cannot_clear(repo):
    write_config(repo, 'clear_code = ['); commit(repo)
    c = load_config(repo, "HEAD")
    assert not c.valid and c.errors and not c.clear_code and not c.clear_docs


def test_malformed_toml_with_docs_flag_cannot_clear(repo):
    write_config(repo, 'clear_docs = true\n[[[bad'); commit(repo)
    c = load_config(repo, "HEAD")
    assert not c.valid and not c.clear_docs


def test_non_utf8_is_invalid(repo):
    (repo / ".prgate.toml").write_bytes(b'language = "\xff\xfe"'); commit(repo)
    c = load_config(repo, "HEAD")
    assert not c.valid and c.errors


def test_wrong_types_are_invalid(repo):
    write_config(repo, 'stage1_s = "fast"\napprovers = "bob"\nclear_docs = "yes"'); commit(repo)
    c = load_config(repo, "HEAD")
    assert not c.valid and len(c.errors) >= 3 and not c.clear_docs


def test_bool_is_not_an_int(repo):
    write_config(repo, 'stage1_s = true'); commit(repo)
    assert not load_config(repo, "HEAD").valid


def test_unknown_key_is_invalid(repo):
    write_config(repo, 'surprise = 1'); commit(repo)
    c = load_config(repo, "HEAD")
    assert not c.valid and "surprise" in " ".join(c.errors)


def test_config_cannot_remove_tool_paths(repo):
    write_config(repo, 'always_human = []'); commit(repo)
    c = load_config(repo, "HEAD")
    assert ".prgate.toml" in c.always_human and ".github/**" in c.always_human


def test_logins_are_lowercased(repo):
    write_config(repo, 'approvers = ["Alice"]\noverriders = ["BOB"]\nagent_identities = ["Bot[bot]"]'); commit(repo)
    c = load_config(repo, "HEAD")
    assert c.valid and c.approvers == frozenset({"alice"}) and c.overriders == frozenset({"bob"})
    assert c.agent_identities == frozenset({"bot[bot]"})


def test_init_written_config_is_valid(repo):
    write_config(repo, 'mode = "silent"\nclear_docs = true\napprovers = ["a"]\n'
                       'ci_checks = ["test"]\nlanguage = "python"\n'); commit(repo)
    c = load_config(repo, "HEAD")
    assert c.valid and c.clear_docs and c.ci_checks == ("test",) and c.language == "python"


def test_unknown_mode_is_invalid(repo):
    write_config(repo, 'mode = "loud"'); commit(repo)
    assert not load_config(repo, "HEAD").valid


def test_unresolvable_base_is_invalid_not_a_crash(repo):
    c = load_config(repo, "0" * 40)
    assert not c.valid and not c.clear_docs


def test_enforce_is_invalid_in_this_release(repo):
    write_config(repo, 'mode = "enforce"'); commit(repo)
    c = load_config(repo, "HEAD")
    assert not c.valid and "report-only" in " ".join(c.errors)


def test_clear_code_is_invalid_in_this_release(repo):
    write_config(repo, 'clear_code = true'); commit(repo)
    c = load_config(repo, "HEAD")
    assert not c.valid and "later release" in " ".join(c.errors) and not c.clear_code


def test_user_always_human_merges_with_defaults(repo):
    write_config(repo, 'always_human = ["billing/**"]'); commit(repo)
    c = load_config(repo, "HEAD")
    assert c.valid and "billing/**" in c.always_human
    assert all(p in c.always_human for p in ("**/auth/**", "**/payments/**", "**/migrations/**", ".github/**", ".prgate.toml"))


def test_deeply_nested_toml_is_invalid_not_a_crash(repo):
    write_config(repo, 'a=' + '[' * 100000 + ']' * 100000); commit(repo)
    c = load_config(repo, "HEAD")
    assert not c.valid and c.errors and not c.clear_docs and not c.clear_code


def test_parse_config_matches_load_config_on_raw_bytes(repo):
    assert parse_config(None) == Config()
    raw = b'approvers = ["Owner"]\nclear_docs = true\n'
    write_config(repo, raw.decode()); commit(repo)
    assert parse_config(raw) == load_config(repo, "HEAD")
    assert parse_config(raw).approvers == frozenset({"owner"})
    assert not parse_config(b"\xff").valid and not parse_config(b"mode = 'enforce'").valid
