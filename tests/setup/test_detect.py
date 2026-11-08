from prgate.setup.detect import ProjectGuess, detect_project, suggest_ci_checks
from tests.setup.fakes import FakeGh


def write(root, name, text):
    (root / name).write_text(text)


def test_python_project(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    g = detect_project(tmp_path)
    assert g.language == "python" and g.image == "python:3.12-slim" and g.unsure == ()
    assert g.install_command == "pip install --target /work/.deps /work pytest"
    assert g.test_command == "PYTHONPATH=/work/.deps python -m pytest -q -p no:cacheprovider --junitxml=/work/.prgate/junit.xml"
    assert g.junit_path == "/work/.prgate/junit.xml"


def test_setup_py_and_setup_cfg_are_python(tmp_path):
    write(tmp_path, "setup.py", "")
    assert detect_project(tmp_path).language == "python"
    other = tmp_path / "b"
    other.mkdir()
    write(other, "setup.cfg", "")
    assert detect_project(other).language == "python"


def test_typescript_is_detected_but_not_configured(tmp_path):
    write(tmp_path, "package.json", '{"devDependencies":{"typescript":"5"}}')
    g = detect_project(tmp_path)
    assert g.language == "typescript" and g.test_command is None
    assert g.image is None and g.install_command is None and g.junit_path is None


def test_tsconfig_alone_is_typescript(tmp_path):
    write(tmp_path, "tsconfig.json", "{}")
    assert detect_project(tmp_path).language == "typescript"


def test_two_languages_at_root_is_unsure(tmp_path):
    write(tmp_path, "pyproject.toml", "[project]\nname='x'\n")
    write(tmp_path, "package.json", '{"devDependencies":{"typescript":"5"}}')
    assert "language" in detect_project(tmp_path).unsure


def test_empty_repo_is_unsure_about_everything(tmp_path):
    g = detect_project(tmp_path)
    assert g.language is None
    assert set(g.unsure) >= {"language", "test_command"}


def test_malformed_pyproject_does_not_crash(tmp_path):
    write(tmp_path, "pyproject.toml", "[project\nname=")
    g = detect_project(tmp_path)
    assert isinstance(g, ProjectGuess) and "language" in g.unsure


def test_malformed_package_json_does_not_crash(tmp_path):
    write(tmp_path, "package.json", "{not json")
    g = detect_project(tmp_path)
    assert g.language is None and "language" in g.unsure
    write(tmp_path, "package.json", "[1]")
    assert "language" in detect_project(tmp_path).unsure


def test_malformed_package_json_with_tsconfig_still_typescript(tmp_path):
    write(tmp_path, "package.json", "{not json")
    write(tmp_path, "tsconfig.json", "{}")
    assert detect_project(tmp_path).language == "typescript"


def test_plain_package_json_without_typescript_is_unsure(tmp_path):
    write(tmp_path, "package.json", '{"dependencies":{"left-pad":"1"}}')
    assert "language" in detect_project(tmp_path).unsure


def test_ci_checks_only_those_on_every_commit():
    gh = FakeGh(check_runs={"c1": ["lint", "test", "pr-gate"], "c2": ["test", "pr-gate"]})
    assert suggest_ci_checks(gh, "o/r", "main", commits=2) == ("test",)


def test_ci_checks_are_sorted_and_limited_to_n_commits():
    gh = FakeGh(check_runs={"c1": ["b", "a", "pr-gate"], "c2": ["a", "b"], "c3": ["zzz"]})
    assert suggest_ci_checks(gh, "o/r", "main", commits=2) == ("a", "b")


def test_ci_checks_no_commits_gives_empty():
    assert suggest_ci_checks(FakeGh(), "o/r", "main") == ()


def test_ci_checks_api_error_gives_empty():
    gh = FakeGh(check_runs={"c1": ["a"]}, fail_once={("GET", "repos/o/r/commits/c1/check-runs?per_page=100"): 500})
    assert suggest_ci_checks(gh, "o/r", "main", commits=1) == ()


def test_ci_checks_fewer_commits_than_requested():
    gh = FakeGh(check_runs={"c1": ["a", "b"], "c2": ["a"]})
    assert suggest_ci_checks(gh, "o/r", "main", commits=10) == ("a",)


def test_ci_checks_quotes_branch():
    seen = []

    class Spy(FakeGh):
        def api(self, method, path, body=None):
            seen.append(path)
            return super().api(method, path, body)

    suggest_ci_checks(Spy(default_branch="feat#1&x", check_runs={"c1": ["a"]}), "o/r", "feat#1&x", commits=1)
    assert seen[0] == "repos/o/r/commits?sha=feat%231%26x&per_page=1"


def test_ci_checks_clamps_commits():
    seen = []

    class Spy(FakeGh):
        def api(self, method, path, body=None):
            seen.append(path)
            return super().api(method, path, body)

    suggest_ci_checks(Spy(), "o/r", "main", commits=0)
    suggest_ci_checks(Spy(), "o/r", "main", commits=5000)
    assert seen[0].endswith("per_page=1") and seen[1].endswith("per_page=100")


def test_oversized_package_json_is_unsure(tmp_path):
    write(tmp_path, "package.json", '{"devDependencies":{"typescript":"5"},"x":"' + "a" * (2 * 1024 * 1024) + '"}')
    g = detect_project(tmp_path)
    assert g.language is None and "language" in g.unsure


def test_deeply_nested_package_json_is_unsure(tmp_path):
    write(tmp_path, "package.json", "[" * 200000)
    assert "language" in detect_project(tmp_path).unsure


def test_deeply_nested_pyproject_is_unsure(tmp_path):
    write(tmp_path, "pyproject.toml", "a = " + "[" * 200000)
    g = detect_project(tmp_path)
    assert g.language is None and "language" in g.unsure


def test_symlinked_manifest_is_not_followed(tmp_path):
    real = tmp_path / "real.toml"
    real.write_text("[project]\nname='x'\n")
    (tmp_path / "pyproject.toml").symlink_to(real)
    g = detect_project(tmp_path)
    assert g.language is None and "language" in g.unsure


def test_symlinked_setup_py_is_unsure(tmp_path):
    (tmp_path / "real.py").write_text("")
    (tmp_path / "setup.py").symlink_to(tmp_path / "real.py")
    assert detect_project(tmp_path).language is None


def test_directory_named_pyproject_is_unsure(tmp_path):
    (tmp_path / "pyproject.toml").mkdir()
    g = detect_project(tmp_path)
    assert g.language is None and "language" in g.unsure


def test_unparseable_pyproject_with_typescript_is_unsure(tmp_path):
    write(tmp_path, "pyproject.toml", "[project\nname=")
    write(tmp_path, "tsconfig.json", "{}")
    g = detect_project(tmp_path)
    assert g.language is None and "language" in g.unsure
