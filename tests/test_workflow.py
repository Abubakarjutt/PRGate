"""The shipped workflow template and action.yml: shape, pinning, permissions, and their shell scripts."""
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

import prgate
from prgate.setup.files import INIT_HEADER, render_workflow
from prgate.templates import ACTION_REF_TOKEN

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src" / "prgate" / "templates" / "pr-gate.yml"
ACTION = ROOT / "action.yml"
REF = "Abubakarjutt/PRGate@v0.1.0"
SHA_REF = re.compile(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}")


# --- a minimal YAML reader for the subset these two files use ---------------------------------

_KEY = re.compile(r"^([\w.-]+):(?:[ \t]+(.*))?$")


def _strip_comment(v):
    if v[:1] in "'\"":
        return v
    return re.split(r"\s+#", v, maxsplit=1)[0].strip()


def _scalar(v):
    v = _strip_comment(v)
    if v[:1] == "'" and v[-1:] == "'":
        return v[1:-1].replace("''", "'")
    if v[:1] == '"' and v[-1:] == '"':
        return json.loads(v)
    if v == "{}":
        return {}
    if v[:1] == "[" and v[-1:] == "]":
        return [_scalar(x.strip()) for x in v[1:-1].split(",") if x.strip()]
    if v in ("true", "false"):
        return v == "true"
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    return v


class _Reader:
    def __init__(self, text):
        self.lines = text.split("\n")
        self.i = 0

    def _skip(self):
        while self.i < len(self.lines) and (not self.lines[self.i].strip()
                                             or self.lines[self.i].lstrip().startswith("#")):
            self.i += 1

    def _peek(self):
        self._skip()
        if self.i >= len(self.lines):
            return None, None
        line = self.lines[self.i]
        return len(line) - len(line.lstrip(" ")), line.strip()

    def node(self, ind):
        _, text = self._peek()
        return self.seq(ind) if text.startswith("- ") else self.map(ind)

    def map(self, ind):
        out = {}
        while True:
            at, text = self._peek()
            if at is None or at < ind or text.startswith("- "):
                return out
            assert at == ind, f"bad indentation at line {self.i + 1}: {text!r}"
            m = _KEY.match(text)
            assert m, f"not a key at line {self.i + 1}: {text!r}"
            assert m[1] not in out, f"duplicate key {m[1]!r}"
            self.i += 1
            out[m[1]] = self.value(m[2] or "", ind)

    def value(self, rest, ind):
        rest = _strip_comment(rest)
        if rest in ("|", "|-", ">", ">-"):
            return self.block(rest, ind)
        if rest:
            return _scalar(rest)
        at, text = self._peek()
        if at is not None and (at > ind or (at == ind and text.startswith("- "))):
            return self.node(at)
        return None

    def block(self, style, ind):
        body = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip() and len(line) - len(line.lstrip(" ")) <= ind:
                break
            body.append(line)
            self.i += 1
        while body and not body[-1].strip():
            body.pop()
        cut = min(len(x) - len(x.lstrip(" ")) for x in body if x.strip())
        body = [x[cut:] for x in body]
        if style.startswith(">"):
            return " ".join(x.strip() for x in body)
        return "\n".join(body) + ("" if style.endswith("-") else "\n")

    def seq(self, ind):
        out = []
        while True:
            at, text = self._peek()
            if at != ind or not text.startswith("- "):
                return out
            item = text[2:]
            if _KEY.match(item):
                self.lines[self.i] = " " * (ind + 2) + item
                out.append(self.map(ind + 2))
            else:
                self.i += 1
                out.append(_scalar(item))


def load(text):
    r = _Reader(text)
    doc = r.map(0)
    assert r._peek() == (None, None), f"unparsed text at line {r.i + 1}"
    return doc


def workflow(text):
    return load(text)


def workflow_jobs(text):
    return workflow(text)["jobs"]


def uses_lines(text):
    return [m.group(1) for m in re.finditer(r"^\s*(?:-\s+)?uses:\s+(\S+)", text, re.M)]


def steps(job):
    return job["steps"]


def run_scripts(doc):
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == "run":
                yield v
            else:
                yield from run_scripts(v)
    elif isinstance(doc, list):
        for v in doc:
            yield from run_scripts(v)


@pytest.fixture
def wf():
    return workflow(render_workflow(REF))


# --- the template -----------------------------------------------------------------------------

def test_template_ships_inside_the_package_with_the_ref_token():
    raw = TEMPLATE.read_text()
    assert ACTION_REF_TOKEN == "__PRGATE_ACTION_REF__" and raw.count(ACTION_REF_TOKEN) == 2
    rendered = render_workflow(REF)
    assert ACTION_REF_TOKEN not in rendered and rendered == INIT_HEADER + "\n" + raw.replace(ACTION_REF_TOKEN, REF)


@pytest.mark.parametrize("bad", ["", "x", "x/y", "x/y@", "x/y@v1\nrun: id", "x/y@v1 # c", "x/y@$(id)",
                                 "./local", "x/y/z@v1", "x/y@v1'", None])
def test_render_refuses_unsafe_action_refs(bad):
    with pytest.raises(ValueError):
        render_workflow(bad)


def test_rendering_is_deterministic():
    assert render_workflow(REF) == render_workflow(REF)


def test_triggers_are_base_branch_events_only(wf):
    assert wf["on"] == {"pull_request_target": {"types": ["opened", "synchronize", "reopened"]},
                        "issue_comment": {"types": ["created"]}}


def test_top_level_permissions_are_empty_and_each_job_declares_its_own(wf):
    assert wf["permissions"] == {}
    assert set(wf["jobs"]) == {"stage1", "verdict"}
    assert wf["jobs"]["stage1"]["permissions"] == {"contents": "read"}
    assert wf["jobs"]["verdict"]["permissions"] == {}


def test_stage1_job_holds_no_secrets_and_runs_no_pr_code():
    jobs = workflow_jobs(render_workflow("Abubakarjutt/PRGate@v0.1.0"))
    s1 = jobs["stage1"]
    assert "environment" not in s1 and "secrets." not in json.dumps(s1)
    text = json.dumps(s1)
    for bad in ("pip install .", "pip install -e", "python -m pytest", "npm ", "make "):
        assert bad not in text


def test_verdict_job_never_checks_out_pr_head():
    v = json.dumps(workflow_jobs(render_workflow("Abubakarjutt/PRGate@v0.1.0"))["verdict"])
    assert "actions/checkout" not in v


def test_all_actions_pinned_by_sha():
    for ref in uses_lines(render_workflow("x/y@v0.1.0")):
        assert ref.startswith("x/y@") or re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref)


def test_every_pinned_action_carries_a_version_comment():
    for text in (TEMPLATE.read_text(), ACTION.read_text()):
        for line in text.splitlines():
            m = re.match(r"^\s*(?:-\s+)?uses:\s+(\S+)(.*)$", line)
            if m and SHA_REF.fullmatch(m[1]):
                assert re.fullmatch(r"\s+# v\d+\.\d+\.\d+", m[2]), line


def test_stage1_job_shape(wf):
    s1 = wf["jobs"]["stage1"]
    assert s1["if"] == "github.event_name == 'pull_request_target'"
    assert s1["timeout-minutes"] == 5
    checkout = next(s for s in steps(s1) if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"
    gate = next(s for s in steps(s1) if s.get("uses") == REF)
    assert gate["with"] == {"mode": "stage1"} and "env" not in gate
    up = next(s for s in steps(s1) if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert up["if"] == "always()" and up["with"]["name"] == "prgate-stage1"
    assert up["with"]["path"] == "prgate-stage1.json"


def test_verdict_job_shape(wf):
    v = wf["jobs"]["verdict"]
    assert v["environment"] == "prgate-verdict" and v["timeout-minutes"] == 10
    assert v["needs"] == "stage1" and v["if"].startswith("always() && ")
    token = next(s for s in steps(v) if s.get("uses", "").startswith("actions/create-github-app-token@"))
    assert token["with"]["app-id"] == "${{ secrets.PRGATE_APP_ID }}"
    assert token["with"]["private-key"] == "${{ secrets.PRGATE_APP_KEY }}"
    assert {k: x for k, x in token["with"].items() if k.startswith("permission-")} == {
        "permission-checks": "write", "permission-contents": "read", "permission-pull-requests": "read"}
    down = next(s for s in steps(v) if s.get("uses", "").startswith("actions/download-artifact@"))
    assert down["if"] == "github.event_name == 'pull_request_target'" and down["with"]["name"] == "prgate-stage1"
    assert token["id"] == "app"


def test_comment_runs_reach_only_the_verdict_job_with_an_override(wf):
    cond = wf["jobs"]["verdict"]["if"]
    assert "github.event.issue.pull_request" in cond and "startsWith(github.event.comment.body, '/gate override ')" in cond
    assert "issue_comment" not in json.dumps(wf["jobs"]["stage1"]).replace(
        "github.event_name == 'pull_request_target'", "")


def test_no_expression_is_interpolated_into_a_shell_script(wf):
    scripts = list(run_scripts(wf)) + list(run_scripts(load(ACTION.read_text())))
    assert scripts
    for script in scripts:
        assert "${{" not in script


def test_untrusted_event_fields_are_never_used(wf):
    text = render_workflow(REF)
    for field in ("pull_request.title", "pull_request.body", "head_ref", "head.ref", "head.label",
                  "comment.body }}", "issue.title", "issue.body", "commits", "author"):
        assert field not in text


def test_each_job_has_a_per_pr_concurrency_group(wf):
    for name, job in wf["jobs"].items():
        group = job["concurrency"]["group"]
        assert "github.event.pull_request.number" in group, name
    assert "github.event.issue.number" in wf["jobs"]["verdict"]["concurrency"]["group"]
    assert wf["jobs"]["verdict"]["concurrency"]["cancel-in-progress"] is False


def test_only_the_verdict_job_names_the_verdict_environment():
    assert render_workflow(REF).count("prgate-verdict") == 1


def test_template_agrees_with_pyyaml_when_it_is_installed():
    yaml = pytest.importorskip("yaml")
    for text in (render_workflow(REF), ACTION.read_text()):
        theirs = yaml.safe_load(text)
        if True in theirs:  # YAML 1.1 reads the key `on` as a boolean
            theirs["on"] = theirs.pop(True)
        assert theirs == load(text)


# --- action.yml -------------------------------------------------------------------------------

@pytest.fixture
def action():
    return load(ACTION.read_text())


def test_action_is_composite_with_its_inputs(action):
    assert action["runs"]["using"] == "composite"
    assert set(action["inputs"]) == {"mode", "index-url", "token", "app-slug"}
    assert action["inputs"]["mode"]["required"] is True
    assert action["inputs"]["index-url"]["default"] == "https://pypi.org/simple"
    py = next(s for s in action["runs"]["steps"] if s.get("uses", "").startswith("actions/setup-python@"))
    assert SHA_REF.fullmatch(py["uses"]) and py["with"]["python-version"] == "3.12"


REQUIREMENTS = ROOT / "action-requirements.txt"


def test_action_requirements_pin_this_version_by_hash():
    lines = [x for x in REQUIREMENTS.read_text().splitlines() if x.strip() and not x.lstrip().startswith("#")]
    assert len(lines) == 1
    assert re.fullmatch(rf"prgate=={re.escape(prgate.__version__)} --hash=sha256:[0-9a-f]{{64}}", lines[0])
    assert prgate.__version__ == "0.0.1"


def test_action_installs_only_from_the_hashed_requirements_file(action):
    text = ACTION.read_text()
    assert "prgate==" not in text
    install = _step(action, "pip install")
    assert install["shell"] == "bash"
    assert install["env"] == {"PRGATE_MODE": "${{ inputs.mode }}", "PRGATE_INDEX_URL": "${{ inputs.index-url }}"}
    for part in ("--require-hashes", "--no-deps", "--only-binary=:all:", '--index-url "$PRGATE_INDEX_URL"',
                 '-r "$GITHUB_ACTION_PATH/action-requirements.txt"', "env -u PRGATE_TOKEN", "-I -m pip"):
        assert part in install["run"], part


def _step(action, needle):
    [step] = [s for s in action["runs"]["steps"] if needle in s.get("run", "")]
    return step


def _token_refs(doc, needle):
    """Paths (as tuples) of every string in `doc` containing `needle`."""
    if isinstance(doc, dict):
        return [(k, *p) for k, v in doc.items() for p in _token_refs(v, needle)]
    if isinstance(doc, list):
        return [(i, *p) for i, v in enumerate(doc) for p in _token_refs(v, needle)]
    return [()] if isinstance(doc, str) and needle in doc else []


def test_the_app_token_reaches_only_the_step_that_runs_prgate(wf, action):
    # Template: the token output is used once, as the prgate action's `token` input; no env carries it.
    v = wf["jobs"]["verdict"]
    gate_i = next(i for i, s in enumerate(steps(v)) if s.get("uses") == REF)
    assert _token_refs(wf, ".outputs.token") == [("jobs", "verdict", "steps", gate_i, "with", "token")]
    assert "env" not in wf and all("env" not in job for job in wf["jobs"].values())
    assert "env" not in steps(v)[gate_i]
    # action.yml: only the final run step's env holds the token; setup-python and pip never see it.
    run_i = action["runs"]["steps"].index(_step(action, "/bin/prgate"))
    assert run_i == len(action["runs"]["steps"]) - 1
    assert _token_refs(action, "inputs.token") == [("runs", "steps", run_i, "env", "PRGATE_TOKEN")]
    assert "env" not in action and "env" not in action["runs"]
    assert "PRGATE_TOKEN" not in ACTION.read_text().replace("env -u PRGATE_TOKEN", "").replace(
        "PRGATE_TOKEN: ${{ inputs.token }}", "")


def test_verdict_step_passes_the_token_and_slug_as_inputs(wf):
    v = wf["jobs"]["verdict"]
    token = next(s for s in steps(v) if s.get("uses", "").startswith("actions/create-github-app-token@"))
    gate = next(s for s in steps(v) if s.get("uses") == REF)
    assert gate["with"] == {"mode": "${{ github.event_name == 'issue_comment' && 'command' || 'verdict' }}",
                            "token": f"${{{{ steps.{token['id']}.outputs.token }}}}",
                            "app-slug": f"${{{{ steps.{token['id']}.outputs.app-slug }}}}"}


def _fake_bin(tmp_path):
    """A `python` whose `-m venv DIR` makes DIR/bin/{python,prgate}; every call logs argv and the token."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "log"
    recorder = (f'#!/bin/sh\nprintf "%s|token=%s|slug=%s\\n" "$(basename "$0") $*" "${{PRGATE_TOKEN:-}}" '
                f'"${{PRGATE_APP_SLUG:-}}" >> "{log}"\n')
    venv = (recorder + 'if [ "$2" = "-m" ] && [ "$3" = "venv" ]; then mkdir -p "$4/bin";'
            f' cp "{bin_dir}/rec" "$4/bin/python"; cp "{bin_dir}/rec" "$4/bin/prgate"; fi\n')
    for name, body in (("python", venv), ("rec", recorder)):
        p = bin_dir / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return bin_dir, log


def _run_action(tmp_path, action, mode, index="https://pypi.org/simple"):
    """Run each run-step in order, with only the env that step declares (inputs substituted), as the runner does."""
    bin_dir, log = _fake_bin(tmp_path)
    inputs = {"mode": mode, "index-url": index, "token": "tok-SECRET", "app-slug": "gate-app"}
    out, code = "", 0
    for step in action["runs"]["steps"]:
        if "run" not in step:
            continue
        env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "RUNNER_TEMP": str(tmp_path / "tmp"),
               "GITHUB_ACTION_PATH": str(ROOT)}
        for k, expr in step.get("env", {}).items():
            m = re.fullmatch(r"\$\{\{ inputs\.([\w-]+) \}\}", expr)
            assert m, expr
            env[k] = inputs[m[1]]
        r = subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True, cwd=tmp_path)
        out += r.stdout + r.stderr
        code = r.returncode
        if code:
            break
    return code, out, (log.read_text().splitlines() if log.exists() else [])


def test_action_script_installs_without_the_token_then_runs_the_mode(tmp_path, action):
    code, out, calls = _run_action(tmp_path, action, "verdict")
    assert code == 0, out
    venv, pip, gate = calls
    assert venv.startswith("python -I -m venv ") and venv.endswith("|token=|slug=")
    assert pip.startswith("python -I -m pip install ") and pip.endswith("|token=|slug=")
    assert "--require-hashes" in pip and "--no-deps" in pip and "--index-url https://pypi.org/simple " in pip
    assert f"-r {ROOT}/action-requirements.txt" in pip and "prgate==" not in pip
    assert gate == "prgate verdict|token=tok-SECRET|slug=gate-app"
    assert "tok-SECRET" not in out


@pytest.mark.parametrize("mode", ["execute", "", "stage1; id", "--help", "verdict\n"])
def test_action_script_refuses_unknown_modes_before_installing(tmp_path, action, mode):
    code, _, calls = _run_action(tmp_path, action, mode)
    assert code == 2 and calls == []


@pytest.mark.parametrize("index", ["http://pypi.org/simple", "file:///x", "", "-r x"])
def test_action_script_refuses_non_https_indexes(tmp_path, action, index):
    code, _, calls = _run_action(tmp_path, action, "stage1", index)
    assert code == 2 and calls == []


def test_action_script_passes_a_test_index_through_as_one_argument(tmp_path, action):
    code, _, calls = _run_action(tmp_path, action, "stage1", "https://test.pypi.org/simple/")
    assert code == 0 and "--index-url https://test.pypi.org/simple/ " in calls[1]


# --- the stage 1 fetch script -----------------------------------------------------------------

def _run_fetch(tmp_path, wf, head):
    script = next(s for s in steps(wf["jobs"]["stage1"]) if "run" in s)["run"]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "git.log"
    git = bin_dir / "git"
    git.write_text(f'#!/bin/sh\nprintf "argv=%s\\nconfig=%s=%s\\n" "$*" "${{GIT_CONFIG_KEY_0:-}}" '
                   f'"${{GIT_CONFIG_VALUE_0:-}}" >> "{log}"\n')
    git.chmod(git.stat().st_mode | stat.S_IEXEC)
    step = next(s for s in steps(wf["jobs"]["stage1"]) if "run" in s)
    assert step["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert step["env"]["FETCH_TOKEN"] == "${{ github.token }}"
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HEAD_SHA": head, "FETCH_TOKEN": "tok-SECRET",
           "GITHUB_SERVER_URL": "https://github.com"}
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, cwd=tmp_path)
    return r, (log.read_text() if log.exists() else "")


@pytest.mark.parametrize("head", ["", "main", "a" * 39, "A" * 40, "$(touch pwned)", "--upload-pack=touch x",
                                  "a" * 40 + "\nb"])
def test_fetch_script_refuses_anything_but_a_full_sha(tmp_path, wf, head):
    r, log = _run_fetch(tmp_path, wf, head)
    assert r.returncode != 0 and log == "" and not (tmp_path / "pwned").exists()


def test_fetch_script_keeps_the_token_out_of_argv_and_output(tmp_path, wf):
    import base64

    r, log = _run_fetch(tmp_path, wf, "a" * 40)
    assert r.returncode == 0, r.stderr
    assert "tok-SECRET" not in log and "tok-SECRET" not in r.stdout + r.stderr
    encoded = base64.b64encode(b"x-access-token:tok-SECRET").decode()
    assert f"argv=fetch --no-tags --no-recurse-submodules origin {'a' * 40}" in log
    assert f"config=http.https://github.com/.extraheader=AUTHORIZATION: basic {encoded}" in log
    # the only line that names the encoded value is the mask command itself
    assert [x for x in r.stdout.splitlines() if encoded in x] == [f"::add-mask::{encoded}"]
