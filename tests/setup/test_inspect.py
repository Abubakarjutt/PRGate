import pytest


from prgate.setup.run import doctor
from prgate.setup.state import LocalState
from tests.setup.fakes import FakeGh, ScriptedPrompter


def test_doctor_writes_nothing(tmp_path):
    gh = FakeGh.fully_set_up()
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 0 and gh.writes == []
    assert p.said[0].endswith("is experimental and report-only.")


def test_doctor_names_each_missing_piece_with_a_fix(tmp_path):
    gh = FakeGh.fully_set_up(); del gh.environments["prgate-verdict"]
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1
    assert any("prgate-verdict" in s and "prgate init" in s for s in p.said)


def test_doctor_reports_missing_secrets(tmp_path):
    gh = FakeGh.fully_set_up(); gh.secrets["prgate-verdict"] = {"PRGATE_APP_ID"}
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1
    assert any("PRGATE_APP_KEY" in s and "prgate init" in s for s in p.said)


def test_doctor_reports_an_app_that_is_gone(tmp_path):
    gh = FakeGh.fully_set_up()
    LocalState(55, "prgate-r-gone00").save("o/r", tmp_path)
    assert doctor(gh, "o/r", ScriptedPrompter({}), home=tmp_path) == 0  # falls back to the owner-verified install
    gh.installations.clear()
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1
    assert any("prgate-r-gone00" in s for s in p.said)


def test_doctor_reports_a_workflow_safety_refusal(tmp_path):
    gh = FakeGh.fully_set_up(); gh.contents[".github/workflows/x.yml"] = "environment: prgate-verdict\n"
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1
    assert any("x.yml" in s and "prgate-verdict" in s for s in p.said)


def test_doctor_prints_workflow_warnings(tmp_path):
    gh = FakeGh.fully_set_up()
    gh.contents[".github/workflows/d.yml"] = "jobs:\n  d:\n    environment: ${{ inputs.e }}\n"
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 0
    assert any("d.yml" in s and "expression" in s for s in p.said)


def test_doctor_reports_an_edited_workflow(tmp_path):
    gh = FakeGh.fully_set_up(); gh.contents[".github/workflows/pr-gate.yml"] += "# edited\n"
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1
    assert any("pr-gate.yml" in s and "differs" in s for s in p.said)


def test_doctor_reports_an_invalid_config(tmp_path):
    gh = FakeGh.fully_set_up(); gh.contents[".prgate.toml"] = 'mode = "enforce"\n'
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1
    assert any(".prgate.toml" in s for s in p.said)


def test_doctor_on_a_free_private_repo_reports_preflight(tmp_path):
    gh = FakeGh.fully_set_up(private=True, plan="free")
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1 and gh.writes == []
    assert any("free plan" in s for s in p.said)


def test_doctor_does_not_trust_a_foreign_prgate_app(tmp_path):
    gh = FakeGh.fully_set_up()
    gh.apps["prgate"]["owner"] = {"login": "mallory", "id": 99, "type": "User"}
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1
    assert any(s.startswith("gate_app: NOT OK") for s in p.said)


def test_doctor_names_several_owned_prgate_apps(tmp_path):
    gh = FakeGh.fully_set_up()
    gh.add_app("prgate-r-bbbbbb", 3)
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path) == 1
    assert any(s.startswith("gate_app: NOT OK") and "prgate-r-bbbbbb" in s for s in p.said)


def _pinned(gh, ref):
    from prgate.setup.files import render_workflow
    gh.contents[".github/workflows/pr-gate.yml"] = render_workflow(ref)


def test_doctor_accepts_an_older_pinned_release_with_an_update_warning(tmp_path):
    gh = FakeGh.fully_set_up()
    _pinned(gh, "Abubakarjutt/PRGate@v0.0.0")
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path, action_ref="Abubakarjutt/PRGate@v0.1.1") == 0
    assert any(s.startswith("warning:") and "v0.0.0" in s and "v0.1.1" in s and "prgate init" in s for s in p.said)
    assert not any("NOT OK" in s for s in p.said)


@pytest.mark.parametrize("ref", ["Abubakarjutt/PRGate@v0.2.0", "someone/Fork@v0.0.0", "Abubakarjutt/PRGate@main"])
def test_doctor_still_refuses_newer_foreign_or_unversioned_pins(tmp_path, ref):
    gh = FakeGh.fully_set_up()
    _pinned(gh, ref)
    p = ScriptedPrompter({})
    assert doctor(gh, "o/r", p, home=tmp_path, action_ref="Abubakarjutt/PRGate@v0.1.1") == 1
    assert any("pr-gate.yml" in s and "differs" in s for s in p.said)


def test_doctor_refuses_an_older_pin_that_was_also_edited(tmp_path):
    gh = FakeGh.fully_set_up()
    _pinned(gh, "Abubakarjutt/PRGate@v0.0.0")
    gh.contents[".github/workflows/pr-gate.yml"] += "# edited\n"
    assert doctor(gh, "o/r", ScriptedPrompter({}), home=tmp_path, action_ref="Abubakarjutt/PRGate@v0.1.1") == 1
