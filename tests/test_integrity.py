from prgate.checks.integrity import TestRecord, integrity
from prgate.models import Severity


def rec(key, asserts=1, skipped=False, h="h1", maybe=False):
    return {key: TestRecord(key, asserts, skipped, h, maybe)}


def test_deleted_test_is_proof():
    r = integrity(rec("tests/test_a.py::test_x"), {})
    assert r.findings[0].severity == Severity.PROOF and "tests/test_a.py::test_x" in r.findings[0].message
    assert r.findings[0].message == "test deleted: tests/test_a.py::test_x"


def test_moved_test_is_not_deleted():
    r = integrity(rec("tests/test_a.py::test_x", h="same"), rec("tests/unit/test_a.py::test_x", h="same"))
    assert r.findings and all(f.severity == Severity.INFO for f in r.findings)


def test_moved_and_changed_test_goes_to_person():
    r = integrity(rec("tests/a.py::test_x", h="1"), rec("tests/b.py::test_x", h="2"))
    assert r.findings[0].severity == Severity.SUSPICION and r.findings[0].question
    assert r.findings[0].question == ("Was tests/a.py::test_x moved to tests/b.py::test_x on purpose? "
                                      "Its body changed.")


def test_class_method_matches_on_last_name_component():
    r = integrity(rec("t.py::TestC.test_x", h="1"), rec("u.py::TestD.test_x", h="2"))
    assert r.findings[0].severity == Severity.SUSPICION


def test_empty_hashes_never_count_as_a_move():
    r = integrity(rec("t.py::test_x", h=""), rec("u.py::test_y", h=""))
    assert r.findings[0].severity == Severity.PROOF


def test_one_new_test_cannot_excuse_two_deleted():
    base = {**rec("t.py::test_a", h="same"), **rec("t.py::test_b", h="same")}
    r = integrity(base, rec("u.py::test_a", h="same"))
    assert sorted(f.severity for f in r.findings) == [Severity.INFO, Severity.PROOF]


def test_asserts_to_zero_is_proof_fewer_is_suspicion():
    assert integrity(rec("t::a", asserts=3), rec("t::a", asserts=0)).findings[0].severity == Severity.PROOF
    assert integrity(rec("t::a", asserts=3), rec("t::a", asserts=1)).findings[0].severity == Severity.SUSPICION


def test_new_skip_is_proof():
    r = integrity(rec("t::a"), rec("t::a", skipped=True))
    assert r.findings[0].severity == Severity.PROOF and r.findings[0].message == "test now skipped: t::a"


def test_moved_test_that_is_newly_skipped_is_proof():
    r = integrity(rec("t::a", h="s"), rec("u::a", h="s", skipped=True))
    assert Severity.PROOF in {f.severity for f in r.findings}


def test_unchanged_and_added_tests_are_quiet():
    assert not integrity(rec("t::a"), {**rec("t::a"), **rec("t::b")}).findings
    assert not integrity(rec("t::a", asserts=0), rec("t::a", asserts=0)).findings
    assert not integrity(rec("t::a", skipped=True), rec("t::a", skipped=True)).findings


def test_newly_conditionally_skipped_test_is_suspicion():
    r = integrity(rec("t::a"), rec("t::a", maybe=True))
    assert [(f.severity, f.message) for f in r.findings] == [
        (Severity.SUSPICION, "test may now be skipped: t::a")]


def test_moved_test_that_may_now_be_skipped_is_suspicion():
    r = integrity(rec("t::a", h="s"), rec("u::a", h="s", maybe=True))
    assert "test may now be skipped: u::a" in [f.message for f in r.findings]


def test_already_conditionally_skipped_test_is_quiet():
    assert not integrity(rec("t::a", maybe=True), rec("t::a", maybe=True)).findings


def test_deletion_with_a_new_test_in_the_same_file_is_suspicion():
    r = integrity({**rec("t.py::test_one", h="1"), **rec("t.py::test_two", h="2")}, rec("t.py::test_both", h="3"))
    assert [f.severity for f in r.findings] == [Severity.SUSPICION, Severity.SUSPICION]
    assert all(f.question == f"Was {k} replaced by t.py::test_both?"
               for f, k in zip(r.findings, ["t.py::test_one", "t.py::test_two"]))


def test_new_test_in_the_renamed_file_also_explains_a_deletion():
    r = integrity(rec("a.py::test_x", h="1"), rec("b.py::test_y", h="2"), renamed={"a.py": "b.py"})
    assert r.findings[0].severity == Severity.SUSPICION


def test_body_still_defined_elsewhere_is_suspicion():
    r = integrity(rec("t.py::TestA.test_x", h="body"), {}, head_hashes=frozenset({"body"}))
    assert r.findings[0].severity == Severity.SUSPICION and "may have moved" in r.findings[0].message


def test_deletion_in_an_opaque_file_is_suspicion():
    assert integrity(rec("t.py::test_x"), {}, opaque=frozenset({"t.py"})).findings[0].severity == Severity.SUSPICION
    assert integrity(rec("t.py::test_x"), {}, opaque=frozenset({"u.py"})).findings[0].severity == Severity.PROOF


def test_unsure_assert_count_of_zero_is_suspicion():
    after = {"t::a": TestRecord("t::a", 0, False, "h", False, True)}
    f = integrity(rec("t::a", asserts=2), after).findings[0]
    assert f.severity == Severity.SUSPICION and f.message == "asserts may have been removed: t::a"
