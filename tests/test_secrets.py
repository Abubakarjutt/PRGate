import pytest

from prgate.checks.secrets import KNOWN_EXAMPLES, scan
from prgate.models import FileChange, Severity

AWS = "AKIA" + "Q7ZK3M9TPL2XW4RN"  # built by concatenation so scanners don't flag the repo
LIVE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
GOOGLE = "AIza" + "Sy" + "D3kQ9xLm2Pz7Rv5Tn8Ws1Yb4Ud6Fh0Jc3"
ANTHROPIC = "sk-ant-" + "api03-" + "Zk3Qm9Lp2Xv7Rt5Nw8Ys1Hb4Ud6Fj0Ca3Ge7Ti"
SLACK = "xoxb-" + "1234567890123-" + "9876543210987-" + "Ab3Kq9Zx2Lm7Pv5Rt8Ws1Yc4"
GHP = "ghp_" + "Zk3Qm9Lp2Xv7Rt5Nw8Ys1Hb4Ud6Fj0Ca3GeX"
PEM_HEADER = "-----BEGIN RSA PRIVATE " + "KEY-----"
PEM_END = "-----END RSA PRIVATE " + "KEY-----"
PEM_BODY = "MIIEow" + "IBAAKCAQEA3Zk9Qm2Lp7Xv5Rt8Nw1Ys4Hb6Ud0Fj3Ca7Ge9Ti2Kq5Zx8Lm1Pv4Rs"  # fake, not a key
PEM = PEM_HEADER  # one line, as the line-based tests below scan it
PEM_LINES = (PEM_HEADER, PEM_BODY, PEM_BODY[::-1], PEM_END)


def change(path, added=(), binary=False):
    return FileChange(path, None, "M", tuple(added), 0, binary)


@pytest.mark.parametrize("text", [AWS, LIVE, GOOGLE, ANTHROPIC, SLACK])
def test_real_looking_secret_in_code_is_proof(text):
    assert scan([change("app/a.py", added=((1, text),))]).findings[0].severity == Severity.PROOF


@pytest.mark.parametrize("text", [
    "AKIAIOSFODNN7EXAMPLE", "ghp_" + "a" * 36, "sk_live_" + "x" * 24, "AKIA" + "A" * 15,
    "AKIA" + "0123456789ABCDEF", "AKIA" + "Q7ZK3M9TPL2XW4RN" + "X",
    "xoxb-" + "1234567890123-" + "9876543210987-" + "a" * 24,
    "AIza" + "a" * 35, "sk-ant-" + "api03-" + "b" * 40,
])
def test_examples_repeats_and_bad_lengths_never_block(text):
    assert all(f.severity != Severity.PROOF for f in scan([change("app/a.py", added=((1, text),))]).findings)


def test_known_examples_are_listed():
    assert "AKIAIOSFODNN7EXAMPLE" in KNOWN_EXAMPLES


def test_ghp_without_confirmed_checksum_is_suspicion_not_proof():
    findings = scan([change("app/a.py", added=((1, GHP),))]).findings
    assert [f.severity for f in findings] == [Severity.SUSPICION]


def test_secret_in_fixture_dir_is_only_suspicion():
    assert scan([change("tests/fixtures/k.py", added=((1, AWS),))]).findings[0].severity == Severity.SUSPICION


@pytest.mark.parametrize("d", ["tests", "test", "testdata", "fixtures", "examples"])
def test_each_fixture_dir_downgrades(d):
    assert scan([change(f"{d}/k.py", added=((1, AWS),))]).findings[0].severity == Severity.SUSPICION


def test_placeholder_is_not_a_secret():
    assert not scan([change("a.py", added=((1, 'key = "${API_KEY}"'),))]).findings


def test_unmatched_lines_and_deleted_files_are_quiet():
    assert not scan([change("a.py", added=((1, "x = 1"),))]).findings
    gone = FileChange("a.py", None, "D", (), 3, False)
    assert not scan([gone], lambda p: 1 / 0).findings


def test_binary_flagged_file_has_its_head_blob_scanned():
    blob = b"\x00junk\nk = " + AWS.encode() + b"\n"
    r = scan([change("a.bin", binary=True)], lambda p: blob)
    assert [(f.severity, f.path, f.line) for f in r.findings] == [(Severity.PROOF, "a.bin", 2)]
    assert AWS[8:] not in str(r)


def test_binary_file_that_cannot_be_read_is_an_error_not_a_skip():
    def unreadable(path):
        raise OSError("gone")
    with pytest.raises(OSError):
        scan([change("a.bin", binary=True)], unreadable)
    with pytest.raises(ValueError):
        scan([change("a.bin", binary=True)])


@pytest.mark.parametrize("text", [AWS, LIVE, PEM, GOOGLE, ANTHROPIC, SLACK, GHP])
def test_findings_never_repeat_the_secret(text):
    for path in ("app/a.py", "tests/a.py"):
        r = scan([change(path, added=((7, f'k = "{text}"'),))])
        assert r.findings
        for f in r.findings:
            blob = " ".join(str(v) for v in (f.message, f.question, f.path, f.check, r.detail))
            secret_tail = text[8:] if not text.startswith("-----") else text[12:]
            assert secret_tail not in blob
            assert f.path == path and f.line == 7


def test_lone_surrogate_path_does_not_crash():
    path = "app/\udcff.py"
    r = scan([change(path, added=((1, AWS),))])
    assert r.findings[0].path == path


def added(*lines, start=1):
    return tuple(enumerate(lines, start))


def severities(path, lines):
    return [f.severity for f in scan([change(path, added=lines)]).findings]


def test_full_private_key_block_is_proof():
    findings = scan([change("app/k.py", added=added(*PEM_LINES, start=10))]).findings
    assert [(f.severity, f.line) for f in findings] == [(Severity.PROOF, 10)]


def test_private_key_inside_a_string_literal_is_proof():
    one_line = 'K = "' + "\\n".join(PEM_LINES) + '\\n"'
    assert severities("app/k.py", added(one_line)) == [Severity.PROOF]
    quoted = ['K = (', f'    "{PEM_HEADER}\\n"', f'    "{PEM_BODY}\\n"', f'    "{PEM_END}\\n"', ')']
    assert severities("app/k.py", added(*quoted)) == [Severity.PROOF]


@pytest.mark.parametrize("lines", [
    pytest.param((f'_HEADER = "{PEM_HEADER.replace("RSA", "OPENSSH")}"',), id="header-constant"),
    pytest.param((f"Keys start with `{PEM_HEADER}`.",), id="readme-prose"),
    pytest.param((PEM_HEADER, PEM_END), id="no-body"),
    pytest.param((PEM_HEADER, "short", PEM_END), id="short-body"),
    pytest.param((PEM_HEADER, "is the line a key starts with"), id="prose-after"),
])
def test_private_key_header_without_a_key_body_is_only_suspicion(lines):
    assert severities("src/lib/keys.py", added(*lines)) == [Severity.SUSPICION]


@pytest.mark.parametrize("token", ["AKIAI44QH8DHBEXAMPLE", "AKIAIOSFODNN7EXAMPLE"])
def test_documented_aws_example_keys_never_block(token):
    assert not scan([change("docs/aws.md", added=((1, f"aws_access_key_id = {token}"),))]).findings


def test_realistic_key_with_a_short_last_body_line_is_proof():
    body = [("MIIEpAIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun" + "VTLw7onLRnrq0")[:64]] * 3
    lines = (PEM_HEADER, *body, "Zx8Lm1Pv4Rs=", PEM_END)
    assert severities("app/k.py", added(*lines)) == [Severity.PROOF]


@pytest.mark.parametrize("lines", [
    pytest.param((PEM_HEADER, PEM_BODY), id="no-end"),
    pytest.param((PEM_HEADER, PEM_BODY, PEM_END.replace("RSA", "EC")), id="mismatched-end"),
])
def test_header_followed_by_a_body_stays_proof_without_a_clean_end(lines):
    assert severities("app/k.py", added(*lines)) == [Severity.PROOF]


def test_many_bare_headers_scan_in_linear_time():
    import time
    line = " ".join([PEM_HEADER] * 40)
    started = time.monotonic()
    result = scan([change("app/k.py", added=tuple((i, line) for i in range(1, 1001)))])
    assert time.monotonic() - started < 2.0  # quadratic took ~19 s on 1.2 MiB
    assert {f.severity for f in result.findings} == {Severity.SUSPICION}


def test_header_field_lines_scan_in_linear_time():
    import time
    lines = tuple((i, f"Proc-Type: {PEM_HEADER}") for i in range(1, 20001))
    started = time.monotonic()
    result = scan([change("app/k.py", added=lines)])
    assert time.monotonic() - started < 2.0
    assert {f.severity for f in result.findings} == {Severity.SUSPICION}


def test_many_distinct_labels_on_one_line_scan_in_linear_time():
    import time
    labels = ["".join(chr(65 + (n // 26 ** k) % 26) for k in range(4)) + " PRIVATE " + "KEY"
              for n in range(20000)]
    line = "\\n".join(f"-----BEGIN {label}-----" for label in labels)
    started = time.monotonic()
    result = scan([change("app/k.py", added=((1, line),))])
    assert time.monotonic() - started < 2.0
    assert {f.severity for f in result.findings} == {Severity.SUSPICION}


def test_a_decoy_sharing_dashes_with_a_real_header_cannot_hide_the_key():
    decoy = PEM_HEADER.replace("RSA", "EC")[:-5]  # "-----BEGIN EC PRIVATE KEY" with its dashes shared
    line = f'k = "{decoy}{PEM_HEADER}\\n{PEM_BODY}\\n{PEM_END}"'
    assert Severity.PROOF in severities("app/k.py", added(line))


def test_a_same_label_decoy_sharing_dashes_cannot_hide_the_key():
    line = f'k = "{PEM_HEADER[:-5]}{PEM_HEADER}\\n{PEM_BODY}\\n{PEM_END}"'
    assert severities("app/k.py", added(line)) == [Severity.PROOF]


def test_decoy_header_cannot_hide_a_real_key():
    line = f'K = "{PEM_HEADER} {PEM_HEADER}\\n{PEM_BODY}\\n{PEM_END}"'
    assert Severity.PROOF in severities("app/k.py", added(line))
    split = f'D = "{PEM_HEADER}"; K = "{PEM_HEADER}\\n{PEM_BODY}\\n{PEM_END}"'
    assert Severity.PROOF in severities("app/k.py", added(split))
