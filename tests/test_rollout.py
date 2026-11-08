from prgate.checks.rollout import rollout_check
from prgate.models import RunStatus, Severity
from test_secrets import change


def test_config_without_rollout_marker_asks():
    r = rollout_check([change("k8s/app.yaml", added=((1, "replicas: 3"),))])
    assert r.status == RunStatus.RAN
    assert r.findings[0].severity == Severity.SUSPICION and "roll" in r.findings[0].question.lower()


def test_config_with_rollout_marker_is_quiet():
    for marker in ("canary: 10", "strategy: RollingUpdate\nmaxUnavailable: 1", "percent: 5", "stage: one", "rollout: x"):
        assert not rollout_check([change("k8s/app.yaml", added=((1, "replicas: 3"), (2, marker)))]).findings


def test_code_and_docs_are_not_config():
    assert not rollout_check([change("src/a.py", added=((1, "x = 1"),)), change("README.md", added=((1, "hi"),))]).findings


def test_config_with_no_added_lines_is_ignored():
    assert not rollout_check([change("k8s/app.yaml")]).findings
