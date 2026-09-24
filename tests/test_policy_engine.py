import pytest

from backend.policy.engine import get_policy_engine
from backend.models.incident import (
    Incident,
    IncidentType,
    PolicyDecisionType,
    RecommendedAction,
)


def make_incident(it: IncidentType, action: str, params: dict | None = None):
    return Incident(
        incident_id="inc-test",
        incident_type=it,
        recommended_action=RecommendedAction(action=action, params=params or {}),
    )


def test_high_cpu_scale_is_automatic():
    pd = get_policy_engine().evaluate(
        make_incident(IncidentType.HIGH_CPU, "scale_deployment", {"desired_replicas": 3, "namespace": "ai-observability-demo", "deployment": "cpu-demo"})
    )
    assert pd.decision == PolicyDecisionType.AUTO
    assert pd.rule_id == "P-01"
    assert pd.auto_allowed is True


@pytest.mark.parametrize(
    "itype,action",
    [
        (IncidentType.HIGH_MEMORY, "scale_deployment"),
        (IncidentType.OOM_KILLED, "scale_deployment"),
        (IncidentType.CRASH_LOOP_BACK_OFF, "restart_deployment"),
        (IncidentType.CERTIFICATE_EXPIRY, "renew_certificate"),
        (IncidentType.FALCO_SECURITY, "none"),
        (IncidentType.SUSPICIOUS_RBAC, "rollback_rbac"),
    ],
)
def test_non_cpu_scenarios_require_approval(itype, action):
    pd = get_policy_engine().evaluate(make_incident(itype, action))
    assert pd.decision == PolicyDecisionType.APPROVAL_REQUIRED


def test_unknown_type_is_no_action():
    pd = get_policy_engine().evaluate(make_incident(IncidentType.UNKNOWN, "scale_deployment"))
    assert pd.decision == PolicyDecisionType.NO_ACTION
    assert pd.rule_id in {"P-99", "P-UNMATCHED"}


def test_high_cpu_but_wrong_action_is_no_action():
    pd = get_policy_engine().evaluate(make_incident(IncidentType.HIGH_CPU, "restart_deployment"))
    assert pd.decision == PolicyDecisionType.NO_ACTION


def test_auto_scale_delta_capped():
    pd = get_policy_engine().evaluate(
        make_incident(IncidentType.HIGH_CPU, "scale_deployment", {"desired_replicas": 99, "deployment": "cpu-demo", "namespace": "ai-observability-demo"})
    )
    assert pd.decision == PolicyDecisionType.NO_ACTION
    assert "-guard" in pd.rule_id


def test_allowlist_rejects_unknown_deployment():
    pd = get_policy_engine().evaluate(
        make_incident(IncidentType.HIGH_CPU, "scale_deployment", {"desired_replicas": 3, "deployment": "diamond-mind", "namespace": "ai-observability-demo"})
    )
    assert pd.decision == PolicyDecisionType.NO_ACTION
    assert "allowlist" in pd.reason


def test_allowlist_rejects_foreign_namespace():
    pd = get_policy_engine().evaluate(
        make_incident(IncidentType.HIGH_CPU, "scale_deployment", {"desired_replicas": 3, "deployment": "cpu-demo", "namespace": "production"})
    )
    assert pd.decision == PolicyDecisionType.NO_ACTION
    assert "namespace" in pd.reason


def test_decision_has_rule_and_made_by():
    pd = get_policy_engine().evaluate(make_incident(IncidentType.SUSPICIOUS_RBAC, "rollback_rbac"))
    assert pd.made_by == "policy_engine"
    assert pd.rule_id == "P-08"