import json

from backend.models.incident import (
    ApprovalStatus,
    Incident,
    IncidentStatus,
    IncidentType,
    PolicyDecision,
    PolicyDecisionType,
)


def test_incident_model_defaults():
    inc = Incident(incident_id="inc-99999", incident_type=IncidentType.HIGH_CPU)
    assert inc.status == IncidentStatus.DETECTED
    assert inc.approval_status == ApprovalStatus.NOT_REQUIRED
    assert inc.execution_status.value == "PENDING"
    assert inc.evidence == []
    assert inc.timeline == []


def test_incident_json_roundtrip():
    inc = Incident(
        incident_id="inc-12345",
        incident_type=IncidentType.SUSPICIOUS_RBAC,
        classification="unauthorised binding",
    )
    inc.add_to_timeline("detected", "falco flagged shell")
    data = json.loads(inc.model_dump_json())
    restored = Incident.model_validate(data)
    assert restored.incident_id == "inc-12345"
    assert restored.incident_type == IncidentType.SUSPICIOUS_RBAC
    assert len(restored.timeline) == 1
    assert restored.timeline[0].step == "detected"


def test_policy_decision_serializable():
    pd = PolicyDecision(
        decision=PolicyDecisionType.APPROVAL_REQUIRED,
        rule_id="P-02",
        action="scale_deployment",
        params={"desired_replicas": 3},
        made_by="policy_engine",
    )
    dumped = pd.model_dump(mode="json")
    assert dumped["decision"] == "APPROVAL_REQUIRED"
    assert dumped["params"]["desired_replicas"] == 3
    assert dumped["made_by"] == "policy_engine"


def test_timeline_touch_advances_updated_at():
    inc = Incident(incident_id="inc-x")
    first = inc.updated_at
    inc.touch()
    assert inc.updated_at >= first