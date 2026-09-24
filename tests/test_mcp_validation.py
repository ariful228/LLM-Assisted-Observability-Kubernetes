import pytest

from backend.mcp.registry import get_registry, reset_registry
from backend.mcp.validator import ValidationError, validate
from backend.models.incident import ExecutionStatus, Incident, IncidentType
from backend.policy.engine import get_policy_engine
from backend.models.incident import PolicyDecision


@pytest.fixture(autouse=True)
def fresh_registry():
    reset_registry()
    yield
    reset_registry()


def test_registered_tools_are_valid():
    tools = get_registry().list()
    assert len(tools) >= 15
    names = {t["name"] for t in tools}
    for expected in ("get_pods", "get_pod_logs", "get_pod_events", "get_deployment", "get_nodes", "get_certificate_status", "query_prometheus", "search_opensearch", "search_audit_logs", "search_falco_events", "get_rbac"):
        assert expected in names, f"missing read tool {expected}"
    for expected in ("scale_deployment", "restart_deployment", "renew_certificate", "rollback_rbac"):
        assert expected in names, f"missing action tool {expected}"
    for t in tools:
        assert t["kind"] in {"read", "action"}


def test_action_tools_require_policy():
    reg = get_registry()
    for name in ("scale_deployment", "restart_deployment", "renew_certificate", "rollback_rbac"):
        t = reg.get(name)
        assert t.kind == "action"
        assert t.requires_policy is True


def test_no_unsafe_tools(current_no_unsafe=True):
    policy = get_policy_engine()
    reg = get_registry()
    unsafe = []
    for t in reg.list():
        name = t["name"]
        if t["kind"] == "read":
            continue
        td = reg.get(name)
        sig = td.impl.__code__.co_varnames
        if any(k in ("shell", "kubectl", "os", "subprocess") for k in sig):
            unsafe.append(name)
    assert unsafe == []


def test_validator_rejects_bad_types():
    schema = {
        "type": "object",
        "properties": {"replicas": {"type": "integer", "description": "count"}},
        "required": ["replicas"],
    }
    with pytest.raises(ValidationError):
        validate(schema, {"replicas": "three"})
    assert validate(schema, {"replicas": 3}) is None


def test_validator_required_is_only_non_default():
    schema = {
        "type": "object",
        "properties": {
            "namespace": {"type": "string", "default": ""},
            "deployment": {"type": "string"},
        },
        "required": ["deployment"],
    }
    # namespace is optional (has default); {} missing namespace is fine
    assert validate(schema, {"deployment": "cpu-demo"}) is None
    with pytest.raises(ValidationError):
        validate(schema, {})


def test_action_tool_execution_requires_authorization():
    reg = get_registry()
    inc = Incident(incident_id="inc-x", incident_type=IncidentType.HIGH_CPU)
    policy = PolicyDecision(
        decision=get_policy_engine().evaluate(
            Incident(incident_id="inc-x", incident_type=IncidentType.HIGH_CPU)
        ).decision,
        rule_id="P-01",
        action="scale_deployment",
    )
    # no approval for an APPROVAL_REQUIRED policy -> refused
    bad_policy = PolicyDecision(rule_id="P-02", action="scale_deployment")
    args = {"deployment": "cpu-demo", "desired_replicas": 3, "namespace": "ai-observability-demo", "delta": 1}
    result = reg.execute(inc, "scale_deployment", args, policy=bad_policy, approved=False, executor="system")
    assert result.status == ExecutionStatus.FAILED
    assert "approval" in result.error.lower() or "policy" in result.error.lower()


def test_unknown_tool_raises():
    with pytest.raises(KeyError):
        get_registry().execute(Incident(incident_id="x"), "rm -rf /", {}, executor="system")


def test_metadata_logging():
    reg = get_registry()
    result = reg.execute(Incident(incident_id="inc-m"), "get_pods", {"namespace": "ai-observability-demo"}, executor="agent")
    assert result.status == ExecutionStatus.SUCCESS
    assert result.metadata["executor"] == "agent"
    assert result.tool == "get_pods"