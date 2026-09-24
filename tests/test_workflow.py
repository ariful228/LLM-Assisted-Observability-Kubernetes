import pytest

from backend.services import simulation, store
from backend.workflows.graph import reset_graphs, resume_workflow, run_workflow


@pytest.fixture(autouse=True)
def fresh():
    store.reset_store()
    simulation.reset_simulation()
    reset_graphs()
    yield


@pytest.fixture
def store_obj():
    return store.get_store()


def seed(store_obj, incident_type, resource, severity, trigger=None):
    from backend.models.incident import Incident, IncidentStatus

    inc = Incident(
        incident_id=store_obj.next_incident_id(),
        incident_type=incident_type,
        severity=severity.lower(),
        resource=resource,
        status=IncidentStatus.DETECTED,
        trigger=trigger or {"source": f"{incident_type}-test"},
        classification=f"{incident_type} test incident",
    )
    return store_obj.create(inc)


def test_high_cpu_auto_remediates(store_obj):
    inc = seed(store_obj, "high_cpu", "cpu-demo", "HIGH")
    done = run_workflow(inc.incident_id)
    assert done.status.value == "REMEDIATED"
    assert done.policy_decision.decision.value == "AUTO"
    assert done.execution_status.value == "SUCCESS"
    assert done.execution_result.tool == "scale_deployment"
    assert done.verification_status.value == "PASSED"
    # simulate applied the scale (2 -> 3)
    cpu_demo = next(
        d for d in simulation.kube_deployments("ai-observability-demo") if d["name"] == "cpu-demo"
    )
    assert cpu_demo["replicas"] == 3


@pytest.mark.parametrize(
    "itype,resource,severity,action",
    [
        ("high_memory", "memory-demo", "HIGH", "scale_deployment"),
        ("oom_killed", "memory-demo", "CRITICAL", "scale_deployment"),
        ("crashloop_backoff", "crash-demo", "CRITICAL", "restart_deployment"),
        ("certificate_expiry", "cert-demo", "HIGH", "renew_certificate"),
        ("falco_security", "test-pod", "CRITICAL", "none"),
        ("suspicious_rbac", "ci-bot-cluster-admin", "HIGH", "rollback_rbac"),
    ],
)
def test_non_cpu_incidents_await_approval(store_obj, itype, resource, severity, action):
    inc = seed(store_obj, itype, resource, severity)
    done = run_workflow(inc.incident_id)
    assert done.approval_status.value == "PENDING"
    assert done.status.value == "AWAITING_APPROVAL"
    assert done.policy_decision.decision.value == "APPROVAL_REQUIRED"
    assert done.execution_status.value == "PENDING"


def test_approve_flow_remediates(store_obj):
    inc = seed(store_obj, "crashloop_backoff", "crash-demo", "CRITICAL")
    run_workflow(inc.incident_id)
    done = resume_workflow(inc.incident_id, decision="approve", approved_by="alice")
    assert done.status.value == "REMEDIATED"
    assert done.execution_status.value == "SUCCESS"
    assert done.verification_status.value == "PASSED"
    assert done.approved_by == "alice"


def test_reject_flow_leaves_no_action(store_obj):
    inc = seed(store_obj, "high_memory", "memory-demo", "HIGH")
    run_workflow(inc.incident_id)
    done = resume_workflow(inc.incident_id, decision="reject", approved_by="bob", reason="false positive")
    assert done.status.value == "REJECTED"
    assert done.approval_status.value == "REJECTED"
    assert done.approval_reason == "false positive"
    assert done.execution_status.value in {"PENDING", "SUCCESS", "FAILED"}


def test_approval_twice_is_rejected(store_obj):
    inc = seed(store_obj, "high_memory", "memory-demo", "HIGH")
    run_workflow(inc.incident_id)
    resume_workflow(inc.incident_id, decision="approve", approved_by="alice")
    with pytest.raises(ValueError, match="not awaiting approval"):
        resume_workflow(inc.incident_id, decision="approve", approved_by="alice")


def test_falco_security_is_noop_action(store_obj):
    inc = seed(store_obj, "falco_security", "test-pod", "CRITICAL")
    done = resume_workflow(run_workflow(inc.incident_id).incident_id, decision="approve", approved_by="alice")
    assert done.execution_result.tool == "none"
    assert done.verification_status.value == "PASSED"
    assert done.status.value == "REMEDIATED"