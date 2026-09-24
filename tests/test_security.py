from backend.models.incident import (
    FindingStatus,
    PolicyDecisionType,
    SecurityLayer,
    VerificationStatus,
)
from backend.services import security, simulation
from backend.workflows.graph import reset_graphs


def _reset():
    simulation.reset_simulation()
    security.reset_findings()
    reset_graphs()


def test_seed_covers_all_four_layers():
    _reset()
    layers = {f.layer.value for f in security.list_findings()}
    assert layers == {layer.value for layer in SecurityLayer}
    assert len(security.list_findings()) >= 7


def test_seed_findings_are_simulated_and_structured():
    _reset()
    for f in security.list_findings():
        assert f.simulated is True
        assert f.issue
        assert f.severity.value in {"critical", "high", "medium", "low"}
        assert f.evidence
        assert f.affected_resource
        assert f.root_cause
        assert f.recommended_solution
        assert f.recommended_action
        assert f.remediation_status in {"not_started", "in_progress", "complete"}
        assert f.status.value


def test_states_resolved_by_pipeline():
    _reset()
    findings = security.list_findings()
    auto = [f for f in findings if f.decision == PolicyDecisionType.AUTO]
    pending = [f for f in findings if f.status == FindingStatus.AWAITING_APPROVAL]
    assert auto, "expected at least one auto-remediated application finding"
    assert all(f.verification_status == VerificationStatus.PASSED for f in auto)
    assert pending, "expected approval-required findings"
    assert all(not f.approval_required for f in auto)
    assert all(f.approval_required for f in pending)


def test_finding_decision_remediates_and_verifies():
    _reset()
    pending = [f for f in security.list_findings() if f.status == FindingStatus.AWAITING_APPROVAL][0]
    done = security.decide_finding(pending.finding_id, "approve", approved_by="tester")
    assert done.status == FindingStatus.REMEDIATED
    assert done.verification_status == VerificationStatus.PASSED
    assert done.remediation_status == "complete"
    if done.recommended_action == "apply_security_config":
        assert done.verification_checks and done.verification_checks[0]["passed"]


def test_reject_leaves_open():
    _reset()
    pending = [f for f in security.list_findings() if f.status == FindingStatus.AWAITING_APPROVAL][0]
    done = security.decide_finding(pending.finding_id, "reject", approved_by="tester", reason="no")
    assert done.status == FindingStatus.OPEN
    assert done.remediation_status == "not_started"


def test_create_finding_runs_pipeline():
    _reset()
    from backend.models.incident import SecurityFindingRequest, Severity

    req = SecurityFindingRequest(
        title="privileged pod injected",
        issue="a pod with privileged=true appeared",
        severity=Severity.HIGH,
        layer=SecurityLayer.CONTAINER,
        domain="Privileged",
        affected_resource="Pod/lab-injected",
        root_cause="manifest drift",
        recommended_solution="drop privilege",
        recommended_action="apply_security_config",
        action_params={"config": "drop-privileged", "target": "lab-injected", "namespace": "ai-observability-demo"},
    )
    finding = security.create_finding(req)
    assert finding.simulated is True
    assert finding.status == FindingStatus.AWAITING_APPROVAL
    assert finding.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert finding.recommended_action == "apply_security_config"


def test_application_layer_low_risk_finding_is_auto():
    _reset()
    from backend.models.incident import SecurityFindingRequest, Severity

    req = SecurityFindingRequest(
        title="demo-app crashloop",
        issue="demo-app keeps restarting",
        severity=Severity.MEDIUM,
        layer=SecurityLayer.APPLICATION,
        domain="ConfigDrift",
        affected_resource="Deployment/demo-app",
        root_cause="missing config",
        recommended_solution="restart",
        recommended_action="restart_deployment",
        action_params={"deployment": "demo-app", "namespace": "ai-observability-demo"},
    )
    finding = security.create_finding(req)
    assert finding.decision == PolicyDecisionType.AUTO
    assert finding.status == FindingStatus.REMEDIATED
    assert finding.verification_status == VerificationStatus.PASSED


def test_lab_catalog_has_nine_scenarios():
    _reset()
    keys = {s["key"] for s in security.lab_scenarios()}
    assert keys == {
        "app_error", "high_cpu", "crashloop", "falco", "trivy",
        "apparmor", "privileged", "rbac", "netpol",
    }


def test_lab_auto_scenario_remediates():
    _reset()
    f = security.run_lab("high_cpu")
    assert f.status == FindingStatus.REMEDIATED
    assert f.verification_status == VerificationStatus.PASSED


def test_lab_approval_scenario_joins_approval_queue():
    _reset()
    f = security.run_lab("netpol")
    assert f.status == FindingStatus.AWAITING_APPROVAL
    assert f.approval_required is True
    approved = security.decide_finding(f.finding_id, "approve", approved_by="tester")
    assert approved.status == FindingStatus.REMEDIATED
    assert approved.verification_status == VerificationStatus.PASSED


def test_lab_unknown_scenario_raises():
    _reset()
    try:
        security.run_lab("does-not-exist")
        raise AssertionError("expected KeyError")
    except KeyError:
        pass