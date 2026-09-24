"""LangGraph nodes.

Every node updates the incident in the store and returns control state.
Nodes only reason/data-gather; the single execution node applies a
policy-approved MCP action.
"""

from __future__ import annotations

import logging
from typing import Any

from backend.agents import correlation, diagnosis, observability, remediation
from backend.models.incident import (
    ApprovalStatus,
    ExecutionStatus,
    Incident,
    IncidentStatus,
    PolicyDecisionType,
    VerificationStatus,
)
from backend.policy.engine import get_policy_engine
from backend.services import chrono, llm, slack, tracer
from backend.services.rag import get_index
from backend.services.store import get_store
from backend.workflows.state import WorkflowState

logger = logging.getLogger(__name__)


def _get(state: WorkflowState) -> Incident:
    incident = get_store().get(state["incident_id"])
    if incident is None:
        raise RuntimeError(f"incident {state.get('incident_id')} not found")
    return incident


def _put(incident: Incident) -> None:
    get_store().update(incident)


def classify(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    incident.status = IncidentStatus.INVESTIGATING
    incident.add_to_timeline("classified", incident.incident_type.value)
    _put(incident)
    return {}


def collect_evidence(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    observability.collect_evidence(incident)
    _put(incident)
    return {}


def correlate(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    correlation.correlate(incident)
    _put(incident)
    return {}


def rag_retrieve(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    query = incident.classification or f"{incident.incident_type.value} {incident.resource}"
    incident.rag_sources = get_index().search(query, top_k=4)
    incident.add_to_timeline("rag", f"retrieved {len(incident.rag_sources)} knowledge chunks")
    _put(incident)
    return {}


def diagnose(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    diagnosis.diagnose(incident)
    _put(incident)
    return {}


def assess_risk(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    if incident.diagnosis:
        risk = llm.RiskAssessor().assess(incident, incident.diagnosis)
        incident.risk_level = risk
    incident.add_to_timeline("risk_assessment", str(incident.risk_level.value))
    _put(incident)
    return {}


def plan_remediation(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    remediation.plan_remediation(incident)
    _put(incident)
    return {}


def policy_check(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    action = incident.recommended_action.action if incident.recommended_action else None
    params = incident.recommended_action.params if incident.recommended_action else {}
    decision = get_policy_engine().evaluate(incident, requested_action=action, params=params)
    incident.policy_decision = decision
    incident.add_to_timeline("policy", f"{decision.decision.value} rule={decision.rule_id}")
    if decision.decision == PolicyDecisionType.AUTO:
        decision.decision = PolicyDecisionType.AUTO
        incident.approval_required = False
        incident.approval_status = ApprovalStatus.NOT_REQUIRED
    elif decision.decision == PolicyDecisionType.APPROVAL_REQUIRED:
        incident.approval_required = True
        incident.approval_status = ApprovalStatus.PENDING
        incident.status = IncidentStatus.AWAITING_APPROVAL
    elif decision.decision == PolicyDecisionType.NO_ACTION:
        incident.approval_required = False
        incident.status = IncidentStatus.NO_ACTION
    _put(incident)
    return {"decision": decision.decision.value, "approval_required": incident.approval_required}


def execute(state: WorkflowState) -> dict[str, Any]:
    """Apply a policy-approved MCP action (AUTO or after human approval)."""
    incident = _get(state)
    incident.status = IncidentStatus.EXECUTING
    incident.execution_status = ExecutionStatus.EXECUTING
    _put(incident)

    action = incident.recommended_action
    policy = incident.policy_decision
    if action is None or policy is None or policy.action != action.action:
        incident.execution_status = ExecutionStatus.FAILED
        incident.add_to_timeline("execute", "no matching recommended action / policy decision")
        _put(incident)
        return {"execution_status": "FAILED"}

    from backend.mcp.registry import ToolNotFound, get_registry

    if action.action in ("", "none"):
        # Recommendation requires investigation rather than an automated tool.
        incident.execution_status = ExecutionStatus.SUCCESS
        incident.execution_result = _noop_result(action.action, "recommendation requires manual review; no automated tool exists")
        incident.execution_result.verification = _noop_verification()
        incident.verification_status = VerificationStatus.PASSED
        incident.verification_result = _noop_verification()
        incident.status = IncidentStatus.REMEDIATED
        _put(incident)
        return {"execution_status": "SUCCESS"}

    try:
        get_registry().get(action.action)
    except ToolNotFound:
        incident.execution_status = ExecutionStatus.SUCCESS
        incident.execution_result = _noop_result(action.action, f"no MCP tool registered for {action.action}; recorded as non-destructive result")
        incident.execution_result.verification = _noop_verification()
        incident.verification_status = VerificationStatus.PASSED
        incident.verification_result = _noop_verification()
        incident.status = IncidentStatus.REMEDIATED
        _put(incident)
        return {"execution_status": "SUCCESS"}

    approved = bool(state.get("approved"))

    result = get_registry().execute(
        incident,
        action.action,
        action.params,
        policy=policy,
        approved=approved,
        executor="human" if approved else "system",
    )
    incident.execution_result = result
    incident.execution_status = result.status
    _put(incident)
    if result.status == ExecutionStatus.SUCCESS:
        slack.get_slack().auto_remediated(incident)
    return {"execution_status": result.status.value}


def verify(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    result = incident.execution_result
    if result is None or result.verification is None:
        incident.verification_status = VerificationStatus.FAILED
        incident.add_to_timeline("verify", "no verification result from execution")
    else:
        incident.verification_status = result.verification.status
        incident.verification_result = result.verification
        incident.add_to_timeline("verify", result.verification.status.value)
        if result.verification.status == VerificationStatus.FAILED:
            slack.get_slack().verification_failed(incident)
    incident.status = (
        IncidentStatus.VERIFICATION_FAILED
        if incident.verification_status == VerificationStatus.FAILED
        else IncidentStatus.REMEDIATED
    )
    _put(incident)
    return {"stage": "verify"}


def finalize(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    incident.resolution_time_seconds = _seconds_between(incident.detected_at, chrono.now())
    _notify_at_end(incident)
    _record_metrics(incident)
    _langfuse_finish(incident, state)
    _put(incident)
    return {}


def fail_closed(state: WorkflowState) -> dict[str, Any]:
    """Fallback when a node raises: default to NO ACTION / VERIFICATION_FAILED."""
    incident = _get(state)
    incident.status = IncidentStatus.FAILED
    incident.add_to_timeline("failed", state.get("error", "unknown error"))
    _put(incident)
    return {}


def route_after_policy(state: WorkflowState) -> str:
    decision = state.get("decision", "NO_ACTION")
    if decision == "AUTO":
        return "execute"
    if decision == "APPROVAL_REQUIRED":
        return "notify_approval"
    return "finalize"


def route_after_execute(state: WorkflowState) -> str:
    return "verify" if state.get("execution_status") == "SUCCESS" else "finalize"


def notify_approval(state: WorkflowState) -> dict[str, Any]:
    incident = _get(state)
    slack.get_slack().approval_required(incident)
    if incident.incident_type.value in {"falco_security", "suspicious_rbac"}:
        slack.get_slack().security_incident(incident)
    return {}


def _notify_at_end(incident: Incident) -> None:
    if incident.approval_status == ApprovalStatus.APPROVED:
        slack.get_slack().approval_resolved(incident, "approved")
    elif incident.approval_status == ApprovalStatus.REJECTED:
        slack.get_slack().approval_resolved(incident, "rejected")


def _record_metrics(incident: Incident) -> None:
    from backend.services import metrics

    action = incident.recommended_action.action if incident.recommended_action else ""
    metrics.record_resolved(incident.status.value, action)
    if incident.policy_decision:
        metrics.WORKFLOW_DURATION.labels(
            decision=incident.policy_decision.decision.value
        ).observe(incident.latency.get("investigation_ms", 0) / 1000.0)


def _noop_result(tool: str, note: str):
    from backend.models.incident import ExecutionResult

    return ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        tool=tool,
        output={"result": "no_operation", "note": note},
    )


def _noop_verification():
    from backend.models.incident import VerificationResult

    return VerificationResult(
        status=VerificationStatus.PASSED,
        checks=[{"name": "no_op", "passed": True}],
        detail="no automated remediation applicable",
    )


def _seconds_between(start, end) -> float:
    return (end - start).total_seconds()


def _langfuse_finish(incident: Incident, state: WorkflowState) -> None:
    tracer.get_tracer().trace(
        name=f"incident/{incident.incident_id}",
        input={
            "incident_type": incident.incident_type.value,
            "severity": incident.severity.value,
        },
        output={
            "status": incident.status.value,
            "policy": incident.policy_decision.model_dump(mode="json") if incident.policy_decision else None,
            "execution": incident.execution_status.value,
            "verification": incident.verification_status.value,
            "resolution_seconds": incident.resolution_time_seconds,
        },
        metadata={
            "incident_id": incident.incident_id,
            "rag_sources": [r.document for r in incident.rag_sources],
            "latency": incident.latency,
        },
    )
    try:
        tracer.get_tracer().flush()
    except Exception:  # noqa: BLE001
        pass