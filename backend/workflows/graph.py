"""LangGraph workflow orchestration (spec section 10).

Two composed graphs keep the approval pause simple, robust and testable:

  investigation_graph  START -> classify -> evidence -> correlate -> RAG ->
                       diagnose -> risk -> plan -> policy_check -> END

  execution_graph      START -> execute -> (SUCCESS ? verify : finalize) ->
                       finalize -> END

The runner decides between AUTO execution, human approval, or no action based
on the authoritative policy decision.
"""

from __future__ import annotations

import logging
from typing import Any

from backend.models.incident import (
    ApprovalStatus,
    Incident,
    IncidentStatus,
    PolicyDecisionType,
    VerificationStatus,
)
from backend.services import slack, tracer
from backend.services.store import get_store
from backend.workflows.state import WorkflowState as _State
from backend.workflows import nodes

logger = logging.getLogger(__name__)

try:
    from langgraph.graph import END, START, StateGraph  # noqa: PLC0415
    from langgraph.types import StreamMode  # noqa: PLC0415
except Exception as exc:  # noqa: BLE001
    logger.warning("langgraph not importable: %s", exc)
    END = START = StateGraph = None  # type: ignore[assignment]


def build_investigation_graph():
    g = StateGraph(_State)
    g.add_node("classify", nodes.classify)
    g.add_node("collect_evidence", nodes.collect_evidence)
    g.add_node("correlate", nodes.correlate)
    g.add_node("rag_retrieve", nodes.rag_retrieve)
    g.add_node("diagnose", nodes.diagnose)
    g.add_node("assess_risk", nodes.assess_risk)
    g.add_node("plan_remediation", nodes.plan_remediation)
    g.add_node("policy_check", nodes.policy_check)

    g.add_edge(START, "classify")
    g.add_edge("classify", "collect_evidence")
    g.add_edge("collect_evidence", "correlate")
    g.add_edge("correlate", "rag_retrieve")
    g.add_edge("rag_retrieve", "diagnose")
    g.add_edge("diagnose", "assess_risk")
    g.add_edge("assess_risk", "plan_remediation")
    g.add_edge("plan_remediation", "policy_check")
    g.add_edge("policy_check", END)
    return g.compile()


def build_execution_graph():
    g = StateGraph(_State)
    g.add_node("execute", nodes.execute)
    g.add_node("verify", nodes.verify)
    g.add_node("finalize", nodes.finalize)

    g.add_edge(START, "execute")
    g.add_conditional_edges(
        "execute",
        nodes.route_after_execute,
        {"verify": "verify", "finalize": "finalize"},
    )
    g.add_edge("verify", "finalize")
    g.add_edge("finalize", END)
    return g.compile()


_investigation_graph = None
_execution_graph = None


def _graphs():
    global _investigation_graph, _execution_graph
    if _investigation_graph is None or _execution_graph is None:
        _investigation_graph = build_investigation_graph()
        _execution_graph = build_execution_graph()
    return _investigation_graph, _execution_graph


def run_workflow(incident_id: str) -> Incident:
    """Run investigation; then AUTO execution or enter approval, per policy."""
    incident = get_store().get(incident_id)
    if incident is None:
        raise ValueError(f"unknown incident {incident_id}")

    slack.get_slack().critical_incident(incident)
    start = _now()

    investigation, execution = _graphs()
    # LangGraph callback receives the Langfuse callback handler when configured.
    investigation.invoke(
        {"incident_id": incident_id},
        config=_langfuse_config(incident_id),
    )

    incident = get_store().get(incident_id)
    decision = incident.policy_decision.decision if incident.policy_decision else PolicyDecisionType.NO_ACTION
    logger.info("incident %s policy decision: %s", incident_id, decision.value)

    if decision == PolicyDecisionType.AUTO:
        execution.invoke(
            {"incident_id": incident_id, "approved": False},
            config=_langfuse_config(incident_id),
        )
    elif decision == PolicyDecisionType.APPROVAL_REQUIRED:
        incident.approval_required = True
        incident.approval_status = ApprovalStatus.PENDING
        incident.status = IncidentStatus.AWAITING_APPROVAL
        get_store().update(incident)
        slack.get_slack().approval_required(incident)
        if incident.incident_type.value in {"falco_security", "suspicious_rbac"}:
            slack.get_slack().security_incident(incident)
    else:
        incident.status = IncidentStatus.NO_ACTION
        get_store().update(incident)
        nodes.finalize({"incident_id": incident_id})

    incident = get_store().get(incident_id)
    incident.latency["investigation_ms"] = (_now() - start).total_seconds() * 1000
    tracer.get_tracer().trace(
        name=f"workflow/{incident_id}",
        input={"decision": decision.value},
        output={"status": incident.status.value, "latency_ms": incident.latency.get("investigation_ms")},
        metadata={"incident_id": incident_id},
    )
    get_store().update(incident)
    return get_store().get(incident_id)


def resume_workflow(
    incident_id: str,
    decision: str,
    approved_by: str = "webui-user",
    reason: str = "",
) -> Incident:
    """Human approval resume: approve / reject the pending remediation."""
    incident = get_store().get(incident_id)
    if incident is None:
        raise ValueError(f"unknown incident {incident_id}")
    if incident.approval_status != ApprovalStatus.PENDING:
        raise ValueError(f"incident {incident_id} is not awaiting approval")

    incident.approval_status = ApprovalStatus.APPROVED if decision == "approve" else ApprovalStatus.REJECTED
    incident.status = IncidentStatus.APPROVED if decision == "approve" else IncidentStatus.REJECTED
    incident.approved_by = approved_by or "webui-user"
    incident.approval_reason = reason
    incident.approved_at = _now()
    get_store().update(incident)
    slack.get_slack().approval_resolved(incident, decision)

    if decision == "approve":
        _, execution = _graphs()
        execution.invoke(
            {"incident_id": incident_id, "approved": True},
            config=_langfuse_config(incident_id),
        )
    else:
        nodes.finalize({"incident_id": incident_id})

    incident = get_store().get(incident_id)
    tracer.get_tracer().trace(
        name=f"approval/{incident_id}",
        input={"decision": decision, "by": approved_by},
        output={"status": incident.status.value},
    )
    return get_store().get(incident_id)


def _now():
    from backend.services.chrono import now

    return now()


def _langfuse_config(incident_id: str) -> dict[str, Any]:
    cb = tracer.get_tracer().get_callback()
    if cb is not None:
        return {"callbacks": [cb]}
    return {}


def reset_graphs() -> None:
    global _investigation_graph, _execution_graph
    _investigation_graph = None
    _execution_graph = None