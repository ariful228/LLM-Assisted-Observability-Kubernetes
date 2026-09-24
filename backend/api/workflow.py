"""Workflow-simulator API.

Serves the ordered pipeline node list and per-incident animation steps so the
web UI can replay an incident through the LangGraph workflow with moving
animation (see frontend/wfsim.js).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from backend.models.incident import Incident
from backend.services.store import get_store

router = APIRouter(prefix="/api/workflow", tags=["workflow"])

# Export order matches backend/workflows/graph.py node sequence.
PIPELINE: list[str] = [
    "classify",
    "collect_evidence",
    "correlate",
    "rag_retrieve",
    "diagnose",
    "assess_risk",
    "plan_remediation",
    "policy_check",
    "approval",
    "execute",
    "verify",
    "finalize",
]

_KEYS = {
    "incident_id",
    "incident_type",
    "status",
    "severity",
    "namespace",
    "resource",
    "approval_status",
    "approved_by",
    "execution_status",
    "verification_status",
    "risk_level",
    "policy_decision",
    "recommended_action",
    "diagnosis",
    "rag_sources",
}


@router.get("/pipeline")
def pipeline() -> dict[str, Any]:
    return {"nodes": PIPELINE}


@router.get("/animate/{incident_id}")
def animate(incident_id: str, with_approval: bool | None = None) -> dict[str, Any]:
    """Serialize an incident into ordered animation steps for the UI."""
    incident = get_store().get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")

    steps = _steps(incident)
    if with_approval is not None:
        steps = [s for s in steps if s["node"] != "approval"] if not with_approval else steps
    nodes = [n for n in PIPELINE if any(s["node"] == n for s in steps)]

    payload = incident.model_dump(mode="json")
    return {
        "incident": {k: payload.get(k) for k in _KEYS if k in payload},
        "nodes": nodes,
        "steps": steps,
    }


def _steps(incident: Incident) -> list[dict[str, Any]]:
    """Map the incident timeline onto pipeline nodes, keeping order + timestamps.

    Synthetic nodes (approval, finalize) are derived from incident state so the
    replay always ends at a resolved state.
    """
    import re as _re

    rules = [
        (_re.compile(r"^detected$"), "classify"),
        (_re.compile(r"^classified$"), "classify"),
        (_re.compile(r"^evidence_collected$"), "collect_evidence"),
        (_re.compile(r"^correlation_"), "correlate"),
        (_re.compile(r"^rag$"), "rag_retrieve"),
        (_re.compile(r"^diagnosis$"), "diagnose"),
        (_re.compile(r"^risk_assessment$"), "assess_risk"),
        (_re.compile(r"^remediation_planned$"), "plan_remediation"),
        (_re.compile(r"^policy$"), "policy_check"),
        (_re.compile(r"^mcp\."), "execute"),
        (_re.compile(r"^execute$"), "execute"),
        (_re.compile(r"^verify$"), "verify"),
        (_re.compile(r"^approved$"), "approval"),
        (_re.compile(r"^rejected$"), "approval"),
    ]

    raw: list[tuple[float, str, str, str]] = []
    for ev in incident.timeline:
        node = next((n for rx, n in rules if rx.match(ev.step)), None)
        if node is None:
            continue
        raw.append((ev.ts.timestamp(), node, ev.step, ev.detail))

    # Group real steps by their pipeline slot, then insert the human-approval
    # step between policy_check and execute so the replay follows the real
    # topology (approval never sits after execute/verify).
    node_slot = {n: i for i, n in enumerate(PIPELINE)}
    groups: dict[int, list[dict[str, Any]]] = {}
    for t, node, step, detail in raw:
        groups.setdefault(node_slot[node], []).append(
            {"t": t, "node": node, "step": step, "detail": detail}
        )

    status = incident.status.value
    approval = incident.approval_status.value
    decided = incident.policy_decision.decision.value if incident.policy_decision else "NO_ACTION"

    def _synthetic(node: str, step: str, detail: str) -> dict[str, Any]:
        return {"t": 0.0, "node": node, "step": step, "detail": detail}

    if approval == "PENDING" or (incident.approval_required and approval != "NOT_REQUIRED"):
        groups.setdefault(node_slot["approval"], []).insert(
            0, _synthetic("approval", "approval", "waiting for a human approver")
        )
    elif approval in ("APPROVED", "REJECTED"):
        by = f" by {incident.approved_by}" if incident.approved_by else ""
        groups.setdefault(node_slot["approval"], []).insert(
            0, _synthetic("approval", approval.lower(), f"{approval}{by}")
        )

    if status in ("REMEDIATED", "VERIFICATION_FAILED", "REJECTED", "NO_ACTION", "CLOSED", "FAILED"):
        groups.setdefault(node_slot["finalize"], []).insert(
            0, _synthetic("finalize", "finalize", f"decision={decided} status={status}")
        )

    # Stitch groups back into pipeline order, keeping intra-node timeline order.
    steps: list[dict[str, Any]] = []
    for slot in sorted(groups):
        chunk = sorted(groups[slot], key=lambda s: s["t"])
        if slot > 0 and steps:
            prev_t = steps[-1]["t"]
            for s in chunk:
                if s["t"] <= prev_t:
                    s["t"] = prev_t + 0.001
                prev_t = s["t"]
        steps.extend(chunk)
    return steps