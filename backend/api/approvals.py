"""Approval API: list pending approvals, approve/reject incidents."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from backend.models.incident import ApprovalRequest, ApprovalStatus
from backend.services.store import get_store

router = APIRouter(prefix="/api", tags=["approvals"])


@router.get("/approvals")
def pending_approvals() -> dict[str, Any]:
    incidents = [i for i in get_store().list() if i.approval_status == ApprovalStatus.PENDING]
    return {
        "approvals": [
            {
                "incident_id": i.incident_id,
                "incident_type": i.incident_type.value,
                "severity": i.severity.value,
                "namespace": i.namespace,
                "resource": i.resource,
                "detected_at": i.detected_at.isoformat(),
                "recommended_action": i.recommended_action,
                "risk_level": i.risk_level.value,
                "policy_decision": i.policy_decision,
                "reason": i.diagnosis.cause if i.diagnosis else "",
                "url": f"/incidents/{i.incident_id}",
            }
            for i in incidents
        ],
        "count": len(incidents),
    }


@router.post("/incidents/{incident_id}/approval")
def approve_or_reject(incident_id: str, req: ApprovalRequest) -> dict[str, Any]:
    """Human approval gate. Only resumes execution, never bypasses the policy."""
    from backend.workflows.graph import resume_workflow

    incident = get_store().get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    if incident.approval_status != ApprovalStatus.PENDING:
        raise HTTPException(status_code=409, detail="incident is not awaiting approval")

    try:
        from backend.services import metrics

        metrics.record_approval(req.decision)
        incident = resume_workflow(
            incident_id,
            decision=req.decision,
            approved_by=req.approved_by or "webui-user",
            reason=req.reason or "",
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"approval failed: {exc}") from exc
    return incident.model_dump(mode="json")