"""Security findings API: CKS four-layer coverage + findings lifecycle.

Endpoints are read-only except the explicit approval / remediation decision
flow and the lab scenario creator, both of which keep the LLM advisory and the
policy engine authoritative.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException

from backend.models.incident import (
    FindingApprovalRequest,
    FindingStatus,
    SecurityFindingRequest,
    SecurityLayer,
)
from backend.services import security

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/layers")
def layers() -> dict[str, Any]:
    """The four CKS security layers with counts."""
    data = security.stats()
    layers_out = []
    for layer in SecurityLayer:
        info = data["by_layer"][layer.value]
        layers_out.append({"layer": layer.value, **info})
    return {"layers": layers_out, "total": data["total"], "simulated": data["simulated"]}


@router.get("/stats")
def stat_snapshot() -> dict[str, Any]:
    return security.stats()


@router.get("/findings")
def list_findings(
    layer: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    domain: Optional[str] = None,
) -> dict[str, Any]:
    findings = security.list_findings(
        layer=layer, status=status, severity=severity, domain=domain
    )
    return {
        "findings": [f.model_dump(mode="json") for f in findings],
        "count": len(findings),
        "filters": {"layer": layer, "status": status, "severity": severity, "domain": domain},
    }


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict[str, Any]:
    finding = security.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding.model_dump(mode="json")


@router.post("/findings", status_code=201)
def create_finding(req: SecurityFindingRequest) -> dict[str, Any]:
    """Inject a finding (Security Test Lab) and run the safe detect->policy pipeline."""
    finding = security.create_finding(req)
    return finding.model_dump(mode="json")


@router.post("/findings/{finding_id}/decision")
def decide_finding(finding_id: str, req: FindingApprovalRequest) -> dict[str, Any]:
    try:
        finding = security.decide_finding(
            finding_id, req.decision, approved_by=req.approved_by, reason=req.reason
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return finding.model_dump(mode="json")


@router.get("/pending")
def pending() -> dict[str, Any]:
    findings = security.list_findings(status=FindingStatus.AWAITING_APPROVAL.value)
    return {
        "findings": [f.model_dump(mode="json") for f in findings],
        "count": len(findings),
    }


@router.post("/reset", status_code=200)
def reset() -> dict[str, Any]:
    security.reset_findings()
    return {"reset": True}


@router.get("/lab")
def lab_catalog() -> dict[str, Any]:
    """The 9 safe Security Test Lab scenarios."""
    return {"scenarios": security.lab_scenarios(), "count": len(security.lab_scenarios())}


@router.post("/lab/run/{key}", status_code=201)
def lab_run(key: str) -> dict[str, Any]:
    """Run one lab scenario: Create Issue -> Detect -> … -> Verify (DEMO-ISOLATED)."""
    try:
        finding = security.run_lab(key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return finding.model_dump(mode="json")