"""Evaluation summary API (spec sections 17-18)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from backend.models.incident import IncidentStatus
from backend.services.store import get_store

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])


@router.get("/stats")
def stats() -> dict[str, Any]:
    incidents = get_store().list()
    open_count = len(get_store().list_open())

    def _count(pred) -> int:
        return sum(1 for i in incidents if pred(i))

    by_type: dict[str, int] = {}
    for i in incidents:
        by_type[i.incident_type.value] = by_type.get(i.incident_type.value, 0) + 1

    latencies = [i.latency for i in incidents if i.latency]
    return {
        "total_incidents": len(incidents),
        "active_incidents": open_count,
        "by_type": by_type,
        "autos": _count(lambda i: i.policy_decision and i.policy_decision.decision.value == "AUTO"),
        "approval_required": _count(lambda i: i.approval_required),
        "approved": _count(lambda i: i.approval_status.value == "APPROVED"),
        "rejected": _count(lambda i: i.approval_status.value == "REJECTED"),
        "remediated": _count(lambda i: i.status == IncidentStatus.REMEDIATED),
        "verification_failed": _count(lambda i: i.verification_status.value == "FAILED"),
        "detection_avg_ms": _avg([i.latency.get("investigation_ms") for i in incidents]),
        "resolution_avg_seconds": _avg([i.resolution_time_seconds for i in incidents if i.resolution_time_seconds is not None]),
    }


def _avg(values: list[Any]) -> float | None:
    vals = [v for v in values if v is not None]
    return round(sum(vals) / len(vals), 3) if vals else None