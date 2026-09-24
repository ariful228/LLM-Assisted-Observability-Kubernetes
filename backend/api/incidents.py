"""Incident API: detection, creation, workflow trigger, retrieval."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException

from backend.models.incident import (
    Incident,
    IncidentStatus,
    IncidentType,
    Severity,
    SimulateIncidentRequest,
)
from backend.services import detector
from backend.services.store import get_store

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

_DEFAULT_RESOURCE = {
    "high_cpu": "cpu-demo",
    "high_memory": "memory-demo",
    "oom_killed": "memory-demo",
    "crashloop_backoff": "crash-demo",
    "certificate_expiry": "cert-demo",
    "falco_security": "test-pod",
    "suspicious_rbac": "ci-bot-cluster-admin",
}


@router.get("")
def list_incidents(status: Optional[str] = None, incident_type: Optional[str] = None) -> dict[str, Any]:
    incidents = get_store().list()
    if status:
        incidents = [i for i in incidents if i.status.value == status.upper()]
    if incident_type:
        incidents = [i for i in incidents if i.incident_type.value == incident_type]
    return {"incidents": [i.model_dump(mode="json") for i in incidents], "count": len(incidents)}


@router.get("/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    incident = get_store().get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident.model_dump(mode="json")


@router.post("", status_code=201)
def create_incident(req: SimulateIncidentRequest) -> dict[str, Any]:
    """Create an incident (from the UI/Grafana/seeder) and start the workflow."""
    from backend.services import metrics
    from backend.workflows.graph import run_workflow

    store = get_store()
    ns = req.namespace or _namespace()
    resource = req.resource or _DEFAULT_RESOURCE.get(req.incident_type.value, "unknown")
    severity = req.severity or Severity.HIGH
    incident = detector.build_incident(
        req.incident_type,
        namespace=ns,
        resource=resource,
        severity=severity,
        trigger=req.trigger_details or {"source": "api"},
    )
    incident.incident_id = store.next_incident_id()
    stored = store.create(incident)
    metrics.record_detected(incident.incident_type.value)

    try:
        stored = run_workflow(stored.incident_id)
    except Exception as exc:  # noqa: BLE001
        stored = store.get(stored.incident_id)
        assert stored is not None
        stored.status = IncidentStatus.FAILED
        stored.add_to_timeline("workflow_error", str(exc))
        store.update(stored)
    return stored.model_dump(mode="json")


@router.post("/detect", status_code=201)
def run_detector() -> dict[str, Any]:
    """Run detection rules against the configured sources."""
    from backend.services import metrics
    from backend.services import chrono
    from backend.workflows.graph import run_workflow

    store = get_store()
    detected = detector.detect()
    created = []
    for shell in detected:
        shell.incident_id = store.next_incident_id()
        stored = store.create(shell)
        metrics.record_detected(shell.incident_type.value)
        start = chrono.now()
        try:
            stored = run_workflow(stored.incident_id)
        except Exception as exc:  # noqa: BLE001
            stored = store.get(stored.incident_id)
            assert stored is not None
            stored.status = IncidentStatus.FAILED
            stored.add_to_timeline("workflow_error", str(exc))
            store.update(stored)
        finally:
            metrics.DETECTION_DURATION.observe((chrono.now() - start).total_seconds())
        created.append(stored.model_dump(mode="json"))
    return {"detected": created, "count": len(created)}


@router.post("/{incident_id}/run")
def run_incident_workflow(incident_id: str) -> dict[str, Any]:
    """(Re)run the LangGraph workflow for an existing incident."""
    from backend.workflows.graph import run_workflow

    if get_store().get(incident_id) is None:
        raise HTTPException(status_code=404, detail="incident not found")
    incident = run_workflow(incident_id)
    return incident.model_dump(mode="json")


def _namespace() -> str:
    from backend.services.config import get_settings

    return get_settings().namespace