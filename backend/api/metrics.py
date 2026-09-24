"""Prometheus /metrics export + health + component status."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter(tags=["meta"])


@router.get("/metrics")
def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/api/status")
def status() -> dict[str, Any]:
    from backend.services.status import component_status

    return {"components": component_status()}


@router.get("/api/cluster")
def cluster() -> dict[str, Any]:
    from backend.services import kube

    mode = kube.get_kube().mode
    try:
        pods = kube.get_kube().get_pods(_ns())
        deployments = kube.get_kube().get_deployments(_ns())
        nodes = kube.get_kube().get_nodes()
    except Exception as exc:  # noqa: BLE001
        return {"mode": mode, "error": str(exc)}
    return {
        "mode": mode,
        "nodes": nodes,
        "deployments": deployments,
        "pods": pods,
        "pod_count": len(pods),
        "running_pods": sum(1 for p in pods if p.get("phase") == "Running"),
        "failed_pods": sum(1 for p in pods if p.get("phase") not in ("Running", "Succeeded")),
    }


def _ns() -> str:
    from backend.services.config import get_settings

    return get_settings().namespace