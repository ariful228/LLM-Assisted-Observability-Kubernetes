"""Prometheus /metrics export + health + component status."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter(tags=["meta"])

# utilisation fans out to two Prometheus range queries per deployment
_UTIL_TTL = 15.0
_UTIL_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}


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


@router.get("/api/utilization")
def utilization() -> dict[str, Any]:
    """Per-deployment CPU/memory pressure.

    Reads live Prometheus when it actually has cAdvisor/kube-state series and
    falls back to the deterministic simulation otherwise, so the dashboard
    always has a utilisation view. Cached briefly — one call fans out to two
    range queries per deployment.
    """
    from backend.services import kube, prometheus, simulation

    ns = _ns()
    now = time.monotonic()
    cached = _UTIL_CACHE.get(ns)
    if cached and now - cached[0] < _UTIL_TTL:
        return cached[1]

    try:
        deployments = kube.get_kube().get_deployments(ns)
    except Exception as exc:  # noqa: BLE001
        return {"mode": "unavailable", "error": str(exc), "items": []}

    client = prometheus.get_prometheus()
    items: list[dict[str, Any]] = []
    sources: set[str] = set()
    for d in deployments:
        name = d.get("name", "")
        cpu, cpu_src = _latest(client, simulation, _cpu_query(name, ns))
        mem, mem_src = _latest(client, simulation, _memory_query(name, ns))
        sources.update(s for s in (cpu_src, mem_src) if s in ("live", "simulated"))
        items.append(
            {
                "deployment": name,
                "namespace": d.get("namespace", ns),
                "replicas": d.get("replicas", 0),
                "ready": d.get("ready", 0),
                "available": d.get("available", 0),
                "cpu_percent": cpu,
                "memory_percent": mem,
            }
        )

    source = "live" if sources == {"live"} else "simulated"
    cpus = [i["cpu_percent"] for i in items if i["cpu_percent"] is not None]
    mems = [i["memory_percent"] for i in items if i["memory_percent"] is not None]
    payload = {
        "mode": kube.get_kube().mode,
        "namespace": ns,
        "source": source,
        "items": items,
        "cpu_percent_avg": round(sum(cpus) / len(cpus), 1) if cpus else None,
        "memory_percent_avg": round(sum(mems) / len(mems), 1) if mems else None,
        "cpu_pressure": sum(1 for v in cpus if v >= 80),
        "memory_pressure": sum(1 for v in mems if v >= 85),
    }
    _UTIL_CACHE[ns] = (now, payload)
    return payload


def _cpu_query(deployment: str, ns: str) -> str:
    sel = f'namespace="{ns}",deployment="{deployment}"'
    # rate() returns cores; scale against one core for a percentage
    return f'sum(rate(container_cpu_usage_seconds_total{{{sel}}}[5m])) by (deployment) * 100'


def _memory_query(deployment: str, ns: str) -> str:
    sel = f'namespace="{ns}",deployment="{deployment}"'
    # working set as a percentage of the container memory limit
    return (
        f'sum(container_memory_working_set_bytes{{{sel}}}) by (deployment) / '
        f'sum(kube_pod_container_resource_limits{{resource="memory",{sel}}}) by (deployment) * 100'
    )


def _latest(client, simulation, query: str) -> tuple[float | None, str]:
    """Most recent value of a per-deployment series, as a percentage."""
    try:
        result = client.query(query, 15)
    except Exception:  # noqa: BLE001
        result = {"result": "unavailable", "series": []}
    if not result.get("series"):
        # Prometheus is up but scrapes no cAdvisor/kubelet series — use the
        # deterministic simulation so the panel still shows real numbers.
        try:
            result = {"result": "simulated", "series": simulation.prometheus_query(query, 15).get("series", [])}
        except Exception:  # noqa: BLE001
            pass
    series = result.get("series") or []
    if not series:
        return None, "unavailable"
    return round(max(0.0, float(series[-1].get("v", 0.0))), 1), result.get("result", "simulated")


def _ns() -> str:
    from backend.services.config import get_settings

    return get_settings().namespace