"""Observability agent: automated, incident-type-specific evidence collection.

Every collection step is bounded, typed and recorded in the incident model so
the Web UI can always show raw evidence (never only the LLM summary).
"""

from __future__ import annotations

import logging
from typing import Any

from backend.models.incident import EvidenceItem, Incident, MetricPoint, IncidentType
from backend.services import kube, prometheus

logger = logging.getLogger(__name__)


def collect_evidence(incident: Incident) -> Incident:
    itype = incident.incident_type.value
    collectors = {
        "high_cpu": _cpu_evidence,
        "high_memory": _memory_evidence,
        "oom_killed": _memory_evidence,
        "crashloop_backoff": _crash_evidence,
        "certificate_expiry": _cert_evidence,
        "falco_security": _security_evidence,
        "suspicious_rbac": _rbac_evidence,
    }
    fn = collectors.get(itype, _generic_evidence)
    try:
        fn(incident)
    except Exception as exc:  # noqa: BLE001
        incident.evidence.append(
            EvidenceItem(
                category="collector",
                source="observability-agent",
                summary=f"evidence step failed: {exc}",
            )
        )
    incident.add_to_timeline("evidence_collected", f"collected {len(incident.evidence)} evidence items")
    return incident


def _kube() -> kube.KubeAdapter:
    return kube.get_kube()


def _pod_evidence(incident: Incident) -> None:
    pods = _kube().get_pods(incident.namespace)
    for p in pods:
        if incident.resource in (p["name"], p.get("deployment", "")):
            incident.evidence.append(
                EvidenceItem(category="kubernetes", source="kube.pods", summary=f"Pod {p['name']} phase={p['phase']} ready={p['ready']} restarts={p['restarts']}", data=p)
            )
    incident.evidence.append(
        EvidenceItem(category="kubernetes", source="kube.events", summary="namespace events", data=_kube().get_pod_events(incident.namespace))
    )


def _cpu_evidence(incident: Incident) -> None:
    q = f'container_cpu_usage_seconds_total{{namespace="{incident.namespace}",pod=~"cpu-demo.*"}}'
    data = prometheus.get_prometheus().query(q)
    incident.metrics["cpu_usage_percent"] = [_mp(p) for p in data.get("series", [])]
    incident.evidence.append(
        EvidenceItem(
            category="prometheus",
            source="prometheus.query_range",
            summary=f"cpu usage series (source={data.get('result')})",
            data=_last_points(data.get("series", []), 5),
        )
    )
    _pod_evidence(incident)
    incident.evidence.append(
        EvidenceItem(category="kubernetes", source="kube.deployment", summary="deployment state", data=_kube().get_deployment(incident.resource or "cpu-demo", incident.namespace))
    )


def _memory_evidence(incident: Incident) -> None:
    q = f'container_memory_working_set_bytes{{namespace="{incident.namespace}",pod=~"(?:memory-demo|crash-demo).*"}}'
    data = prometheus.get_prometheus().query(q)
    incident.metrics["memory_usage_percent"] = [_mp(p) for p in data.get("series", [])]
    incident.evidence.append(
        EvidenceItem(category="prometheus", source="prometheus.query_range", summary="memory usage series", data=_last_points(data.get("series", []), 5))
    )
    _pod_evidence(incident)
    pod = _find_pod(_kube().get_pods(incident.namespace), incident.resource)
    if pod:
        for c in pod.get("containers", []):
            incident.evidence.append(
                EvidenceItem(
                    category="kubernetes",
                    source="kube.pod.container",
                    summary=f"container {c['name']} state={c.get('state')} restarts={c.get('restart_count')}",
                    data=c,
                )
            )
        incident.evidence.append(
            EvidenceItem(
                category="logs",
                source="kube.podlogs",
                summary="current container logs",
                data=_kube().get_pod_logs(pod["name"], incident.namespace, previous=False),
            )
        )
        incident.evidence.append(
            EvidenceItem(
                category="logs",
                source="kube.podlogs.previous",
                summary="previous container logs",
                data=_kube().get_pod_logs(pod["name"], incident.namespace, previous=True),
            )
        )
    incident.evidence.append(
        EvidenceItem(category="kubernetes", source="kube.deployment", summary="deployment resources", data=_deployment_summary(incident))
    )


def _crash_evidence(incident: Incident) -> None:
    _pod_evidence(incident)
    pod = _find_pod(_kube().get_pods(incident.namespace), incident.resource)
    if pod:
        for c in pod.get("containers", []):
            incident.evidence.append(
                EvidenceItem(category="kubernetes", source="kube.pod.container", summary=f"container status {c['name']}", data=c)
            )
        incident.evidence.append(
            EvidenceItem(category="logs", source="kube.podlogs.current", summary="current logs", data=_kube().get_pod_logs(pod["name"], incident.namespace, previous=False))
        )
        incident.evidence.append(
            EvidenceItem(category="logs", source="kube.podlogs.previous", summary="previous logs", data=_kube().get_pod_logs(pod["name"], incident.namespace, previous=True))
        )
    incident.evidence.append(
        EvidenceItem(category="kubernetes", source="kube.deployment", summary="deployment state", data=_kube().get_deployment(incident.resource.split("-")[0] + "-demo" if "-" in (incident.resource or "") else incident.resource, incident.namespace))
    )


def _cert_evidence(incident: Incident) -> None:
    from backend.services.certmon import get_certificate_monitor

    status = get_certificate_monitor().status().to_dict()
    incident.evidence.append(
        EvidenceItem(category="certificates", source="certificate.monitor", summary="certificate expiry status", data=status)
    )
    _pod_evidence(incident)


def _security_evidence(incident: Incident) -> None:
    # Falco events
    falco = _falco_events(incident.namespace)
    incident.evidence.append(
        EvidenceItem(category="falco", source="falco.events", summary=f"{len(falco)} falco events", data=falco)
    )
    # Kubernetes audit log
    audit = _audit_events(incident.namespace)
    incident.evidence.append(
        EvidenceItem(category="audit", source="kubernetes.audit", summary=f"{len(audit)} audit events", data=audit)
    )
    _pod_evidence(incident)
    pod = _find_pod(_kube().get_pods(incident.namespace), incident.resource)
    if pod:
        incident.evidence.append(
            EvidenceItem(category="logs", source="kube.podlogs", summary="pod logs", data=_kube().get_pod_logs(pod["name"], incident.namespace, previous=False))
        )


def _rbac_evidence(incident: Incident) -> None:
    audit = _audit_events(incident.namespace)
    incident.evidence.append(
        EvidenceItem(category="audit", source="kubernetes.audit", summary="audit log around RBAC change", data=audit)
    )
    rbac_state = _kube().get_rbac()
    incident.evidence.append(
        EvidenceItem(category="rbac", source="kube.rbac", summary="current rbac bindings", data=rbac_state)
    )
    _pod_evidence(incident)


def _generic_evidence(incident: Incident) -> None:
    incident.evidence.append(
        EvidenceItem(category="kubernetes", source="kube.pods", summary="pods in namespace", data=_kube().get_pods(incident.namespace))
    )


def _falco_events(namespace: str) -> list[dict[str, Any]]:
    from backend.services.opensearch import get_opensearch

    settings = get_opensearch().settings
    return get_opensearch().search(
        settings.opensearch_index_falco,
        {"query": {"match_all": {}}},
        size=20,
    )


def _audit_events(namespace: str) -> list[dict[str, Any]]:
    from backend.services.opensearch import get_opensearch

    settings = get_opensearch().settings
    return get_opensearch().search(
        settings.opensearch_index_audit,
        {"query": {"match_all": {}}},
        size=30,
    )


def _find_pod(pods: list[dict], resource: str) -> dict | None:
    for p in pods:
        if p["name"] == resource:
            return p
    for p in pods:
        if p.get("deployment") == resource:
            return p
    return pods[0] if pods else None


def _deployment_summary(incident: Incident) -> dict[str, Any]:
    try:
        return _kube().get_deployment(incident.resource.split("-")[0] + "-demo", incident.namespace)
    except Exception:  # noqa: BLE001
        return {"error": "deployment lookup failed"}


def _mp(point: dict) -> MetricPoint:
    from datetime import datetime  # noqa: PLC0415

    try:
        t = datetime.fromisoformat(str(point["t"]))
    except Exception:  # noqa: BLE001
        t = None
    return MetricPoint(t=t, v=float(point["v"]))


def _last_points(series: list[dict], n: int) -> list[dict]:
    return series[-n:]