"""Incident detection (scenario triggers).

Detectors mirror the Grafana alert rules. The API `POST /api/incidents` also
accepts externally detected incidents (e.g. from Grafana) through the same path.
"""

from __future__ import annotations

import logging
from typing import Any

from backend.models.incident import (
    Incident,
    IncidentStatus,
    IncidentType,
    RiskLevel,
    Severity,
)
from backend.services import chrono, simulation
from backend.services.config import get_settings
from backend.services.status import component_status

logger = logging.getLogger(__name__)


def detect(ns_snapshot: dict[str, Any] | None = None) -> list[Incident]:
    """Scan configured sources and emit incidents for the six scenarios."""
    settings = get_settings()
    ns = settings.namespace
    incidents: list[Incident] = []

    prom = _prometheus_cpu(ns)
    if prom:
        incidents.append(prom)

    mem = _prometheus_memory(ns)
    if mem:
        incidents.append(mem)

    oom = _oom(ns)
    if oom and not any(i.incident_type == IncidentType.OOM_KILLED for i in incidents):
        incidents.append(oom)

    crash = _crashloop(ns)
    if crash and not any(
        i.incident_type == IncidentType.CRASH_LOOP_BACK_OFF for i in incidents
    ):
        incidents.append(crash)

    cert = _certificate()
    if cert:
        incidents.append(cert)

    falco = _falco(ns)
    if falco:
        incidents.append(falco)

    rbac = _rbac(ns)
    if rbac:
        incidents.append(rbac)

    return incidents


def _prometheus_cpu(ns: str) -> Incident | None:
    settings = get_settings()
    from backend.services import prometheus

    result = prometheus.get_prometheus().query(
        f'container_cpu_usage_seconds_total{{namespace="{ns}",pod=~"cpu-demo.*"}}'
    )
    series = result.get("series", [])
    sustained = [p for p in series if p["v"] >= settings.cpu_threshold_percent]
    if len(sustained) >= settings.cpu_sustain_minutes:  # high for the sustain window
        return Incident(
            incident_id="",  # assigned by store
            incident_type=IncidentType.HIGH_CPU,
            severity=Severity.HIGH,
            status=IncidentStatus.DETECTED,
            namespace=ns,
            resource="cpu-demo",
            trigger={"source": "prometheus", "threshold": settings.cpu_threshold_percent},
            metrics={"cpu_usage_percent": _series(series)},
            classification="sustained high cpu utilisation on cpu-demo",
        )
    return None


def _prometheus_memory(ns: str) -> Incident | None:
    settings = get_settings()
    from backend.services import prometheus

    result = prometheus.get_prometheus().query(
        f'container_memory_working_set_bytes{{namespace="{ns}",pod=~"memory-demo.*"}}'
    )
    series = result.get("series", [])
    peak = max((p["v"] for p in series), default=0)
    if peak >= settings.memory_threshold_percent:
        return Incident(
            incident_id="",
            incident_type=IncidentType.HIGH_MEMORY,
            severity=Severity.HIGH,
            status=IncidentStatus.DETECTED,
            namespace=ns,
            resource="memory-demo",
            trigger={"source": "prometheus", "threshold": settings.memory_threshold_percent},
            metrics={"memory_usage_percent": _series(series)},
            classification="high memory utilisation on memory-demo",
        )
    return None


def _oom(ns: str) -> Incident | None:
    pods = simulation.kube_pods(ns) if not _live_kube() else []
    for pod in pods:
        for c in pod.get("containers", []):
            term = (c.get("last_state") or {}).get("terminated") or {}
            if term.get("reason") == "OOMKilled":
                return Incident(
                    incident_id="",
                    incident_type=IncidentType.OOM_KILLED,
                    severity=Severity.CRITICAL,
                    status=IncidentStatus.DETECTED,
                    namespace=ns,
                    resource=pod.get("deployment") or pod["name"],
                    trigger={"source": "kubernetes", "reason": "OOMKilled", "exit_code": term.get("exit_code")},
                    classification="container terminated by OOM killer",
                )
    return None


def _crashloop(ns: str) -> Incident | None:
    pods = simulation.kube_pods(ns) if not _live_kube() else []
    for pod in pods:
        if pod.get("restarts", 0) >= 5:
            return Incident(
                incident_id="",
                incident_type=IncidentType.CRASH_LOOP_BACK_OFF,
                severity=Severity.CRITICAL,
                status=IncidentStatus.DETECTED,
                namespace=ns,
                resource=pod.get("deployment") or pod["name"],
                trigger={"source": "kubernetes", "reason": "CrashLoopBackOff", "restarts": pod.get("restarts")},
                classification="workload stuck in CrashLoopBackOff",
            )
    return None


def _certificate() -> Incident | None:
    settings = get_settings()
    from backend.services.certmon import get_certificate_monitor

    cert = get_certificate_monitor().status()
    if cert.expired_soon:
        return Incident(
            incident_id="",
            incident_type=IncidentType.CERTIFICATE_EXPIRY,
            severity=Severity.HIGH,
            status=IncidentStatus.DETECTED,
            namespace=settings.namespace,
            resource="cert-demo",
            trigger={
                "source": "certificate-monitor",
                "days_remaining": cert.days_remaining,
                "threshold": settings.cert_expiry_days_threshold,
            },
            classification="TLS certificate expiring soon",
        )
    return None


def _falco(ns: str) -> Incident | None:
    events = simulation.falco_events(ns)
    crit = [e for e in events if e.get("priority") in ("CRITICAL", "HIGH")]
    if crit:
        e = crit[0]
        return Incident(
            incident_id="",
            incident_type=IncidentType.FALCO_SECURITY,
            severity=Severity.CRITICAL,
            status=IncidentStatus.DETECTED,
            namespace=ns,
            resource=e.get("pod", "test-pod"),
            trigger={
                "source": "falco",
                "rule": e.get("rule"),
                "priority": e.get("priority"),
                "proc": e.get("proc"),
                "cmdline": e.get("cmdline"),
            },
            classification=e.get("rule", "falco security event"),
        )
    return None


def _rbac(ns: str) -> Incident | None:
    bindings = simulation.kube_rbac()
    for b in bindings:
        if b.get("suspicious") or b.get("role", "").endswith("cluster-admin"):
            return Incident(
                incident_id="",
                incident_type=IncidentType.SUSPICIOUS_RBAC,
                severity=Severity.HIGH,
                status=IncidentStatus.DETECTED,
                namespace=ns,
                resource=b.get("name", "unknown-binding"),
                trigger={
                    "source": "kubernetes-audit",
                    "binding": b.get("name"),
                    "role": b.get("role"),
                    "subjects": b.get("subjects"),
                },
                classification="unauthorised ClusterRoleBinding with elevated permissions",
            )
    return None


def _series(points: list[dict]) -> list[dict]:
    return points


def _live_kube() -> bool:
    try:
        from backend.services import kube

        return kube.get_kube().mode == "live"
    except Exception:  # noqa: BLE001
        return False


def build_incident(
    incident_type: IncidentType,
    namespace: str,
    resource: str,
    severity: Severity,
    trigger: dict[str, Any] | None = None,
) -> Incident:
    """Construct an incident shell for an externally-detected event (Grafana)."""
    settings = get_settings()
    return Incident(
        incident_id="",
        incident_type=incident_type,
        severity=severity,
        namespace=namespace or settings.namespace,
        resource=resource or "unknown",
        trigger=trigger or {"source": "grafana-alert"},
        classification=f"{incident_type.value} incident detected",
    )