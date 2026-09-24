"""Remediation planner.

Converts an LLM recommendation into a concrete, policy-checkable action.
The planner itself cannot execute anything — it only proposes parameters.
"""

from __future__ import annotations

from backend.models.incident import (
    Diagnosis,
    Incident,
    RecommendedAction,
    RiskLevel,
)
from backend.services import kube


def plan_remediation(incident: Incident) -> Incident:
    diagnosis = incident.diagnosis or Diagnosis(summary="", cause="")
    action_name = diagnosis.recommended_action or _default_action(incident)
    params = _build_params(incident, action_name)
    description, risk, expected = _describe(incident, action_name)
    incident.recommended_action = RecommendedAction(
        action=action_name,
        params=params,
        description=description,
        risk=risk,
        expected_result=expected,
        reason=diagnosis.cause,
    )
    incident.risk_level = risk
    incident.add_to_timeline("remediation_planned", f"{action_name} {params}")
    return incident


def _default_action(incident: Incident) -> str:
    mapping = {
        "high_cpu": "scale_deployment",
        "high_memory": "request_memory_review",
        "oom_killed": "scale_deployment",
        "crashloop_backoff": "restart_deployment",
        "certificate_expiry": "renew_certificate",
        "falco_security": "isolate_pod",
        "suspicious_rbac": "rollback_rbac",
    }
    return mapping.get(incident.incident_type.value, "none")


def _build_params(incident: Incident, action: str) -> dict:
    from backend.services.config import get_settings

    deploy = incident.resource
    ns = incident.namespace or get_settings().namespace
    if action == "scale_deployment":
        current = _current_replicas(incident)
        return {
            "deployment": deploy,
            "namespace": ns,
            "delta": 1,
            "desired_replicas": current + 1,
        }
    if action == "restart_deployment":
        return {"deployment": deploy, "namespace": ns}
    if action == "renew_certificate":
        return {"namespace": ns, "secret_name": "cert-demo-tls", "dns_name": "cert-demo.ai-observability-demo.svc"}
    if action == "rollback_rbac":
        return {"binding_name": incident.resource}
    return {}


def _current_replicas(incident: Incident) -> int:
    try:
        dep = kube.get_kube().get_deployment(incident.resource, incident.namespace)
        return int(dep.get("replicas", 2))
    except Exception:  # noqa: BLE001
        return 2


def _describe(incident: Incident, action: str) -> tuple[str, RiskLevel, str]:
    table = {
        "scale_deployment": ("increase deployment replicas by 1 to shed load", RiskLevel.LOW, "replicas increased; CPU utilisation expected to drop"),
        "request_memory_review": ("investigate and raise memory limit after review", RiskLevel.MEDIUM, "memory limit adjusted after approval"),
        "restart_deployment": ("rollout restart of the deployment", RiskLevel.MEDIUM, "pods restart; CrashLoopBackOff should clear if config is fixed"),
        "renew_certificate": ("re-issue the serving TLS certificate", RiskLevel.MEDIUM, "certificate valid for a new term; no downtime"),
        "rollback_rbac": ("delete the suspicious ClusterRoleBinding", RiskLevel.HIGH, "privileged binding removed; least privilege restored"),
        "isolate_pod": ("quarantine/terminate the compromised pod after review", RiskLevel.HIGH, "suspicious pod removed"),
    }
    return table.get(action, ("no automatic action required", RiskLevel.LOW, "no change expected"))