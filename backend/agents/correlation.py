"""Event correlation agent.

Extracts structured evidence from raw evidence items and — for security
scenarios — builds a unified timeline that merges Kubernetes audit events
and Falco runtime events (see spec scenario 5).
"""

from __future__ import annotations

import json
from typing import Any

from backend.models.incident import EvidenceItem, Incident, TimelineEvent
from backend.services import chrono

_SECURITY_TYPES = {"falco_security", "suspicious_rbac"}


def correlate(incident: Incident) -> Incident:
    incident.add_to_timeline("correlation_started", incident.incident_type.value)
    if incident.incident_type.value in _SECURITY_TYPES:
        incident = _correlate_security(incident)
    else:
        incident = _correlate_generic(incident)
    incident.add_to_timeline("correlation_finished", f"timeline={len(incident.timeline)} events")
    return incident


def _evidence(incident: Incident, category: str) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for e in incident.evidence:
        if e.category != category:
            continue
        data = e.data
        if isinstance(data, dict):
            flattened.append(data)
        elif isinstance(data, list):
            flattened.extend(d for d in data if isinstance(d, dict))
    return flattened


def _summary_of(incident: Incident) -> str:
    parts: list[str] = []
    for e in incident.evidence[:8]:
        parts.append(f"[{e.category}] {e.summary}")
    return "\n".join(parts[:12]) or "no evidence"


def _correlate_security(incident: Incident) -> Incident:
    """Merge Kubernetes audit activity with Falco runtime events into a timeline."""
    from datetime import datetime  # noqa: PLC0415

    audit_events = _evidence(incident, "audit")
    falco_events = _evidence(incident, "falco")
    timeline: list[dict[str, Any]] = []
    for ev in audit_events:
        timeline.append(
            {
                "ts": _ts(ev, "timestamp"),
                "source": "kubernetes-audit",
                "activity": f"{ev.get('verb')} {ev.get('resource')}",
                "actor": _actor(ev),
                "object": ev.get("object", {}).get("name", ""),
                "ip": (ev.get("sourceIPs") or [""])[0],
                "status": (ev.get("responseStatus") or {}).get("code", ""),
            }
        )
    for ev in falco_events:
        timeline.append(
            {
                "ts": _ts(ev, "time"),
                "source": "falco",
                "rule": ev.get("rule"),
                "priority": ev.get("priority"),
                "process": ev.get("proc"),
                "cmdline": ev.get("cmdline"),
                "user": ev.get("user"),
                "container": ev.get("container"),
            }
        )
    timeline.sort(key=lambda t: t.get("ts") or "")
    for entry in timeline:
        incident.timeline.append(
            TimelineEvent(ts=entry.get("ts") or chrono.now(), step=entry["source"], detail=json.dumps({k: v for k, v in entry.items() if k != "ts"}, default=str))
        )
    incident.evidence.append(
        EvidenceItem(
            category="correlation",
            source="correlation-agent",
            summary=f"merged {len(timeline)} audit+falco events into one timeline",
            data=timeline,
        )
    )
    return incident


def _correlate_generic(incident: Incident) -> Incident:
    order = (
        ("prometheus", "metrics anomaly observed"),
        ("kubernetes", "kubernetes resource state"),
        ("logs", "application logs"),
        ("certificates", "certificate state"),
        ("rbac", "rbac state"),
    )
    for category, label in order:
        found = [e for e in incident.evidence if e.category == category]
        if found:
            incident.add_to_timeline(label, "; ".join(e.summary for e in found[:3]))
    return incident


def evidence_text(incident: Incident) -> str:
    """Textual rendering of evidence for the LLM diagnosis step."""
    lines = [_summary_of(incident)]
    for e in incident.evidence[:10]:
        if e.data is not None:
            lines.append(f"--- {e.category}:{e.source} ---")
            lines.append(json.dumps(e.data, default=str)[:1200])
    return "\n".join(lines[:60])


def _ts(item: dict, key: str) -> str:
    v = item.get(key) or ""
    return v


def _actor(item: dict) -> str:
    user = item.get("user")
    if isinstance(user, str):
        return user or "unknown"
    user = user or {}
    return user.get("username") or user.get("uid") or "unknown"