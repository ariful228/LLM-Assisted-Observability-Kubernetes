"""Prometheus instrumentation counters used by the platform.

Registered globally so `generate_latest()` (used by /metrics) picks them up.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

INCIDENTS_DETECTED = Counter(
    "app_incidents_detected_total",
    "Incidents detected by type",
    ["incident_type"],
)
INCIDENTS_RESOLVED = Counter(
    "app_incidents_resolved_total",
    "Incidents resolved by final status",
    ["status", "action"],
)
APPROVALS_TOTAL = Counter(
    "app_approvals_total",
    "Human approval decisions",
    ["decision"],
)
DETECTION_DURATION = Histogram(
    "app_detection_duration_seconds",
    "Detection scan duration",
)
WORKFLOW_DURATION = Histogram(
    "app_workflow_duration_seconds",
    "Workflow investigation+execution duration",
    ["decision"],
)


def record_detected(incident_type: str) -> None:
    INCIDENTS_DETECTED.labels(incident_type=incident_type).inc()


def record_resolved(status: str, action: str = "") -> None:
    INCIDENTS_RESOLVED.labels(status=status, action=action or "none").inc()


def record_approval(decision: str) -> None:
    APPROVALS_TOTAL.labels(decision=decision).inc()