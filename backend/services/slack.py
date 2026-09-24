"""Slack notifications (notification-only channel).

Messages never carry secrets and never trigger actions. A failed Slack call
must never block remediation, so all failures are logged and swallowed.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from prometheus_client import Counter

from backend.services.config import get_settings

logger = logging.getLogger(__name__)

SLACK_SENT = Counter("aio_slack_messages_total", "Slack messages sent")
SLACK_FAILED = Counter("aio_slack_failures_total", "Slack send failures")


class SlackNotifier:
    def __init__(self) -> None:
        self._settings_provider = get_settings

    @property
    def settings(self):
        return self._settings_provider()

    def enabled(self) -> bool:
        s = self.settings
        return bool(s.slack_enabled and s.slack_webhook_url)

    def send(self, text: str, blocks: list[dict[str, Any]] | None = None) -> bool:
        if not self.enabled():
            logger.info("Slack disabled; skipping notification: %s", text[:120])
            return False
        payload: dict[str, Any] = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        if self.settings.slack_channel:
            payload["channel"] = self.settings.slack_channel
        try:
            resp = httpx.post(self.settings.slack_webhook_url, json=payload, timeout=5.0)
            if resp.status_code >= 400:
                raise RuntimeError(f"slack http {resp.status_code}")
            SLACK_SENT.inc()
            logger.info("Slack notification sent")
            return True
        except Exception as exc:  # noqa: BLE001
            SLACK_FAILED.inc()
            logger.warning("Slack notification failed (ignored): %s", exc)
            return False

    # -- notification builders ---------------------------------------------
    def critical_incident(self, incident: Any) -> None:
        text = (
            f"[{incident.severity.upper()}] Incident {incident.incident_id} "
            f"({incident.incident_type.value}) namespace={incident.namespace} "
            f"resource={incident.resource} detected={incident.detected_at.isoformat()}"
        )
        self.send(text, self._link_blocks(text, incident))

    def auto_remediated(self, incident: Any) -> None:
        exec_result = incident.execution_result
        detail = (
            f"execution={exec_result.status.value} error={exec_result.error}"
            if exec_result
            else ""
        )
        text = (
            f"[AUTO-REMEDIATED] {incident.incident_id} action={incident.policy_decision.action} "
            f"target={incident.resource} result={incident.execution_status.value} {detail}"
        )
        self.send(text, self._link_blocks(text, incident))

    def approval_required(self, incident: Any) -> None:
        action = incident.recommended_action
        text = (
            f"[APPROVAL REQUIRED] {incident.incident_id} type={incident.incident_type.value} "
            f"target={incident.resource} action={action.action if action else 'n/a'} "
            f"risk={incident.risk_level.value} reason={incident.policy_decision.reason if incident.policy_decision else ''}"
        )
        self.send(text, self._link_blocks(text, incident))

    def security_incident(self, incident: Any, falco: Any = None, audit: Any = None) -> None:
        detail = "falco_suspicious"
        text = (
            f"[SECURITY] {incident.incident_id} ({incident.incident_type.value}) "
            f"pod={incident.resource} namespace={incident.namespace} risk={incident.risk_level.value} "
            f"approval={incident.approval_status.value} detail={detail}"
        )
        self.send(text, self._link_blocks(text, incident))

    def approval_resolved(self, incident: Any, verdict: str) -> None:
        text = (
            f"[APPROVAL {verdict.upper()}] {incident.incident_id} action="
            f"{incident.recommended_action.action if incident.recommended_action else 'n/a'} "
            f"by={incident.approved_by}"
        )
        self.send(text, self._link_blocks(text, incident))

    def verification_failed(self, incident: Any) -> None:
        text = (
            f"[VERIFICATION FAILED] {incident.incident_id} after "
            f"{incident.policy_decision.action if incident.policy_decision else 'n/a'}"
        )
        self.send(text, self._link_blocks(text, incident))

    def _link_blocks(self, text: str, incident: Any) -> list[dict[str, Any]]:
        blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
        links = []
        if self.settings.grafana_url:
            links.append(
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Grafana"},
                    "url": self.settings.grafana_url,
                }
            )
        links.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Incident UI"},
                "url": self.settings.frontend_url(f"incidents/{incident.incident_id}"),
            }
        )
        if links:
            blocks.append({"type": "actions", "elements": list(links)})
        return blocks


_slack: SlackNotifier | None = None


def get_slack() -> SlackNotifier:
    global _slack
    if _slack is None:
        _slack = SlackNotifier()
    return _slack