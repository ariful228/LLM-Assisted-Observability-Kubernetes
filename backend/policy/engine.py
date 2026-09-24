"""Policy engine.

The authoritative decision point. The LLM proposes a recommendation; this
engine decides whether that action is AUTO, APPROVAL_REQUIRED or blocked.
A failed policy check MUST default to NO_ACTION (spec section 23).

Rules are deterministic and auditable; every decision records rule_id + reason.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from backend.models.incident import (
    Incident,
    IncidentType,
    PolicyDecision,
    PolicyDecisionType,
    SecurityFinding,
    SecurityLayer,
)
from backend.services.config import get_settings

logger = logging.getLogger(__name__)


class PolicyError(RuntimeError):
    """Raised when policy evaluation itself fails -> caller must fail closed."""


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    incident_type: IncidentType
    action: str
    decision: PolicyDecisionType
    reason: str


@dataclass(frozen=True)
class FindingRule:
    """Static policy rule for security findings (spec §23 extended).

    Keyed on control-layer; the decision is the only thing the policy engine
    may output for a finding — the LLM only proposes, it never decides.
    """

    rule_id: str
    layer: str
    allowed_actions: frozenset[str]
    decision: PolicyDecisionType
    reason: str


def _rules() -> list[PolicyRule]:
    """Static policy table (spec section 15). Ordered, first match wins."""
    return [
        PolicyRule("P-01", IncidentType.HIGH_CPU, "scale_deployment", PolicyDecisionType.AUTO, "sustained high CPU is predefined low-risk; scale +1 is allowed automatically"),
        PolicyRule("P-02", IncidentType.HIGH_MEMORY, "request_memory_review", PolicyDecisionType.APPROVAL_REQUIRED, "changing resource limits can trigger evictions; human approval required"),
        PolicyRule("P-03", IncidentType.HIGH_MEMORY, "scale_deployment", PolicyDecisionType.APPROVAL_REQUIRED, "memory incidents require human confirmation before any scaling action"),
        PolicyRule("P-04", IncidentType.OOM_KILLED, "scale_deployment", PolicyDecisionType.APPROVAL_REQUIRED, "OOM incidents require human confirmation before any scaling action"),
        PolicyRule("P-05", IncidentType.CRASH_LOOP_BACK_OFF, "restart_deployment", PolicyDecisionType.APPROVAL_REQUIRED, "restart requires human confirmation before disruptive rollout"),
        PolicyRule("P-06", IncidentType.CERTIFICATE_EXPIRY, "renew_certificate", PolicyDecisionType.APPROVAL_REQUIRED, "certificate renewal is not automatic unless explicitly permitted"),
        PolicyRule("P-07", IncidentType.FALCO_SECURITY, "none", PolicyDecisionType.APPROVAL_REQUIRED, "security remediation follows a human-approved plan; pods are not terminated automatically"),
        PolicyRule("P-08", IncidentType.SUSPICIOUS_RBAC, "rollback_rbac", PolicyDecisionType.APPROVAL_REQUIRED, "RBAC rollback is a privileged action; human approval required"),
        PolicyRule("P-99", IncidentType.UNKNOWN, "none", PolicyDecisionType.NO_ACTION, "unknown incident type; no action"),
    ]


def _finding_rules() -> list[FindingRule]:
    """Security-finding policy table (ordered, first match wins).

    Layer-0 is the host policy rule set: recovery actions on a misbehaving app
    workload are low-risk and may auto-run; everything at container / node /
    cluster layer requires a human-approved plan.
    """
    return [
        FindingRule(
            "F-01",
            SecurityLayer.APPLICATION.value,
            frozenset({"restart_deployment", "scale_deployment"}),
            PolicyDecisionType.AUTO,
            "application-layer recovery (restart/scale of an allow-listed demo workload) is low-risk and auto-allowed",
        ),
        FindingRule(
            "F-02",
            SecurityLayer.CONTAINER.value,
            frozenset({"apply_security_config", "restart_deployment"}),
            PolicyDecisionType.APPROVAL_REQUIRED,
            "container hardening changes require human approval before being applied",
        ),
        FindingRule(
            "F-03",
            SecurityLayer.NODE_CLOUD.value,
            frozenset({"apply_security_config"}),
            PolicyDecisionType.APPROVAL_REQUIRED,
            "node/cloud-plane hardening requires human approval",
        ),
        FindingRule(
            "F-04",
            SecurityLayer.KUBERNETES_CLUSTER.value,
            frozenset({"rollback_rbac", "apply_security_config"}),
            PolicyDecisionType.APPROVAL_REQUIRED,
            "cluster-scoped remediation (RBAC / policy) requires human approval",
        ),
        FindingRule(
            "F-99",
            "unknown",
            frozenset(),
            PolicyDecisionType.NO_ACTION,
            "unknown security layer or action; no remediation",
        ),
    ]


class PolicyEngine:
    def __init__(self) -> None:
        self._settings_provider = get_settings

    @property
    def settings(self):
        return self._settings_provider()

    def evaluate(self, incident: Incident, requested_action: str | None = None, params: dict | None = None) -> PolicyDecision:
        """Evaluate the policy for the incident and (optionally) a specific action.

        Failures default to NO_ACTION so the LLM can never trigger unintended work.
        """
        try:
            return self._evaluate(incident, requested_action, params)
        except Exception:  # noqa: BLE001
            logger.exception("policy evaluation failed; failing closed to NO_ACTION")
            return PolicyDecision(
                decision=PolicyDecisionType.NO_ACTION,
                rule_id="P-FAIL",
                reason="policy evaluation failed; failed closed",
                made_by="policy_engine",
            )

    def _evaluate(self, incident: Incident, requested_action: str | None, params: dict | None) -> PolicyDecision:
        action = requested_action or (incident.recommended_action.action if incident.recommended_action else None) or "none"
        params = params or (incident.recommended_action.params if incident.recommended_action else {})
        incident_type = incident.incident_type

        for rule in _rules():
            if rule.incident_type == incident_type and (
                rule.action == action or rule.action == "none"
            ):
                decision = self._apply_guardrails(rule, action, params)
                decision.action = action
                decision.params = dict(params)
                return decision

        return PolicyDecision(
            decision=PolicyDecisionType.NO_ACTION,
            rule_id="P-UNMATCHED",
            reason=f"no policy rule matched incident type {incident_type.value}",
            action=action,
            params=dict(params),
            made_by="policy_engine",
        )

    def evaluate_finding(self, finding: SecurityFinding) -> PolicyDecision:
        """Authoritative decision for a security finding.

        Same fail-closed contract as incidents: a finding that is not covered
        by an explicit rule defaults to NO_ACTION, so the (advisory) LLM can
        never cause remediation work by itself.
        """
        try:
            return self._evaluate_finding(finding)
        except Exception:  # noqa: BLE001
            logger.exception("finding policy evaluation failed; failing closed to NO_ACTION")
            return PolicyDecision(
                decision=PolicyDecisionType.NO_ACTION,
                rule_id="F-FAIL",
                reason="finding policy evaluation failed; failed closed",
                made_by="policy_engine",
            )

    def _evaluate_finding(self, finding: SecurityFinding) -> PolicyDecision:
        layer = finding.layer.value
        action = finding.recommended_action or "none"
        params = dict(finding.action_params)

        for rule in _finding_rules():
            if rule.layer != layer:
                continue
            if action != "none" and action not in rule.allowed_actions:
                return PolicyDecision(
                    decision=PolicyDecisionType.NO_ACTION,
                    rule_id=rule.rule_id + "-guard",
                    reason=f"action {action!r} not allowed at layer {layer}",
                    action=action,
                    params=params,
                    made_by="policy_engine",
                )
            decision = self._apply_finding_guardrails(rule, action, params)
            decision.action = action
            decision.params = params
            return decision

        return PolicyDecision(
            decision=PolicyDecisionType.NO_ACTION,
            rule_id="F-UNMATCHED",
            reason=f"no finding policy rule matched layer {layer}",
            action=action,
            params=params,
            made_by="policy_engine",
        )

    def _apply_finding_guardrails(self, rule: FindingRule, action: str, params: dict) -> PolicyDecision:
        settings = self.settings
        if "namespace" in params and params["namespace"] not in settings.allowed_namespace_list():
            return PolicyDecision(
                decision=PolicyDecisionType.NO_ACTION,
                rule_id=rule.rule_id + "-guard",
                reason=f"namespace {params['namespace']} not allowed",
                auto_allowed=False,
                made_by="policy_engine",
            )
        if "deployment" in params and params["deployment"] not in settings.allowed_deployment_list():
            return PolicyDecision(
                decision=PolicyDecisionType.NO_ACTION,
                rule_id=rule.rule_id + "-guard",
                reason=f"deployment {params['deployment']} not in allowlist",
                auto_allowed=False,
                made_by="policy_engine",
            )
        return PolicyDecision(
            decision=rule.decision,
            rule_id=rule.rule_id,
            reason=rule.reason,
            auto_allowed=rule.decision == PolicyDecisionType.AUTO,
            made_by="policy_engine",
        )

    def _apply_guardrails(self, rule: PolicyRule, action: str, params: dict) -> PolicyDecision:
        """Enforce allowlists, max deltas and max replicas before ANY action."""
        settings = self.settings
        # 1) maximum scale delta for AUTO actions
        if action == "scale_deployment":
            delta = int(params.get("delta", 0) or 0)
            desired = int(params.get("desired_replicas", 0) or 0)
            if rule.decision == PolicyDecisionType.AUTO and delta > settings.max_autoscale_delta:
                return PolicyDecision(decision=PolicyDecisionType.NO_ACTION, rule_id=rule.rule_id + "-guard", reason="auto scale delta exceeds configured max", auto_allowed=False, made_by="policy_engine")
            if desired > settings.max_autoscale_replicas:
                return PolicyDecision(decision=PolicyDecisionType.NO_ACTION, rule_id=rule.rule_id + "-guard", reason="desired replicas exceed configured max", auto_allowed=False, made_by="policy_engine")

        # 2) namespace allowlist
        if "namespace" in params and params["namespace"] not in settings.allowed_namespace_list():
            return PolicyDecision(decision=PolicyDecisionType.NO_ACTION, rule_id=rule.rule_id + "-guard", reason=f"namespace {params['namespace']} not allowed", auto_allowed=False, made_by="policy_engine")

        # 3) deployment allowlist
        if "deployment" in params and params["deployment"] not in settings.allowed_deployment_list():
            return PolicyDecision(
                decision=PolicyDecisionType.NO_ACTION,
                rule_id=rule.rule_id + "-guard",
                reason=f"deployment {params['deployment']} not in allowlist",
                auto_allowed=False,
                made_by="policy_engine",
            )
        return PolicyDecision(
            decision=rule.decision,
            rule_id=rule.rule_id,
            reason=rule.reason,
            auto_allowed=rule.decision == PolicyDecisionType.AUTO,
            made_by="policy_engine",
        )


_policy: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    global _policy
    if _policy is None:
        _policy = PolicyEngine()
    return _policy