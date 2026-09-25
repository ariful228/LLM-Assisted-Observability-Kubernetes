"""LLM provider abstraction.

`mock`  -> deterministic, evidence-driven "diagnosis" so the demo runs offline.
`openai`-> any OpenAI-compatible endpoint (also local models via vLLM/llama.cpp).
`ollama` -> local Ollama.

The LLM is used ONLY for investigation / correlation / explanation / reasoning,
never for executing Kubernetes actions.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from backend.models.incident import Diagnosis, Incident, RiskLevel, SecurityFinding
from backend.services.config import get_settings

logger = logging.getLogger(__name__)


class LLM:
    def __init__(self) -> None:
        self._settings_provider = get_settings

    @property
    def settings(self):
        return self._settings_provider()

    def provider(self) -> str:
        return self.settings.llm_provider

    # -- structured invocation ---------------------------------------------
    def diagnose(self, incident: Incident, evidence_text: str, rag_context: str) -> Diagnosis:
        if self.provider() == "mock":
            return _mock_diagnosis(incident, evidence_text)
        prompt = _diagnosis_prompt(incident, evidence_text, rag_context)
        raw = self._chat(prompt)
        try:
            data = _extract_json(raw)
            return Diagnosis.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM structured output failed, falling back to mock: %s", exc)
            return _mock_diagnosis(incident, evidence_text)

    def diagnose_finding(self, finding: SecurityFinding) -> str:
        """Advisory prose diagnosis for a security finding.

        The LLM explains *what* the issue is and *proposes* a remedy. It never
        executes anything — the policy engine decides the remediation path.
        """
        if self.provider() == "mock":
            return _mock_finding_diagnosis(finding)
        prompt = (
            "You are a Kubernetes security engineer. Given the "
            "security finding below return a single paragraph: what the issue is, "
            "why it matters, and a proposed remediation. End with the line "
            "'POLICY ENGINE AUTHORITATIVE — LLM IS ADVISORY ONLY.'\n"
            f"FINDING: {finding.model_dump_json(exclude={'evidence', 'timeline', 'verification_checks'})}\n"
        )
        return self._chat(prompt) or _mock_finding_diagnosis(finding)

    def _chat(self, prompt: str) -> str:
        provider = self.provider()
        try:
            if provider == "openai":
                from langchain_openai import ChatOpenAI  # noqa: PLC0415

                model = ChatOpenAI(
                    model=self.settings.llm_model,
                    api_key=self.settings.llm_api_key,
                    base_url=self.settings.llm_base_url or None,
                    temperature=self.settings.llm_temperature,
                    timeout=self.settings.llm_timeout_seconds,
                )
            elif provider == "ollama":
                from langchain_ollama import ChatOllama  # noqa: PLC0415

                model = ChatOllama(
                    model=self.settings.llm_model,
                    temperature=self.settings.llm_temperature,
                    base_url=self.settings.llm_base_url or "http://localhost:11434",
                )
            else:
                raise RuntimeError(f"unknown provider {provider}")
            response = model.invoke(prompt)
            return str(response.content)
        except Exception as exc:  # noqa: BLE001
            logger.warning("LLM call failed (%s), using mock diagnosis: %s", provider, exc)
            return ""

    def ready(self) -> bool:
        return True


class RiskAssessor:
    def __init__(self, llm: LLM | None = None) -> None:
        self.llm = llm or get_llm()

    def assess(self, incident: Incident, diagnosis: Diagnosis) -> RiskLevel:
        """Combine incident type, diagnosis confidence and evidence into a risk level."""
        if self.llm.provider() != "mock":
            # heuristic guard: risk is computed deterministically and bounded
            # even when a real LLM is used, so the policy engine never trusts an
            # unrestricted model judgment.
            pass
        return _risk_for(incident, diagnosis)


def _risk_for(incident: Incident, diagnosis: Diagnosis) -> RiskLevel:
    # Security and crash incidents are inherently higher risk.
    if incident.incident_type.value in {
        "falco_security",
        "suspicious_rbac",
        "crashloop_backoff",
        "oom_killed",
    }:
        return RiskLevel.HIGH
    if incident.incident_type.value == "high_memory":
        return RiskLevel.MEDIUM
    if incident.incident_type.value in {"high_cpu", "certificate_expiry"}:
        return RiskLevel.LOW
    return diagnosis.risk_level


def _mock_finding_diagnosis(finding: SecurityFinding) -> str:
    return (
        f"Why: {finding.root_cause or finding.issue} "
        f"(layer={finding.layer.value}, domain={finding.domain or 'n/a'}). "
        f"Proposed remedy: {finding.recommended_solution}. "
        "POLICY ENGINE AUTHORITATIVE — LLM IS ADVISORY ONLY."
    )


def _mock_diagnosis(incident: Incident, evidence_text: str) -> Diagnosis:
    itype = incident.incident_type.value
    ns = incident.namespace
    resource = incident.resource
    summary = f"{itype.replace('_', ' ').title()} detected on {resource} in namespace {ns}."
    cause = ""
    action = ""
    expected = ""
    confidence = 0.62

    if itype == "high_cpu":
        cause = "cpu-demo workload sustains high CPU utilisation (>80%) for more than 5 minutes; no CPU limit is configured."
        action = "scale_deployment"
        expected = "scaling cpu-demo from 2 to 3 replicas distributes load and lowers per-pod utilisation."
        confidence = 0.8
    elif itype in ("high_memory", "oom_killed"):
        cause = "memory-demo container exceeds its memory limit and is terminated by the kernel OOM killer; memory growth without a limit hit."
        action = "scale_deployment"
        expected = "scaling deployment reduces memory pressure; long-term fix requires memory leak investigation."
        confidence = 0.72
    elif itype == "crashloop_backoff":
        cause = "container exits immediately with code 1 (config file not found); readiness/termination causes CrashLoopBackOff."
        action = "restart_deployment"
        expected = "restarting the deployment re-fetches the config sidecar; remains a config fix."
        confidence = 0.78
    elif itype == "certificate_expiry":
        cause = "TLS serving certificate for cert-demo expires in under 7 days."
        action = "renew_certificate"
        expected = "renewing the certificate re-issues a 1-year valid certificate."
        confidence = 0.84
    elif itype == "falco_security":
        cause = "Falco detected an interactive shell spawned inside test-pod followed by a read of a sensitive file; Kubernetes audit log shows a pods/exec request by admin@example.com."
        action = "none"
        expected = "no automatic remediation; investigate and quarantine the pod."
        confidence = 0.7
    elif itype == "suspicious_rbac":
        cause = "A ClusterRoleBinding granted cluster-admin to ServiceAccount/ci-bot; audit log attributes the request to a CI bot user."
        action = "rollback_rbac"
        expected = "deleting the binding restores least-privilege RBAC."
        confidence = 0.82
    else:
        cause = "Evidence does not clearly identify a single root cause."
        action = "none"

    evidence_summary = evidence_text[:400] if evidence_text else "no structured evidence available"
    explanation = (
        f"Recommendation {action} is proposed based on collected evidence. "
        "The policy engine makes the final authority decision."
    )
    return Diagnosis(
        summary=summary,
        cause=cause,
        evidence_summary=evidence_summary,
        recommended_action=action,
        risk_level=_risk_for(incident, Diagnosis(summary=summary, cause=cause, confidence=confidence)),
        expected_result=expected,
        confidence=confidence,
        explanation=explanation,
    )


def _diagnosis_prompt(incident: Incident, evidence_text: str, rag_context: str) -> str:
    return (
        "You are a Kubernetes site-reliability engineer. Given the incident below, "
        "return ONLY a JSON object with keys: summary, cause, evidence_summary, "
        "recommended_action (one of scale_deployment, restart_deployment, "
        "renew_certificate, rollback_rbac, or none), risk_level (low|medium|high|critical), "
        "expected_result, confidence (0..1), explanation.\n"
        f"INCIDENT: {incident.model_dump_json(exclude={'timeline', 'evidence', 'metrics', 'rag_sources'})}\n"
        f"EVIDENCE: {evidence_text[:3000]}\n"
        f"KNOWLEDGE: {rag_context[:2500]}\n"
    )


def _extract_json(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no json in response")
    return json.loads(text[start : end + 1])


_llm: LLM | None = None
_llm_lock = threading.Lock()


def get_llm() -> LLM:
    global _llm
    if _llm is None:
        with _llm_lock:
            if _llm is None:
                _llm = LLM()
    return _llm