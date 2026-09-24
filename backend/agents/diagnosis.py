"""Diagnosis agent: LLM-based reasoning over collected evidence + RAG context.

Only produces a recommendation; it has no execution capability.
"""

from __future__ import annotations

from backend.agents.correlation import evidence_text
from backend.models.incident import Diagnosis, Incident
from backend.services import llm
from backend.services.rag import get_index


def diagnose(incident: Incident) -> Incident:
    rag_context = _rag_context(incident)
    incident.rag_sources = get_index().search(incident.classification or incident.incident_type.value, top_k=4)
    evidence = evidence_text(incident)
    diagnosis = llm.get_llm().diagnose(incident, evidence, rag_context)
    incident.diagnosis = diagnosis
    incident.add_to_timeline("diagnosis", diagnosis.summary)
    return incident


def _rag_context(incident: Incident) -> str:
    docs = incident.rag_sources
    if not docs:
        return ""
    return "\n\n".join(f"[{d.document}] {d.excerpt}" for d in docs)