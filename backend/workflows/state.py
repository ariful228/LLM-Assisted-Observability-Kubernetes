"""LangGraph workflow state (spec section 10)."""

from __future__ import annotations

from typing import TypedDict


class WorkflowState(TypedDict, total=False):
    incident_id: str
    decision: str  # AUTO | APPROVAL_REQUIRED | NO_ACTION
    approval_required: bool
    approved: bool  # set true on approval resume
    approve_payload: dict  # resume payload: {"approved": bool, "by": str, "reason": str}
    execution_status: str
    error: str
    stage: str