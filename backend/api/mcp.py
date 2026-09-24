"""MCP tool display + safe invocation endpoints (read tools only)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from backend.mcp.registry import ToolNotFound, get_registry
from backend.mcp.validator import ValidationError, validate

router = APIRouter(prefix="/api/mcp", tags=["mcp"])


@router.get("/tools")
def list_tools() -> dict[str, Any]:
    return {"tools": get_registry().list()}


@router.get("/no-unsafe-tools")
def no_unsafe_tools() -> dict[str, Any]:
    """Prove the controlled layer exposes no shell/kubectl/arbitrary exec."""
    blocked = {"execute_shell", "run_kubectl", "run_command", "arbitrary_exec"}
    names = {t["name"] for t in get_registry().list()}
    return {"blocked_tools": sorted(blocked), "present": sorted(blocked & names), "pass": not (blocked & names)}


@router.post("/invoke/{tool_name}")
def invoke(tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Demo invocation of a READ tool only. Action tools require an incident flow."""
    try:
        tool = get_registry().get(tool_name)
    except ToolNotFound:
        raise HTTPException(status_code=404, detail="tool not found") from None
    if tool.kind != "read":
        raise HTTPException(status_code=403, detail="action tools are gated by the policy engine; use the approval workflow")
    try:
        required = [k for k, v in tool.input_schema.items() if "default" not in v]
        validate(
            {"type": "object", "properties": tool.input_schema, "required": required},
            payload or {},
        )
        from backend.mcp.registry import _bind, _run_with_timeout, _serialize

        args = _bind(tool.impl, payload or {})
        output = _run_with_timeout(tool.impl, args, 10.0)
        return {"tool": tool_name, "result": "ok", "output": _serialize(output)}
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=f"invalid input: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc