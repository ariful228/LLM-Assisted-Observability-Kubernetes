"""MCP tool registry and controlled executor.

The LLM can only *propose* tool calls. Actual execution goes through this
gate: input validation -> allowlist -> policy -> authorization -> execution
-> result capture -> audit logging -> verification.

Never expose shell / arbitrary kubectl tools here.
"""

from __future__ import annotations

import inspect
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from backend.mcp.validator import ValidationError, validate
from backend.models.incident import (
    ExecutionResult,
    ExecutionStatus,
    Incident,
    PolicyDecision,
    VerificationResult,
    VerificationStatus,
)

logger = logging.getLogger(__name__)


class ToolNotFound(KeyError):
    pass


class InputInvalid(ValueError):
    pass


class PolicyRefused(PermissionError):
    pass


@dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict[str, Any]
    kind: str  # "read" | "action"
    impl: Callable[..., Any]
    requires_policy: bool = False
    timeout_seconds: Optional[float] = None
    verify: Optional[Callable[..., VerificationResult]] = None
    metadata: dict[str, Any] = field(default_factory=dict)


def _tool_timeout(tool: ToolDef) -> float:
    if tool.timeout_seconds is not None:
        return tool.timeout_seconds
    from backend.services.config import get_settings

    return get_settings().action_timeout_seconds


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDef] = {}
        self._lock = threading.RLock()

    def register(self, tool: ToolDef) -> None:
        with self._lock:
            self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDef:
        with self._lock:
            try:
                return self._tools[name]
            except KeyError as exc:
                raise ToolNotFound(name) from exc

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            tools = []
            for name, t in self._tools.items():
                tools.append(
                    {
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": {
                            "type": "object",
                            "properties": t.input_schema,
                        },
                        "kind": t.kind,
                        "requires_policy": t.requires_policy,
                    }
                )
            return tools

    # -- executor ---------------------------------------------------------
    def execute(
        self,
        incident: Incident,
        tool_name: str,
        args: dict[str, Any],
        policy: PolicyDecision | None = None,
        approved: bool = False,
        executor: str = "system",
    ) -> ExecutionResult:
        tool = self.get(tool_name)
        result = ExecutionResult(tool=tool_name)
        result.metadata = {"executor": executor}
        from backend.services import chrono

        result.started_at = chrono.now()
        result.status = ExecutionStatus.EXECUTING
        try:
            # 1) input validation (required = params without a default)
            required = [k for k, v in tool.input_schema.items() if "default" not in v]
            validate(
                {"type": "object", "properties": tool.input_schema, "required": required},
                args,
            )
        except ValidationError as exc:
            result.status = ExecutionStatus.FAILED
            result.error = f"input validation failed: {exc}"
            from backend.services import chrono

            result.finished_at = chrono.now()
            self._audit(incident, tool, args, result, executor, policy)
            return result

        try:
            # 2/3) policy + authorization for action tools
            if tool.kind == "action" and tool.requires_policy:
                self._authorize(incident, tool, args, policy, approved, executor)
                result.metadata = {"policy": policy.model_dump(mode="json") if policy else None, "authorized": True}
            # 4) execution with timeout
            timeout = _tool_timeout(tool)
            kwargs = _bind(tool.impl, args)
            output = _run_with_timeout(tool.impl, kwargs, timeout)
            result.output = _serialize(output)
            result.status = ExecutionStatus.SUCCESS
        except PolicyRefused as exc:
            result.status = ExecutionStatus.FAILED
            result.error = f"policy refusal: {exc}"
        except Exception as exc:  # noqa: BLE001
            result.status = ExecutionStatus.FAILED
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            from backend.services import chrono

            result.finished_at = chrono.now()
            if result.started_at is not None:
                result.duration_ms = (
                    result.finished_at - result.started_at
                ).total_seconds() * 1000
            self._audit(incident, tool, args, result, executor, policy)
        # 5) post-action verification
        if tool.verify is not None and result.status == ExecutionStatus.SUCCESS:
            try:
                result.verification = tool.verify(incident, args, result.output)
            except Exception as exc:  # noqa: BLE001
                result.verification = VerificationResult(
                    status=VerificationStatus.FAILED, detail=f"verification error: {exc}"
                )
        return result

    def _authorize(
        self,
        incident: Incident,
        tool: ToolDef,
        args: dict[str, Any],
        policy: PolicyDecision | None,
        approved: bool,
        executor: str,
    ) -> None:
        """Authorization gate for action tools.

        Requires a policy decision whose action matches, and either an
        AUTO decision or an explicit human approval.
        """
        if policy is None or policy.decision.value == "NO_ACTION":
            raise PolicyRefused("no policy decision; actions cannot run without one")
        if policy.action != tool.name:
            raise PolicyRefused(f"policy authorizes {policy.action}, not {tool.name}")
        if policy.decision.value == "APPROVAL_REQUIRED":
            if not approved:
                raise PolicyRefused("action requires human approval")
        # else: AUTO decision is itself the authorization
        if executor != "system" and not approved and policy.decision.value == "APPROVAL_REQUIRED":
            raise PolicyRefused("approval required from a human")

    def _audit(
        self,
        incident: Incident,
        tool: ToolDef,
        args: dict[str, Any],
        result: ExecutionResult,
        executor: str,
        policy: PolicyDecision | None,
    ) -> None:
        incident.execution_result = result
        incident.execution_status = result.status
        incident.add_to_timeline(
            f"mcp.{tool.name}",
            f"status={result.status.value} executor={executor} policy={policy.rule_id if policy else 'none'}",
        )


def _bind(fn: Callable, args: dict[str, Any]) -> dict[str, Any]:
    """Map keyword args to the target callable's parameters."""
    sig = inspect.signature(fn)
    kwargs = {}
    for pname, p in sig.parameters.items():
        if pname in args:
            kwargs[pname] = args[pname]
    return kwargs


def _run_with_timeout(fn: Callable, kwargs: dict[str, Any], timeout: float) -> Any:
    """Execute synchronously with a hard-ish timeout via threaded future."""
    from concurrent.futures import ThreadPoolExecutor, TimeoutError  # noqa: PLC0415

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fn, **kwargs)
        try:
            return future.result(timeout=timeout)
        except TimeoutError as exc:
            raise TimeoutError(f"tool timed out after {timeout}s") from exc


def _serialize(value: Any) -> Any:
    try:
        from pydantic import BaseModel  # noqa: PLC0415

        if isinstance(value, BaseModel):
            return value.model_dump(mode="json")
    except Exception:  # noqa: BLE001
        pass
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return value
    try:
        import json  # noqa: PLC0415

        return json.loads(json.dumps(value, default=str))
    except Exception:  # noqa: BLE001
        return str(value)


_registry: ToolRegistry | None = None
_registry_lock = threading.Lock()


def get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = ToolRegistry()
                _register_defaults(_registry)
    return _registry


def _register_defaults(registry: ToolRegistry) -> None:
    from backend.mcp.tools_actions import register_action_tools
    from backend.mcp.tools_read import register_read_tools

    register_read_tools(registry)
    register_action_tools(registry)


def reset_registry() -> None:
    global _registry
    with _registry_lock:
        _registry = None