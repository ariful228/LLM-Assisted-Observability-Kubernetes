"""Action MCP tools.

Only four controlled actions exist. Every one requires a policy decision and
goes through input validation -> allowlist -> policy -> authorization ->
execution -> result capture -> audit logging -> verification.

There is deliberately NO shell / kubectl / arbitrary exec tool.
"""

from __future__ import annotations

from typing import Any

from backend.mcp.registry import ToolDef, ToolRegistry
from backend.models.incident import Incident, VerificationResult, VerificationStatus
from backend.services import kube
from backend.services.config import get_settings

_ACTION_REASON = (
    "Action tool: input validated, allow-listed, policy checked, authorized, "
    "executed, result captured, audited and verified. Requires a policy decision."
)


def register_action_tools(registry: ToolRegistry) -> None:
    registry.register(
        ToolDef(
            name="scale_deployment",
            description="Scale a deployed workload by the given delta to the desired replica count.",
            input_schema={
                "deployment": {"type": "string"},
                "namespace": {"type": "string"},
                "delta": {"type": "integer", "default": 1},
                "desired_replicas": {"type": "integer"},
            },
            kind="action",
            impl=_scale_deployment,
            requires_policy=True,
            verify=_verify_scale,
            metadata={"reason": _ACTION_REASON, "allowlist": "deployments"},
        )
    )
    registry.register(
        ToolDef(
            name="restart_deployment",
            description="Rollout-restart a deployment.",
            input_schema={
                "deployment": {"type": "string"},
                "namespace": {"type": "string"},
            },
            kind="action",
            impl=_restart_deployment,
            requires_policy=True,
            verify=_verify_restart,
            metadata={"reason": _ACTION_REASON},
        )
    )
    registry.register(
        ToolDef(
            name="renew_certificate",
            description="Renew the demo serving TLS certificate stored in a Secret.",
            input_schema={
                "namespace": {"type": "string"},
                "secret_name": {"type": "string", "enum": ["cert-demo-tls"]},
                "dns_name": {"type": "string", "enum": ["cert-demo.ai-observability-demo.svc"]},
            },
            kind="action",
            impl=_renew_certificate,
            requires_policy=True,
            verify=_verify_certificate,
            metadata={"reason": _ACTION_REASON},
        )
    )
    registry.register(
        ToolDef(
            name="rollback_rbac",
            description="Delete a suspicious ClusterRoleBinding (rollback).",
            input_schema={
                "binding_name": {"type": "string"},
                "allowed_subjects": {"type": "array", "items": {"type": "string"}, "default": []},
            },
            kind="action",
            impl=_rollback_rbac,
            requires_policy=True,
            verify=_verify_rbac,
            metadata={"reason": _ACTION_REASON},
        )
    )
    registry.register(
        ToolDef(
            name="apply_security_config",
            description=(
                "Apply a security hardening configuration to the simulated demo cluster. "
                "Allowlist-only input; mutation touches the in-process simulation, never live objects."
            ),
            input_schema={
                "config": {
                    "type": "string",
                    "enum": [
                        "drop-privileged",
                        "enable-apparmor",
                        "enable-seccomp",
                        "default-deny-network-policy",
                        "lockdown-kubelet",
                        "tidy-image",
                    ],
                },
                "target": {"type": "string"},
                "namespace": {"type": "string", "enum": ["ai-observability-demo"]},
            },
            kind="action",
            impl=_apply_security_config,
            requires_policy=True,
            verify=_verify_security_config,
            metadata={"reason": _ACTION_REASON, "allowlist": "security-configs"},
        )
    )


def _scale_deployment(deployment: str, namespace: str, delta: int = 1, desired_replicas: int = 0) -> dict[str, Any]:
    if desired_replicas <= 0:
        _raise_guard("desired_replicas required")
    settings = get_settings()
    if deployment not in settings.allowed_deployment_list():
        _raise_guard(f"deployment {deployment} not in allowlist")
    if namespace not in settings.allowed_namespace_list():
        _raise_guard(f"namespace {namespace} not in allowlist")
    _scale_guard(delta, desired_replicas)
    return kube.get_kube().scale_deployment(deployment, namespace, desired_replicas)


def _restart_deployment(deployment: str, namespace: str) -> dict[str, Any]:
    settings = get_settings()
    if deployment not in settings.allowed_deployment_list():
        _raise_guard(f"deployment {deployment} not in allowlist")
    if namespace not in settings.allowed_namespace_list():
        _raise_guard(f"namespace {namespace} not in allowlist")
    return kube.get_kube().restart_deployment(deployment, namespace)


def _renew_certificate(namespace: str, secret_name: str, dns_name: str) -> dict[str, Any]:
    settings = get_settings()
    if namespace not in settings.allowed_namespace_list():
        _raise_guard(f"namespace {namespace} not in allowlist")
    if secret_name not in {"cert-demo-tls"}:
        _raise_guard("secret not allowed")
    return kube.get_kube().renew_certificate(namespace, secret_name, dns_name)


def _rollback_rbac(binding_name: str, allowed_subjects: list[str] | None = None) -> dict[str, Any]:
    settings = get_settings()
    if allowed_subjects:
        configured = settings.allowed_rbac_subjects
        if not configured or not any(s in configured for s in allowed_subjects):
            _raise_guard("binding subject not allowed for rollback")
    return kube.get_kube().rollback_rbac(binding_name)


def _scale_guard(delta: int, desired: int) -> None:
    settings = get_settings()
    if delta is not None and abs(delta) > settings.max_autoscale_delta:
        _raise_guard("delta exceeds max autoscale delta")
    if desired > settings.max_autoscale_replicas:
        _raise_guard("desired replicas exceed max")


def _raise_guard(reason: str) -> None:
    from backend.mcp.registry import PolicyRefused

    raise PolicyRefused(reason)


# -- verification functions ---------------------------------------------------


def _verify_scale(incident: Incident, args: dict[str, Any], output: dict[str, Any]) -> VerificationResult:
    checks: list[dict[str, Any]] = []
    try:
        dep = kube.get_kube().get_deployment(args["deployment"], args["namespace"])
        replicas = int(dep.get("replicas", 0))
        checks.append({"name": "replicas", "expected": args.get("desired_replicas"), "actual": replicas, "passed": replicas == args.get("desired_replicas")})
        checks.append({"name": "desired==available", "passed": dep.get("ready", 0) == dep.get("available", 0)})
        return VerificationResult(
            status=VerificationStatus.PASSED if all(c.get("passed") for c in checks) else VerificationStatus.FAILED,
            checks=checks,
            detail="deployment reached desired replica count",
        )
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(status=VerificationStatus.FAILED, checks=checks, detail=str(exc))


def _verify_restart(incident: Incident, args: dict[str, Any], output: dict[str, Any]) -> VerificationResult:
    checks: list[dict[str, Any]] = []
    try:
        pods = kube.get_kube().get_pods(args["namespace"])
        targets = [p for p in pods if p.get("deployment") == args["deployment"]]
        if not targets:
            return VerificationResult(status=VerificationStatus.FAILED, checks=[], detail="no pods found for deployment")
        all_ready = all("1/1" == p.get("ready") for p in targets)
        all_running = all(p.get("phase") == "Running" for p in targets)
        not_crashing = all(p.get("restarts", 0) < 3 for p in targets)
        checks = [
            {"name": "pods_ready", "passed": all_ready},
            {"name": "all_running", "passed": all_running},
            {"name": "no_crashloop", "passed": not_crashing},
        ]
        return VerificationResult(
            status=VerificationStatus.PASSED if all(c["passed"] for c in checks) else VerificationStatus.FAILED,
            checks=checks,
            detail="pods ready and no CrrLoopBackOff",
        )
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(status=VerificationStatus.FAILED, checks=checks, detail=str(exc))


def _verify_certificate(incident: Incident, args: dict[str, Any], output: dict[str, Any]) -> VerificationResult:
    from backend.services.certmon import get_certificate_monitor

    cert = get_certificate_monitor().status().to_dict()
    checks = [
        {"name": "valid", "passed": cert.get("valid", False)},
        {"name": "days_remaining", "actual": cert.get("days_remaining"), "passed": cert.get("days_remaining", 0) > get_settings().cert_expiry_days_threshold},
        {"name": "chain_valid", "passed": cert.get("chain_valid", False)},
    ]
    return VerificationResult(
        status=VerificationStatus.PASSED if all(c["passed"] for c in checks) else VerificationStatus.FAILED,
        checks=checks,
        detail="certificate renewed and currently valid",
    )


def _verify_rbac(incident: Incident, args: dict[str, Any], output: dict[str, Any]) -> VerificationResult:
    bindings = kube.get_kube().get_rbac()
    gone = not any(b.get("name") == args["binding_name"] for b in bindings)
    checks = [{"name": "binding_removed", "passed": gone}]
    return VerificationResult(
        status=VerificationStatus.PASSED if gone else VerificationStatus.FAILED,
        checks=checks,
        detail="suspicious binding no longer present",
    )


def _apply_security_config(config: str, target: str, namespace: str) -> dict[str, Any]:
    settings = get_settings()
    if namespace not in settings.allowed_namespace_list():
        _raise_guard(f"namespace {namespace} not in allowlist")
    return kube.get_kube().apply_security_config(config, target, namespace)


def _verify_security_config(incident: Incident, args: dict[str, Any], output: dict[str, Any]) -> VerificationResult:
    applied = kube.get_kube().security_config_applied(args.get("config", ""), args.get("target", ""))
    checks = [
        {"name": f"config:{args.get('config')}", "expected": True, "actual": applied, "passed": applied}
    ]
    return VerificationResult(
        status=VerificationStatus.PASSED if applied else VerificationStatus.FAILED,
        checks=checks,
        detail="security config applied to simulated target",
    )