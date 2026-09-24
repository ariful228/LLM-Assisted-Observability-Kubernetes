"""Deterministic, stateful simulated data for the six demo scenarios.

Used when `EXTERNAL_MODE=simulated` or when live integrations are unavailable.
Provides realistic-looking Prometheus series, Kubernetes objects, Falco events,
Kubernetes audit-log events and certificate state so the whole research demo
can run on a single laptop.

The state is mutable so that MCP actions (scale / restart / rollback / renew)
produce verifiable side effects during the demo.
"""

from __future__ import annotations

import random
import threading
from datetime import timedelta
from typing import Any

from backend.services import chrono

_lock = threading.RLock()


def _rand(seed: int, lo: float = 0.0, hi: float = 1.0) -> float:
    return random.Random(seed).uniform(lo, hi)


# ---------------------------------------------------------------------------
# Mutable simulated cluster state ---------------------------------------------
# ---------------------------------------------------------------------------


def _base_deployments() -> dict[str, dict[str, Any]]:
    return {
        "demo-app": {"replicas": 2, "ready": 2, "available": 2},
        "cpu-demo": {"replicas": 2, "ready": 2, "available": 2},
        "memory-demo": {"replicas": 1, "ready": 1, "available": 1, "ready_pods": ["memory-demo-65467c7b58-r9jjk"]},
        "crash-demo": {"replicas": 1, "ready": 0, "available": 0, "crashing": True},
        "cert-demo": {"replicas": 1, "ready": 1, "available": 1},
    }


def _base_pods() -> list[dict[str, Any]]:
    return [
        _pod("demo-app-7d5f8bdf4c-abc11", "demo-app", "Running", "1/1", 0, "nginx:1.25", 35.2, 48.0, [["demo-app", "running", 0, "nginx:1.25"]]),
        _pod("cpu-demo-55966f7b94-x87zz", "cpu-demo", "Running", "1/1", 0, "python:3.12-slim", 94.0, 30.0, [["cpu-demo", "running", 0, "python:3.12-slim"]]),
        _pod("cpu-demo-55966f7b94-y11aa", "cpu-demo", "Running", "1/1", 0, "python:3.12-slim", 91.0, 28.0, [["cpu-demo", "running", 0, "python:3.12-slim"]]),
        _pod("memory-demo-65467c7b58-r9jjk", "memory-demo", "Running", "1/1", 2, "python:3.12-slim", 12.0, 93.0, [["memory-demo", "waiting", 2, "python:3.12-slim", "OOMKilled", 137]]),
        _pod("crash-demo-765c8f7d21-qqw44", "crash-demo", "Running", "0/1", 7, "busybox:1.36", 1.0, 2.0, [["crash-demo", "waiting", 7, "busybox:1.36", "Error", 1]]),
        _pod("test-pod", "", "Running", "1/1", 0, "nginx:1.25", 5.0, 20.0, [["test-pod", "running", 0, "nginx:1.25"]]),
    ]


def _pod(name, deployment, phase, ready, restarts, image, cpu, mem, containers):
    return {
        "name": name,
        "deployment": deployment,
        "namespace": "ai-observability-demo",
        "phase": phase,
        "ready": ready,
        "restarts": restarts,
        "image": image,
        "cpu_usage_percent": cpu,
        "memory_usage_percent": mem,
        "containers": [
            {
                "name": c[0],
                "state": c[1],
                "restart_count": c[2],
                "image": c[3],
                **(
                    {
                        "last_state": {
                            "terminated": {
                                "reason": c[4],
                                "exit_code": c[5],
                                "message": "simulated termination",
                            }
                        }
                    }
                    if len(c) > 4
                    else {}
                ),
            }
            for c in containers
        ],
    }


def _base_rbac() -> list[dict[str, Any]]:
    now = chrono.now()
    return [
        {
            "kind": "ClusterRoleBinding",
            "name": "ai-observability-reader",
            "role": "ClusterRole/ai-observability-reader",
            "subjects": ["ServiceAccount/ai-observability-backend/ai-observability-demo"],
            "created_at": (now - timedelta(days=30)).isoformat(),
        },
        {
            "kind": "ClusterRoleBinding",
            "name": "ci-bot-cluster-admin",
            "role": "ClusterRole/cluster-admin",
            "subjects": ["ServiceAccount/ci-bot/ci"],
            "created_at": (now - timedelta(minutes=18)).isoformat(),
            "suspicious": True,
        },
    ]


_STATE: dict[str, Any] = {}


def _ensure_state() -> dict[str, Any]:
    if not _STATE:
        _STATE["deployments"] = _base_deployments()
        _STATE["pods"] = _base_pods()
        _STATE["rbac"] = _base_rbac()
        _STATE["cert"] = {
            "days_remaining": 4.0,
            "valid": True,
            "chain_valid": True,
            "renewed": False,
        }
        _STATE["security_configs"] = {}
    return _STATE


def reset_simulation() -> None:
    with _lock:
        _STATE.clear()


def _deploy_state(name: str) -> dict[str, Any]:
    state = _ensure_state()
    if name not in state["deployments"]:
        state["deployments"][name] = {"replicas": 1, "ready": 1, "available": 1}
    return state["deployments"][name]


def _pod_state() -> list[dict[str, Any]]:
    return _ensure_state()["pods"]


# ---------------------------------------------------------------------------
# Prometheus ---------------------------------------------------------------
# ---------------------------------------------------------------------------


def prometheus_cpu_series(
    deployment: str, namespace: str, minutes: int = 15, utilization: float = 0.93
):
    now = chrono.now()
    rng = random.Random(hash(f"cpu-{deployment}") % 10**9)
    series = []
    for idx in range(minutes):
        t = now - timedelta(minutes=(minutes - idx))
        base = utilization * 100
        v = max(0.0, min(100.0, base + rng.uniform(-4, 3)))
        if idx < minutes - 8:
            v = max(20.0, min(60.0, 40 + rng.uniform(-10, 10)))
        series.append({"t": t.isoformat(), "v": round(v, 2)})
    return series


def prometheus_memory_series(
    deployment: str, namespace: str, minutes: int = 15, utilization: float = 0.92
):
    now = chrono.now()
    rng = random.Random(hash(f"mem-{deployment}") % 10**9)
    series = []
    for idx in range(minutes):
        t = now - timedelta(minutes=(minutes - idx))
        base = utilization * 100
        v = max(0.0, min(100.0, base + rng.uniform(-5, 3)))
        if idx < minutes - 6:
            v = max(30.0, min(70.0, 50 + rng.uniform(-10, 10)))
        series.append({"t": t.isoformat(), "v": round(v, 2)})
    return series


def prometheus_query(query: str, _steps: int = 15) -> dict[str, Any]:
    """Simulated answer for a subset of the queries the collector issues."""
    q = query.lower()
    now = chrono.now()
    deploy = _deployment_in(q) or "demo-app"

    def points(series: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return series

    if "container_cpu_usage_seconds_total" in q:
        return {"series": points(prometheus_cpu_series(deploy, "ai-observability-demo"))}
    if "container_memory_working_set_bytes" in q:
        return {"series": points(prometheus_memory_series(deploy, "ai-observability-demo"))}
    if "restarts_total" in q:
        base = 3.0 if deploy == "crash-demo" else 0.5
        return {"series": [{"t": (now - timedelta(minutes=i)).isoformat(), "v": base} for i in range(15)]}
    if "deployment_status_replicas" in q:
        return {"series": [{"t": (now - timedelta(minutes=i)).isoformat(), "v": _deploy_state(deploy)["replicas"]} for i in range(15)]}
    return {"series": []}


def _deployment_in(query: str) -> str | None:
    import re

    m = re.search(r"deployment\s*=\s*[\"']([^\"']+)[\"']", query)
    if m:
        return m.group(1)
    m2 = re.search(r"(cpu-demo|memory-demo|demo-app|crash-demo|cert-demo)", query)
    return m2.group(1) if m2 else "demo-app"


def prometheus_healthy() -> bool:
    return True


# ---------------------------------------------------------------------------
# Kubernetes -----------------------------------------------------------------
# ---------------------------------------------------------------------------


def kube_pods(namespace: str = "ai-observability-demo") -> list[dict[str, Any]]:
    return [p for p in _pod_state() if p["namespace"] == namespace]


def kube_deployments(namespace: str = "ai-observability-demo") -> list[dict[str, Any]]:
    state = _ensure_state()
    images = {
        "demo-app": "nginx:1.25",
        "cpu-demo": "python:3.12-slim",
        "memory-demo": "python:3.12-slim",
        "crash-demo": "busybox:1.36",
        "cert-demo": "nginx:1.25",
    }
    out = []
    for name, st in state["deployments"].items():
        out.append(
            {
                "name": name,
                "namespace": namespace,
                "replicas": st["replicas"],
                "ready": st["ready"],
                "available": st["available"],
                "image": images.get(name, "unknown"),
            }
        )
    return out


def kube_events(namespace: str = "ai-observability-demo") -> list[dict[str, Any]]:
    now = chrono.now()
    return [
        {
            "type": "Warning",
            "reason": "FailedScheduling",
            "message": "0/2 nodes are available: insufficient cpu.",
            "involved_object": "Pod/cpu-demo",
            "count": 1,
            "last_timestamp": (now - timedelta(minutes=4)).isoformat(),
        },
        {
            "type": "Warning",
            "reason": "BackOff",
            "message": "Back-off restarting failed container",
            "involved_object": "Pod/crash-demo",
            "count": 7,
            "last_timestamp": (now - timedelta(minutes=2)).isoformat(),
        },
        {
            "type": "Warning",
            "reason": "OOMKilled",
            "message": "Container memory-demo was OOM-killed",
            "involved_object": "Pod/memory-demo",
            "count": 2,
            "last_timestamp": (now - timedelta(minutes=12)).isoformat(),
        },
        {
            "type": "Normal",
            "reason": "SuccessfulCreate",
            "message": "Created replica set",
            "involved_object": "Deployment/demo-app",
            "count": 1,
            "last_timestamp": (now - timedelta(minutes=30)).isoformat(),
        },
        {
            "type": "Warning",
            "reason": "Exec",
            "message": "exec 'kubectl exec -it test-pod -- /bin/sh' detected",
            "involved_object": "Pod/test-pod",
            "count": 1,
            "last_timestamp": (now - timedelta(minutes=6)).isoformat(),
        },
    ]


def kube_pod_logs(pod: str, previous: bool = False, tail: int = 40) -> list[str]:
    logs: dict[str, list[str]] = {
        "cpu-demo": [
            "2026-09-24T09:00:00Z starting stress workload",
            "2026-09-24T09:01:00Z computing heavy loops...",
            "2026-09-24T09:02:00Z cpu utilization high (sustained)",
            "2026-09-24T09:03:00Z computing heavy loops...",
            "2026-09-24T09:04:00Z computing heavy loops...",
        ],
        "memory-demo": [
            "2026-09-24T08:00:00Z starting memory allocator",
            "2026-09-24T08:30:00Z allocating 256MB buffer",
            "2026-09-24T08:45:00Z allocating 512MB buffer",
            "2026-09-24T08:50:00Z allocating 1GB buffer",
            "2026-09-24T08:55:00Z memory pressure detected",
            "2026-09-24T09:00:00Z OOMKilled by kernel (oom-kill)",
        ],
        "crash-demo": [
            "2026-09-24T09:00:00Z loading config from /etc/demo/config.yaml",
            "2026-09-24T09:00:01Z ERROR config file not found: /etc/demo/config.yaml",
            "2026-09-24T09:00:02Z Fatal: exiting (exit code 1)",
        ],
        "test-pod": [
            "2026-09-24T09:00:00Z nginx started",
            "2026-09-24T09:02:00Z 10.0.0.5 - - \"GET /index.html\" 200",
        ],
        "demo-app": [
            "2026-09-24T09:00:00Z nginx started",
            "2026-09-24T09:05:00Z 10.0.0.9 - - \"GET /api\" 200 latency=80ms",
        ],
    }
    if previous:
        for key in list(logs):
            logs[key] = logs[key] + ["[previous container instance logs]"]
    if pod in logs:
        return logs[pod][-tail:]
    return [f"(no logs for pod {pod} in simulation)"]


def kube_get_pod(pod: str, namespace: str = "ai-observability-demo") -> dict[str, Any]:
    for p in kube_pods(namespace):
        if p["name"] == pod:
            return p
    return {"name": pod, "namespace": namespace, "phase": "Unknown", "ready": "0/1", "restarts": 0}


def kube_get_deployment(name: str, namespace: str = "ai-observability-demo") -> dict[str, Any]:
    for d in kube_deployments(namespace):
        if d["name"] == name:
            return d
    return {"name": name, "namespace": namespace, "replicas": 0, "ready": 0}


def kube_nodes() -> list[dict[str, Any]]:
    return [
        {"name": "demo-control-plane", "role": "control-plane", "status": "Ready", "cpu_capacity": 4, "memory_capacity_gb": 8},
        {"name": "demo-worker-1", "role": "worker", "status": "Ready", "cpu_capacity": 8, "memory_capacity_gb": 16},
    ]


def kube_rbac() -> list[dict[str, Any]]:
    return list(_ensure_state()["rbac"])


def cluster_health() -> dict[str, Any]:
    return {
        "nodes": kube_nodes(),
        "deployments": kube_deployments(),
        "pods": kube_pods(),
    }


# ---------------------------------------------------------------------------
# Application logs (kubernetes-logs index) ------------------------------------
# ---------------------------------------------------------------------------


def app_logs(namespace: str = "ai-observability-demo", limit: int = 80) -> list[dict[str, Any]]:
    """Deterministic application logs for the ``kubernetes-logs`` index.

    Mirrors the mutable cluster state so remediation is visible in the logs:
    crash-demo's ERROR/CrashLoopBackOff lines disappear after a restart and
    OOMKilled lines for memory-demo are replaced by a clean startup sequence.
    """
    now = chrono.now()
    out: list[dict[str, Any]] = []
    for pod in kube_pods(namespace):
        out.extend(_logs_for_pod(pod, now))
    out.sort(key=lambda e: e["timestamp"], reverse=True)
    return out[:limit]


def _logs_for_pod(pod: dict[str, Any], now) -> list[dict[str, Any]]:
    name = pod["name"]
    deploy = pod.get("deployment") or name
    containers = pod.get("containers") or []
    cont = containers[0]["name"] if containers else name
    ns = pod.get("namespace", "ai-observability-demo")
    img = pod.get("image", "unknown")
    restarts = pod.get("restarts", 0) or 0
    ready = pod.get("ready", "0/1")
    healthy = pod.get("phase") == "Running" and ready == "1/1" and restarts == 0

    def line(level: str, message: str, minutes_ago: float) -> dict[str, Any]:
        return {
            "timestamp": (now - timedelta(minutes=minutes_ago)).isoformat(),
            "namespace": ns,
            "pod": name,
            "deployment": deploy,
            "container": cont,
            "image": img,
            "level": level,
            "message": message,
            "source": "kubernetes-logs",
        }

    if deploy == "crash-demo":
        if healthy:
            return [
                line("INFO", "loading config from /etc/demo/config.yaml", 4),
                line("INFO", "config loaded — serving requests", 3),
                line("INFO", "healthcheck passed (1/1 replicas ready)", 1),
            ]
        return [
            line("ERROR", "config file not found: /etc/demo/config.yaml", 18),
            line("ERROR", "Fatal: exiting (exit code 1)", 17),
            line("WARN", f"CrashLoopBackOff: back-off restarting failed container (count={restarts})", 2),
        ]
    if deploy == "memory-demo":
        if healthy:
            return [
                line("INFO", "starting memory allocator", 14),
                line("INFO", "allocated 256MB warmup buffer", 10),
                line("WARN", "memory pressure 85% — reviewing limits", 2),
            ]
        oom = (containers[0].get("last_state", {}).get("terminated") if containers else None) or {}
        return [
            line("INFO", "starting memory allocator", 14),
            line("WARN", "allocating 1GB buffer — pressure rising", 4),
            line("ERROR", f"OOMKilled by kernel (reason={oom.get('reason', 'OOMKilled')}, exit={oom.get('exit_code', 137)})", 1),
        ]
    if deploy == "cpu-demo":
        return [
            line("INFO", "stress workload started", 8),
            line("WARN", "cpu utilization high (sustained >80%)", 4),
            line("INFO", "computing heavy loops...", 1),
        ]
    if deploy == "demo-app":
        return [
            line("INFO", "nginx started — listening on :8080", 30),
            line("INFO", '10.0.0.9 - - "GET /api" 200 latency=80ms', 6),
            line("INFO", '10.0.0.14 - - "GET /healthz" 200', 1),
        ]
    if deploy == "cert-demo":
        return [
            line("INFO", "tls server started — serving on :8443", 10),
            line("WARN", f"certificate expiring in 4 days — renew soon", 5),
            line("INFO", "tls handshake accepted (chain valid)", 1),
        ]
    return [
        line("INFO", f"{cont} started (image {img})", 5),
        line("INFO", "ready for traffic", 1),
    ]


# ---------------------------------------------------------------------------
# Falco ----------------------------------------------------------------------
# ---------------------------------------------------------------------------


def falco_events(namespace: str = "ai-observability-demo", limit: int = 20) -> list[dict[str, Any]]:
    now = chrono.now()
    return [
        {
            "rule": "Terminal shell in container",
            "priority": "CRITICAL",
            "time": (now - timedelta(minutes=6)).isoformat(),
            "pod": "test-pod",
            "namespace": namespace,
            "container": "test-pod",
            "image": "nginx:1.25",
            "proc": "/bin/sh",
            "cmdline": "sh -i",
            "user": "root",
            "source": "syscall",
            "k8s_extra": {"deployment": None},
            "message": "A shell was spawned in a container with an attached terminal.",
        },
        {
            "rule": "Read sensitive file untrusted",
            "priority": "WARNING",
            "time": (now - timedelta(minutes=5)).isoformat(),
            "pod": "test-pod",
            "namespace": namespace,
            "container": "test-pod",
            "image": "nginx:1.25",
            "proc": "cat",
            "cmdline": "cat /etc/shadow",
            "user": "root",
            "source": "syscall",
            "k8s_extra": {},
            "message": "An attempt to read a sensitive file was blocked.",
        },
    ]


def falco_healthy() -> bool:
    return True


# ---------------------------------------------------------------------------
# Kubernetes Audit Logs ------------------------------------------------------
# ---------------------------------------------------------------------------


def audit_events(namespace: str = "ai-observability-demo", limit: int = 30) -> list[dict[str, Any]]:
    now = chrono.now()
    return [
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "timestamp": (now - timedelta(minutes=18)).isoformat(),
            "user": {"username": "ci-bot@example.com", "uid": "user-cibot"},
            "verb": "create",
            "requestURI": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
            "resource": "clusterrolebindings",
            "namespace": namespace,
            "object": {
                "name": "ci-bot-cluster-admin",
                "roleRef": {"name": "cluster-admin", "kind": "ClusterRole"},
                "subjects": [{"kind": "ServiceAccount", "name": "ci-bot", "namespace": "ci"}],
            },
            "sourceIPs": ["203.0.113.7"],
            "responseStatus": {"code": 201},
        },
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "timestamp": (now - timedelta(minutes=6)).isoformat(),
            "user": {"username": "admin@example.com", "uid": "user-admin"},
            "verb": "create",
            "requestURI": "/api/v1/namespaces/ai-observability-demo/pods/test-pod/exec",
            "resource": "pods/exec",
            "namespace": namespace,
            "object": {"name": "test-pod", "command": ["/bin/sh", "-i"]},
            "sourceIPs": ["192.168.1.44"],
            "responseStatus": {"code": 101},
        },
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "timestamp": (now - timedelta(minutes=30)).isoformat(),
            "user": {"username": "admin@example.com", "uid": "user-admin"},
            "verb": "patch",
            "requestURI": "/apis/apps/v1/namespaces/ai-observability-demo/deployments/demo-app",
            "resource": "deployments",
            "namespace": namespace,
            "object": {"name": "demo-app", "patch": '{"spec":{"replicas":2}}'},
            "sourceIPs": ["192.168.1.44"],
            "responseStatus": {"code": 200},
        },
    ]


# ---------------------------------------------------------------------------
# Certificates ---------------------------------------------------------------
# ---------------------------------------------------------------------------


def certificate_status(path: str = "") -> dict[str, Any]:
    state = _ensure_state()["cert"]
    now = chrono.now()
    days = state["days_remaining"]
    not_after = now + timedelta(days=days)
    return {
        "path": path or "/etc/demo/tls/server.crt",
        "common_name": "cert-demo.ai-observability-demo.svc",
        "issuer": "demo-local-ca",
        "not_before": (now - timedelta(days=60)).isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days,
        "valid": state["valid"],
        "chain_valid": state["chain_valid"],
    }


# ---------------------------------------------------------------------------
# Action side effects ----------------------------------------------------------
# ---------------------------------------------------------------------------


def simulate_scale(deployment: str, desired: int, current: int) -> dict[str, Any]:
    with _lock:
        st = _deploy_state(deployment)
        st["replicas"] = desired
        st["ready"] = desired
        st["available"] = desired
        now = chrono.now()
        return {
            "action": "scale_deployment",
            "deployment": deployment,
            "current_replicas": current,
            "desired_replicas": desired,
            "result": "scaled",
            "pods": [f"{deployment}-pod-{i}" for i in range(desired)],
            "scaled_at": now.isoformat(),
        }


def simulate_restart(deployment: str = "") -> dict[str, Any]:
    with _lock:
        for pod in _pod_state():
            if pod.get("deployment") in ("crash-demo", "memory-demo", "demo-app", "cpu-demo"):
                pod["phase"] = "Running"
                pod["ready"] = "1/1"
                pod["restarts"] = 0
                for c in pod["containers"]:
                    c["state"] = "running"
                    c["restart_count"] = 0
                    c.pop("last_state", None)
        _deploy_state("crash-demo")["ready"] = 1
        _deploy_state("crash-demo")["available"] = 1
        return {"action": "restart_deployment", "result": "restarted", "restart_rolled_out": True}


def simulate_rollback_rbac(binding_name: str) -> dict[str, Any]:
    with _lock:
        state = _ensure_state()
        state["rbac"] = [b for b in state["rbac"] if b.get("name") != binding_name]
        return {"action": "rollback_rbac", "binding": binding_name, "result": "deleted"}


def simulate_renew_certificate() -> dict[str, Any]:
    with _lock:
        state = _ensure_state()["cert"]
        state["days_remaining"] = 365.0
        state["valid"] = True
        state["renewed"] = True
        return {"action": "renew_certificate", "result": "renewed", "days_remaining": 365.0}


# ---------------------------------------------------------------------------
# Security-config side effects (Security Test Lab / findings)
# ---------------------------------------------------------------------------

# Static allowlist of supported security configurations. Everything is applied
# to the in-process simulated cluster only — never to live objects.
_SECURITY_CONFIGS = (
    "drop-privileged",
    "enable-apparmor",
    "enable-seccomp",
    "default-deny-network-policy",
    "lockdown-kubelet",
    "tidy-image",
    "use-secret",
    "set-image-pull-policy",
    "disallow-host-network",
    "drop-capabilities",
    "disable-auto-mount-token",
)


def allowed_security_configs() -> list[str]:
    return list(_SECURITY_CONFIGS)


def simulate_apply_security_config(config: str, target: str, namespace: str = "ai-observability-demo") -> dict[str, Any]:
    if config not in _SECURITY_CONFIGS:
        return {"action": "apply_security_config", "config": config, "target": target, "result": "rejected", "reason": "config not in allowlist"}
    with _lock:
        state = _ensure_state()
        state["security_configs"][(config, target)] = True
        now = chrono.now()
        return {
            "action": "apply_security_config",
            "config": config,
            "target": target,
            "namespace": namespace,
            "result": "applied",
            "applied_at": now.isoformat(),
            "simulated": True,
        }


def security_config_applied(config: str, target: str) -> bool:
    state = _ensure_state()
    return bool(state["security_configs"].get((config, target)))