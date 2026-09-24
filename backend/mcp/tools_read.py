"""Read-only MCP tools.

These are safe to expose: no state is changed. Backed by the kube/OpenSearch/
Prometheus adapters with simulation fallback. Never expose arbitrary exec.
"""

from __future__ import annotations

from typing import Any

from backend.mcp.registry import ToolDef, ToolRegistry
from backend.services import kube, opensearch, prometheus

_NAMESPACE = "string"
_OPTIONAL_NS = {"description": "Kubernetes namespace", "type": "string", "default": ""}


def register_read_tools(registry: ToolRegistry) -> None:
    registry.register(
        ToolDef(
            name="get_pods",
            description="List pods in a namespace with status, restarts and container state.",
            input_schema={"namespace": _OPTIONAL_NS},
            kind="read",
            impl=_get_pods,
        )
    )
    registry.register(
        ToolDef(
            name="get_pod_logs",
            description="Fetch current or previous container logs for a pod.",
            input_schema={
                "pod": {"type": "string"},
                "namespace": _OPTIONAL_NS,
                "previous": {"type": "boolean", "default": False},
                "tail": {"type": "integer", "default": 80},
            },
            kind="read",
            impl=_get_pod_logs,
        )
    )
    registry.register(
        ToolDef(
            name="get_pod_events",
            description="List Kubernetes events for a namespace.",
            input_schema={"namespace": _OPTIONAL_NS},
            kind="read",
            impl=_get_pod_events,
        )
    )
    registry.register(
        ToolDef(
            name="get_deployment",
            description="Read a deployment's replica and rollout state.",
            input_schema={
                "name": {"type": "string"},
                "namespace": _OPTIONAL_NS,
            },
            kind="read",
            impl=_get_deployment,
        )
    )
    registry.register(
        ToolDef(
            name="get_nodes",
            description="List cluster nodes and their readiness.",
            input_schema={},
            kind="read",
            impl=_get_nodes,
        )
    )
    registry.register(
        ToolDef(
            name="get_certificate_status",
            description="Return TLS certificate expiry information.",
            input_schema={},
            kind="read",
            impl=_get_certificate_status,
        )
    )
    registry.register(
        ToolDef(
            name="query_prometheus",
            description="Run a PromQL query against the metrics store.",
            input_schema={
                "query": {"type": "string"},
                "steps": {"type": "integer", "default": 15},
            },
            kind="read",
            impl=_query_prometheus,
        )
    )
    registry.register(
        ToolDef(
            name="search_opensearch",
            description="Search OpenSearch for application logs.",
            input_schema={
                "query": {"type": "string"},
                "size": {"type": "integer", "default": 10},
            },
            kind="read",
            impl=_search_logs,
        )
    )
    registry.register(
        ToolDef(
            name="search_audit_logs",
            description="Search the Kubernetes audit-log store.",
            input_schema={
                "query": {"type": "string"},
                "size": {"type": "integer", "default": 10},
            },
            kind="read",
            impl=_search_audit,
        )
    )
    registry.register(
        ToolDef(
            name="search_falco_events",
            description="Search Falco runtime-security events.",
            input_schema={
                "query": {"type": "string"},
                "size": {"type": "integer", "default": 10},
            },
            kind="read",
            impl=_search_falco,
        )
    )
    registry.register(
        ToolDef(
            name="get_rbac",
            description="List RoleBindings and ClusterRoleBindings in the cluster.",
            input_schema={},
            kind="read",
            impl=_get_rbac,
        )
    )


def _get_pods(namespace: str = "") -> list[dict[str, Any]]:
    return kube.get_kube().get_pods(namespace or _ns())


def _get_pod_logs(pod: str, namespace: str = "", previous: bool = False, tail: int = 80) -> list[str]:
    return kube.get_kube().get_pod_logs(pod, namespace or _ns(), previous=previous, tail=tail)


def _get_pod_events(namespace: str = "") -> list[dict[str, Any]]:
    return kube.get_kube().get_pod_events(namespace or _ns())


def _get_deployment(name: str, namespace: str = "") -> dict[str, Any]:
    return kube.get_kube().get_deployment(name, namespace or _ns())


def _get_nodes() -> list[dict[str, Any]]:
    return kube.get_kube().get_nodes()


def _get_certificate_status() -> dict[str, Any]:
    from backend.services.certmon import get_certificate_monitor

    return get_certificate_monitor().status().to_dict()


def _query_prometheus(query: str, steps: int = 15) -> dict[str, Any]:
    return prometheus.get_prometheus().query(query, steps=steps)


def _search_logs(query: str, size: int = 10) -> list[dict[str, Any]]:
    os_ = opensearch.get_opensearch()
    body = {"query": _match(query)}
    return os_.search(os_.settings.opensearch_index_logs, body, size=size)


def _search_audit(query: str, size: int = 10) -> list[dict[str, Any]]:
    os_ = opensearch.get_opensearch()
    body = {"query": _match(query)}
    return os_.search(os_.settings.opensearch_index_audit, body, size=size)


def _search_falco(query: str, size: int = 10) -> list[dict[str, Any]]:
    os_ = opensearch.get_opensearch()
    body = {"query": _match(query)}
    return os_.search(os_.settings.opensearch_index_falco, body, size=size)


def _get_rbac() -> list[dict[str, Any]]:
    return kube.get_kube().get_rbac()


def _match(query: str) -> dict[str, Any]:
    if query:
        return {"multi_match": {"query": query}}
    return {"match_all": {}}


def _ns() -> str:
    from backend.services.config import get_settings

    return get_settings().namespace