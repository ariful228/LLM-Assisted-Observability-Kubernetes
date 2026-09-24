"""Kubernetes adapter.

Reads and controlled actions. The MCP action layer calls only these functions.
The Kubernetes python client is used only when a real cluster is configured;
otherwise a deterministic simulation backs the same interface.
"""

from __future__ import annotations

import threading
from typing import Any, Optional

from backend.services import simulation
from backend.services.config import get_settings


class KubernetesUnavailable(RuntimeError):
    pass


class KubeAdapter:
    def __init__(self) -> None:
        self._api = None
        self._apps = None
        self._rbac = None
        self._settings_provider = get_settings

    # -- plumbing ----------------------------------------------------------
    @property
    def settings(self):
        return self._settings_provider()

    @property
    def mode(self) -> str:
        mode = self.settings.external_mode
        if mode == "auto":
            return "live" if self.available() else "simulated"
        if mode == "live":
            return "live"
        return "simulated"

    def available(self) -> bool:
        if self.settings.external_mode == "simulated":
            return False
        try:
            self._ensure_clients()
            return self._api is not None
        except Exception:
            return False

    def _ensure_clients(self) -> None:
        """Load the Kubernetes clients if a cluster is configured."""
        import os

        import kubernetes  # noqa: PLC0415
        from kubernetes import config as kubeconfig  # noqa: PLC0415

        if self._api is not None:
            return
        if self.settings.kubernetes_in_cluster:
            kubeconfig.load_incluster_config()
        elif self.settings.kubeconfig_path:
            kubeconfig.load_kube_config(config_file=self.settings.kubeconfig_path)
        elif os.environ.get("KUBECONFIG"):
            kubeconfig.load_kube_config(config_file=os.environ["KUBECONFIG"])
        else:
            kubeconfig.load_kube_config()
        self._api = kubernetes.client.CoreV1Api()
        self._apps = kubernetes.client.AppsV1Api()
        self._rbac = kubernetes.client.RbacAuthorizationV1Api()

    # -- reads -------------------------------------------------------------
    def get_pods(self, namespace: str) -> list[dict[str, Any]]:
        if self.mode == "simulated":
            return simulation.kube_pods(namespace)
        self._ensure_clients()
        try:
            pods = self._api.list_namespaced_pod(namespace=namespace).items
            return [_pod_dict(p) for p in pods]
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def get_pod(self, pod: str, namespace: str) -> dict[str, Any]:
        if self.mode == "simulated":
            return simulation.kube_get_pod(pod, namespace)
        self._ensure_clients()
        try:
            p = self._api.read_namespaced_pod(name=pod, namespace=namespace)
            return _pod_dict(p)
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def get_deployment(self, name: str, namespace: str) -> dict[str, Any]:
        if self.mode == "simulated":
            return simulation.kube_get_deployment(name, namespace)
        self._ensure_clients()
        try:
            d = self._apps.read_namespaced_deployment(name=name, namespace=namespace)
            return _deployment_dict(d)
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def get_deployments(self, namespace: str) -> list[dict[str, Any]]:
        if self.mode == "simulated":
            return simulation.kube_deployments(namespace)
        self._ensure_clients()
        try:
            return [_deployment_dict(d) for d in self._apps.list_namespaced_deployment(namespace=namespace).items]
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def get_nodes(self) -> list[dict[str, Any]]:
        if self.mode == "simulated":
            return simulation.kube_nodes()
        self._ensure_clients()
        try:
            return [_node_dict(n) for n in self._api.list_node().items]
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def get_pod_logs(self, pod: str, namespace: str, previous: bool = False, tail: int = 80) -> list[str]:
        if self.mode == "simulated":
            return simulation.kube_pod_logs(pod, previous=previous, tail=tail)
        self._ensure_clients()
        try:
            body = self._api.read_namespaced_pod_log(
                name=pod,
                namespace=namespace,
                previous=previous,
                tail_lines=tail,
                timestamps=True,
            )
            return [line for line in body.splitlines() if line]
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def get_pod_events(self, namespace: str) -> list[dict[str, Any]]:
        if self.mode == "simulated":
            return simulation.kube_events(namespace)
        self._ensure_clients()
        try:
            events = self._api.list_namespaced_event(namespace=namespace).items
            result = []
            for e in events:
                result.append(
                    {
                        "type": e.type,
                        "reason": e.reason,
                        "message": e.message,
                        "involved_object": f"{e.involved_object.kind}/{e.involved_object.name}",
                        "count": e.count,
                        "last_timestamp": str(e.last_timestamp),
                    }
                )
            return result
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def get_rbac(self, namespace: str = "") -> list[dict[str, Any]]:
        if self.mode == "simulated":
            return simulation.kube_rbac()
        self._ensure_clients()
        try:
            result: list[dict[str, Any]] = []
            for crb in self._rbac.list_cluster_role_binding().items:
                subjects = [
                    f"{s.kind}/{s.name}/{s.namespace or ''}" for s in (crb.subjects or [])
                ]
                result.append(
                    {
                        "kind": "ClusterRoleBinding",
                        "name": crb.metadata.name,
                        "role": f"ClusterRole/{crb.role_ref.name}",
                        "subjects": subjects,
                        "created_at": str(crb.metadata.creation_timestamp or "")[:19],
                    }
                )
            return result
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    # -- controlled actions (called only via the MCP policy gate) -------------
    def scale_deployment(self, name: str, namespace: str, replicas: int) -> dict[str, Any]:
        current = self.get_deployment(name, namespace).get("replicas", 0)
        if self.mode == "simulated":
            return simulation.simulate_scale(name, replicas, current)
        self._ensure_clients()
        try:
            body = {"spec": {"replicas": replicas}}
            self._apps.patch_namespaced_deployment_scale(name, namespace, body)
            return {
                "action": "scale_deployment",
                "current_replicas": current,
                "desired_replicas": replicas,
                "result": "scaled",
            }
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def restart_deployment(self, name: str, namespace: str) -> dict[str, Any]:
        if self.mode == "simulated":
            return simulation.simulate_restart(name)
        self._ensure_clients()
        try:
            import datetime  # noqa: PLC0415

            annotation = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {"aio/restarted-at": annotation}
                        }
                    }
                }
            }
            self._apps.patch_namespaced_deployment(name, namespace, body)
            return {"action": "restart_deployment", "result": "restarted"}
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def rollback_rbac(self, binding_name: str) -> dict[str, Any]:
        if self.mode == "simulated":
            return simulation.simulate_rollback_rbac(binding_name)
        self._ensure_clients()
        try:
            self._rbac.delete_cluster_role_binding(binding_name)
            return {"action": "rollback_rbac", "binding": binding_name, "result": "deleted"}
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def renew_certificate(self, namespace: str, secret_name: str, dns_name: str) -> dict[str, Any]:
        """Renew demo certificate: mint a fresh self-signed cert into the Secret.

        Only meaningful for the demo namespace `ai-observability-demo`.
        """
        if self.mode == "simulated":
            return simulation.simulate_renew_certificate()
        try:
            from cryptography import x509  # noqa: PLC0415
            from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
            from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415
            from cryptography.x509.oid import NameOID  # noqa: PLC0415
            import datetime, ipaddress  # noqa: PLC0415

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, dns_name)]
            )
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName(
                        [x509.DNSName(dns_name), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                    ),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            self._ensure_clients()
            self._api.patch_namespaced_secret(
                secret_name,
                namespace,
                {"data": {"tls.crt": cert_pem.decode(), "tls.key": key_pem.decode()}},
            )
            return {
                "action": "renew_certificate",
                "secret": secret_name,
                "namespace": namespace,
                "result": "renewed",
                "days_remaining": 365,
            }
        except Exception as exc:
            raise KubernetesUnavailable(str(exc)) from exc

    def apply_security_config(self, config: str, target: str, namespace: str) -> dict[str, Any]:
        """Apply a security hardening config to the (simulated) cluster.

        Deliberately limited to the fixed allowlist in ``simulation``; the
        mutation only ever touches the in-process simulated state, never live
        objects, so the Security Test Lab is always safe.
        """
        return simulation.simulate_apply_security_config(config, target, namespace)

    def security_config_applied(self, config: str, target: str) -> bool:
        return simulation.security_config_applied(config, target)


def _pod_dict(p) -> dict[str, Any]:
    containers = []
    for c in (p.status.container_statuses or []):
        containers.append(
            {
                "name": c.name,
                "state": (_state_summary(c.state)),
                "restart_count": c.restart_count,
                "image": c.image,
                "last_state": {"terminated": _terminated(c.last_state.terminated)} if c.last_state and c.last_state.terminated else None,
            }
        )
    return {
        "name": p.metadata.name,
        "deployment": "unknown",
        "namespace": p.metadata.namespace,
        "phase": getattr(p.status, "phase", "Unknown"),
        "ready": _ready(p.status),
        "restarts": sum(c.restart_count for c in (p.status.container_statuses or [])),
        "image": (p.spec.containers[0].image if p.spec.containers else ""),
        "containers": containers,
    }


def _state_summary(state) -> str:
    if state is None:
        return "unknown"
    if state.running:
        return "running"
    if state.waiting:
        return f"waiting({state.waiting.reason})"
    if state.terminated:
        return f"terminated({state.terminated.reason})"
    return "unknown"


def _terminated(t) -> dict[str, Any] | None:
    if t is None:
        return None
    return {"reason": t.reason, "exit_code": t.exit_code, "message": t.message}


def _ready(status) -> str:
    try:
        if not status.conditions:
            return "0/1"
        ready = any(c.type == "Ready" and c.status == "True" for c in status.conditions)
        return "1/1" if ready else "0/1"
    except Exception:
        return "0/1"


def _deployment_dict(d) -> dict[str, Any]:
    return {
        "name": d.metadata.name,
        "namespace": d.metadata.namespace,
        "replicas": d.spec.replicas or 0,
        "ready": d.status.ready_replicas or 0,
        "available": d.status.available_replicas or 0,
        "image": (d.spec.template.spec.containers[0].image if d.spec.template.spec.containers else ""),
    }


def _node_dict(n) -> dict[str, Any]:
    return {
        "name": n.metadata.name,
        "role": "worker",
        "status": "Ready" if any(c.type == "Ready" and c.status == "True" for c in n.status.conditions) else "NotReady",
    }


_kube: KubeAdapter | None = None
_kube_lock = threading.Lock()


def get_kube() -> KubeAdapter:
    global _kube
    if _kube is None:
        with _kube_lock:
            if _kube is None:
                _kube = KubeAdapter()
    return _kube