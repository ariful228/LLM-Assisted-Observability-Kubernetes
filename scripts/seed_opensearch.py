#!/usr/bin/env python3
"""Seed the local OpenSearch with demo log / audit / falco datasets.

Indexes the same deterministic datasets the platform's simulation uses, so a
live OpenSearch (docker compose) returns the demo events the workflows expect.

  PYTHONPATH=. .venv/bin/python scripts/seed_opensearch.py [--reset]

Requires: docker compose -f docker/docker-compose.yml up -d opensearch
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.services.config import get_settings  # noqa: E402


class _API:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def _req(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        req = urllib.request.Request(self.base + path, data=body, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, {}

    def put_index(self, index: str, mapping: dict) -> dict:
        status, _ = self._req("HEAD", f"/{index}")
        if status == 200:
            return {}
        _, body = self._req("PUT", f"/{index}", json.dumps(mapping).encode())
        return body

    def delete_index(self, index: str) -> None:
        self._req("DELETE", f"/{index}")

    def count(self, index: str) -> int:
        status, body = self._req("GET", f"/{index}/_count")
        return body.get("count", 0) if status == 200 else 0

    def bulk(self, rows: list[dict], index: str) -> None:
        lines: list[str] = []
        for row in rows:
            meta = {"index": {"_index": index}}
            lines.append(json.dumps(meta))
            lines.append(json.dumps(row, default=str))
        if not lines:
            return
        self._req("POST", "/_bulk", ("\n".join(lines) + "\n").encode())
        self._req("POST", "/_refresh")


def mapping(base: dict, index: str) -> dict:
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {"properties": base},
    }


LOG_MAPPING = {
    "kubernetes-logs": {
        "message": {"type": "text"},
        "pod": {"type": "keyword"},
        "container": {"type": "keyword"},
        "namespace": {"type": "keyword"},
        "level": {"type": "keyword"},
        "timestamp": {"type": "date"},
    },
    "kubernetes-audit": {
        "verb": {"type": "keyword"},
        "resource": {"type": "keyword"},
        "user": {"type": "keyword"},
        "namespace": {"type": "keyword"},
        "objectRef": {"type": "object"},
        "level": {"type": "keyword"},
        "stageTimestamp": {"type": "date"},
        "message": {"type": "text"},
    },
    "falco-events": {
        "proc_name": {"type": "keyword"},
        "proc_tty": {"type": "boolean"},
        "user": {"type": "keyword"},
        "event": {"type": "keyword"},
        "priority": {"type": "keyword"},
        "pod": {"type": "keyword"},
        "namespace": {"type": "keyword"},
        "output": {"type": "text"},
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed local OpenSearch with demo datasets")
    parser.add_argument("--reset", action="store_true", help="delete+recreate the indices first")
    parser.add_argument("--url", default=None, help="OpenSearch base URL (default: from .env)")
    args = parser.parse_args()

    settings = get_settings()
    base = args.url or settings.opensearch_url or "http://localhost:9200"
    api = _API(base)

    from backend.services import simulation  # noqa: PLC0415

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for kind, index in (
        ("kubernetes-logs", settings.opensearch_index_logs),
        ("kubernetes-audit", settings.opensearch_index_audit),
        ("falco-events", settings.opensearch_index_falco),
    ):
        if args.reset:
            api.delete_index(index)
        api.put_index(index, mapping(LOG_MAPPING[kind], index))

    # logs: already structured list of strings
    log_rows = []
    for line in simulation.kube_pod_logs("demo-app-0", previous=True, tail=80):
        log_rows.append(
            {
                "message": line,
                "pod": "memory-demo-5f67c9f6d4-abc12",
                "container": "memory-demo",
                "namespace": settings.namespace,
                "level": "ERROR" if "error" in line.lower() or "exceeded" in line.lower() else "INFO",
                "timestamp": now,
            }
        )
    api.bulk(log_rows, settings.opensearch_index_logs)

    audit_rows = []
    for ev in simulation.audit_events(namespace=settings.namespace, limit=30):
        audit_rows.append({**ev, "message": f"{ev.get('verb')} {ev.get('resource')} {ev.get('user')}"})
    api.bulk(audit_rows, settings.opensearch_index_audit)

    falco_rows = []
    for ev in simulation.falco_events(namespace=settings.namespace, limit=20):
        falco_rows.append({**ev, "output": ev.get("output", ev.get("proc_name", ""))})
    api.bulk(falco_rows, settings.opensearch_index_falco)

    # --- enrich with the six demo-scenario records --------------------------
    ns = settings.namespace
    logs = [
        {"message": "2026-05-05 12:00:11 INFO  cpu-demo scaling replicas 2 -> 3 (cpu 94%)", "pod": "cpu-demo-6fdd9bb97c-xyz", "container": "cpu-demo", "namespace": ns, "level": "INFO", "timestamp": now},
        {"message": "2026-05-05 12:01:03 WARN  memory-demo RSS 812Mi exceeds 512Mi limit", "pod": "memory-demo-5f67c9f6d4-abc12", "container": "memory-demo", "namespace": ns, "level": "WARN", "timestamp": now},
        {"message": "2026-05-05 12:01:19 ERROR memory-demo OOMKilled (memory limit exceeded)", "pod": "memory-demo-5f67c9f6d4-abc12", "container": "memory-demo", "namespace": ns, "level": "ERROR", "timestamp": now},
        {"message": "2026-05-05 12:02:41 ERROR crash-demo container exited with code 1 - CrashLoopBackOff", "pod": "crash-demo-77bc6cf4f6-1a2b", "container": "crash-demo", "namespace": ns, "level": "ERROR", "timestamp": now},
        {"message": "2026-05-05 12:03:15 INFO  cert-demo TLS certificate expires in 6 days - rotation ran", "pod": "cert-demo", "container": "cert-demo", "namespace": ns, "level": "WARN", "timestamp": now},
        {"message": "2026-05-05 12:04:00 INFO  ci-bot pod started shell /bin/sh -c 'curl ...' in test-pod", "pod": "test-pod", "container": "test-pod", "namespace": ns, "level": "WARN", "timestamp": now},
    ]
    api.bulk(logs, settings.opensearch_index_logs)

    audit = [
        {"verb": "create", "resource": "clusterrolebindings", "user": "ci-bot", "namespace": "", "level": "RequestResponse", "stageTimestamp": now, "message": "user ci-bot created clusterrolebinding ci-bot-cluster-admin binding ClusterRole cluster-admin"},
        {"verb": "get", "resource": "pods", "user": "system:serviceaccount:ai-observability-demo:ai-observability-backend", "namespace": "ai-observability-demo", "level": "Request", "stageTimestamp": now, "message": "health scrape pods in ai-observability-demo"},
        {"verb": "list", "resource": "secrets", "user": "system:kube-controller-manager", "namespace": "", "level": "RequestResponse", "stageTimestamp": now, "message": "controller-manager listing secrets"},
        {"verb": "update", "resource": "deployments", "user": "sre-alice", "namespace": ns, "level": "RequestResponse", "stageTimestamp": now, "message": "approve scale memory-demo 2 -> 3"},
        {"verb": "delete", "resource": "clusterrolebindings", "user": "admin", "namespace": "", "level": "RequestResponse", "stageTimestamp": now, "message": "rollback suspicious ci-bot-cluster-admin binding"},
    ]
    for ev in audit:
        audit_rows.append({k: v for k, v in ev.items()})
    api.bulk(audit_rows, settings.opensearch_index_audit)

    falco = [
        {"proc_name": "sh", "proc_tty": False, "user": "root", "event": "execve", "priority": "Warning", "pod": "test-pod", "namespace": ns, "output": "Executing 'curl' inside container (test-pod)"},
        {"proc_name": "bash", "proc_tty": False, "user": "root", "event": "execve", "priority": "Critical", "pod": "test-pod", "namespace": ns, "output": "Interactive shell spawned inside container (test-pod)"},
        {"proc_name": "python3", "proc_tty": False, "user": "root", "event": "openat", "priority": "Warning", "pod": "cpu-demo-6fdd9bb97c-xyz", "namespace": ns, "output": "Read sensitive file /etc/shadow (cpu-demo)"},
        {"proc_name": "kubectl", "proc_tty": True, "user": "ci-bot", "event": "execve", "priority": "Notice", "pod": "ci-bot", "namespace": ns, "output": "kubectl create clusterrolebinding from within pod ci-bot"},
    ]
    for ev in falco:
        falco_rows.append({**ev, "output": ev["output"]})
    api.bulk(falco_rows, settings.opensearch_index_falco)

    def count(self, index: str) -> int:
        status, body = self._req("GET", f"/{index}/_count")
        return body.get("count", 0) if status == 200 else 0

    print("[seed-opensearch] done")
    for index in (settings.opensearch_index_logs, settings.opensearch_index_audit, settings.opensearch_index_falco):
        print(f"  index {index:<22} {api.count(index)} docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())