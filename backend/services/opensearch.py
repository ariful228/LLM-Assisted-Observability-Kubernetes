"""OpenSearch client for logs / audit / falco events, with simulation fallback."""

from __future__ import annotations

import threading
from typing import Any

from backend.services.config import get_settings


class OpenSearchClient:
    def __init__(self) -> None:
        self._client = None
        self._settings_provider = get_settings

    @property
    def settings(self):
        return self._settings_provider()

    def available(self) -> bool:
        if not self.settings.opensearch_url:
            return False
        try:
            if self._client is None:
                from opensearchpy import OpenSearch as _OS  # noqa: PLC0415

                self._client = _OS(
                    hosts=[self.settings.opensearch_url],
                    http_auth=(
                        (self.settings.opensearch_username, self.settings.opensearch_password)
                        if self.settings.opensearch_username
                        else None
                    ),
                    use_ssl=self.settings.opensearch_url.startswith("https"),
                    verify_certs=False,
                )
            return bool(self._client.ping())
        except Exception:
            return False

    def search(self, index: str, query: dict[str, Any], size: int = 20) -> list[dict[str, Any]]:
        if self.available():
            try:
                resp = self._client.search(index=index, body=query, size=size)
                return [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])]
            except Exception:
                pass
        return self._simulated(index, query, size)

    def query_logs(
        self,
        index: str | None = None,
        namespace: str | None = None,
        pod: str | None = None,
        container: str | None = None,
        levels: list[str] | None = None,
        keyword: str | None = None,
        since: str | None = None,
        until: str | None = None,
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """Application logs (kubernetes-logs index) with live OpenSearch fallback."""
        index = index or self.settings.opensearch_index_logs
        if self.available():
            try:
                resp = self._client.search(index=index, body=self._logs_query(
                    namespace, pod, container, levels, keyword, since, until
                ), size=size)
                hits = resp.get("hits", {}).get("hits", [])
                hits = sorted(hits, key=lambda h: h.get("_source", {}).get("timestamp", ""), reverse=True)
                return [h.get("_source", {}) for h in hits]
            except Exception:
                pass
        return self._simulated_logs(index, namespace, pod, container, levels, keyword, since, until, size)

    def _logs_query(
        self,
        namespace: str | None,
        pod: str | None,
        container: str | None,
        levels: list[str] | None,
        keyword: str | None,
        since: str | None,
        until: str | None,
    ) -> dict[str, Any]:
        must: list[Any] = [{"match_all": {}}]
        if keyword:
            must = [{"multi_match": {"query": keyword, "fields": ["message^2", "pod^1.5", "container", "deployment", "image"]}}]
        filters: list[Any] = []
        if namespace:
            filters.append({"term": {"namespace.keyword": namespace}})
        if pod:
            filters.append({"term": {"pod.keyword": pod}})
        if container:
            filters.append({"term": {"container.keyword": container}})
        if levels:
            filters.append({"terms": {"level.keyword": [l.upper() for l in levels]}})
        rng: dict[str, Any] = {}
        if since or until:
            if since:
                rng["gte"] = since
            if until:
                rng["lte"] = until
            filters.append({"range": {"timestamp": rng}})
        return {"query": {"bool": {"must": must, "filter": filters}}, "sort": [{"timestamp": {"order": "desc"}}]}

    def log_facets(self, index: str | None = None) -> dict[str, Any]:
        """Distinct namespace / pod / container / level values for log filters."""
        index = index or self.settings.opensearch_index_logs
        if self.available():
            agg: dict[str, Any] = {}
            for field in ("namespace", "pod", "container", "level"):
                agg[field] = {"terms": {"field": f"{field}.keyword", "size": 200}}
            try:
                resp = self._client.search(
                    index=index,
                    body={"aggs": agg, "size": 0},
                )
                return {
                    "namespaces": self._agg_keys(resp, "namespace"),
                    "pods": self._agg_keys(resp, "pod"),
                    "containers": self._agg_keys(resp, "container"),
                    "levels": self._agg_keys(resp, "level"),
                }
            except Exception:
                pass
        return self._simulated_log_facets()

    @staticmethod
    def _agg_keys(resp: dict[str, Any], name: str) -> list[str]:
        buckets = resp.get("aggregations", {}).get(name, {}).get("buckets", [])
        return [b.get("key") for b in buckets]

    def _simulated_log_facets(self) -> dict[str, Any]:
        from backend.services import simulation

        events = simulation.app_logs(limit=500)
        return {
            "namespaces": sorted({e.get("namespace", "") for e in events if e.get("namespace")}),
            "pods": sorted({e.get("pod", "") for e in events if e.get("pod")}),
            "containers": sorted({e.get("container", "") for e in events if e.get("container")}),
            "levels": sorted({e.get("level", "") for e in events if e.get("level")}),
        }

    def _simulated_logs(
        self,
        index: str,
        namespace: str | None,
        pod: str | None,
        container: str | None,
        levels: list[str] | None,
        keyword: str | None,
        since: str | None,
        until: str | None,
        size: int,
    ) -> list[dict[str, Any]]:
        from backend.services import simulation

        events = simulation.app_logs(namespace or "ai-observability-demo", limit=500)
        kw = (keyword or "").lower()
        return [
            e for e in events
            if (not namespace or e.get("namespace") == namespace)
            and (not pod or e.get("pod") == pod)
            and (not container or e.get("container") == container)
            and (not levels or (e.get("level") or "").upper() in {l.upper() for l in levels})
            and (not kw or kw in (e.get("message") or "").lower() or kw in (e.get("pod") or "").lower())
            and (not since or (e.get("timestamp") or "") >= since)
            and (not until or (e.get("timestamp") or "") <= until)
        ][:size]

    def _simulated(self, index: str, query: dict[str, Any], size: int) -> list[dict[str, Any]]:
        from backend.services import simulation

        if index == self.settings.opensearch_index_falco or "falco" in index:
            events = simulation.falco_events()
        elif index == self.settings.opensearch_index_audit or "audit" in index:
            events = simulation.audit_events() + simulation.audit_events()[:1]
        else:
            events = simulation.audit_events()
        return events[:size]


_opensearch: OpenSearchClient | None = None
_opensearch_lock = threading.Lock()


def get_opensearch() -> OpenSearchClient:
    global _opensearch
    if _opensearch is None:
        with _opensearch_lock:
            if _opensearch is None:
                _opensearch = OpenSearchClient()
    return _opensearch