"""Application logs API (OpenSearch ``kubernetes-logs`` index, simulated fallback)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from backend.services.opensearch import get_opensearch

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("")
def query_logs(
    namespace: str = "",
    pod: str = "",
    container: str = "",
    level: str = "",
    keyword: str = "",
    since: str = "",
    until: str = "",
    size: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Query application logs with optional filters.

    Filters are AND-ed. ``level``/``namespace``/``pod``/``container`` come from
    the log facets; ``keyword`` does a substring (or multi_match) search across
    message / pod / container / deployment; ``since``/``until`` are inclusive
    RFC3339 timestamps.
    """
    levels = [l.strip().upper() for l in level.split(",") if l.strip()] if level else None
    os = get_opensearch()
    hits = os.query_logs(
        namespace=namespace or None,
        pod=pod or None,
        container=container or None,
        levels=levels,
        keyword=keyword or None,
        since=since or None,
        until=until or None,
        size=size,
    )
    return {
        "index": os.settings.opensearch_index_logs,
        "count": len(hits),
        "filters": {
            "namespace": namespace or None,
            "pod": pod or None,
            "container": container or None,
            "levels": levels or None,
            "keyword": keyword or None,
            "since": since or None,
            "until": until or None,
        },
        "hits": hits,
    }


@router.get("/facets")
def log_facets() -> dict[str, Any]:
    """Distinct namespaces / pods / containers / levels for the log filters."""
    facets = get_opensearch().log_facets()
    facets["index"] = get_opensearch().settings.opensearch_index_logs
    return facets