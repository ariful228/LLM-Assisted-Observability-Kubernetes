"""Component availability probe used by /api/status and reliability handling."""

from __future__ import annotations

import functools
import logging
from typing import Callable

from backend.services.config import get_settings

logger = logging.getLogger(__name__)


def component_status() -> dict[str, dict]:
    """Return reachability state for every external component."""
    settings = get_settings()
    return {
        "prometheus": {
            "configured": bool(settings.prometheus_url),
            "available": _probe("prometheus"),
        },
        "opensearch": {
            "configured": bool(settings.opensearch_url),
            "available": _probe("opensearch"),
        },
        "kubernetes": {
            "configured": True,
            "available": _probe("kube"),
            "mode": _probe("kube_mode"),
        },
        "falco": {
            "configured": bool(settings.opensearch_url),
            "available": _probe("falco"),
        },
        "grafana": {
            "configured": bool(settings.grafana_url),
            "available": _probe("grafana"),
        },
        "slack": {
            "configured": bool(settings.slack_webhook_url),
            "available": bool(settings.slack_enabled and settings.slack_webhook_url),
        },
        "langfuse": {
            "configured": bool(settings.langfuse_enabled),
            "available": bool(
                settings.langfuse_enabled and settings.langfuse_host and settings.langfuse_public_key
            ),
        },
        "rag": {
            "store": settings.rag_store,
            "configured": settings.rag_store != "",
            "available": _probe("rag"),
            "pgvector_url": settings.pgvector_url_value(),
        },
        "llm": {
            "provider": settings.llm_provider,
            "configured": settings.llm_provider in ("mock", "openai", "ollama"),
            "available": True,
        },
    }


def _probe(name: str):
    try:
        if name == "prometheus":
            from backend.services import prometheus

            return prometheus.get_prometheus().available()
        if name == "opensearch":
            from backend.services import opensearch

            return opensearch.get_opensearch().available()
        if name == "kube":
            from backend.services import kube

            return kube.get_kube().available()
        if name == "kube_mode":
            from backend.services import kube

            return kube.get_kube().mode
        if name == "falco":
            return _probe("opensearch")
        if name == "grafana":
            from backend.services.config import get_settings as gs

            url = gs().grafana_url
            if not url:
                return False
            import httpx

            try:
                resp = httpx.get(f"{url.rstrip('/')}/api/health", timeout=2.0)
                return resp.status_code == 200
            except Exception:  # noqa: BLE001
                return False
        if name == "rag":
            from backend.services.rag import get_index

            return get_index().available_backends()
    except Exception as exc:  # noqa: BLE001
        logger.debug("component probe %s failed: %s", name, exc)
        return False
    return False


def guarded(mode_names: tuple[str, ...] = ("simulated",)):
    """Decorator that on live-mode failure falls back to simulation.

    Used by evidence collectors so a failed live integration degrades
    gracefully instead of aborting the workflow.
    """

    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            from backend.services import kube

            try:
                return fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                if kube.get_kube().mode == "simulated":
                    raise
                logger.warning("%s failed, falling back to simulation: %s", fn.__name__, exc)
                raise NotImplementedError(f"live {fn.__name__} unavailable")

        return wrapper

    return deco