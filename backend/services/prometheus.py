"""Prometheus client with graceful simulation fallback.

`query` is used by the evidence collector. If the live Prometheus is
unavailable the simulated series are returned (research-demo behaviour).
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
from prometheus_client import Counter, Gauge

from backend.services.config import get_settings
from backend.services import simulation

QUERIES_TOTAL = Counter("aio_prometheus_queries_total", "Prometheus queries issued", ["target"])
PROMETHEUS_UP = Gauge("aio_prometheus_up", "Is live Prometheus reachable")


class PrometheusClient:
    def __init__(self) -> None:
        self._settings_provider = get_settings

    @property
    def settings(self):
        return self._settings_provider()

    def available(self) -> bool:
        if not self.settings.prometheus_url:
            return False
        try:
            resp = httpx.get(self.settings.prometheus_url + "/-/healthy", timeout=2.0)
            return resp.status_code == 200
        except Exception:
            return False

    def query(self, query: str, steps: int = 15) -> dict[str, Any]:
        """Range query -> {result, series:[{t,v}], live: bool}."""
        QUERIES_TOTAL.labels("live" if self.settings.prometheus_url else "simulated").inc()
        if self.settings.prometheus_url:
            try:
                data = self._live_query(query, steps)
                if data is not None:
                    PROMETHEUS_UP.set(1)
                    return {"result": "live", "series": data}
            except Exception:
                PROMETHEUS_UP.set(0)
        PROMETHEUS_UP.set(0)
        data = simulation.prometheus_query(query, steps)
        return {"result": "simulated", "series": data.get("series", [])}

    def _live_query(self, query: str, steps: int) -> Any | None:
        settings = self.settings
        params = {
            "query": query,
            "start": time.time() - 900,
            "end": time.time(),
            "step": max(15, 900 // max(1, steps)),
        }
        resp = httpx.get(
            settings.prometheus_url + "/api/v1/query_range", params=params, timeout=5.0
        )
        resp.raise_for_status()
        body = resp.json()
        series: list[dict[str, Any]] = []
        for result in body.get("data", {}).get("result", []):
            for value in result.get("values", []):
                series.append({"t": _ts(value[0]), "v": float(value[1])})
        return series


def _ts(unix: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(unix, tz=timezone.utc).isoformat()


_prom: PrometheusClient | None = None
_prom_lock = threading.Lock()


def get_prometheus() -> PrometheusClient:
    global _prom
    if _prom is None:
        with _prom_lock:
            if _prom is None:
                _prom = PrometheusClient()
    return _prom