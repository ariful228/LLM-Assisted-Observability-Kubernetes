"""Langfuse tracing wrapper with a no-op fallback.

Captures the full lifecycle: workflow -> evidence -> RAG -> LLM -> policy ->
MCP -> Kubernetes -> verification. Safe to call even when Langfuse is not
configured or reachable.

Uses the Langfuse v4 OpenTelemetry API: every `trace()` becomes a standalone
root span (observation) that is ended and flushed immediately, so it shows up
as a trace in the Langfuse UI without any lifecycle maintenance at call sites.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable

from backend.services.config import get_settings

logger = logging.getLogger(__name__)


class LangfuseTracer:
    def __init__(self) -> None:
        self._settings_provider = get_settings
        self._client = None

    @property
    def settings(self):
        return self._settings_provider()

    def enabled(self) -> bool:
        s = self.settings
        return bool(s.langfuse_enabled and s.langfuse_host and s.langfuse_public_key)

    def _ensure(self):
        if self._client is not None:
            return
        try:
            from langfuse import Langfuse  # noqa: PLC0415

            s = self.settings
            self._client = Langfuse(
                host=s.langfuse_host,
                public_key=s.langfuse_public_key,
                secret_key=s.langfuse_secret_key,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Langfuse init failed, tracing disabled: %s", exc)
            self._client = None

    def get_callback(self):
        # langchain callback integration is not available in the v4 event path
        return None

    def trace(self, name: str, **kwargs: Any) -> Any | None:
        """Record a root span/trace into Langfuse (best effort, ends it)."""
        if not self.enabled():
            return None
        try:
            self._ensure()
            span = self._client.start_observation(name=name, as_type="span", **kwargs)
            span.end()
            return span
        except Exception as exc:  # noqa: BLE001
            logger.warning("Langfuse trace failed (ignored): %s", exc)
            return None

    def update(self, trace: Any | None, **kwargs: Any) -> None:
        if trace is None or not self.enabled():
            return
        try:
            trace.update(**kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Langfuse update failed (ignored): %s", exc)

    def flush(self) -> None:
        if not self.enabled():
            return
        try:
            self._ensure()
            self._client.flush()
        except Exception:  # noqa: BLE001
            pass


_tracer: LangfuseTracer | None = None
_tracer_lock = threading.Lock()


def get_tracer() -> LangfuseTracer:
    global _tracer
    if _tracer is None:
        with _tracer_lock:
            if _tracer is None:
                _tracer = LangfuseTracer()
    return _tracer


def traced(name: str) -> Callable[[Callable], Callable]:
    def deco(fn):
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            trace = tracer.trace(name=name)
            try:
                result = fn(*args, **kwargs)
                if trace is not None:
                    tracer.update(trace, output=str(result)[:2000])
                return result
            except Exception as exc:  # noqa: BLE001
                if trace is not None:
                    tracer.update(trace, error=str(exc))
                raise
            finally:
                if trace is not None:
                    tracer.flush()

        return wrapper

    return deco