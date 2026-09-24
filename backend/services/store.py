"""In-memory incident store with lightweight JSON file persistence.

Keeps the demo dependency-free. Records are persisted to `data/incidents.json`
so the Web UI / evaluation can inspect them after restarts.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Optional

from backend.models.incident import Incident, IncidentStatus

_EMPTY = object()


class IncidentStore:
    def __init__(self, data_dir: str = "data"):
        self._data_dir = data_dir
        self._path = os.path.join(data_dir, "incidents.json")
        self._lock = threading.RLock()
        self._incidents: dict[str, Incident] = {}
        self._seq = 0
        os.makedirs(data_dir, exist_ok=True)
        self._load()

    # -- persistence ----------------------------------------------------
    def _load(self) -> None:
        try:
            if os.path.exists(self._path):
                with open(self._path, encoding="utf-8") as fh:
                    raw = json.load(fh)
                for item in raw:
                    inc = Incident.model_validate(item)
                    self._incidents[inc.incident_id] = inc
                self._seq = max((int(i.split("-")[-1]) for i in self._incidents), default=0)
        except Exception:
            # Corrupt/unreadable state must not crash the demo controller.
            self._incidents = {}
            self._seq = 0

    def _flush(self) -> None:
        try:
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(
                    [i.model_dump(mode="json") for i in self._incidents.values()],
                    fh,
                    indent=2,
                )
        except OSError:
            pass

    # -- ids -------------------------------------------------------------
    def next_incident_id(self, prefix: str = "inc") -> str:
        with self._lock:
            self._seq += 1
            return f"{prefix}-{self._seq:05d}"

    # -- CRUD ------------------------------------------------------------
    def create(self, incident: Incident) -> Incident:
        with self._lock:
            self._incidents[incident.incident_id] = incident
            self._flush()
            return incident

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            return self._incidents.get(incident_id)

    def update(self, incident: Incident) -> Incident:
        with self._lock:
            incident.touch()
            self._incidents[incident.incident_id] = incident
            self._flush()
            return incident

    def list(self) -> list[Incident]:
        with self._lock:
            return sorted(
                self._incidents.values(),
                key=lambda i: i.detected_at,
                reverse=True,
            )

    def list_open(self) -> list[Incident]:
        active = {
            IncidentStatus.DETECTED,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.AWAITING_APPROVAL,
            IncidentStatus.APPROVED,
            IncidentStatus.EXECUTING,
        }
        return [i for i in self.list() if i.status in active]

    def clear(self) -> None:
        with self._lock:
            self._incidents = {}
            self._seq = 0
            self._flush()


_store: Optional[IncidentStore] = None
_store_lock = threading.Lock()


def get_store() -> IncidentStore:
    global _store
    if _store is None:
        from backend.services.config import get_settings

        with _store_lock:
            if _store is None:
                _store = IncidentStore(get_settings().data_dir)
    return _store


def reset_store() -> None:
    global _store
    with _store_lock:
        _store = None
        from backend.services.config import get_settings

        path = os.path.join(get_settings().data_dir, "incidents.json")
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass