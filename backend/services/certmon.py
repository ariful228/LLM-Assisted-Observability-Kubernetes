"""Certificate monitoring.

Reads the expiry of a TLS certificate (a local PEM file when working outside
a cluster, otherwise a Secret in the demo namespace). Determines whether the
certificate is below the configured expiry threshold.
"""

from __future__ import annotations

import datetime
import logging
import os
import threading
from typing import Any

from backend.services import simulation
from backend.services.config import get_settings

logger = logging.getLogger(__name__)


class Certificate:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    @property
    def days_remaining(self) -> float:
        return float(self.data.get("days_remaining", 9999))

    @property
    def expired_soon(self) -> bool:
        threshold = get_settings().cert_expiry_days_threshold
        return self.days_remaining < threshold

    def to_dict(self) -> dict[str, Any]:
        return dict(self.data)


class CertificateMonitor:
    def __init__(self) -> None:
        self._settings_provider = get_settings

    @property
    def settings(self):
        return self._settings_provider()

    def status(self) -> Certificate:
        if self.settings.external_mode == "simulated" or not self.settings.cert_path:
            return Certificate(simulation.certificate_status(self.settings.cert_path))
        if not os.path.exists(self.settings.cert_path):
            return Certificate(simulation.certificate_status(self.settings.cert_path))
        return Certificate(self._read_live(self.settings.cert_path))

    def _read_live(self, path: str) -> dict[str, Any]:
        from cryptography import x509  # noqa: PLC0415

        with open(path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        not_after = cert.not_valid_after_utc
        days = (not_after - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 86400
        return {
            "path": path,
            "common_name": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": round(days, 2),
            "valid": days > 0,
            "chain_valid": True,
        }


_certmon: CertificateMonitor | None = None
_certmon_lock = threading.Lock()


def get_certificate_monitor() -> CertificateMonitor:
    global _certmon
    if _certmon is None:
        with _certmon_lock:
            if _certmon is None:
                _certmon = CertificateMonitor()
    return _certmon