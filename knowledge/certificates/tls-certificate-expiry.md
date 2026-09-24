# TLS Certificate Expiry

Certificates are checked by `days_left_to_expiry`. A threshold below the global
`cert_threshold_days` triggers the certificate threat scenario, which includes
the original certificate source plus an additional threat-detection certificate.

## Detection signals

- Certificate metadata file(s) under `data/certs/` with low `days_left_to_expiry`.
- Repeated TLS handshake failures after expiry.
- Log lines from ingress/proxy components mentioning certificate validation.

## Remediation

`renew_certificate` regenerates the certificate for the target and updates the
certificate state:

- `expires_days` resets to `cert_validity_days`.
- `chain_valid` recomputed for both certificates.

## Verification checklist

- Certificate expiry days now greater than (or equal to) `cert_validity_days`.
- TLS chain valid for all tracked certificates.
- No remaining 5xx / TLS validation errors in the window.

Certificate renewal is a cluster-wide operation with availability impact, so it
requires human approval before the tool runs.