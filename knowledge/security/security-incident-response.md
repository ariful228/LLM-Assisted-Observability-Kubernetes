# Security Incident Response

Kubernetes security signals come from multiple sources: Falco runtime events,
audit log entries, and RBAC changes. An effective response correlates them
instead of reacting to a single alert.

## Alert flow

1. Falco flags a suspicious action in a pod (e.g. shell spawned in a container,
   unexpected file read, suspicious network call).
2. The audit log may confirm privileged commands or `kubectl` actions by a
   service account.
3. RBAC changes (new ClusterRoleBindings, escalations) are a separate high-risk
   signal.

Never execute destructive actions from a security alert. The correct first step
is evidence collection and human triage.

## Handling security incidents

- Preserve evidence instead of restarting pods (a restart destroys volatile
  forensics).
- Check the audit log for the corresponding API request and principal.
- Escalate to a human; security responses are never fully automated in this
  prototype.
- For RBAC abuse: roll back the RoleBinding/ClusterRoleBinding and verify
  via audit log that no new escalations exist.