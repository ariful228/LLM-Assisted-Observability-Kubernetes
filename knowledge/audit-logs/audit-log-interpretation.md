# Interpreting Orchestrator Audit Logs

Kubernetes audit logging records every API request against the control plane.
Each entry contains authentication context, the requested resource, the
verb, and the response.

## Anatomy of an audit entry

- `user.username`, `user.groups` — who acted.
- `verb` — `get`, `list`, `create`, `update`, `patch`, `delete`, `bind`.
- `resource` — group/version and resource type (pod, secret, clusterrolebinding).
- `objectRef.name`, `objectRef.namespace` — target.
- `responseStatus.code` — 200/201 allowed, 401/403 denied.
- `requestURI` — full path.

## Red flags

- **Escalation**: creating or binding roles with elevated verbs — a service
  account binding `cluster-admin` for itself.
- **Credential access**: reading secrets, especially across namespaces.
- **Destructive operations**: delete/scale of production workloads from an
  unusual principal or at odd hours.
- **Denied repeated attempts** followed by a sudden allowed sensitive action.

## Correlation

Start a timeline from the audit entries, overlay Falco events in the same
window, then tie to RBAC objects. This prototype demonstrates exactly that
three-way correlation on the `rbac` and `falco` scenarios.