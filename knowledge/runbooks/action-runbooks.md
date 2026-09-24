# Runbook: Scale a Deployment

**Trigger:** sustained high CPU / memory pressure on a workload.

1. Confirm evidence: CPU > 80% for 5 min, or memory working set at limit.
2. Policy engine evaluates `scale_deployment`; only `high_cpu` is auto-approvable;
   memory/OOM scale actions require human approval.
3. Tool `scale_deployment` sets desired replicas; delta capped by policy
   (`max_autoscale_delta`, `max_autoscale_replicas`) and the deployment must be
   in the allowlist.
4. Verify: `availableReplicas == desiredReplicas`, all Ready, no scheduling
   failures, and post-action usage below threshold.

## Runbook: Restart a Deployment

**Trigger:** CrashLoopBackOff / unhealthy deployment needing a reset.

1. Collect logs (current + previous), exit code, events.
2. Approve `restart_deployment` (disruptive → human approval required).
3. Tool restarts the workload; verify recreate rollout completes and pod ready
   within timeout, restart count stabilises.

## Runbook: Renew a Certificate

**Trigger:** certificate expiry below `cert_threshold_days`.

1. Confirm `days_left_to_expiry` and both cert chain files.
2. Approve `renew_certificate`.
3. Tool regenerates cert; verify expiry resets and `chain_valid == true`.

## Runbook: Roll Back a Suspicious RBAC Binding

**Trigger:** audit-log or Falco signal of RBAC escalation.

1. Correlate audit entries (who bound cluster-admin / when) with Falco events.
2. Approve `rollback_rbac` (high risk).
3. Tool removes/reverts the RoleBinding; verify binding gone and no new
   escalations in the audit window.

**Golden rule:** the LLM proposes and explains; the policy engine decides;
humans approve anything non-trivial; tools verify their own work.