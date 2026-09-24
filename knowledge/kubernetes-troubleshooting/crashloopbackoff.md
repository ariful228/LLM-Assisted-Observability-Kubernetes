# CrashLoopBackOff

CrashLoopBackOff means a container starts, exits, and the kubelet backs off restarts.
The container status shows `waiting` with reason `CrashLoopBackOff` and a growing
restart count (usually 5+).

## Likely causes

- **Configuration error** — the container fatals because a config file / env var /
  secret is missing or wrong (common exit code 1).
- **Application error** — an unhandled exception at startup (exit code != 0).
- **Probe failure** — liveness/readiness probe fails repeatedly, so kubelet restarts.
- **OOM** — container exceeds memory limit (check for OOMKilled in last state).
- **Dependency failure** — DB/API/service it depends on is not reachable.
- **Deployment issue** — wrong image tag, missing command, bad volume mount.

## Evidence to review

1. Current logs: `kubectl logs <pod>`; previous logs `kubectl logs <pod> --previous`.
2. Exit code and last terminated reason from container status.
3. Kubernetes events (`BackOff`, `FailedScheduling`, `Unhealthy`).
4. Deployment spec and recent rollout changes.

## Runbook

- Diagnosis is presented to a human with the collected evidence.
- A restart or rollback of the deployment can clear transient conditions but a
  config/application defect needs a fix.
- Restart/rollback requires approval in this prototype because it is disruptive.