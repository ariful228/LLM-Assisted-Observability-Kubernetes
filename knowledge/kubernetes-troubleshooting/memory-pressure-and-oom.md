# Memory Pressure and OOM Killed Containers

When `container_memory_working_set_bytes` is above 85% of the pod limit, or a
container is terminated with reason `OOMKilled` (exit code 137), the kernel
memory cgroup killed the container because its usage exceeded the configured
limit.

## Evidence to collect

- Prometheus memory working-set series over the last 15 minutes.
- Pod status: container `last_state.terminated.reason == OOMKilled`, exit code 137.
- Restart count and Kubernetes events for the pod.
- Current and previous container logs (a runaway allocator or leak often shows a
  steady allocation log before the kill).
- Deployment resource requests/limits.

## Reasoning

A rising memory footprint ending in OOMKilled points to a memory leak or unbounded
buffering, not a transient burst. Scaling the deployment reduces per-pod pressure
but does not fix the leak. Raising the resource limit can delay the failure and is
therefore a human-review decision in this prototype.

## Runbook

1. Confirm the OOM evidence (restart count, exited 137, working set at limit).
2. Recommend a scaling action for immediate relief.
3. Require human approval before changing resource limits.
4. Verify post-action memory working set falls below threshold and restarts stop.