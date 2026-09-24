# Deployment Scaling Patterns

Kubernetes deployments own a ReplicaSet that creates pods. Scaling changes
`spec.replicas`; the deployment controller converges desired and actual state.

## Auto-scaling considerations

- Scaling out by one replica is reversible and low risk when sustained CPU load
  causes degraded latency.
- Always cap the maximum replica count. In this prototype the policy engine
  enforces `max_autoscale_delta` and `max_autoscale_replicas`.
- Verify convergence: `kubectl rollout status deployment/<name>` and check
  `availableReplicas == desiredReplicas`.

## Verification checklist

- Desired replicas reached (`spec.replicas == status.availableReplicas`).
- All replicas Ready.
- No new scheduling failures (insufficient cpu/memory).
- Observe 5-10 minutes of load to confirm per-pod utilisation dropped.