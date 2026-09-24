# Sustained High CPU Utilisation

A pod reporting CPU above 80% for five minutes or longer usually means one of:
an un-scaled workload receiving more traffic, a tight loop / busy-wait, a metric
scrape or batch job running inside the pod, or missing CPU limits that let the
container consume all available cores.

## Investigation steps

1. Query Prometheus for `container_cpu_usage_seconds_total` and `node_cpu_utilization`
   to separate per-pod usage from node-level contention.
2. Look at deployment replica count and recent scaling events in Kubernetes events.
3. Inspect pod logs for a repeated busy loop, and check for `rate()` of request
   volume on the service.

## Remediation

- Scaling the deployment by one replica (`scale_deployment`) is a low-risk,
  reversible action that distributes load. This is the only CPU remediation
  that is allowed to run automatically in this research prototype.
- If CPU stays high after scaling, consider request/limit tuning, autoscaling,
  or application profiling — these require human review.

## Never

- Never change limits or kill pods automatically for a plain CPU spike.
- Never bypass the policy engine to scale manually.