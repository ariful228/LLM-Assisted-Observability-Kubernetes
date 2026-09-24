"""Locust load-test profile for the locust-demo workload.

Hammers /work — every request burns ~100ms of CPU on the pod, so aggregate
traffic drives the deployment's CPU utilisation past the HPA threshold and
the HorizontalPodAutoscaler scales replicas up.

Run (from repo root, stack up):
    ./scripts/loadtest.sh --users 60 --time 3m
    # or manually:
    .venv/bin/locust --headless -u 60 -r 10 -t 3m \
        --host http://127.0.0.1:8080 -f tools/locustfile.py
"""

from locust import HttpUser, between, task


class WorkUser(HttpUser):
    wait_time = between(0.1, 0.3)

    @task
    def burn_cpu(self):
        self.client.get("/work")