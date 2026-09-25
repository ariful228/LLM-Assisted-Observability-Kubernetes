# LLM-Assisted Observability & Security System for Kubernetes

A research-grade, dependency-light **demo** (Advanced LLM-Assisted Observability and
Security Operations Platform) that integrates an LLM assistant with Kubernetes
observability — while keeping the **LLM out of the execution path** and making the
**policy engine** the authoritative decision point.

- LLM proposes recommendations and explains evidence; a deterministic **policy engine** decides.
- **AUTO** only for sustained-high-CPU auto-scale; everything else requires **human approval**.
- The LLM can only *propose* MCP tool calls; execution goes through validation → allowlist → policy → authorization → audit → verification.
- RAG retrieval grounds diagnoses in a curated knowledge base (`knowledge/`).
- Runs fully standalone in `simulated` mode (no cluster, no LLM API key).

## The six scenarios

| # | Scenario | Detection source | Recommended action | Policy |
|---|----------|------------------|--------------------|--------|
| 1 | Sustained high CPU | Prometheus | `scale_deployment` | **AUTO** |
| 2 | High memory | Prometheus | memory review / scale | APPROVAL_REQUIRED |
| 3 | OOM killed | K8s pod status | `scale_deployment` | APPROVAL_REQUIRED |
| 4 | CrashLoopBackOff | K8s pod status | `restart_deployment` | APPROVAL_REQUIRED |
| 5 | Certificate expiring (incl. threat-detection cert) | cert monitor | `renew_certificate` | APPROVAL_REQUIRED |
| 6 | Falco shell in container | Falco events | investigation (noop) | APPROVAL_REQUIRED |
| 7 | Suspicious RBAC (cluster-admin) | audit log | `rollback_rbac` | APPROVAL_REQUIRED |

## Architecture

```
Grafana alerts ─> /api/incidents (/detect, /ingest)
Prometheus / OpenSearch / K8s / Falco / cert-monitor ─> evidence collectors (simulated fallbacks)
        │
        ▼
LANGRAPH WORKFLOW (investigation graph)
  classify → collect_evidence → correlate → rag_retrieve → diagnose → risk → plan → policy_check
        │ AUTO                       │ APPROVAL_REQUIRED            │ NO_ACTION
        ▼                            ▼                              ▼
  execution graph              human approval                finalize / no action
   execute → verify → finalize   (API / CLI / web UI)
        │
        ▼  MCP controlled tool layer (validation → allowlist → policy → authorization
            → execution → audit → verification). No shell / kubectl tools exposed.
```

## Quick start (simulated, no infra needed)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env            # optional; defaults are fine
.venv/bin/python -m uvicorn backend.main:app --reload --port 8199
```

Open http://localhost:8199 — the web UI dashboard is organised by category
(**Security · Utilization · OS & Node · Cluster & Workloads · AI Pipeline ·
Observability Stack**), with deep links into the Pipeline Simulator, plus an
incident list, approval panels, MCP tools, live RAG search, an **Application
Logs** view backed by the `kubernetes-logs` OpenSearch index, and an animated
**Workflow Sim** view that replays any incident through the LangGraph pipeline.

The **Application Logs** tab streams structured container logs
(`GET /api/logs`) and facet values (`GET /api/logs/facets`) with namespace /
pod / container / level / keyword / time-window filters. When OpenSearch is
reachable it runs a real Query DSL search against `kubernetes-logs`; otherwise
it falls back to a deterministic simulation that reflects the current cluster
state (crash-demo ERROR lines disappear once it is restarted, etc.).

### One-command demo

```bash
./scripts/run_demo.sh                          # venv + deps + .env + serve
./scripts/run_demo.sh --drive-demo             # also run detect + approve-all
./scripts/run_demo.sh --skip-install --no-reset --port 8199
```

### Drive the demo from the CLI

```bash
PYTHONPATH=. .venv/bin/python scripts/demo_driver.py --reset --detect     # run all scenarios
PYTHONPATH=. .venv/bin/python scripts/demo_driver.py --approve-all        # act as human approver
PYTHONPATH=. .venv/bin/python scripts/demo_driver.py --list
```

## Run everything locally (self-managed, case-aiops style)

Everything runs on one machine — infra + trace stack via docker compose, a local
Kubernetes cluster via kind, and the RAG databases seeded in place. One script
manages it all; every port binds to `127.0.0.1`.

```bash
./scripts/run_stack.sh all              # stack up + kube up + seed + run (one shot)
./scripts/run_stack.sh status           # what is reachable right now
./scripts/run_stack.sh stack up|down    # Prometheus/Grafana/OpenSearch/pgvector (+ Langfuse)
./scripts/run_stack.sh kube up|down     # local kind cluster + apply manifests
./scripts/run_stack.sh kube install-tools  # fetch kind+kubectl into tools/bin (project-local)
./scripts/run_stack.sh seed             # seed RAG DBs + OpenSearch demo logs
./scripts/run_stack.sh rag              # RAG database information (backends, freshness)
./scripts/run_stack.sh run              # start the platform (uvicorn)
```

| Service | URL | Notes |
|---------|-----|-------|
| Platform | http://localhost:8199 | FastAPI + web UI at `/` |
| Prometheus | http://localhost:9090 | alert rules for the 7 scenarios |
| Grafana | http://localhost:3001 | `admin / admin`, dashboard provisioned |
| OpenSearch | http://localhost:9200 | logs/audit/falco + RAG BM25 index |
| pgvector | `localhost:5434` | hybrid vector+tsvector RAG store |
| Langfuse | http://localhost:3000 | self-hosted tracing (UI / project `ai-observability`) |
| Slack sink | http://localhost:5050 | local inbox for platform "Slack" webhooks |
| kind cluster | `kind-ai-observability-local` | all demo workloads + Falco/aggregator |

`kind` and `kubectl` live in `tools/bin/` (git-ignored) so the whole stack is
managed from this checkout — no system-wide installs required.

From the platform's System tab, every component reads `configured · available`:
Prometheus, OpenSearch, **Kubernetes (live)** and Falco talk to the local infra;
Grafana is health-probed, Slack POSTs to the local sink, Langfuse receives each
workflow/incident as a trace, RAG uses the reachable backends, and the mock LLM
counts as configured. `run_stack.sh` starts a tiny host TCP forwarder
(`tools/host_forward.py`) so the platform container can reach the loopback-bound
Langfuse and kind API server.

### Generate load & watch auto-scaling (Locust + HPA)

A real-cluster demo: metrics-server is deployed, `locust-demo` runs a web
service that burns ~100ms CPU per request, and an `autoscaling/v2` HPA scales
replicas on CPU pressure.

```bash
./tools/bin/kubectl apply -f kubernetes/loadtest/locust-demo.yaml -f kubernetes/loadtest/hpa.yaml
./scripts/loadtest.sh -u 60 -t 2m            # auto-installs locust + port-forwards
```

While it runs, watch scaling live:

```bash
watch -n 3 ./tools/bin/kubectl -n ai-observability-demo get hpa,deploy,pods
# or
./tools/bin/kubectl -n ai-observability-demo get hpa -o jsonpath='{.status.currentMetrics[0].resource.current.averageUtilization}{" -> desired "}{.status.desiredReplicas}{"\n"}' -w
```

```
# 60 users -> HPA reaction (target 60% of the 200m CPU request):
cpu: 146% -> desired 2      # t=+10s
cpu:  92% -> desired 4      # t=+30s  (new pods scheduling)
cpu: ~50% -> desired 4      # converged; scales down after idle (stabilization 120s)
```

## Files / layout

```
backend/
  agents/        observability, correlation, diagnosis, remediation
  api/           incidents, approvals, mcp, knowledge, logs, metrics,
                 evaluation, workflow
  mcp/           controlled tool registry + executor (+ validator)
  models/        incident / evidence / policy / execution models (spec §14)
  policy/        policy engine (P-01..P-08, P-99) + guardrails
  services/      config, simulation, prometheus, opensearch (query logs + facets),
                 kube, falco, slack, langfuse trace, cert monitor, detector,
                 llm, rag, store, metrics
  workflows/     LangGraph investigation + execution graphs
frontend/        dashboard UI (vanilla JS, served at /) + pipeline simulator
                 (self-contained simulator.html → /static/simulator.html)
                 + Application Logs view (OpenSearch-backed)
knowledge/       RAG knowledge base (markdown, per category)
monitoring/      Prometheus rules, Grafana dashboard, Alertmanager, Falco rules
kubernetes/      namespace, rbac, demo workloads, test scenarios, monitoring
docker/          Dockerfile + docker-compose (platform, prometheus, grafana, opensearch, pgvector)
                 + langfuse-compose.yml (self-hosted Langfuse, local)
tools/bin/       project-local kind + kubectl (git-ignored)
scripts/         demo_driver.py + run_demo.sh + run_stack.sh (everything-local manager)
                 + seed_rag.py + seed_opensearch.py
tests/           pytest suite (85 tests: policy, MCP, workflow, API, RAG, logs, models)
docs/            architecture.drawio (incl. self-managed local infra)
```

## Security model (important)

1. **LLM never executes** Kubernetes actions — it proposes a recommendation; only the MCP tool executor can run actions, and only after passing all gates.
2. **Policy engine is authoritative** — the LLM's recommendation is advisory. Unknown → FAIL CLOSED to NO_ACTION (P-99, P-FAIL).
3. **Human in the loop** — every action other than high-CPU auto-scale requires explicit approval.
4. **No dangerous tools** — `/api/mcp/no-unsafe-tools` returns `true`; the registry has zero shell/kubectl/delete tools.
5. **Auditable** — every execution records the policy decision, executor identity, output, and a verification result.

## Tests

```bash
.venv/bin/python -m pytest -q        # 85 passed
```

## Going live

Set `EXTERNAL_MODE=live` (or remove `FORCE_SIMULATION=true`) and point
`PROMETHEUS_URL` / `OPENSEARCH_URL` / `OPENAI_API_KEY` at real systems. The
adapters degrade per-component to simulation so nothing hard-crashes. In-cluster
manifests under `kubernetes/` (plus `docker/docker-compose.yml`) show how to run
the supporting stack.

## Notes for reviewers

- The simulated Prometheus series is **deterministic but stateful**: scaling a
  deployment actually increases its reported replica count, restarting clears
  CrashLoopBackOff, renewing resets certificate expiry, RBAC rollback removes
  the binding — so every verify step checks real post-conditions.
- RAG is a pure-python TF-IDF index over `knowledge/**/*.md`; swap
  `backend/services/rag.py::KnowledgeIndex` for a dense retriever without
  touching the workflow.
- Mock LLM (`LLM_PROVIDER=mock`) is deterministic and evidence-driven; use
  `openai` / `ollama` providers via LangChain with automatic fallback to mock.
- The security posture seed covers all four layers — application
  (config drift), container (privileged, apparmor, seccomp, SCA/CVE image,
  secrets-in-env, capabilities, image pull policy), node/cloud (kubelet
  hardening on both control-plane and workers) and cluster (netpol, RBAC,
  service-account token auto-mount). One application finding auto-remediates;
  everything else is a `apply_security_config` proposal needing human approval.
- Every RAG hit in the UI is labelled with its real backend
  (`tfidf` / `pgvector` / `opensearch`), so the retrieved-document → chunk →
  similarity → source chain is always auditable.