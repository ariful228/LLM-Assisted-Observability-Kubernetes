#!/usr/bin/env bash
#
# run_stack.sh — manage the entire LLM-Assisted Observability demo locally,
# case-aiops style: infra (Prometheus/Grafana/OpenSearch/pgvector/Langfuse)
# via docker compose, a local Kubernetes cluster (kind), RAG seeding, and a
# status/run wrapper. Everything binds to 127.0.0.1 / localhost.
#
# Usage:
#   ./scripts/run_stack.sh status                 # what is reachable right now
#   ./scripts/run_stack.sh stack up               # start dex infra + langfuse
#   ./scripts/run_stack.sh stack down
#   ./scripts/run_stack.sh kube up                # create kind cluster + apply manifests
#   ./scripts/run_stack.sh kube down
#   ./scripts/run_stack.sh seed                   # seed RAG + OpenSearch demo data
#   ./scripts/run_stack.sh rag                    # show RAG database information
#   ./scripts/run_stack.sh run                    # start the platform (uvicorn)
#   ./scripts/run_stack.sh all                    # stack up + kube up + seed + run
#
# Requirements: docker (+ compose), [kind + kubectl], python3. See README.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Local tooling lives inside the repo (tools/bin) so the whole stack is
# managed from this directory — no system-wide installs of kind/kubectl needed.
export PATH="$ROOT/tools/bin:$PATH"

PY="${PYTHON_BIN:-$ROOT/.venv/bin/python}"
PORT="${PORT:-8199}"
COMPOSE="docker compose -f docker/docker-compose.yml"
LANGFUSE="docker compose -f docker/langfuse-compose.yml"

nocolor() { sed -r 's/\x1B\[[0-9;]*[mK]//g'; }
info()  { printf '\033[1;36m[stack]\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m[ok]\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m[warn]\033[0m %s\n' "$1"; }
die()   { printf '\033[1;31m[error]\033[0m %s\n' "$1" >&2; exit 1; }

ensure_env() {
  [[ -f .env ]] || { cp .env.example .env; info "created .env from .env.example"; }
  # local-management additions (idempotent, never overwrite an existing value)
  ensure_env_line() {
    local key="$1" value="$2"
    grep -qE "^${key}=" .env || printf '%s=%s\n' "$key" "$value" >> .env
  }
  ensure_env_line RAG_STORE auto
  ensure_env_line PGVECTOR_URL "postgresql://rag:rag@localhost:5434/rag"
  ensure_env_line OPENSEARCH_INDEX_KNOWLEDGE knowledge-chunks
  ensure_env_line LANGFUSE_ENABLED true
  ensure_env_line LANGFUSE_HOST http://localhost:3000
  ensure_env_line LANGFUSE_PUBLIC_KEY pk-lf-976d879582b60acf
  ensure_env_line LANGFUSE_SECRET_KEY sk-lf-31905c84394ffc10
  ok "env prepared (EXTERNAL_MODE/RAG/LANGFUSE set when applicable)"
}

wait_http() {
  local url="$1" name="$2" tries="${3:-30}"
  local i=0
  until curl -fsSo /dev/null "$url"; do
    i=$((i + 1))
    if [[ $i -ge $tries ]]; then warn "$name not reachable at $url after ${tries}s"; return 1; fi
    sleep 1
  done
  ok "$name up ($url)"
}

# ------------------------------------------------------------ host forward --
# Containers reach host services via host.docker.internal (compose bridge
# gateway). Infra services bind 127.0.0.1 only, so we proxy gateway ->
# loopback: port 3000 (Langfuse web) and 6443 -> the kind API server mapping.
# The proxy is a plain background process (pidfile-managed).
FORWARD_PID="data/host-forward.pid"

compose_gateway() {
  # host-gateway as seen from compose containers = docker0 bridge gateway
  docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null
}

kind_api_port() {
  docker port ai-observability-local-control-plane 6443 2>/dev/null | head -1 | sed 's/.*://'
}

start_host_forward() {
  local gw kind_port rules
  gw="$(compose_gateway)" || gw="172.18.0.1"
  if [[ -z "$gw" ]]; then warn "compose gateway not found — host forwarder not started"; return; fi
  rules=("3000:3000")
  kind_port="$(kind_api_port)"
  [[ -n "$kind_port" ]] && rules+=("6443:$kind_port")
  if [[ -f "$FORWARD_PID" ]] && kill -0 "$(cat "$FORWARD_PID")" 2>/dev/null; then
    kill "$(cat "$FORWARD_PID")" 2>/dev/null || true
    sleep 0.3
  fi
  nohup "$PY" tools/host_forward.py --bind "$gw" "${rules[@]}" >>"data/host-forward.log" 2>&1 &
  echo "$!" > "$FORWARD_PID"
  ok "host forwarder on $gw (${rules[*]})"
}

stop_host_forward() {
  if [[ -f "$FORWARD_PID" ]] && kill -0 "$(cat "$FORWARD_PID")" 2>/dev/null; then
    kill "$(cat "$FORWARD_PID")" 2>/dev/null || true
    rm -f "$FORWARD_PID"
    ok "host forwarder stopped"
  fi
}

# ---------------------------------------------------------------- stack -----
stack_up() {
  ensure_env
  info "starting observability stack (prometheus, grafana, opensearch, pgvector)"
  $COMPOSE up -d
  $COMPOSE ps --services | sed 's/^/  + /'
  info "starting self-hosted Langfuse (traces at http://localhost:3000)"
  $LANGFUSE up -d 2>/dev/null || warn "langfuse stack failed to start — check docker/langfuse-compose.yml"
  wait_http "http://localhost:9090/-/healthy" prometheus 40 || true
  wait_http "http://localhost:9200/_cluster/health" opensearch 60 || true
  wait_http "http://localhost:3001/api/health" grafana 40 || true
  wait_http "http://localhost:5434" pgvector 20 || true
  start_host_forward
  ok "stack ready"
}

stack_down() {
  info "stopping infra stack"
  $COMPOSE down
  $LANGFUSE down 2>/dev/null || true
  stop_host_forward
}

stack_status() {
  echo "--- docker compose --"
  $COMPOSE ps --format 'table {{.Name}}\t{{.Status}}' 2>/dev/null || echo "  (compose project not up)"
  echo "--- langfuse compose --"
  $LANGFUSE ps --format 'table {{.Name}}\t{{.Status}}' 2>/dev/null || echo "  (langfuse project not up)"
}

# ------------------------------------------------------------------ kube -----
have() { command -v "$1" >/dev/null 2>&1; }

kube_check() {
  have kind || die "kind not found in tools/bin — run ./scripts/run_stack.sh kube install-tools (or https://kind.sigs.k8s.io)"
  have kubectl || die "kubectl not found in tools/bin — run ./scripts/run_stack.sh kube install-tools"
  ok "kind + kubectl available"
}

kube_up() {
  ensure_env
  kube_check
  if kind get clusters 2>/dev/null | grep -q "^ai-observability-local$"; then
    info "kind cluster 'ai-observability-local' already exists"
  else
    info "creating kind cluster 'ai-observability-local'"
    kind create cluster --config kubernetes/kind/kind-cluster.yaml || die "kind create failed"
  fi
  info "applying kubernetes manifests"
  kubectl apply -f kubernetes/namespace/namespace.yaml
  for _ in $(seq 1 30); do
    kubectl -n ai-observability-demo get serviceaccount default >/dev/null 2>&1 && break
    sleep 1
  done
  kubectl -n ai-observability-demo get serviceaccount default >/dev/null 2>&1 \
    || die "default ServiceAccount missing in ai-observability-demo"
  apply_failed=0
  for manifest in \
    kubernetes/rbac/rbac.yaml \
    kubernetes/workloads/demo-applications.yaml \
    kubernetes/test-scenarios/scenario-manifests.yaml \
    kubernetes/monitoring/falco-and-grafana-configmaps.yaml \
    kubernetes/aggregation-layer/aggregator.yaml \
    kubernetes/monitoring/prometheus-grafana.yaml; do
    kubectl apply -f "$manifest" || { warn "FAILED to apply $manifest"; apply_failed=1; }
  done
  # container-usable kubeconfig (points at the host-forwarder on 6443 so the
  # ai-obsv-platform container can reach this cluster as "live")
  mkdir -p "$ROOT/tools/bin/kubeconfig"
  kubectl config view --minify --flatten -o yaml \
    > "$ROOT/tools/bin/kubeconfig/kubeconfig-kind.yaml"
  "$PY" - <<'PY'
import pathlib, yaml
p = pathlib.Path("tools/bin/kubeconfig/kubeconfig-kind.yaml")
k = yaml.safe_load(p.read_text())
for c in k["clusters"]:
    c["cluster"]["server"] = "https://host.docker.internal:6443"
    c["cluster"]["insecure-skip-tls-verify"] = True
p.write_text(yaml.safe_dump(k, default_flow_style=False, sort_keys=False))
print("kubeconfig rewritten -> https://host.docker.internal:6443 (skip-tls-verify)")
PY
  start_host_forward
  kubectl get pods -A | sed 's/^/  /'
  (( apply_failed == 0 )) || die "some manifests failed to apply — cluster is incomplete"
  ok "cluster ready — kubectl get ns ai-observability-demo"
}

kube_down() {
  info "deleting kind cluster"
  kind delete cluster --name ai-observability-local 2>/dev/null || true
}

kube_install_tools() {
  mkdir -p "$ROOT/tools/bin"
  info "downloading kind + kubectl into tools/bin (kept local to this project)"
  if [[ ! -x "$ROOT/tools/bin/kind" ]]; then
    curl -fLo "$ROOT/tools/bin/kind" \
      https://kind.sigs.k8s.io/dl/v0.26.0/kind-linux-amd64
    chmod +x "$ROOT/tools/bin/kind"
  fi
  if [[ ! -x "$ROOT/tools/bin/kubectl" ]]; then
    curl -fLo "$ROOT/tools/bin/kubectl" \
      "https://dl.k8s.io/release/v1.31.2/bin/linux/amd64/kubectl"
    chmod +x "$ROOT/tools/bin/kubectl"
  fi
  "$ROOT/tools/bin/kind" version
  "$ROOT/tools/bin/kubectl" version --client
  ok "tools installed under tools/bin"
}

kube_status() {
  have kubectl || { warn "kubectl missing"; return; }
  kubectl cluster-info --request-timeout=3s 2>/dev/null | head -3 || echo "  (no cluster reachable)"
  kubectl get pods -A 2>/dev/null | head -12 || true
}

# ------------------------------------------------------------------ seed -----
seed() {
  ensure_env
  info "seeding RAG databases (pgvector deep + opensearch bm25 + tfidf)"
  "$PY" scripts/seed_rag.py
  info "seeding OpenSearch demo logs / audit / falco"
  "$PY" scripts/seed_opensearch.py --reset
  ok "seed complete"
}

rag_info() {
  ensure_env
  if curl -fsSo /dev/null "http://localhost:${PORT}/health" 2>/dev/null; then
    curl -fs "http://localhost:${PORT}/api/knowledge/db/info"
    echo
  else
    info "server not running — reading RAG info directly from python"
    "$PY" - <<'PY'
from backend.services.rag import get_index
import json
info = get_index().info()
print(json.dumps(info, indent=2))
PY
  fi
}

# ------------------------------------------------------------------ run ------
run() {
  ensure_env
  export PYTHONPATH="$ROOT"
  export FORCE_SIMULATION=false EXTERNAL_MODE=auto RAG_STORE=auto
  export LANGFUSE_ENABLED=true LANGFUSE_HOST=${LANGFUSE_HOST:-http://localhost:3000}
  export LANGFUSE_PUBLIC_KEY=${LANGFUSE_PUBLIC_KEY:-pk-lf-976d879582b60acf}
  export LANGFUSE_SECRET_KEY=${LANGFUSE_SECRET_KEY:-sk-lf-31905c84394ffc10}
  ok "starting platform on :${PORT} (EXTERNAL_MODE=auto — live locals, sim fallback)"
  exec "$PY" -m uvicorn backend.main:app --host 0.0.0.0 --port "$PORT"
}

status() {
  stack_status
  echo
  kube_status
  echo
  rag_info | head -40
  echo
  if curl -fsSo /dev/null "http://localhost:${PORT}/health" 2>/dev/null; then
    ok "platform healthy on :${PORT}"
  else
    warn "platform not running (start with ./scripts/run_stack.sh run)"
  fi
}

all() {
  stack_up
  kube_up
  seed
  run
}

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

cmd="${1:-status}"
shift || true
case "$cmd" in
  stack)  case "${1:-status}" in
            up|start) stack_up ;; down|stop) stack_down ;; *) stack_status ;; esac ;;
  kube)   case "${1:-status}" in
            up|create) kube_up ;; down|delete) kube_down ;; install-tools|tools) kube_install_tools ;; *) kube_status ;; esac ;;
  seed|seed-all)  seed ;;
  rag|rag-info)   rag_info ;;
  run|serve)      run ;;
  status|info)    status ;;
  all|everything) all ;;
  help|-h|--help) usage ;;
  *) die "unknown command '$cmd' — try: stack | kube | seed | rag | run | status | all" ;;
esac