#!/usr/bin/env bash
#
# run_demo.sh — bootstrap and run the whole LLM-Assisted Observability demo.
#
# Creates the venv, installs dependencies, prepares .env, (optionally) resets
# the simulated cluster and drives the six scenarios, then starts the FastAPI
# web server so you can open http://localhost:8199.
#
# Everything can be hosted locally. Use --stack/--kube/--seed (each delegates to
# scripts/run_stack.sh) to bring up the observability stack (Prometheus, Grafana,
# OpenSearch, pgvector RAG), the self-hosted Langfuse stack, the local kind
# cluster, and to seed the RAG databases + OpenSearch datasets.
#
# Examples:
#   ./scripts/run_demo.sh                     # full setup + serve
#   ./scripts/run_demo.sh --drive-demo        # also run detect + approve-all first
#   ./scripts/run_demo.sh --skip-install --no-reset
#   ./scripts/run_demo.sh --stack --kube --seed   # everything managed locally
#   PORT=9000 ./scripts/run_demo.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV="$ROOT/.venv"
PY="$VENV/bin/python"
PIP="$VENV/bin/pip"
PORT="${PORT:-8199}"

RUN_STACK="$ROOT/scripts/run_stack.sh"
DO_RESET=1
DO_DRIVE=0
SKIP_INSTALL=0
DO_STACK=0
DO_KUBE=0
DO_SEED=0

usage() {
    cat <<'EOF'
run_demo.sh — bootstrap and run the whole LLM-Assisted Observability demo.

Creates the .venv, installs dependencies, prepares .env, (optionally) resets
the simulated cluster and drives the six scenarios, then starts the FastAPI
    web server so you can open http://localhost:8199.

You can run everything locally (case-aiops style) with --stack --kube --seed:
  * --stack  docker compose: Prometheus, Grafana, OpenSearch + pgvector RAG DB
  * --kube   local kind cluster + manifests (needs kind + kubectl installed)
  * --seed   seed RAG databases (pgvector/OpenSearch/TF-IDF) + OpenSearch datasets

Examples:
  ./scripts/run_demo.sh                        # full setup + serve
  ./scripts/run_demo.sh --drive-demo           # also run detect + approve-all
  ./scripts/run_demo.sh --stack --kube --seed  # everything managed locally
  PORT=9000 ./scripts/run_demo.sh

Options:
  --no-reset        do not reset incident store / simulation before starting
  --drive-demo      run the CLI demo (detect + approve all) before serving
  --skip-install    skip venv + dependency installation
  --stack           bring up local observability stack via docker compose
  --kube            create local kind cluster + apply k8s manifests
  --seed            re-seed RAG databases and OpenSearch demo datasets
  --port PORT       uvicorn port (default 8199)
  --help, -h        show this help
EOF
}

nocolor() { sed -r 's/\x1B\[[0-9;]*[mK]//g'; }

info()  { printf '\033[1;36m[run-demo]\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m[ok]\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m[warn]\033[0m %s\n' "$1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-reset)      DO_RESET=0 ;;
    --drive-demo)    DO_DRIVE=1 ;;
    --skip-install)  SKIP_INSTALL=1 ;;
    --stack)         DO_STACK=1 ;;
    --kube)          DO_KUBE=1 ;;
    --seed)          DO_SEED=1 ;;
    --port)          PORT="$2"; shift ;;
    --help|-h)       usage; exit 0 ;;
    *)               echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

# --- 0. local stack (docker compose / kind / seeding) ---------------------------------
if [[ "$DO_STACK" -eq 1 ]]; then
    info "bringing up local stack (Prometheus, Grafana, OpenSearch, pgvector RAG)"
    "$RUN_STACK" stack up
fi
if [[ "$DO_KUBE" -eq 1 ]]; then
    info "creating local kind cluster and applying manifests"
    "$RUN_STACK" kube up
fi

# --- 1. Python -----------------------------------------------------------------
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "error: $PYTHON_BIN not found" >&2; exit 1
fi
info "using $("$PYTHON_BIN" --version 2>&1)"

# --- 2. venv + dependencies -----------------------------------------------------
if [[ "$SKIP_INSTALL" -eq 1 ]]; then
    warn "--skip-install set — assuming .venv exists and packages are installed"
elif [[ ! -x "$PY" ]]; then
    info "creating virtualenv at .venv"
    "$PYTHON_BIN" -m venv "$VENV"
    info "installing dependencies from requirements.txt"
    "$PIP" install --upgrade pip >/dev/null
    "$PIP" install -r requirements.txt
else
    info "venv found — running pip install -r requirements.txt (idempotent)"
    "$PIP" install -q -r requirements.txt
fi

if ! "$PY" -c "import fastapi, langgraph, pydantic" >/dev/null 2>&1; then
    echo "error: core imports failed — check virtualenv/installation" >&2; exit 1
fi
ok "python environment ready"

# --- 3. .env ---------------------------------------------------------------------
if [[ ! -f "$ROOT/.env" ]]; then
    info "creating .env from .env.example"
    cp "$ROOT/.env.example" "$ROOT/.env"
else
    info ".env already present — leaving it untouched"
fi

export PYTHONPATH="$ROOT"

# --- 4. optional reset / demo drive -----------------------------------------------
if [[ "$DO_DRIVE" -eq 1 ]]; then
    info "driving the six scenarios (detect + approve all)"
    "$PY" scripts/demo_driver.py --reset --detect --approve-all 2>&1 | sed -r 's/\x1B\[[0-9;]*[mK]//g' | grep -E '^  (inc|detected|approved|reset)' || true
elif [[ "$DO_RESET" -eq 1 ]]; then
    info "resetting simulated cluster + incident store"
    "$PY" scripts/demo_driver.py --reset >/dev/null 2>&1 || true
fi

# --- 5. seed RAG databases + OpenSearch datasets (optional) --------------------------
if [[ "$DO_SEED" -eq 1 ]]; then
    info "seeding RAG databases (pgvector, OpenSearch, TF-IDF) + OpenSearch datasets"
    "$RUN_STACK" seed
fi

# --- 6. serve ---------------------------------------------------------------------
cat <<BANNER
╔══════════════════════════════════════════════════════════════════╗
║  LLM-Assisted Observability & Security — AI O11y Demo             ║
║                                                                  ║
║  Web UI     http://localhost:${PORT}                                ║
║  Health     http://localhost:${PORT}/health                         ║
║  Metrics    http://localhost:${PORT}/metrics                        ║
║  OpenAPI     http://localhost:${PORT}/openapi.json                  ║
║                                                                  ║
║  Tip: run ./scripts/demo_driver.py --help for demo CLI controls  ║
╚══════════════════════════════════════════════════════════════════╝
BANNER

info "starting server (Ctrl+C to stop)"
exec "$PY" -m uvicorn backend.main:app --host 0.0.0.0 --port "$PORT"