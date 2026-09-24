#!/usr/bin/env bash
#
# loadtest.sh — run a Locust burst against the locust-demo workload and watch
# the HorizontalPodAutoscaler scale the deployment.
#
# Requirements: kind cluster up (scripts/run_stack.sh kube up), loadtest
# manifests applied (see below), locust installed into .venv (auto-installs).
#
# Usage:
#   ./scripts/loadtest.sh                  # 60 users for 3m
#   ./scripts/loadtest.sh -u 120 -t 5m -p 8080
#
# While it runs, watch scaling in another terminal:
#   watch -n 3 kubectl -n ai-observability-demo get hpa,deploy,pods

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PATH="$ROOT/tools/bin:$PATH"
PY="${PYTHON_BIN:-$ROOT/.venv/bin/python}"

USERS=60
TIME="3m"
PORT=8080

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--users) USERS="$2"; shift 2 ;;
    -t|--time)  TIME="$2";  shift 2 ;;
    -p|--port)  PORT="$2";  shift 2 ;;
    -h|--help)  sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1"; exit 1 ;;
  esac
done

[[ -x "$ROOT/tools/bin/kubectl" ]] || { echo "kubectl missing — run ./scripts/run_stack.sh kube install-tools"; exit 1; }

echo "[loadtest] applying manifests (idempotent)"
./tools/bin/kubectl apply -f kubernetes/loadtest/locust-demo.yaml -f kubernetes/loadtest/hpa.yaml >/dev/null
./tools/bin/kubectl -n ai-observability-demo rollout status deploy/locust-demo --timeout=120s >/dev/null

echo "[loadtest] installing locust if needed"
"$PY" -m pip install -q locust 2>/dev/null || true

LISTEN_CHECK=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" 2>/dev/null || true)
if [[ "$LISTEN_CHECK" != "200" ]]; then
  echo "[loadtest] port-forwarding svc/locust-demo ${PORT}:80"
  ./tools/bin/kubectl -n ai-observability-demo port-forward svc/locust-demo "${PORT}:80" >/tmp/opencode/locust-pf.log 2>&1 &
  PF_PID=$!
  trap "kill $PF_PID 2>/dev/null || true" EXIT
  for _ in $(seq 1 20); do
    curl -fs -o /dev/null "http://127.0.0.1:${PORT}/" && break || sleep 0.5
  done
fi

echo "[loadtest] firing ${USERS} users for ${TIME} at http://127.0.0.1:${PORT}"
echo "[loadtest] watch scaling: kubectl -n ai-observability-demo get hpa,deploy -w"
"$PY" -m locust --headless -u "$USERS" -r 10 -t "$TIME" \
  --host "http://127.0.0.1:${PORT}" -f tools/locustfile.py

echo "[loadtest] done. HPA + deployment state:"
./tools/bin/kubectl -n ai-observability-demo get hpa,deploy | grep -E "NAME|locust-demo"