#!/usr/bin/env bash
# Run the full NANDA prototype locally with uv, WITHOUT Docker.
#
# Brings up the four services on localhost (index 8000, facts-primary 8001,
# facts-neutral 8002, agent 8003), runs the end-to-end demo against them, and
# tears everything down on exit.
#
#   ./demo/run_local.sh          # or: make demo
set -euo pipefail

cd "$(dirname "$0")/.."
export FORCE_COLOR=1

command -v uv >/dev/null 2>&1 || {
  echo "uv is required — install it: https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
}

echo "syncing environment with uv (Python $(cat .python-version)) ..."
uv sync --quiet

# --- start services -----------------------------------------------------------
PIDS=()
cleanup() {
  echo; echo "stopping services ..."
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

start() { # name module port [extra env...]
  local name="$1" module="$2" port="$3"; shift 3
  env "$@" uv run uvicorn "$module" --host 0.0.0.0 --port "$port" --log-level warning \
      > "/tmp/nanda_${name}.log" 2>&1 &
  PIDS+=("$!")
}

echo "starting services ..."
start index   index.app:app 8000
start primary facts.app:app 8001 HOST_ROLE=primary  HOST_LABEL="Provider-hosted Primary Facts"
start neutral facts.app:app 8002 HOST_ROLE=neutral  HOST_LABEL="Neutral Third-Party Host (privacy path)"
start agent   agent.app:app 8003

# --- wait for health ----------------------------------------------------------
for url in localhost:8000 localhost:8001 localhost:8002 localhost:8003; do
  ok=false
  for _ in $(seq 1 40); do
    if curl -sf "http://${url}/healthz" >/dev/null 2>&1; then ok=true; break; fi
    sleep 0.25
  done
  if ! $ok; then
    echo "ERROR: ${url} did not become healthy after 10s; see /tmp/nanda_*.log" >&2
    exit 1
  fi
done
echo "services healthy."; echo

# --- run the demo -------------------------------------------------------------
uv run python -m demo.run_all
