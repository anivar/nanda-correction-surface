#!/usr/bin/env bash
# Run the full NANDA prototype locally, WITHOUT Docker.
#
# Brings up the four services on localhost (index 8000, facts-primary 8001,
# facts-neutral 8002, agent 8003), runs the end-to-end demo against them, and
# tears everything down on exit.
#
#   ./demo/run_local.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export FORCE_COLOR=1

# --- venv + deps --------------------------------------------------------------
if [[ ! -d .venv ]]; then
  echo "creating .venv ..."
  if command -v uv >/dev/null 2>&1; then uv venv .venv; else python3 -m venv .venv; fi
fi
# shellcheck disable=SC1091
source .venv/bin/activate
if ! python -c "import fastapi, cryptography, jwt, rfc8785, base58, httpx" 2>/dev/null; then
  echo "installing dependencies ..."
  if command -v uv >/dev/null 2>&1; then uv pip install -r requirements.txt
  else pip install -q -r requirements.txt; fi
fi

# --- start services -----------------------------------------------------------
PIDS=()
cleanup() {
  echo; echo "stopping services ..."
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

start() { # name module port [extra env...]
  local name="$1" module="$2" port="$3"; shift 3
  env "$@" uvicorn "$module" --host 0.0.0.0 --port "$port" --log-level warning \
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
  for _ in $(seq 1 40); do
    if curl -sf "http://${url}/healthz" >/dev/null 2>&1; then break; fi
    sleep 0.25
  done
done
echo "services healthy."; echo

# --- run the demo -------------------------------------------------------------
python -m demo.run_all
