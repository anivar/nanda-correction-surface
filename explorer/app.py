"""Protocol Explorer — a self-contained visual walk-through of the resolution flow.

Two ways to run it:

  • Dynamic (local / docker):  uv run uvicorn explorer.app:app --port 8090
      Serves the UI and `/api/walk?scenario=` (a fresh in-process crypto trace per call).

  • Fully static (host anywhere, e.g. your own domain):
      uv run python -m explorer.build_static     # writes explorer/static/data/*.json
      then publish the explorer/static/ folder as-is — no backend needed.

The UI fetches the precomputed `data/*.json` and falls back to the live `api/*`
endpoints, so the same page works in both modes.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .trace import SCENARIOS, walk

app = FastAPI(title="NANDA Protocol Explorer", version="0.1.0")
_STATIC = Path(__file__).parent / "static"


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/api/scenarios")
def scenarios():
    return {"scenarios": [{"key": k, "title": v} for k, v in SCENARIOS.items()]}


@app.get("/api/walk")
def api_walk(scenario: str = "resolve"):
    return walk(scenario)


# Serve the static UI (index.html + any precomputed data/) at the root. Registered
# last so the explicit /healthz and /api routes above take precedence.
app.mount("/", StaticFiles(directory=_STATIC, html=True), name="static")
