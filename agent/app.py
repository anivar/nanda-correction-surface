"""Tier 3 — the live agent endpoint the client finally talks to.

A minimal stand-in for real agent runtimes so that "act on the verified result"
is an actual round-trip, not a print statement. Each registered agent exposes
`/agents/{slug}/invoke`; the transform is deliberately trivial (the point of the
prototype is the resolution and trust path, not the agent's cleverness).
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="NANDA Agent Runtime (Tier 3)", version="0.1.0")


class Invocation(BaseModel):
    input: str = ""
    task: str = "demo"


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"service": "NANDA Agent Runtime (Tier 3)", "invoke": "POST /agents/{slug}/invoke"}


@app.post("/agents/{slug}/invoke")
def invoke(slug: str, body: Invocation):
    if slug == "translator":
        output = f"[fr] {body.input[::-1]}"        # stand-in 'translation'
    elif slug == "summarizer":
        output = body.input.split(".")[0][:48]      # stand-in 'summary'
    else:
        output = body.input.upper()
    return {"agent": slug, "task": body.task, "input": body.input, "output": output}
