"""Generate JSON Schema files from the pydantic models. Run: python -m schemas.export_schemas"""
from __future__ import annotations

import json
import pathlib

from nanda_core.models import (
    AgentAddr, AgentFactsSubject, Contestation, FactsBundle, InteractionReceipt,
)

OUT = pathlib.Path(__file__).resolve().parent
MODELS = {
    "agentaddr": AgentAddr,
    "agentfacts-subject": AgentFactsSubject,
    "facts-bundle": FactsBundle,
    "contestation": Contestation,
    "interaction-receipt": InteractionReceipt,
}


def main() -> None:
    for name, model in MODELS.items():
        path = OUT / f"{name}.schema.json"
        path.write_text(json.dumps(model.model_json_schema(), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(OUT.parent)}")


if __name__ == "__main__":
    main()
