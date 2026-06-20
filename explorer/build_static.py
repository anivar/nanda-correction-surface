"""Precompute the explorer traces to static JSON so the UI can be hosted with no
backend — e.g. GitHub Pages or any static domain.

    uv run python -m explorer.build_static

Writes explorer/static/data/scenarios.json and one <scenario>.json per scenario.
Publish the explorer/static/ folder as-is (it uses relative paths, so it works under
a subpath like username.github.io/repo/). Re-run to refresh (each run mints fresh keys).
"""

from __future__ import annotations

import json
import pathlib

from .trace import SCENARIOS, walk

OUT = pathlib.Path(__file__).resolve().parent / "static" / "data"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "scenarios.json").write_text(
        json.dumps({"scenarios": [{"key": k, "title": v} for k, v in SCENARIOS.items()]}, indent=2),
        encoding="utf-8",
    )
    for key in SCENARIOS:
        (OUT / f"{key}.json").write_text(json.dumps(walk(key), indent=2), encoding="utf-8")
        print(f"wrote static/data/{key}.json")


if __name__ == "__main__":
    main()
