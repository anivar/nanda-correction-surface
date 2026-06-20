"""Run the whole demo end-to-end, in order, against running services.

  Level 1 (NANDA paper):   register → resolve → tamper → spoof
  Level 2 (extensions):    contest → exit → registrations → revoke

Used by `docker compose --profile demo run --rm demo` and by ./demo/run_local.sh.
Run directly via `python -m demo.run_all`.
"""

from __future__ import annotations

from client import console as C

from . import contest, register, registrations, resolve, revoke, spoof, tamper
from . import exit as exit_demo


def main() -> None:
    print(C.bold("\n╔══════════════════════════════════════════════════════════════╗"))
    print(C.bold("║   NANDA Index prototype — full end-to-end demonstration      ║"))
    print(C.bold("╚══════════════════════════════════════════════════════════════╝\n"))

    # Level 1 — the NANDA paper's core flow.
    register.main()
    resolve.main()
    tamper.main()
    spoof.main()

    # Level 2 — extensions on top of a solid core.
    contest.main()
    exit_demo.main()
    registrations.main()
    revoke.main()

    print(C.rule())
    print(C.ok(C.bold("ALL STEPS PASSED")))
    print(C.info("Level 1 (paper):    register → resolve (primary + privacy) → tamper → spoof"))
    print(C.info("Level 2 (extensions): contest → exit (severance) → registration types → revoke"))
    print()


if __name__ == "__main__":
    main()
