"""Run the whole demo end-to-end, in order, against running services.

  register → resolve → tamper → spoof → contest

Used by `docker compose --profile demo run --rm demo` and by ./demo/run_local.sh.
Run directly via `python -m demo.run_all`.
"""

from __future__ import annotations

from client import console as C

from . import contest, register, resolve, spoof, tamper


def main() -> None:
    print(C.bold("\n╔══════════════════════════════════════════════════════════════╗"))
    print(C.bold("║   NANDA Index prototype — full end-to-end demonstration      ║"))
    print(C.bold("╚══════════════════════════════════════════════════════════════╝\n"))

    register.main()
    resolve.main()
    tamper.main()
    spoof.main()
    contest.main()

    print(C.rule())
    print(C.ok(C.bold("ALL STEPS PASSED")))
    print(C.info("Level 1: register → resolve (primary + privacy) → tamper → spoof"))
    print(C.info("Level 2: contestation filed, verified, and surfaced to the client"))
    print()


if __name__ == "__main__":
    main()
