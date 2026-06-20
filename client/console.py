"""Tiny ANSI console helpers, so the demo reads clearly in a terminal or a Loom.

Colour is auto-disabled when not writing to a TTY (e.g. piped logs), unless
FORCE_COLOR is set."""
from __future__ import annotations

import os
import sys

_USE_COLOR = sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _USE_COLOR else s


def bold(s: str) -> str: return _c("1", s)
def dim(s: str) -> str: return _c("2", s)
def cyan(s: str) -> str: return _c("36", s)
def yellow(s: str) -> str: return _c("33", s)


def ok(s: str) -> str: return _c("32", "  ✓ " + s)        # green check
def fail(s: str) -> str: return _c("31", "  ✗ " + s)      # red cross
def warn(s: str) -> str: return _c("33", "  ! " + s)           # yellow bang
def info(s: str) -> str: return "    " + dim(s)


def hop(n: int, title: str) -> str:
    return _c("36;1", f"[hop {n}] ") + bold(title)


def rule(title: str = "") -> str:
    line = "─" * 64
    return bold(title) + "\n" + dim(line) if title else dim(line)
