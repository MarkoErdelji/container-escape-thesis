"""Tiny stderr logger so you can watch an episode happen live.

On by default; silence with THESIS_VERBOSE=0. Everything goes to stderr so the
final machine-readable summary on stdout stays clean.
"""
import os
import sys

_ON = os.environ.get("THESIS_VERBOSE", "1").lower() not in ("0", "false", "no", "")


def enabled() -> bool:
    return _ON


def log(msg: str = "") -> None:
    if _ON:
        print(msg, file=sys.stderr, flush=True)


def banner(msg: str) -> None:
    if _ON:
        print("\n=== %s ===" % msg, file=sys.stderr, flush=True)


def command(phase: str, cmd: str, result: dict) -> None:
    """One line per mediated command: phase, exit status, the command, output preview."""
    if not _ON:
        return
    lines = cmd.strip().splitlines()
    head = (lines[0] if lines else "")[:120]
    if len(lines) > 1:
        head += " …(+%d lines)" % (len(lines) - 1)
    code = result.get("exit_code")
    mark = "ok " if code == 0 else "x%-2s" % code
    print("  [%-9s] %s %s" % (phase or "?", mark, head), file=sys.stderr, flush=True)
    out = (result.get("stdout") or result.get("stderr") or "").strip().splitlines()
    if out:
        print("              ↳ %s" % out[0][:110], file=sys.stderr, flush=True)
