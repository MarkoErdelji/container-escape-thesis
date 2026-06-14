import os
import sys

_verbose = os.environ.get("THESIS_VERBOSE", "1").lower() not in ("0", "false", "no", "")


def log(msg: str = "") -> None:
    if _verbose:
        print(msg, file=sys.stderr, flush=True)


def banner(msg: str) -> None:
    if not _verbose:
        return
    pad = max(0, 72 - len(msg) - 4)
    print("\n\033[1m== %s %s\033[0m" % (msg, "─" * pad), file=sys.stderr, flush=True)


def command(phase: str, cmd: str, result: dict) -> None:
    if not _verbose:
        return
    lines = cmd.strip().splitlines()
    head = (lines[0] if lines else "")
    if len(lines) > 1:
        head += "  \033[2m…(+%d lines)\033[0m" % (len(lines) - 1)
    code = result.get("exit_code")
    mark = "\033[32mok \033[0m" if code == 0 else "\033[31mx%-2s\033[0m" % code
    print("  [%-9s] %s %s" % (phase or "?", mark, head), file=sys.stderr, flush=True)
    stdout = (result.get("stdout") or "").rstrip()
    stderr = (result.get("stderr") or "").rstrip()
    shown  = stdout or stderr
    if shown:
        for line in shown.splitlines():
            if line.strip():
                print("              \033[2m│\033[0m %s" % line, file=sys.stderr, flush=True)
    if stderr and stderr != stdout:
        for line in stderr.splitlines():
            if line.strip():
                print("              \033[33m!\033[0m %s" % line, file=sys.stderr, flush=True)


def thought(phase: str, text: str) -> None:
    if not _verbose:
        return
    text = text.strip()
    if not text:
        return
    lines = text.splitlines()
    print("  [%-9s] \033[2m···\033[0m" % (phase or "?"), file=sys.stderr, flush=True)
    for line in lines:
        print("              \033[2m│ %s\033[0m" % line, file=sys.stderr, flush=True)
