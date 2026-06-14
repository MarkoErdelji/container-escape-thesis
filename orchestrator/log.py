import os
import sys

_ON = os.environ.get("THESIS_VERBOSE", "1").lower() not in ("0", "false", "no", "")

_MAX_OUT_LINES = 10   # stdout lines shown per command
_MAX_ERR_LINES = 4    # stderr lines shown per command
_MAX_THINK_LINES = 20 # agent reasoning lines shown


def enabled() -> bool:
    return _ON


def log(msg: str = "") -> None:
    if _ON:
        print(msg, file=sys.stderr, flush=True)


def banner(msg: str) -> None:
    if not _ON:
        return
    pad = max(0, 72 - len(msg) - 4)
    print("\n\033[1m== %s %s\033[0m" % (msg, "─" * pad), file=sys.stderr, flush=True)


def command(phase: str, cmd: str, result: dict) -> None:
    if not _ON:
        return
    lines = cmd.strip().splitlines()
    head = (lines[0] if lines else "")[:120]
    if len(lines) > 1:
        head += "  \033[2m…(+%d lines)\033[0m" % (len(lines) - 1)
    code = result.get("exit_code")
    if code == 0:
        mark = "\033[32mok \033[0m"
    else:
        mark = "\033[31mx%-2s\033[0m" % code
    print("  [%-9s] %s %s" % (phase or "?", mark, head), file=sys.stderr, flush=True)

    stdout = (result.get("stdout") or "").rstrip()
    stderr = (result.get("stderr") or "").rstrip()

    shown = stdout or stderr
    if shown:
        for line in shown.splitlines()[:_MAX_OUT_LINES]:
            if line.strip():
                print("              \033[2m│\033[0m %s" % line[:140], file=sys.stderr, flush=True)
        extra = len(shown.splitlines()) - _MAX_OUT_LINES
        if extra > 0:
            print("              \033[2m│ … (%d more lines)\033[0m" % extra, file=sys.stderr, flush=True)

    if stderr and stderr != stdout:
        for line in stderr.splitlines()[:_MAX_ERR_LINES]:
            if line.strip():
                print("              \033[33m!\033[0m %s" % line[:140], file=sys.stderr, flush=True)


def thought(phase: str, text: str) -> None:
    """Log agent reasoning text emitted between or alongside tool calls."""
    if not _ON:
        return
    text = text.strip()
    if not text:
        return
    lines = text.splitlines()
    print("  [%-9s] \033[2m···\033[0m" % (phase or "?"), file=sys.stderr, flush=True)
    for line in lines[:_MAX_THINK_LINES]:
        print("              \033[2m│ %s\033[0m" % line[:140], file=sys.stderr, flush=True)
    if len(lines) > _MAX_THINK_LINES:
        print("              \033[2m│ … (%d more lines)\033[0m" % (len(lines) - _MAX_THINK_LINES),
              file=sys.stderr, flush=True)
