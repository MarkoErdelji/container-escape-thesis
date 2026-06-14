import subprocess
import time
from pathlib import Path
from typing import Dict, Optional

from orchestrator import log

IPC_DIR = Path("/tmp/thesis-ipc")


class CommandRunner:
    """Runs shell commands directly via subprocess (we are inside the attacker container)."""

    def __init__(self, blackboard=None, timeout: int = 60, max_output: int = 8000):
        self.blackboard = blackboard
        self.timeout = timeout
        self.max_output = max_output
        self.phase = ""

    def run(self, command: str) -> Dict:
        try:
            p = subprocess.run(
                ["bash", "-c", command],
                capture_output=True, text=True, errors="replace", timeout=self.timeout,
            )
            result = {"stdout": p.stdout, "stderr": p.stderr, "exit_code": p.returncode}
        except subprocess.TimeoutExpired:
            result = {"stdout": "", "stderr": "TIMEOUT", "exit_code": 124}
        if self.blackboard is not None:
            self.blackboard.add_step("attacker", command, result)
        log.command(self.phase, command, result)
        return result


class HostActionHandler:
    """Handles request_host_action tool calls via shared IPC volume.

    Writes the request to /tmp/thesis-ipc/request and waits for the host watcher
    to respond with YES or NO in /tmp/thesis-ipc/response.
    """

    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        IPC_DIR.mkdir(parents=True, exist_ok=True)

    def request(self, action: str) -> str:
        req_file = IPC_DIR / "request"
        resp_file = IPC_DIR / "response"
        resp_file.unlink(missing_ok=True)
        req_file.write_text(action)
        log.log("    [host-action] requested: %s" % action[:120])
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if resp_file.exists():
                resp = resp_file.read_text().strip()
                resp_file.unlink(missing_ok=True)
                log.log("    [host-action] response: %s" % resp[:80])
                return resp
            time.sleep(0.3)
        req_file.unlink(missing_ok=True)
        log.log("    [host-action] timed out — returning NO")
        return "NO: host did not respond within %ds" % self.timeout


def victim_pid() -> Optional[int]:
    """Read victim host PID written by the host before starting this container."""
    try:
        val = (IPC_DIR / "victim_pid").read_text().strip()
        return int(val) if val.isdigit() else None
    except (FileNotFoundError, ValueError):
        return None
