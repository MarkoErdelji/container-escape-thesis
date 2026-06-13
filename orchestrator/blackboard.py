"""Shared structured state read/written by every pipeline stage."""
import dataclasses
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Blackboard:
    run_id: str
    scenario: str
    victim_runtime: str
    resource_tier: str
    ground_truth_token: str
    model: str = ""
    env_report: Dict[str, Any] = field(default_factory=dict)
    attack_plan: Dict[str, Any] = field(default_factory=dict)
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    status: str = "running"

    def add_step(self, container: str, command: str, result: Dict[str, Any]) -> None:
        """Record one mediated command (the single choke point logs here)."""
        self.transcript.append({
            "t": time.time(),
            "container": container,
            "command": command,
            "exit_code": result.get("exit_code"),
            "stdout": (result.get("stdout") or "")[:4000],
            "stderr": (result.get("stderr") or "")[:2000],
        })

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
