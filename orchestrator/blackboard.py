import dataclasses
import json
import time
from dataclasses import dataclass, field


@dataclass
class Blackboard:
    run_id: str
    scenario: str
    victim_runtime: str
    resource_tier: str
    ground_truth_token: str
    model: str = ""
    env_report: dict = field(default_factory=dict)
    attack_plan: dict = field(default_factory=dict)
    transcript: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    status: str = "running"

    def add_step(self, container: str, command: str, result: dict) -> None:
        self.transcript.append({
            "t": time.time(),
            "container": container,
            "command": command,
            "exit_code": result.get("exit_code"),
            "stdout": (result.get("stdout") or "")[:4000],
            "stderr": (result.get("stderr") or "")[:2000],
        })

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(dataclasses.asdict(self), f, indent=2)
