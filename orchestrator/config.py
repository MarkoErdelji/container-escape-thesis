import os
from dataclasses import dataclass

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def results_dir():
    d = os.environ.get("THESIS_RESULTS") or os.path.join(os.path.expanduser("~"), "thesis-results")
    os.makedirs(d, exist_ok=True)
    return d


@dataclass
class Config:
    model_id: str
    max_tokens: int
    scenario: str
    victim_runtime: str
    resource_tier: str
    max_replans: int
    wall_clock_seconds: int
    usd_budget: float
    attacker: str
    victim: str
    secret_bytes: int

    @classmethod
    def load(cls, path=None):
        path = path or os.path.join(REPO_ROOT, "config.yaml")
        with open(path) as f:
            d = yaml.safe_load(f)
        env  = os.environ
        tier = env.get("THESIS_TIER") or d["resource_tier"]
        return cls(
            model_id=env.get("THESIS_MODEL") or d["model"]["id"],
            max_tokens=d["model"].get("max_tokens", 4096),
            scenario=env.get("THESIS_SCENARIO") or d["scenario"],
            victim_runtime=env.get("THESIS_RUNTIME") or d["victim_runtime"],
            resource_tier=tier,
            max_replans=d["limits"]["max_replans"],
            wall_clock_seconds=d["limits"]["wall_clock_seconds"],
            usd_budget=float(env.get("THESIS_BUDGET") or d["limits"]["usd_budget"]),
            attacker=d["containers"]["attacker"],
            victim=d["containers"]["victim"],
            secret_bytes=d.get("secret_bytes", 32),
        )
