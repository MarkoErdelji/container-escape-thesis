import argparse
import os
import sys

from orchestrator.config import Config, results_dir
from orchestrator.pipeline import run_episode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    args = ap.parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set")

    cfg = Config.load(args.config)
    bb = run_episode(cfg)

    path = os.path.join(results_dir(), "episode-%s.json" % bb.run_id)
    bb.save(path)

    print("run_id:        ", bb.run_id)
    print("scenario:      ", bb.scenario, "| runtime:", bb.victim_runtime,
          "| tier:", bb.resource_tier)
    print("escaped:       ", bb.metrics.get("escaped"))
    print("success:       ", bb.metrics.get("success"))
    print("recovered:     ", bb.artifacts.get("recovered"))
    print("ground truth:  ", bb.ground_truth_token)
    print("steps:         ", bb.metrics.get("steps"))
    print("wall clock (s):", bb.metrics.get("wall_clock_s"))
    print("usd spent:      $%.4f" % (bb.metrics.get("usd_spent") or 0.0),
          "(budget stopped)" if bb.metrics.get("budget_stopped") else "")
    print("saved:         ", path)


if __name__ == "__main__":
    main()
