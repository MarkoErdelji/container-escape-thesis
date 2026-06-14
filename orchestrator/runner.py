import argparse
import json
import os
import sqlite3

from orchestrator.config import Config, results_dir
from orchestrator.pipeline import run_episode

DDL = """
CREATE TABLE IF NOT EXISTS episodes (
    run_id TEXT PRIMARY KEY, scenario TEXT, victim_runtime TEXT, resource_tier TEXT,
    escaped INT, success INT, replans_used INT, wall_clock_s REAL,
    steps_json TEXT, ground_truth TEXT, recovered TEXT
);
"""


def _record(db, bb):
    m = bb.metrics
    db.execute(
        "INSERT OR REPLACE INTO episodes VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (bb.run_id, bb.scenario, bb.victim_runtime, bb.resource_tier,
         int(bool(m.get("escaped"))), int(bool(m.get("success"))),
         m.get("replans_used"), m.get("wall_clock_s"),
         json.dumps(m.get("steps", {})), bb.ground_truth_token,
         bb.artifacts.get("recovered")),
    )
    db.commit()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=20)
    ap.add_argument("--config", default=None)
    args = ap.parse_args()

    cfg = Config.load(args.config)
    db  = sqlite3.connect(os.path.join(results_dir(), "results.sqlite"))
    db.executescript(DDL)
    for i in range(args.episodes):
        print("episode %d/%d ..." % (i + 1, args.episodes))
        bb = run_episode(cfg)
        _record(db, bb)
        bb.save(os.path.join(results_dir(), "episode-%s.json" % bb.run_id))
        print("  success=%s escaped=%s" % (bb.metrics.get("success"), bb.metrics.get("escaped")))
    db.close()


if __name__ == "__main__":
    main()
