#!/usr/bin/env python3
"""Roll results/episode-*.json into a scenario x tier x model summary table.

Run on the Mac after some episodes:
    python3 scripts/aggregate.py            # pretty table from ./results
    python3 scripts/aggregate.py --csv      # CSV (paste into the thesis / a sheet)
    python3 scripts/aggregate.py path/to/results

Columns: n episodes, escape rate, success rate, mean exploit steps, mean USD/episode.
Outcomes come from the deterministic oracles recorded per episode, not self-reports.
"""
import glob
import json
import os
import sys
from collections import defaultdict


def short_model(mid):
    for k in ("haiku", "sonnet", "opus", "fable", "mythos"):
        if k in (mid or ""):
            return k
    return (mid or "?")[:14]


def main():
    args = sys.argv[1:]
    as_csv = "--csv" in args
    args = [a for a in args if a != "--csv"]
    here = os.path.dirname(os.path.abspath(__file__))
    results_dir = args[0] if args else os.path.join(here, "..", "results")
    files = sorted(glob.glob(os.path.join(results_dir, "episode-*.json")))
    if not files:
        sys.exit("no episode-*.json found in %s" % os.path.abspath(results_dir))

    cells = defaultdict(list)
    for f in files:
        try:
            d = json.load(open(f))
        except (ValueError, OSError):
            continue
        m = d.get("metrics", {}) or {}
        key = (d.get("scenario", "?"), d.get("resource_tier", "?"), short_model(d.get("model")))
        cells[key].append({
            "escaped": bool(m.get("escaped")),
            "success": bool(m.get("success")),
            "steps": (m.get("steps") or {}).get("exploit", 0) or 0,
            "usd": float(m.get("usd_spent") or 0.0),
        })

    rows = []
    for key in sorted(cells):
        ep = cells[key]
        n = len(ep)
        rows.append((
            key[0], key[1], key[2], n,
            100.0 * sum(e["escaped"] for e in ep) / n,
            100.0 * sum(e["success"] for e in ep) / n,
            sum(e["steps"] for e in ep) / n,
            sum(e["usd"] for e in ep) / n,
        ))

    header = ["scenario", "tier", "model", "n", "esc%", "succ%", "steps", "$/ep"]
    if as_csv:
        print(",".join(header))
        for r in rows:
            print("%s,%s,%s,%d,%.0f,%.0f,%.1f,%.4f" % r)
        return

    def cells_of(r):
        return [r[0], r[1], r[2], str(r[3]), "%.0f" % r[4], "%.0f" % r[5],
                "%.1f" % r[6], "$%.3f" % r[7]]

    table = [header] + [cells_of(r) for r in rows]
    widths = [max(len(row[i]) for row in table) for i in range(len(header))]
    for i, row in enumerate(table):
        print("  ".join(c.ljust(widths[j]) for j, c in enumerate(row)))
        if i == 0:
            print("  ".join("-" * widths[j] for j in range(len(header))))

    total = sum(len(v) for v in cells.values())
    wins = sum(e["success"] for v in cells.values() for e in v)
    print("\n%d episodes across %d cells | overall success %d/%d (%.0f%%)"
          % (total, len(cells), wins, total, 100.0 * wins / total))


if __name__ == "__main__":
    main()
