#!/usr/bin/env python3
"""
Convert episode JSONs into human-readable text files.

Usage:
  python3 scripts/format_episode.py results/*.json

Output goes to results-readable/, one .txt per episode.
"""
import json
import sys
import os
import textwrap

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results-readable")


def fmt_time(t0, t):
    elapsed = t - t0
    m, s = divmod(int(elapsed), 60)
    return f"{m:02d}:{s:02d}"


def classify_steps(transcript):
    recon_patterns = ["CapEff", "ls -la /dev", "command -v", "curl -s -o /dev/null",
                      "docker.sock", "uname -", "readlink /proc/1", "dockerenv",
                      "/proc/self/mountinfo", "/proc/version", "Seccomp", "/proc/1/fd"]
    recon, research, exploit = [], [], []
    phase = "recon"
    for step in transcript:
        cmd = step.get("command", "")
        if phase == "recon":
            if any(p in cmd for p in recon_patterns):
                recon.append(step)
                continue
            else:
                phase = "research"
        if phase == "research" and not exploit:
            research.append(step)
            if any(kw in cmd for kw in ["gcc ", "python3 -c", "echo ", "chmod +x",
                                         "/proc/self/cwd/", "nsenter", "mount ",
                                         "cat /proc/", "/mnt/runc", "core_pattern",
                                         "splice", "dd ", "crontab"]):
                exploit.append(research.pop())
                phase = "exploit"
        elif phase == "exploit" or exploit:
            exploit.append(step)
            phase = "exploit"
    return recon, research, exploit


def format_episode(ep):
    metrics = ep.get("metrics", {})
    plan = ep.get("attack_plan", {})
    transcript = ep.get("transcript", [])
    artifacts = ep.get("artifacts", {})
    escaped = metrics.get("escaped", False)
    success = metrics.get("success", False)
    status = ep.get("status", "unknown")
    recovered = artifacts.get("recovered", "")
    gt = ep.get("ground_truth_token", "")

    lines = []
    w = lines.append

    # Header
    w("=" * 80)
    w(f"  EPISODE: {ep['run_id']}  [{status.upper()}]")
    w("=" * 80)
    w("")
    w(f"  Scenario:    {ep['scenario']} / {ep.get('victim_runtime', '?')}")
    w(f"  Model:       {ep.get('model', '?')}")
    w(f"  Status:      {status.upper()}")
    w(f"  Escaped:     {'yes' if escaped else 'no'}")
    w(f"  Success:     {'yes' if success else 'no'}")
    w(f"  Cost:        ${metrics.get('usd_spent', 0):.2f}")
    w(f"  Wall clock:  {metrics.get('wall_clock_s', 0):.0f}s")
    w(f"  Steps:       {metrics.get('steps', {})}")
    w(f"  Replans:     {metrics.get('replans_used', 0)}")
    if metrics.get("budget_stopped"):
        w("  ** BUDGET STOPPED **")

    # Attack plan
    w("")
    w("--- ATTACK PLAN " + "-" * 63)
    w(f"  Chosen:    {plan.get('chosen', 'none')}")
    rationale = plan.get("rationale", "")
    if rationale:
        w("")
        w("  Rationale:")
        for line in textwrap.wrap(rationale, width=76):
            w(f"    {line}")
    chain = plan.get("escape_chain", [])
    if chain:
        w("")
        w("  Escape chain:")
        for i, step in enumerate(chain, 1):
            wrapped = textwrap.wrap(step, width=72)
            w(f"    {i}. {wrapped[0]}")
            for cont in wrapped[1:]:
                w(f"       {cont}")
    ranked = plan.get("ranked", [])
    if ranked:
        w("")
        w("  Ranked techniques:")
        for r in ranked:
            conf = r.get("confidence", 0)
            w(f"    - {r.get('technique', '?')} (confidence={conf:.0%})")
            why = r.get("why", "")
            if why:
                for line in textwrap.wrap(why, width=70):
                    w(f"      {line}")
    fallbacks = plan.get("fallbacks", [])
    if fallbacks:
        w("")
        w("  Fallbacks:")
        for fb in fallbacks:
            w(f"    - {fb}")

    # Recovered token
    if recovered:
        w("")
        marker = "MATCH" if success else "MISMATCH"
        w(f"  Recovered: {recovered}")
        if gt and not success:
            w(f"  Expected:  {gt}")
        w(f"  Verdict:   {marker}")

    # Transcript
    if not transcript:
        w("")
        w("  (no transcript)")
        return "\n".join(lines)

    t0 = transcript[0]["t"]
    recon, research, exploit = classify_steps(transcript)

    w("")
    w(f"--- TRANSCRIPT ({len(transcript)} commands) " + "-" * 43)

    def write_phase(name, steps):
        if not steps:
            return
        w("")
        w(f"  [{name.upper()}] — {len(steps)} commands")
        w(f"  {'─' * 60}")
        for step in steps:
            cmd = step.get("command", "")
            rc = step.get("exit_code", "?")
            ts = fmt_time(t0, step["t"])
            stdout = (step.get("stdout") or "").strip()
            stderr = (step.get("stderr") or "").strip()

            rc_marker = "ok" if rc == 0 else f"ERR({rc})"
            w("")
            w(f"  {ts}  [{rc_marker}]  $ {cmd}")

            if "THESISKEY" in stdout:
                for line in stdout.splitlines():
                    if "THESISKEY" in line:
                        w(f"           >>> {line.strip()}")
                    else:
                        w(f"           {line}")
            elif stdout:
                out_lines = stdout.splitlines()
                limit = 5 if name == "recon" else 15
                for line in out_lines[:limit]:
                    w(f"           {line}")
                if len(out_lines) > limit:
                    w(f"           ... ({len(out_lines) - limit} more lines)")

            if stderr and rc != 0:
                for line in stderr.splitlines()[:5]:
                    w(f"           STDERR: {line}")

    write_phase("recon", recon)
    write_phase("research", research)
    write_phase("exploit", exploit)

    # Footer
    w("")
    w("─" * 80)
    w(f"  Result: {status.upper()}  |  ${metrics.get('usd_spent', 0):.2f}  |  "
      f"{metrics.get('wall_clock_s', 0):.0f}s  |  {len(transcript)} commands")
    w("")

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    files = [a for a in sys.argv[1:] if os.path.isfile(a)]
    if not files:
        print("No valid files given", file=sys.stderr)
        sys.exit(1)

    os.makedirs(OUT_DIR, exist_ok=True)

    for path in sorted(files):
        with open(path) as f:
            ep = json.load(f)
        text = format_episode(ep)
        name = f"episode-{ep['run_id']}.txt"
        out_path = os.path.join(OUT_DIR, name)
        with open(out_path, "w") as f:
            f.write(text)
        status = ep.get("status", "?")
        print(f"  {name}  [{status}]")

    print(f"\nWritten {len(files)} files to {OUT_DIR}/")
