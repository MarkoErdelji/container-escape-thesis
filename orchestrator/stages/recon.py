"""Recon stage: DETERMINISTIC read-only enumeration -> structured environment report.

This used to be an LLM agent, but recon is just a fixed battery of read-only probes —
the same every time. Making it deterministic (a) costs ~0 tokens, (b) gives every
episode an identical starting env_report so outcome differences are attributable to the
evaluator/operator (lower variance for the study), and (c) is faster. The autonomy that
matters stays with the LLM: the evaluator picks the technique and the operator can run
any further commands it needs. Output keys match what the evaluator consumes.
"""

# CAP_* names indexed by bit position in the capability bitmask (Linux 6.x order).
CAP_NAMES = [
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
    "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
    "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
    "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
    "sys_tty_config", "mknod", "lease", "audit_write", "audit_control",
    "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
    "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
]

_PROBES = 9  # number of read-only commands issued below (no LLM calls)


def _out(runner, cmd: str) -> str:
    return (runner.run(cmd).get("stdout") or "").strip()


def _decode_caps(status_line: str):
    """status_line like 'CapEff:\t000001ffffffffff' -> (hex, [cap names])."""
    parts = status_line.split()
    hex_str = parts[-1] if parts else "0"
    try:
        bits = int(hex_str, 16)
    except ValueError:
        return hex_str, []
    return hex_str, [n for i, n in enumerate(CAP_NAMES) if bits & (1 << i)]


def _mounts(mountinfo: str):
    notable = []
    for line in mountinfo.splitlines():
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        lf, rf = left.split(), right.split()
        if len(lf) < 5 or len(rf) < 2:
            continue
        mountpoint, fstype, source = lf[4], rf[0], rf[1]
        if source.startswith("/dev/") or fstype == "overlay":
            notable.append("%s on %s (%s)" % (source, mountpoint, fstype))
    return notable[:8]


def run(cl, cfg, runner, bb):
    # cl is unused — recon is deterministic. Signature kept for stage parity.
    cap_hex, caps = _decode_caps(_out(runner, "grep -m1 CapEff /proc/self/status"))
    devices = _out(
        runner, "ls -la /dev 2>/dev/null | awk '$1 ~ /^b/ {print $NF}' | tr '\\n' ' '"
    ).split()
    tooling = _out(
        runner,
        "for t in gcc cc python3 perl curl wget nc ncat gdb nsenter mount unshare; do "
        "command -v $t >/dev/null 2>&1 && printf '%s ' \"$t\"; done",
    ).split()
    http = _out(
        runner,
        "curl -s -o /dev/null -m 5 -w '%{http_code}' https://www.google.com 2>/dev/null "
        "|| echo 000",
    )
    runc = _out(runner, "runc --version 2>/dev/null | head -1") or None
    privileged = "sys_admin" in caps
    docker_sock = _out(
        runner, "test -S /var/run/docker.sock && echo yes || echo no") == "yes"

    bb.env_report = {
        "containerized": _out(runner, "test -f /.dockerenv && echo yes || echo no") == "yes",
        "privileged": privileged,
        "capabilities": caps,
        "cap_eff": cap_hex,
        "kernel": _out(runner, "uname -r"),
        "mounts": _mounts(_out(runner, "cat /proc/self/mountinfo 2>/dev/null")),
        "devices": devices,
        "docker_socket": docker_sock,
        "runc_version": runc,
        "tooling": tooling,
        "network_egress": http.startswith(("2", "3")),
        "notes": "%s; block devices: %s; docker socket: %s; egress http: %s" % (
            "privileged container" if privileged else "unprivileged container",
            ",".join(devices) or "none", docker_sock, http),
    }
    bb.metrics.setdefault("steps", {})["recon"] = _PROBES
    return bb.env_report
