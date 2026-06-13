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

_PROBES = 19  # number of read-only commands issued below (no LLM calls)


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
    kernel = _out(runner, "uname -r")
    arch = _out(runner, "uname -m")

    # General /proc/1 observables — raw facts, no interpretation.
    proc1_cwd = _out(runner, "readlink /proc/1/cwd 2>/dev/null || echo unknown")
    proc1_exe = _out(runner, "readlink /proc/1/exe 2>/dev/null || echo unknown")
    proc1_fd_sample = _out(
        runner,
        "for fd in $(ls /proc/1/fd/ 2>/dev/null | head -8); do "
        "  t=$(readlink /proc/1/fd/$fd 2>/dev/null); "
        "  [ -n \"$t\" ] && echo \"fd$fd=$t\"; "
        "done",
    )

    # DirtyPipe scenario: runc exposed via a read-only bind mount at /mnt/runc.
    # DirtyPipe can overwrite it by writing to the page cache even though the mount is :ro.
    # A shared result dir is bind-mounted at /tmp/dirtypipe-result for the payload to write to.
    mnt_runc_path = _out(runner, "test -f /mnt/runc && echo /mnt/runc || true") or None

    # Host component versions — read via /proc/1/root/ (accessible to container UID 0
    # in standard Docker which doesn't remap the user namespace). Strings-only reads,
    # no execution on the host.
    #
    # runc_host_path: exact filesystem path (the escape chain needs to know where to overwrite).
    # runc_host: version string (for CVE version-range matching by the evaluator).
    # The version string may sit deep in the binary (>128KB in); strings the full file.
    runc_host_path = _out(
        runner,
        "for p in /proc/1/root/usr/local/sbin/runc"
        "         /proc/1/root/usr/sbin/runc"
        "         /proc/1/root/usr/bin/runc; do"
        "  [ -f \"$p\" ] && echo \"$p\" && break;"
        " done",
    ) or None
    runc_host = _out(
        runner,
        "p=%s; [ -n \"$p\" ] && strings \"$p\" 2>/dev/null | grep -m1 'runc version'" % (
            runc_host_path or ""),
    ) or None
    containerd_host = _out(
        runner,
        "head -c 131072 /proc/1/root/usr/bin/containerd 2>/dev/null"
        " | strings 2>/dev/null | grep -m1 'containerd v' | head -1",
    ) or None
    kernel_full = _out(runner, "cat /proc/version 2>/dev/null")
    seccomp = _out(runner, "grep -m1 Seccomp /proc/self/status 2>/dev/null")
    host_os = _out(
        runner,
        "grep -E '^(NAME|VERSION|ID)=' /proc/1/root/etc/os-release 2>/dev/null | head -3",
    )

    bb.env_report = {
        "containerized": _out(runner, "test -f /.dockerenv && echo yes || echo no") == "yes",
        "privileged": privileged,
        "capabilities": caps,
        "cap_eff": cap_hex,
        "kernel": kernel,
        "kernel_full": kernel_full,
        "arch": arch,
        "mounts": _mounts(_out(runner, "cat /proc/self/mountinfo 2>/dev/null")),
        "devices": devices,
        "docker_socket": docker_sock,
        "runc_version_in_container": runc,
        "runc_host_path": runc_host_path,
        "mnt_runc_path": mnt_runc_path,
        "runc_version_host": runc_host,
        "containerd_version_host": containerd_host,
        "host_os": host_os,
        "seccomp": seccomp,
        "proc1_cwd": proc1_cwd,
        "proc1_exe": proc1_exe,
        "proc1_fd_sample": [l for l in proc1_fd_sample.splitlines() if l],
        "tooling": tooling,
        "network_egress": http.startswith(("2", "3")),
        "notes": "%s; arch=%s; kernel=%s; runc_host_path=%s; mnt_runc_path=%s; "
                 "runc_host=%s; containerd_host=%s; block_devices=%s; docker_socket=%s; "
                 "egress=%s; proc1_cwd=%s; seccomp=%s" % (
            "privileged" if privileged else "unprivileged",
            arch, kernel, runc_host_path, mnt_runc_path, runc_host, containerd_host,
            ",".join(devices) or "none", docker_sock, http,
            proc1_cwd, seccomp),
    }
    bb.metrics.setdefault("steps", {})["recon"] = _PROBES
    return bb.env_report
