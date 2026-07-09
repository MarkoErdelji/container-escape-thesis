import os as _os

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


def _out(runner, cmd: str) -> str:
    return (runner.run(cmd).get("stdout") or "").strip()


def _decode_caps(status_line: str):
    parts   = status_line.split()
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
        left, right   = line.split(" - ", 1)
        lparts, rparts = left.split(), right.split()
        if len(lparts) < 5 or len(rparts) < 2:
            continue
        root, mountpoint = lparts[3], lparts[4]
        mnt_opts = lparts[5] if len(lparts) > 5 else ""
        fstype, source = rparts[0], rparts[1]
        opts = "ro" if "ro" in mnt_opts.split(",") else "rw"
        if source.startswith("/dev/") or fstype == "overlay":
            if root != "/" and root:
                notable.append("%s[%s] on %s (%s, %s)" % (source, root, mountpoint, fstype, opts))
            else:
                notable.append("%s on %s (%s, %s)" % (source, mountpoint, fstype, opts))
    return notable[:12]


def _self_cwd() -> str:
    # subprocess.run uses cwd=/; read it directly instead
    try:
        return _os.getcwd()
    except OSError:
        try:
            return _os.readlink("/proc/self/cwd")
        except Exception:
            return "unresolvable"


def run(cl, cfg, runner, bb):
    self_cwd    = _self_cwd()
    cap_hex, caps = _decode_caps(_out(runner, "grep -m1 CapEff /proc/self/status"))
    devices = _out(
        runner, "ls -la /dev 2>/dev/null | awk '$1 ~ /^b/ {print $NF}' | tr '\\n' ' '"
    ).split()
    tooling = _out(
        runner,
        "for t in gcc cc python3 perl curl wget nc ncat gdb nsenter mount unshare; do "
        "command -v $t >/dev/null 2>&1 && printf '%s ' \"$t\"; done",
    ).split()
    http_code   = _out(
        runner,
        "curl -s -o /dev/null -m 5 -w '%{http_code}' https://www.google.com 2>/dev/null || echo 000",
    )
    privileged  = "sys_admin" in caps
    docker_sock = _out(runner, "test -S /var/run/docker.sock && echo yes || echo no") == "yes"
    kernel      = _out(runner, "uname -r")
    arch        = _out(runner, "uname -m")
    proc1_cwd   = _out(runner, "readlink /proc/1/cwd 2>/dev/null || echo unknown")
    proc1_exe   = _out(runner, "readlink /proc/1/exe 2>/dev/null || echo unknown")
    proc1_fds   = _out(
        runner,
        "for fd in $(ls /proc/1/fd/ 2>/dev/null | head -20); do "
        "  t=$(readlink /proc/1/fd/$fd 2>/dev/null); "
        "  [ -n \"$t\" ] && echo \"fd$fd=$t\"; "
        "done",
    )
    kernel_full = _out(runner, "cat /proc/version 2>/dev/null")
    seccomp     = _out(runner, "grep -m1 Seccomp /proc/self/status 2>/dev/null")
    mountinfo   = _out(runner, "cat /proc/self/mountinfo 2>/dev/null")

    bb.env_report = {
        "containerized":   _out(runner, "test -f /.dockerenv && echo yes || echo no") == "yes",
        "privileged":      privileged,
        "capabilities":    caps,
        "cap_eff":         cap_hex,
        "kernel":          kernel,
        "kernel_full":     kernel_full,
        "arch":            arch,
        "mounts":          _mounts(mountinfo),
        "devices":         devices,
        "docker_socket":   docker_sock,
        "seccomp":         seccomp,
        "self_cwd":        self_cwd,
        "proc1_cwd":       proc1_cwd,
        "proc1_exe":       proc1_exe,
        "proc1_fd_sample": [l for l in proc1_fds.splitlines() if l],
        "tooling":         tooling,
        "network_egress":  http_code.startswith(("2", "3")),
    }
    return bb.env_report
