#!/bin/bash
# One-command end-to-end runner. Run this FROM THE MAC (host) — it drives the Lima VM.
#
# It will: bring the VM up if needed, install Python deps, build the Docker images,
# pass your ANTHROPIC_API_KEY in, and run the orchestrator. The orchestrator itself
# starts/stops the victim+attacker containers per episode and enforces the per-episode
# USD budget, so this script is purely the setup-and-launch glue.
#
# Usage:
#   export ANTHROPIC_API_KEY=sk-ant-...        # (or use the session "! export ..." trick)
#   ./scripts/run_all.sh                       # one episode from config.yaml
#   ./scripts/run_all.sh -n 20                 # batch of 20  (orchestrator.runner)
#   ./scripts/run_all.sh --skip-build          # skip image build (faster on repeat runs)
#   ./scripts/run_all.sh -q                     # quiet: only the final summary
#   ./scripts/run_all.sh --config /lab/config.yaml
#   # Per-case overrides (no need to edit config.yaml; --scenario also picks the VM):
#   ./scripts/run_all.sh --scenario cve-2024-21626 --tier offline-staged --runtime c
#   ./scripts/run_all.sh --scenario privileged --tier full-internet --model claude-haiku-4-5-20251001
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST_RESULTS="$REPO/results"   # results are copied here on the Mac after each run

EPISODES=""
CONFIG=""
SKIP_BUILD=0
VERBOSE=1
SCENARIO=""   # override config.yaml scenario (also selects the VM): privileged | cve-2024-21626
TIER=""       # override resource_tier: offline-bare | offline-staged | full-internet
RUNTIME=""    # override victim_runtime: c | python | java
MODEL=""      # override model.id, e.g. claude-haiku-4-5-20251001
BUDGET=""     # override per-episode USD cap (raise it for Opus runs)

usage() {
  sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--episodes) EPISODES="${2:?--episodes needs a number}"; shift 2 ;;
    --config)      CONFIG="${2:?--config needs a path}"; shift 2 ;;
    --scenario)    SCENARIO="${2:?--scenario needs a value}"; shift 2 ;;
    --tier)        TIER="${2:?--tier needs a value}"; shift 2 ;;
    --runtime)     RUNTIME="${2:?--runtime needs a value}"; shift 2 ;;
    --model)       MODEL="${2:?--model needs a value}"; shift 2 ;;
    --budget)      BUDGET="${2:?--budget needs a USD value}"; shift 2 ;;
    --skip-build)  SKIP_BUILD=1; shift ;;
    -q|--quiet)    VERBOSE=0; shift ;;
    -h|--help)     usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 1 ;;
  esac
done

# Pick the Lima VM by scenario (flag overrides config.yaml) — each escape class needs a
# differently-provisioned host (privileged container vs. a VM running vulnerable runc 1.1.11).
[[ -z "$SCENARIO" ]] && SCENARIO="$(sed -nE 's/^scenario:[[:space:]]*([^[:space:]#]+).*/\1/p' "$REPO/config.yaml" 2>/dev/null)"
case "$SCENARIO" in
  cve-2024-21626) VM=thesis-runc;       LIMA_YAML="$REPO/lima/lima-runc.yaml" ;;
  dirtypipe)      VM=thesis-lab-kernel;  LIMA_YAML="$REPO/lima/lima-dirtypipe.yaml" ;;
  *)              VM=thesis-privileged; LIMA_YAML="$REPO/lima/lima-privileged.yaml" ;;
esac
echo ">> scenario='$SCENARIO'  tier='${TIER:-<config>}'  runtime='${RUNTIME:-<config>}'  model='${MODEL:-<config>}'  -> VM '$VM'"

# --- Preflight (host) --------------------------------------------------------
command -v limactl >/dev/null 2>&1 || {
  echo "error: limactl not found on PATH. Install Lima (brew install lima)." >&2
  exit 1
}
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "error: ANTHROPIC_API_KEY is not set in this shell." >&2
  echo "       Set it first, e.g. in this Claude session type:" >&2
  echo "         ! export ANTHROPIC_API_KEY=sk-ant-..." >&2
  exit 1
fi

# --- Ensure the VM is up (idempotent) ----------------------------------------
status="$(limactl list --format '{{.Status}}' "$VM" 2>/dev/null || true)"
if [[ -z "$status" ]]; then
  echo ">> VM '$VM' does not exist — creating it (first boot provisions docker; takes a few min)..."
  limactl start --name="$VM" "$LIMA_YAML" --tty=false
elif [[ "$status" == "Running" ]]; then
  echo ">> VM '$VM' is already Running."
else
  echo ">> VM '$VM' is '$status' — starting it..."
  limactl start "$VM" --tty=false
fi

# --- Dirtypipe: verify the VM is running the custom vulnerable kernel ---------
# On first provisioning the VM boots the stock Ubuntu kernel; provision replaces
# the stock kernel files in /boot with 5.15.24, so one stop+start is enough.
# Lima VZ EFI NVRAM points to the stock kernel path by name — updating grub.cfg
# alone does nothing; only replacing the files at those paths works.
if [[ "$SCENARIO" == "dirtypipe" ]]; then
  RUNNING_KERNEL=$(limactl shell "$VM" -- uname -r 2>/dev/null | tr -d '[:space:]' || true)
  if [[ "$RUNNING_KERNEL" != "5.15.24" ]]; then
    echo ">> Kernel is '$RUNNING_KERNEL', need 5.15.24 — rebooting VM into custom kernel..."
    limactl stop "$VM" --tty=false
    limactl start "$VM" --tty=false
    RUNNING_KERNEL=$(limactl shell "$VM" -- uname -r 2>/dev/null | tr -d '[:space:]' || true)
    echo ">> Kernel after reboot: $RUNNING_KERNEL"
    if [[ "$RUNNING_KERNEL" != "5.15.24" ]]; then
      echo "ERROR: still on '$RUNNING_KERNEL' after reboot." >&2
      echo "       If this is a fresh VM, provisioning may still be running — wait and retry." >&2
      echo "       If provisioning finished, check: limactl shell $VM -- ls /boot/vmlinuz-5.15.24" >&2
      exit 1
    fi
  else
    echo ">> Kernel $RUNNING_KERNEL ✓"
  fi
fi

# --- Build the remote command ------------------------------------------------
if [[ -n "$EPISODES" ]]; then
  RUN="python3 -m orchestrator.runner --episodes $EPISODES"
else
  RUN="python3 -m orchestrator.main"
fi
[[ -n "$CONFIG" ]] && RUN="$RUN --config $CONFIG"

BUILD="bash /lab/scripts/lab.sh build"
[[ "$SKIP_BUILD" -eq 1 ]] && BUILD="echo '>> skipping image build (--skip-build)'"

REMOTE=$(cat <<EOF
set -e
# Manual PATH: avoids sourcing ~/.bash_profile (which has stale Mac cd commands) while
# still finding pip --user binaries and /usr/local/sbin (where vulnerable runc lives).
export PATH="\$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Open the docker socket to all users for this boot session. Needed when the lima user
# isn't in the docker group (usermod -aG docker takes effect only on fresh login; sg docker
# asks for a group password which doesn't exist). Lima users have passwordless sudo.
sudo chmod 666 /var/run/docker.sock
echo '>> installing Python deps (orchestrator/requirements.txt)...'
python3 -m pip install --user -q -r /lab/orchestrator/requirements.txt
echo '>> building Docker images...'
$BUILD
echo '>> running orchestrator...'
cd /lab && $RUN
EOF
)

# --- Run in the VM, passing the API key through ------------------------------
# bash -c (not -lc): skips the login profile so the Mac-path cd commands don't fire.
echo ">> handing off to the VM..."
set +e
limactl shell "$VM" -- env ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  THESIS_VERBOSE="$VERBOSE" \
  THESIS_SCENARIO="$SCENARIO" THESIS_TIER="$TIER" \
  THESIS_RUNTIME="$RUNTIME" THESIS_MODEL="$MODEL" THESIS_BUDGET="$BUDGET" \
  bash -c "$REMOTE"
rc=$?
set -e

# --- Copy results VM -> Mac --------------------------------------------------
# /lab is mounted read-only, so the orchestrator writes to ~/thesis-results in the
# VM; mirror that onto the host here (tar stream — recursive, no extra flags needed).
echo
echo ">> copying results to host: $HOST_RESULTS/"
mkdir -p "$HOST_RESULTS"
limactl shell "$VM" -- sh -c 'cd "$HOME" && tar -cf - thesis-results 2>/dev/null' \
  | tar -C "$HOST_RESULTS" -xf - --strip-components=1 2>/dev/null || true
ls -1t "$HOST_RESULTS" 2>/dev/null | head -5 | sed 's/^/   /'

echo ">> done (orchestrator exit $rc). Results are on your Mac at $HOST_RESULTS/"
exit "$rc"
