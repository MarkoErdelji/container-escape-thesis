#!/bin/bash
# Runs INSIDE the Lima VM. Builds images and brings the manual lab up/down (milestone 0).
# Usage: lab.sh build | up <c|python|java> | down
set -euo pipefail
LAB=/lab
RUNTIME="${2:-c}"
ATTACKER=thesis-attacker
VICTIM=thesis-victim

build() {
  docker build -t thesis-victim-c      "$LAB/victim/c"
  docker build -t thesis-victim-python "$LAB/victim/python"
  docker build -t thesis-victim-java   "$LAB/victim/java"
  docker build -t thesis-attacker -f "$LAB/attacker/Dockerfile" "$LAB"
}

up() {
  docker rm -f "$VICTIM" "$ATTACKER" 2>/dev/null || true
  docker run -d --name "$VICTIM" "thesis-victim-$RUNTIME"
  local token_hash=""
  for i in $(seq 1 15); do
    token_hash=$(docker logs "$VICTIM" 2>/dev/null | grep '^TOKEN_HASH:' | head -1 | sed 's/^TOKEN_HASH://')
    [ -n "$token_hash" ] && break
    sleep 1
  done
  echo "victim token hash: $token_hash"
  docker run -d --name "$ATTACKER" --privileged thesis-attacker
  echo "victim host PID: $(docker inspect -f '{{.State.Pid}}' "$VICTIM")"
  echo "attacker shell:  docker exec -it $ATTACKER bash"
}

down() { docker rm -f "$VICTIM" "$ATTACKER" 2>/dev/null || true; }

case "${1:-}" in
  build) build ;;
  up)    build; up ;;
  down)  down ;;
  *) echo "usage: lab.sh {build | up <c|python|java> | down}"; exit 1 ;;
esac
