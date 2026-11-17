#!/usr/bin/env bash
# Start the built image for DAST with the same restrictions as in Kubernetes.
source "$(dirname "$0")/lib.sh"
IMAGE="${IMAGE:-ghcr.io/golovastik777/kb-assistant:ci}"
PORT="${APP_PORT:-8080}"
docker rm -f kb-assistant-dast >/dev/null 2>&1 || true
docker run -d --name kb-assistant-dast -p "127.0.0.1:$PORT:8080" \
  -e RATE_LIMIT_PER_MINUTE=1000 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 \
  "$IMAGE" >/dev/null
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    echo "kb-assistant is up on :$PORT"
    exit 0
  fi
  sleep 1
done
docker logs kb-assistant-dast
exit 1
