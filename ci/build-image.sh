#!/usr/bin/env bash
# Build the image, scan it and produce an SBOM.
source "$(dirname "$0")/lib.sh"
IMAGE="${IMAGE:-ghcr.io/golovastik777/kb-assistant:ci}"
log "docker build $IMAGE"
docker build -t "$IMAGE" app/
log "trivy image"
mkdir -p .cache/images
docker save "$IMAGE" -o .cache/images/kb-assistant.tar
trivy image --quiet --input .cache/images/kb-assistant.tar --scanners vuln,secret \
  --secret-config .trivy-secret.yaml \
  --format json --output "$REPORTS_DIR/trivy-image.json"
log "SBOM (CycloneDX)"
trivy image --quiet --input .cache/images/kb-assistant.tar --format cyclonedx --output "$REPORTS_DIR/sbom.cdx.json"
