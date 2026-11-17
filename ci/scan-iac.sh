#!/usr/bin/env bash
# IaC / configuration scanning: Terraform, Kubernetes manifests, Dockerfile.
source "$(dirname "$0")/lib.sh"
log "checkov"
checkov --quiet --soft-fail --compact --skip-download \
  -d infra/terraform -d deploy/k8s/base -f app/Dockerfile \
  --framework terraform kubernetes dockerfile \
  -o json > "$REPORTS_DIR/checkov.json"
log "trivy config (tfsec engine)"
# Test fixtures are deliberately insecure (they prove the Kyverno policies reject them);
# kustomize patches are partial manifests and are covered by the rendered overlay test;
# ci/k8s holds the e2e network probe.
trivy config --quiet --ignorefile .trivyignore.yaml \
  --skip-dirs security/kyverno/tests --skip-dirs deploy/k8s/overlays --skip-dirs ci/k8s \
  --skip-dirs .cache --skip-dirs reports \
  --format json --output "$REPORTS_DIR/trivy-config.json" .
