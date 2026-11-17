#!/usr/bin/env bash
# IaC / configuration scanning: Terraform, Kubernetes manifests, Dockerfile.
source "$(dirname "$0")/lib.sh"
log "checkov"
: > .cache/checkov.raw.json
# One run per framework: combining several -d/-f in one run duplicates or drops results.
for target in infra/terraform:terraform deploy/k8s/base:kubernetes app:dockerfile; do
  checkov --quiet --soft-fail --compact --skip-download \
    -d "${target%%:*}" --framework "${target##*:}" -o json >> .cache/checkov.raw.json
done
# Checkov prints one JSON document per scanned directory; DefectDojo and the gate expect one.
python3 - .cache/checkov.raw.json "$REPORTS_DIR/checkov.json" <<'PY'
import json, sys
text, decoder, pos, docs = open(sys.argv[1]).read(), json.JSONDecoder(), 0, []
while pos < len(text):
    while pos < len(text) and text[pos].isspace():
        pos += 1
    if pos < len(text):
        doc, pos = decoder.raw_decode(text, pos)
        docs.extend(doc if isinstance(doc, list) else [doc])
json.dump(docs, open(sys.argv[2], "w"), indent=1)
PY
log "trivy config (tfsec engine)"
# Test fixtures are deliberately insecure (they prove the Kyverno policies reject them);
# kustomize patches are partial manifests and are covered by the rendered overlay test;
# ci/k8s holds the e2e network probe.
trivy config --quiet --ignorefile .trivyignore.yaml \
  --skip-dirs security/kyverno/tests --skip-dirs deploy/k8s/overlays --skip-dirs ci/k8s \
  --skip-dirs .cache --skip-dirs reports \
  --format json --output "$REPORTS_DIR/trivy-config.json" .
