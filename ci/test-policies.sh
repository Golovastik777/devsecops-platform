#!/usr/bin/env bash
# Policy-as-code and config tests. Unlike scanners, these fail the job directly.
source "$(dirname "$0")/lib.sh"

log "kubeconform: Kubernetes schema validation"
# CRD schemas (ServiceMonitor, PrometheusRule, Argo CD) come from the community catalog.
CRD_SCHEMAS='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
for overlay in deploy/k8s/base deploy/k8s/overlays/kind; do
  kubectl kustomize "$overlay" | kubeconform -strict -summary -schema-location default -schema-location "$CRD_SCHEMAS" -
done
kubeconform -strict -summary -schema-location default -schema-location "$CRD_SCHEMAS" \
  security/kyverno/tests/resources deploy/argocd

log "kyverno: policy unit tests"
kyverno test security/kyverno/tests

log "falco: rule validation"
if type -P falco >/dev/null 2>&1; then
  falco -V /etc/falco/falco_rules.yaml -V deploy/falco/kb-assistant-rules.yaml
else
  docker run --rm -v "$REPO_ROOT/deploy/falco:/rules:ro" --entrypoint /usr/bin/falco "$FALCO_IMAGE" \
    -V /etc/falco/falco_rules.yaml -V /rules/kb-assistant-rules.yaml
fi

log "terraform: fmt + validate"
for dir in infra/terraform/*/; do
  terraform -chdir="$dir" fmt -check -diff
  terraform -chdir="$dir" init -backend=false -input=false -lockfile=readonly >/dev/null
  terraform -chdir="$dir" validate
done

log "prometheus: alert rules check + unit tests"
mkdir -p .cache/prometheus
${PYTHON:-python3} - <<'PY'
import yaml
rule = yaml.safe_load(open("deploy/k8s/base/prometheusrule.yaml"))
yaml.safe_dump(rule["spec"], open(".cache/prometheus/kb-assistant.rules.yaml", "w"), sort_keys=False)
PY
promtool check rules .cache/prometheus/kb-assistant.rules.yaml
promtool test rules deploy/k8s/tests/alerts.test.yaml

log "nuclei: template validation"
nuclei -silent -validate -t security/nuclei/templates/

log "wazuh rules: XML well-formedness"
python3 - <<'PY'
import xml.etree.ElementTree as ET
from pathlib import Path
for path in Path("deploy/wazuh").glob("*.xml"):
    # Wazuh rule files contain several top-level <group> elements.
    ET.fromstring(f"<root>{path.read_text()}</root>")
    print(f"ok {path}")
PY
