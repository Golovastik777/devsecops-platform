#!/usr/bin/env bash
# Shared helpers for every CI system (GitHub Actions, GitLab CI, Jenkins) and for local runs.
# A tool runs from PATH when it is installed (GitLab/Jenkins jobs use the tool's own image),
# otherwise from the pinned container image below. Versions live here and nowhere else.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTS_DIR="${REPORTS_DIR:-reports}"
cd "$REPO_ROOT"
mkdir -p "$REPORTS_DIR" .cache

TRIVY_IMAGE="aquasec/trivy:0.76.1"
GITLEAKS_IMAGE="ghcr.io/gitleaks/gitleaks:v8.30.1"
SEMGREP_IMAGE="semgrep/semgrep:1.183.0"
CHECKOV_IMAGE="bridgecrew/checkov:3.4.3"
KYVERNO_IMAGE="ghcr.io/kyverno/kyverno-cli:v1.19.2"
FALCO_IMAGE="falcosecurity/falco:0.45.2"
NUCLEI_IMAGE="projectdiscovery/nuclei:v3.11.1"
ZAP_IMAGE="zaproxy/zap-stable:2.17.0"
KUBECONFORM_IMAGE="ghcr.io/yannh/kubeconform:v0.8.0"
TERRAFORM_IMAGE="hashicorp/terraform:1.17.1"
PROMETHEUS_IMAGE="prom/prometheus:v3.15.0"

DOCKER_NETWORK="${DOCKER_NETWORK:-host}"

# run_tool <binary> <image> <entrypoint-in-image> [args...]
run_tool() {
  local bin="$1" image="$2" entrypoint="$3"
  shift 3
  if type -P "$bin" >/dev/null 2>&1; then
    command "$bin" "$@"
  else
    docker run --rm -i --network "$DOCKER_NETWORK" \
      --user "$(id -u):$(id -g)" -e HOME=/tmp \
      -e TRIVY_CACHE_DIR=/src/.cache/trivy -e SEMGREP_SEND_METRICS=off \
      -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
      -v "$REPO_ROOT:/src" -w /src \
      --entrypoint "$entrypoint" "$image" "$@"
  fi
}

trivy()       { run_tool trivy       "$TRIVY_IMAGE"       trivy                     "$@"; }
gitleaks()    { run_tool gitleaks    "$GITLEAKS_IMAGE"    gitleaks                  "$@"; }
semgrep()     { run_tool semgrep     "$SEMGREP_IMAGE"     semgrep                   "$@"; }
checkov()     { run_tool checkov     "$CHECKOV_IMAGE"     checkov                   "$@"; }
kyverno()     { run_tool kyverno     "$KYVERNO_IMAGE"     /ko-app/kubectl-kyverno   "$@"; }
nuclei()      { run_tool nuclei      "$NUCLEI_IMAGE"      nuclei                    "$@"; }
kubeconform() { run_tool kubeconform "$KUBECONFORM_IMAGE" /kubeconform              "$@"; }
terraform()   { run_tool terraform   "$TERRAFORM_IMAGE"   /bin/terraform            "$@"; }
promtool()    { run_tool promtool    "$PROMETHEUS_IMAGE"  /bin/promtool             "$@"; }

log() { printf '\n==> %s\n' "$*"; }
