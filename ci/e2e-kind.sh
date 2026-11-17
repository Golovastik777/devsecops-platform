#!/usr/bin/env bash
# End-to-end security test on a kind cluster:
#   1. Kyverno policies enforced, hardened app rolls out under PSA "restricted"
#   2. every insecure pod from the fixtures is rejected at admission (PSA or Kyverno)
#   3. NetworkPolicy: only the ingress namespace can reach the app
source "$(dirname "$0")/lib.sh"
CLUSTER="${KIND_CLUSTER:-devsecops}"
IMAGE="${IMAGE:-ghcr.io/golovastik777/kb-assistant:ci}"
KYVERNO_CHART_VERSION="3.9.2"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kind load docker-image "$IMAGE" --name "$CLUSTER"

log "Kyverno (chart $KYVERNO_CHART_VERSION)"
helm upgrade --install kyverno kyverno --repo https://kyverno.github.io/kyverno/ \
  --version "$KYVERNO_CHART_VERSION" -n kyverno --create-namespace --wait --timeout 6m
kubectl apply -f security/kyverno/policies/
kubectl wait --for=condition=Ready clusterpolicy --all --timeout=180s

log "Deploy kb-assistant"
kubectl apply -k deploy/k8s/overlays/kind
kubectl -n kb-assistant rollout status deploy/kb-assistant --timeout=180s

log "Admission: insecure pods must be rejected"
out=$(kubectl apply --dry-run=server -f security/kyverno/tests/resources/bad-pods.yaml 2>&1 || true)
echo "$out"
expected=$(grep -c '^kind: Pod' security/kyverno/tests/resources/bad-pods.yaml)
rejected=$(grep -c 'Error from server' <<<"$out" || true)
by_kyverno=$(grep -c 'kyverno' <<<"$out" || true)
echo "rejected $rejected/$expected (Kyverno messages: $by_kyverno)"
[ "$rejected" -eq "$expected" ] || { echo "FAIL: some insecure pods were admitted"; exit 1; }
[ "$by_kyverno" -ge 4 ] || { echo "FAIL: Kyverno did not block the PSA-compliant violations"; exit 1; }

log "NetworkPolicy: ingress only from the ingress-nginx namespace"
probe() {  # probe <namespace> -> prints pod phase
  local ns="$1"
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$ns" delete pod probe --ignore-not-found >/dev/null
  sed "s/__NS__/$ns/" ci/k8s/probe-pod.yaml | kubectl apply -f - >/dev/null
  kubectl -n "$ns" wait pod/probe --for=jsonpath='{.status.phase}'=Succeeded --timeout=60s >/dev/null 2>&1 \
    || kubectl -n "$ns" wait pod/probe --for=jsonpath='{.status.phase}'=Failed --timeout=30s >/dev/null 2>&1 || true
  kubectl -n "$ns" get pod probe -o jsonpath='{.status.phase}'
}
allowed=$(probe ingress-nginx)
denied=$(probe untrusted)
echo "from ingress-nginx: $allowed (want Succeeded); from untrusted: $denied (want Failed)"
[ "$allowed" = "Succeeded" ] && [ "$denied" = "Failed" ] || { echo "FAIL: NetworkPolicy check"; exit 1; }
echo "e2e OK"
