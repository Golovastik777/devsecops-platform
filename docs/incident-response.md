# Incident response runbook: kb-assistant

Applies to alerts from Falco, Wazuh rules 100100-100199 and DefectDojo critical findings.

## Severity

| Level | Examples | Response |
|---|---|---|
| SEV1 | Shell in app container, miner connection, prompt leak (Wazuh 100102), confirmed secret exposure | Immediately, page on-call |
| SEV2 | Unexpected outbound connection, prompt-injection campaign (100101), CRITICAL CVE exploitable in our code path | Within 4 hours |
| SEV3 | Isolated guardrail blocks, HIGH CVE with no exposure | Next business day, via DefectDojo |

## 1. Triage (first 15 minutes)

1. Read the alert: rule, pod, namespace, image tag, command line or client.
2. Confirm it is real: `kubectl -n kb-assistant get pods -o wide`, the pod's logs
   (`kubectl logs <pod> | grep '"event"'`), Falco output for the same pod.
3. Open an incident channel, assign an incident lead, start a timeline.

## 2. Contain

Prefer actions that keep evidence:

* **Isolate the pod** without killing it - move it out of the Service and cut its network:
  ```bash
  kubectl -n kb-assistant label pod <pod> app.kubernetes.io/name=quarantine --overwrite
  kubectl -n kb-assistant apply -f - <<'YAML'
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata: {name: quarantine}
  spec:
    podSelector: {matchLabels: {app.kubernetes.io/name: quarantine}}
    policyTypes: [Ingress, Egress]
  YAML
  ```
  The Deployment starts a clean replacement automatically.
* **Prompt-injection campaign**: lower `RATE_LIMIT_PER_MINUTE`, block the client at the ingress,
  check that answers to that client contained no internal data (sources in the app log).
* **Leaked secret**: rotate first (LLM key, staff token), then investigate. Rotation is never
  blocked by the investigation.

## 3. Collect evidence

* `kubectl -n kb-assistant get pod <pod> -o yaml > pod.yaml`, `kubectl logs --previous`, events.
* Falco events for the pod, Wazuh alerts for the window, the image digest and its SBOM
  (`reports/sbom.cdx.json` from the pipeline run that built it).
* If needed, a forensic copy of the container before it is removed.

## 4. Eradicate and recover

* Find the entry point (vulnerable dependency, guardrail bypass, leaked credential).
* Fix in code, add a regression test (unit test, red-team case or Nuclei template), ship
  through the normal pipeline - no manual hotfixes in the cluster.
* Remove the quarantined pod once evidence is stored.

## 5. Post-incident

* Blameless review within 5 working days: timeline, root cause, what detected it, what did not.
* Every action item becomes a ticket with an owner; detection gaps become Falco/Wazuh rules.
