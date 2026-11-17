# Threat model: kb-assistant

Scope: the assistant API, its knowledge base, the LLM provider call, the CI/CD pipeline and
the Kubernetes runtime. Method: STRIDE per component, with the control that addresses each threat.

## Assets

* Internal knowledge-base documents (anti-fraud rules) - must never reach players.
* System prompt and its canary - leaking it helps attackers tune injections.
* LLM API key and staff token - mounted secrets.
* Player trust: the assistant must not tell players to do something harmful
  (e.g. "send your password to ...").
* The pipeline itself: a compromised pipeline ships anything.

## Threats and controls

| # | Threat | STRIDE | Control | Verified by |
|---|---|---|---|---|
| T1 | Direct prompt injection: player overrides instructions | Tampering / EoP | Input rail, Llama Guard rail, system prompt | Red-team suite, Nuclei template, unit tests |
| T2 | Indirect injection planted in a KB document | Tampering | Retrieval rail strips instruction-like lines; passages wrapped as data | `test_poisoned_document_is_sanitised` |
| T3 | Player extracts internal documents | Info disclosure | Audience ACL at retrieval (not in the prompt) | `test_internal_docs_are_not_retrieved_for_players` |
| T4 | System prompt leak | Info disclosure | Canary token, output rail blocks the answer | `test_claude_answer_leaking_canary_is_blocked` |
| T5 | Model output echoes secrets or card numbers | Info disclosure | Output redaction (Luhn-checked PANs, key patterns) | unit tests |
| T6 | Model output executed as code | EoP | Semgrep rule `llm-output-to-dangerous-sink` | `semgrep --test` |
| T7 | Abuse / cost exhaustion of the LLM endpoint | DoS | Per-client rate limit, body size limit, question length limit | `test_rate_limit`, `test_oversized_body_is_rejected` |
| T8 | Vulnerable dependency or base image | Tampering / EoP | Hash-locked deps, Trivy fs + image, OS patching at build, Dependabot | security gate |
| T9 | Secret committed to git | Info disclosure | Gitleaks over full history, pre-commit hook | security gate |
| T10 | Container breakout after RCE | EoP | Non-root, read-only rootfs, drop ALL, seccomp, PSA restricted, Kyverno | kind e2e |
| T11 | Lateral movement from a compromised pod | EoP | Default-deny NetworkPolicy, egress only DNS + 443 outside RFC1918, no SA token | kind e2e |
| T12 | Post-exploitation activity (shell, miners, outbound SSH) | - | Falco rules -> Wazuh alerts | `falco -V` |
| T13 | Compromised CI credentials | Spoofing | OIDC role limited to `main`, write-only to `reports/*`; SHA-pinned actions; read-only default token | Checkov, review |
| T14 | Prompt injection against the AI triage agent | Tampering | Agent is advisory, cannot change the gate; read-only tools confined to repo | `test_tools_are_confined_to_repo` |

## Accepted residual risks

* The heuristic input rail misses paraphrased attacks (see red-team known gaps). Mitigated by
  T3 (nothing secret is in the context of a public request) and the Llama Guard rail.
* Base-image CVEs without a Debian fix stay until upstream releases one; tracked in DefectDojo.
