#!/usr/bin/env bash
# SAST: Semgrep community rulesets + our own rules for LLM-specific risks.
source "$(dirname "$0")/lib.sh"
log "semgrep: rule self-tests"
semgrep --test --metrics=off security/semgrep/rules/
log "semgrep: scan"
semgrep scan --metrics=off --disable-version-check --quiet \
  --config p/python --config p/security-audit --config p/secrets \
  --config security/semgrep/rules/ \
  --json --output "$REPORTS_DIR/semgrep.json" \
  app ci triage security/llm-redteam
