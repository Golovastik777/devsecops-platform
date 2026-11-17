#!/usr/bin/env bash
# SCA: known vulnerabilities in locked Python dependencies.
source "$(dirname "$0")/lib.sh"
log "trivy fs: dependencies"
trivy fs --quiet --scanners vuln --format json --output "$REPORTS_DIR/trivy-deps.json" app/
