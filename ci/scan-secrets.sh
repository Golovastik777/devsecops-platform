#!/usr/bin/env bash
# Secret scanning of the whole git history (not only the working tree).
source "$(dirname "$0")/lib.sh"
log "gitleaks: full git history"
# Merge commits carry no diff of their own, so gitleaks does not count them.
expected=$(git rev-list --all --no-merges --count)
out=$(gitleaks git --no-banner --redact --exit-code 0 \
  --config .gitleaks.toml \
  --report-format json --report-path "$REPORTS_DIR/gitleaks.json" . 2>&1) || true
echo "$out"
# A scanner that silently scans nothing must not look like "no leaks found".
scanned=$(grep -oE '[0-9]+ commits scanned' <<<"$out" | grep -oE '^[0-9]+' || echo 0)
if [ "$scanned" -lt "$expected" ] || grep -q 'ERR' <<<"$out"; then
  echo "gitleaks scanned $scanned of $expected commits - failing" >&2
  exit 1
fi
