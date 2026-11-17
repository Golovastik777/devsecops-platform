#!/usr/bin/env bash
# DAST against a running instance: ZAP baseline, Nuclei (official + own templates), LLM red-team suite.
source "$(dirname "$0")/lib.sh"
TARGET_URL="${TARGET_URL:-http://127.0.0.1:8080}"

log "ZAP baseline -> $TARGET_URL"
chmod a+rwx "$REPORTS_DIR"
rc=0
docker run --rm --network "$DOCKER_NETWORK" -v "$REPO_ROOT/$REPORTS_DIR:/zap/wrk:rw" "$ZAP_IMAGE" \
  zap-baseline.py -t "$TARGET_URL" -J zap.json -x zap.xml -r zap.html -I || rc=$?
# 0 pass, 1 fail, 2 warn; 3 = ZAP itself failed
[ "$rc" -le 2 ] || { echo "ZAP failed to run (exit $rc)"; exit "$rc"; }

log "nuclei: own templates (headers, API docs, prompt-injection guardrail)"
nuclei -silent -disable-update-check -u "$TARGET_URL" -t security/nuclei/templates/ \
  -jsonl -o "$REPORTS_DIR/nuclei-custom.jsonl" || true
log "nuclei: community templates (exposures, misconfigurations)"
nuclei -silent -disable-update-check -u "$TARGET_URL" \
  -tags exposure,misconfig -etags intrusive,dos,fuzz,osint \
  -rate-limit 50 -jsonl -o "$REPORTS_DIR/nuclei-community.jsonl" || true
cat "$REPORTS_DIR"/nuclei-custom.jsonl "$REPORTS_DIR"/nuclei-community.jsonl > "$REPORTS_DIR/nuclei.jsonl" 2>/dev/null || true
touch "$REPORTS_DIR/nuclei.jsonl"

log "LLM red-team suite"
python3 security/llm-redteam/redteam.py --url "$TARGET_URL" --out "$REPORTS_DIR/llm-redteam.json"
