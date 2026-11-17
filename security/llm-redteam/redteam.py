#!/usr/bin/env python3
"""LLM red-team regression suite for the assistant endpoint (stdlib only).

Sends every case from corpus.json to POST /api/v1/ask and checks the guardrail decision:
  expect=block -> HTTP 400, expect=allow -> HTTP 200.
Cases marked known_gap document attacks the heuristic layer misses; they are reported
but do not fail the run. Exit code 1 if any other case behaves unexpectedly.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

CORPUS = Path(__file__).with_name("corpus.json")


def send(url: str, prompt: str, timeout: float = 10.0) -> int:
    body = json.dumps({"question": prompt}).encode()
    request = urllib.request.Request(f"{url.rstrip('/')}/api/v1/ask", data=body,
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosemgrep: dynamic-urllib-use-detected
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--out", default="reports/llm-redteam.json")
    args = ap.parse_args()

    cases = json.loads(CORPUS.read_text(encoding="utf-8"))["cases"]
    results = []
    for case in cases:
        status = send(args.url, case["prompt"])
        expected_status = 400 if case["expect"] == "block" else 200
        results.append({k: case.get(k) for k in ("id", "category", "expect", "known_gap")}
                       | {"expected": expected_status, "status": status, "passed": status == expected_status})

    attacks = [r for r in results if r["expect"] == "block" and not r.get("known_gap")]
    benign = [r for r in results if r["expect"] == "allow"]
    report = {
        "target": args.url,
        "summary": {
            "attacks_blocked": f"{sum(r['passed'] for r in attacks)}/{len(attacks)}",
            "benign_allowed": f"{sum(r['passed'] for r in benign)}/{len(benign)}",
            "known_gaps_open": sum(1 for r in results if r.get("known_gap") and not r["passed"]),
            "by_category": dict(Counter(r["category"] for r in results if not r["passed"])),
        },
        "results": results,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2, ensure_ascii=False))

    unexpected = [r for r in results if not r["passed"] and not r.get("known_gap")]
    for r in unexpected:
        print(f"UNEXPECTED {r['id']} ({r['category']}): expected {r['expected']}, got {r['status']}", file=sys.stderr)
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
