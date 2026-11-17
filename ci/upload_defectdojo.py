#!/usr/bin/env python3
"""Push scanner reports to DefectDojo (vulnerability management).

Uses /api/v2/reimport-scan/ with auto_create_context, so product, engagement and tests are
created on first run and findings are deduplicated / closed on later runs.
Skips quietly when DD_URL or DD_API_KEY is not set (forks, local runs).

Env: DD_URL, DD_API_KEY, DD_PRODUCT (default kb-assistant), DD_PRODUCT_TYPE (default Web),
     DD_ENGAGEMENT (default "CI <branch>"), CI_COMMIT_SHA / GITHUB_SHA, CI branch vars.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import httpx

# report file -> DefectDojo parser name
SCAN_TYPES = {
    "gitleaks.json": "Gitleaks Scan",
    "semgrep.json": "Semgrep JSON Report",
    "trivy-deps.json": "Trivy Scan",
    "trivy-image.json": "Trivy Scan",
    "trivy-config.json": "Trivy Scan",
    "checkov.json": "Checkov Scan",
    "zap.xml": "ZAP Scan",
    "nuclei.jsonl": "Nuclei Scan",
}


def ci_context() -> dict:
    branch = os.getenv("GITHUB_REF_NAME") or os.getenv("CI_COMMIT_REF_NAME") or os.getenv("BRANCH_NAME") or "local"
    commit = os.getenv("GITHUB_SHA") or os.getenv("CI_COMMIT_SHA") or os.getenv("GIT_COMMIT") or ""
    build = os.getenv("GITHUB_RUN_ID") or os.getenv("CI_PIPELINE_ID") or os.getenv("BUILD_ID") or ""
    return {"branch": branch, "commit": commit, "build": build}


def upload(client: httpx.Client, base_url: str, report: Path, scan_type: str, ctx: dict, env=os.environ) -> dict:
    data = {
        "scan_type": scan_type,
        "test_title": report.stem,
        "product_type_name": env.get("DD_PRODUCT_TYPE", "Web"),
        "product_name": env.get("DD_PRODUCT", "kb-assistant"),
        "engagement_name": env.get("DD_ENGAGEMENT", f"CI {ctx['branch']}"),
        "auto_create_context": "true",
        "deduplication_on_engagement": "true",
        "close_old_findings": "true",
        "active": "true",
        "verified": "false",
        "minimum_severity": "Info",
        "branch_tag": ctx["branch"],
        "commit_hash": ctx["commit"],
        "build_id": ctx["build"],
    }
    with report.open("rb") as fh:
        response = client.post(f"{base_url.rstrip('/')}/api/v2/reimport-scan/", data=data,
                               files={"file": (report.name, fh)})
    response.raise_for_status()
    return response.json()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default=os.getenv("REPORTS_DIR", "reports"))
    args = ap.parse_args()

    url, key = os.getenv("DD_URL"), os.getenv("DD_API_KEY")
    if not url or not key:
        print("DefectDojo upload skipped: DD_URL / DD_API_KEY not set")
        return 0

    ctx = ci_context()
    failures = 0
    with httpx.Client(headers={"Authorization": f"Token {key}"}, timeout=120) as client:
        for name, scan_type in SCAN_TYPES.items():
            report = Path(args.reports) / name
            if not report.is_file() or report.stat().st_size == 0:
                continue
            try:
                result = upload(client, url, report, scan_type, ctx)
                stats = (result.get("statistics") or {}).get("after", {}).get("total", {})
                print(f"{name:20} -> test {result.get('test_id')} ({scan_type}); active findings: {stats.get('active', '?')}")
            except httpx.HTTPError as exc:
                failures += 1
                detail = exc.response.text[:300] if isinstance(exc, httpx.HTTPStatusError) else str(exc)
                print(f"{name:20} -> upload failed: {detail}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
