#!/usr/bin/env python3
"""Security gate: decide whether the pipeline may continue.

Reads every report in reports/, applies .security/policy.yaml and the time-limited
exceptions in .security/accepted-risks.yaml, then writes:
  reports/findings.json         normalised findings (input for DefectDojo / AI triage)
  reports/security.sarif        file-based findings for GitHub code scanning
  reports/security-summary.md   human summary (also appended to the CI job summary)
Exit code 1 when a blocking finding is not covered by a valid exception.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import SEVERITIES, Finding, load_findings  # noqa: E402

FILE_CATEGORIES = {"secret", "sast", "iac"}
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note", "UNKNOWN": "note"}


def load_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def matches(rule: dict, f: Finding) -> bool:
    return all(str(getattr(f, key, "")) == str(value) or (key == "location" and str(value) in f.location)
               for key, value in rule.items())


def check_exceptions(entries: list[dict], max_days: int, today: dt.date) -> tuple[list[dict], list[str]]:
    valid, errors = [], []
    for i, e in enumerate(entries):
        missing = [k for k in ("match", "reason", "owner", "expires") if not e.get(k)]
        if missing:
            errors.append(f"exception #{i}: missing {', '.join(missing)}")
            continue
        expires = e["expires"] if isinstance(e["expires"], dt.date) else dt.date.fromisoformat(str(e["expires"]))
        if expires < today:
            errors.append(f"exception #{i} ({e['match']}) expired on {expires}")
        elif (expires - today).days > max_days:
            errors.append(f"exception #{i} ({e['match']}) is longer than {max_days} days")
        else:
            valid.append(e)
    return valid, errors


def is_blocking(f: Finding, policy: dict) -> bool:
    if f.category == "iac" and policy.get("block_iac_failures", True):
        return True
    if f.severity not in policy.get("block_severities", ["CRITICAL", "HIGH"]):
        return False
    if f.category in {"sca", "image"} and policy.get("ignore_unfixed", True) and not f.fixed_version:
        return False
    return True


def to_sarif(findings: list[Finding]) -> dict:
    runs = []
    for tool in sorted({f.tool for f in findings if f.category in FILE_CATEGORIES}):
        items = [f for f in findings if f.tool == tool and f.category in FILE_CATEGORIES]
        rules = {f.rule_id: {"id": f.rule_id, "shortDescription": {"text": f.title[:200] or f.rule_id}} for f in items}
        results = [{
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"[{f.severity}] {f.title}"},
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.location},
                "region": {"startLine": max(int(f.line or 1), 1)},
            }}],
        } for f in items]
        runs.append({"tool": {"driver": {"name": tool, "rules": list(rules.values())}}, "results": results})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def summary(findings, blocking, accepted, present, errors) -> str:
    by_tool = Counter((f.tool, f.severity) for f in findings)
    tools = sorted({f.tool for f in findings})
    lines = ["## Security gate", "",
             f"Reports: {', '.join(present) or 'none'}", "",
             "| Tool | " + " | ".join(SEVERITIES) + " |", "|---" * (len(SEVERITIES) + 1) + "|"]
    for tool in tools:
        lines.append(f"| {tool} | " + " | ".join(str(by_tool.get((tool, s), 0) or "") for s in SEVERITIES) + " |")
    lines += ["", f"**Blocking:** {len(blocking)} · **Accepted by exception:** {len(accepted)} · **Total:** {len(findings)}", ""]
    if blocking:
        lines += ["### Blocking findings", "", "| Severity | Tool | Rule | Location | Title |", "|---|---|---|---|---|"]
        for f in sorted(blocking, key=lambda x: SEVERITIES.index(x.severity))[:50]:
            loc = f"{f.location}:{f.line}" if f.line else f.location
            lines.append(f"| {f.severity} | {f.tool} | `{f.rule_id}` | `{loc}` | {f.title[:90]} |")
    if errors:
        lines += ["", "### Exception file problems", ""] + [f"- {e}" for e in errors]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default=os.getenv("REPORTS_DIR", "reports"))
    ap.add_argument("--policy", default=".security/policy.yaml")
    ap.add_argument("--exceptions", default=".security/accepted-risks.yaml")
    ap.add_argument("--no-fail", action="store_true", help="report only, always exit 0")
    args = ap.parse_args()

    reports = Path(args.reports)
    policy = load_yaml(Path(args.policy))
    findings, present = load_findings(reports)
    exceptions, errors = check_exceptions(load_yaml(Path(args.exceptions)).get("accepted") or [],
                                          int(policy.get("max_exception_days", 90)), dt.date.today())

    blocking, accepted = [], []
    for f in findings:
        if not is_blocking(f, policy):
            continue
        (accepted if any(matches(e["match"], f) for e in exceptions) else blocking).append(f)

    blocking_ids = {f.fingerprint for f in blocking}
    (reports / "findings.json").write_text(json.dumps(
        {"findings": [f.to_dict() | {"blocking": f.fingerprint in blocking_ids} for f in findings]}, indent=2),
        encoding="utf-8")
    (reports / "security.sarif").write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
    text = summary(findings, blocking, accepted, present, errors)
    (reports / "security-summary.md").write_text(text, encoding="utf-8")
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(text)
    print(text)

    failed = bool(blocking or errors)
    return 0 if args.no_fail or not failed else 1


if __name__ == "__main__":
    sys.exit(main())
