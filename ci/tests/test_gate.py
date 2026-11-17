import datetime as dt
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from findings import Finding, load_findings  # noqa: E402
from security_gate import check_exceptions, is_blocking, matches, to_sarif  # noqa: E402
import upload_defectdojo  # noqa: E402

POLICY = {"block_severities": ["CRITICAL", "HIGH"], "block_iac_failures": True, "ignore_unfixed": True}


def write_reports(d: Path) -> None:
    (d / "gitleaks.json").write_text(json.dumps([{"RuleID": "aws-access-token", "Description": "AWS key",
                                                   "File": "/src/app/x.py", "StartLine": 3, "Commit": "abc"}]))
    (d / "semgrep.json").write_text(json.dumps({"results": [{"check_id": "python.lang.eval", "path": "app/a.py",
                                                             "start": {"line": 7},
                                                             "extra": {"severity": "WARNING", "message": "eval"}}]}))
    (d / "trivy-image.json").write_text(json.dumps({"Results": [{"Target": "img (debian 13)", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "libc", "InstalledVersion": "1", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2", "PkgName": "zlib", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "CRITICAL"},
    ]}]}))
    (d / "checkov.json").write_text(json.dumps([{"check_type": "kubernetes", "results": {"failed_checks": [
        {"check_id": "CKV_K8S_43", "check_name": "Image should use digest", "file_abs_path": "/src/deploy/k8s/base/deployment.yaml",
         "file_line_range": [1, 40], "severity": None}]}}]))
    (d / "zap.json").write_text(json.dumps({"site": [{"@name": "http://t", "alerts": [
        {"pluginid": "10038", "alert": "CSP not set", "riskcode": "2", "instances": [{"uri": "http://t/"}]}]}]}))
    (d / "nuclei.jsonl").write_text(json.dumps({"template-id": "llm-prompt-injection-guardrail",
                                                "info": {"name": "Guardrail bypass", "severity": "high"},
                                                "matched-at": "http://t/api/v1/ask"}) + "\n")


def test_all_parsers_and_paths(tmp_path):
    write_reports(tmp_path)
    findings, present = load_findings(tmp_path)
    assert len(present) == 6
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["aws-access-token"].location == "app/x.py"
    assert by_rule["python.lang.eval"].severity == "MEDIUM"
    assert by_rule["CKV_K8S_43"].location == "deploy/k8s/base/deployment.yaml"
    assert by_rule["10038"].severity == "MEDIUM"
    assert by_rule["llm-prompt-injection-guardrail"].severity == "HIGH"


def test_blocking_rules(tmp_path):
    write_reports(tmp_path)
    blocking = {f.rule_id for f in load_findings(tmp_path)[0] if is_blocking(f, POLICY)}
    # unfixed HIGH CVE-1 is reported but not blocking; fixed CRITICAL CVE-2 blocks; IaC always blocks
    assert blocking == {"aws-access-token", "CVE-2", "CKV_K8S_43", "llm-prompt-injection-guardrail"}


def test_exceptions_must_be_complete_and_short_lived():
    today = dt.date(2026, 11, 17)
    good = {"match": {"rule_id": "CVE-2"}, "reason": "r", "owner": "o", "expires": "2026-12-01"}
    expired = good | {"expires": "2026-11-01"}
    too_long = good | {"expires": "2027-06-01"}
    incomplete = {"match": {"rule_id": "CVE-3"}}
    valid, errors = check_exceptions([good, expired, too_long, incomplete], 90, today)
    assert valid == [good] and len(errors) == 3
    assert matches(good["match"], Finding("trivy", "image", "CVE-2", "t", "CRITICAL", "img"))


def test_sarif_contains_only_file_findings(tmp_path):
    write_reports(tmp_path)
    sarif = to_sarif(load_findings(tmp_path)[0])
    runs = {run["tool"]["driver"]["name"]: run for run in sarif["runs"]}
    assert set(runs) == {"checkov", "gitleaks", "semgrep", "trivy"}
    assert runs["trivy"]["results"] == []  # image CVEs have no file location
    region = runs["gitleaks"]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] >= 1


def test_sarif_is_never_empty():
    assert len(to_sarif([])["runs"]) == 4


def test_defectdojo_reimport_request(tmp_path):
    report = tmp_path / "semgrep.json"
    report.write_text("{}")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers["authorization"]
        seen["body"] = request.content
        return httpx.Response(201, json={"test_id": 7})

    client = httpx.Client(transport=httpx.MockTransport(handler), headers={"Authorization": "Token k"})
    ctx = {"branch": "main", "commit": "abc", "build": "1"}
    result = upload_defectdojo.upload(client, "https://dd.example", report, "Semgrep JSON Report", ctx, env={})
    assert result["test_id"] == 7
    assert seen["path"] == "/api/v2/reimport-scan/" and seen["auth"] == "Token k"
    assert b"Semgrep JSON Report" in seen["body"] and b"auto_create_context" in seen["body"]
