"""Normalise scanner reports into one finding model.

Every scanner writes its native format into reports/. The gate, SARIF export, DefectDojo
upload and AI triage all work on the same normalised list, so adding a scanner means
adding one parser here.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


@dataclass
class Finding:
    tool: str
    category: str  # secret | sast | sca | image | iac | dast | llm
    rule_id: str
    title: str
    severity: str
    location: str
    line: int | None = None
    fixed_version: str | None = None
    description: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        key = f"{self.tool}|{self.rule_id}|{self.location}|{self.line or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {**asdict(self), "fingerprint": self.fingerprint}


def _sev(value: str | None, default: str = "UNKNOWN") -> str:
    value = (value or "").upper()
    return value if value in SEVERITIES else default


def _repo_path(path: str) -> str:
    """Scanners run in containers (/src/...) or on runners (/home/...): keep the repo-relative part."""
    match = re.search(r"(?:^|/)((?:app|ci|deploy|infra|security|triage)/.*)$", path)
    return match.group(1) if match else path.lstrip("/")


def parse_gitleaks(data) -> Iterator[Finding]:
    for item in data or []:
        yield Finding("gitleaks", "secret", item.get("RuleID", "secret"), item.get("Description", "Secret"),
                      "HIGH", _repo_path(item.get("File", "")), item.get("StartLine"),
                      description=f"commit {item.get('Commit', '')[:12]}")


SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def parse_semgrep(data) -> Iterator[Finding]:
    for r in data.get("results", []):
        extra = r.get("extra", {})
        yield Finding("semgrep", "sast", r["check_id"], extra.get("message", "")[:300],
                      SEMGREP_SEVERITY.get(extra.get("severity", ""), "MEDIUM"),
                      _repo_path(r["path"]), r.get("start", {}).get("line"),
                      extra={"cwe": extra.get("metadata", {}).get("cwe")})


def _trivy(category_for_vulns: str) -> Callable:
    def parse(data) -> Iterator[Finding]:
        for result in data.get("Results", []) or []:
            target = result.get("Target", "")
            for v in result.get("Vulnerabilities", []) or []:
                yield Finding("trivy", category_for_vulns, v["VulnerabilityID"], v.get("Title") or v["VulnerabilityID"],
                              _sev(v.get("Severity")), f"{target}:{v.get('PkgName')}@{v.get('InstalledVersion')}",
                              fixed_version=v.get("FixedVersion") or None)
            for s in result.get("Secrets", []) or []:
                yield Finding("trivy", "secret", s.get("RuleID", "secret"), s.get("Title", "Secret"),
                              _sev(s.get("Severity"), "HIGH"), _repo_path(target), s.get("StartLine"))
            for m in result.get("Misconfigurations", []) or []:
                if m.get("Status") != "FAIL":
                    continue
                yield Finding("trivy", "iac", m.get("AVDID") or m.get("ID"), m.get("Title", ""),
                              _sev(m.get("Severity")), _repo_path(target),
                              (m.get("CauseMetadata") or {}).get("StartLine"),
                              description=m.get("Resolution", ""))
    return parse


def parse_checkov(data) -> Iterator[Finding]:
    for block in data if isinstance(data, list) else [data]:
        for c in block.get("results", {}).get("failed_checks", []):
            lines = c.get("file_line_range") or [None]
            yield Finding("checkov", "iac", c["check_id"], c.get("check_name", ""),
                          _sev(c.get("severity"), "MEDIUM"),
                          _repo_path(c.get("file_abs_path") or c.get("file_path", "")), lines[0],
                          extra={"resource": c.get("resource"), "guideline": c.get("guideline")})


ZAP_RISK = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


def parse_zap(data) -> Iterator[Finding]:
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            instances = a.get("instances") or [{}]
            yield Finding("zap", "dast", str(a.get("pluginid")), a.get("alert", ""),
                          ZAP_RISK.get(str(a.get("riskcode")), "INFO"), instances[0].get("uri", site.get("@name", "")),
                          description=re.sub(r"<[^>]+>", "", a.get("solution", ""))[:500])


def parse_nuclei(lines: Iterable[dict]) -> Iterator[Finding]:
    for r in lines:
        info = r.get("info", {})
        yield Finding("nuclei", "dast", r.get("template-id", ""), info.get("name", ""),
                      _sev(info.get("severity"), "INFO"), r.get("matched-at", ""))


def parse_redteam(data) -> Iterator[Finding]:
    for r in data.get("results", []):
        if r.get("passed"):
            continue
        severity = "LOW" if r.get("known_gap") else "HIGH"
        title = f"LLM guardrail {'known gap' if r.get('known_gap') else 'bypass'}: {r['id']} ({r['category']})"
        yield Finding("llm-redteam", "llm", r["id"], title, severity, data.get("target", ""),
                      description=f"expected {r['expected']}, got HTTP {r.get('status')}")


PARSERS: dict[str, Callable] = {
    "gitleaks.json": parse_gitleaks,
    "semgrep.json": parse_semgrep,
    "trivy-deps.json": _trivy("sca"),
    "trivy-image.json": _trivy("image"),
    "trivy-config.json": _trivy("iac"),
    "checkov.json": parse_checkov,
    "zap.json": parse_zap,
    "nuclei.jsonl": parse_nuclei,
    "llm-redteam.json": parse_redteam,
}


def _json_documents(text: str) -> list:
    """Checkov prints one JSON document per scanned directory; accept concatenated documents."""
    decoder, docs, pos = json.JSONDecoder(), [], 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        doc, pos = decoder.raw_decode(text, pos)
        docs.extend(doc if isinstance(doc, list) else [doc])
    return docs


def load_findings(reports_dir: Path) -> tuple[list[Finding], list[str]]:
    """Returns (findings, names of reports that were present)."""
    findings: list[Finding] = []
    present: list[str] = []
    for name, parser in PARSERS.items():
        path = reports_dir / name
        if not path.is_file():
            continue
        present.append(name)
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            continue
        if name.endswith(".jsonl"):
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        elif name == "checkov.json":
            data = _json_documents(text)
        else:
            data = json.loads(text)
        findings.extend(parser(data))
    # The same issue can be reported twice (e.g. Checkov and Trivy on one manifest line).
    unique = {f.fingerprint: f for f in findings}
    return list(unique.values()), present
