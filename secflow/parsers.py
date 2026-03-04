import json
from typing import List, Dict, Any
from .models import Finding

def _sev_norm(s: str) -> str:
    if not s:
        return "info"
    s = s.lower()
    mapping = {
        "informational": "info",
        "info": "info",
        "low": "low",
        "medium": "medium",
        "moderate": "medium",
        "high": "high",
        "critical": "critical",
        "error": "high"
    }
    return mapping.get(s, "info")

def parse_semgrep_json(raw: str) -> List[Finding]:
    data = json.loads(raw) if raw.strip() else {}
    findings: List[Finding] = []
    for r in data.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        meta = {
            "engine_kind": data.get("engine_kind"),
            "metadata": extra.get("metadata", {}),
        }
        findings.append(Finding(
            tool="semgrep",
            rule_id=r.get("check_id", "semgrep.unknown"),
            severity=_sev_norm((extra.get("severity") or "info")),
            title=(extra.get("message") or "Semgrep finding"),
            file=(r.get("path")),
            line=(r.get("start", {}) or {}).get("line"),
            message=(extra.get("message") or ""),
            metadata=meta
        ))
    return findings

def parse_gitleaks_json(raw: str) -> List[Finding]:
    data = json.loads(raw) if raw.strip() else []
    findings: List[Finding] = []
    for r in data or []:
        findings.append(Finding(
            tool="gitleaks",
            rule_id=str(r.get("RuleID", "gitleaks.unknown")),
            severity="high",
            title=str(r.get("Description", "Secret detected")),
            file=r.get("File"),
            line=r.get("StartLine"),
            message=f"Secret type: {r.get('RuleID')}",
            metadata={"entropy": r.get("Entropy"), "tags": r.get("Tags")}
        ))
    return findings

def parse_trivy_fs_json(raw: str) -> List[Finding]:
    data = json.loads(raw) if raw.strip() else {}
    findings: List[Finding] = []
    # Trivy report formats differ; handle a common one
    results = data.get("Results") or []
    for res in results:
        vulns = res.get("Vulnerabilities") or []
        for v in vulns:
            findings.append(Finding(
                tool="trivy",
                rule_id=str(v.get("VulnerabilityID", "trivy.unknown")),
                severity=_sev_norm(v.get("Severity", "info")),
                title=str(v.get("Title") or v.get("PkgName") or "Dependency vulnerability"),
                file=res.get("Target"),
                line=None,
                message=str(v.get("Description") or ""),
                metadata={
                    "pkg": v.get("PkgName"),
                    "installed": v.get("InstalledVersion"),
                    "fixed": v.get("FixedVersion"),
                    "references": v.get("References", []),
                }
            ))
    return findings
