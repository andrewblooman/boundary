"""SARIF 2.1.0 output for GitHub Code Scanning and other SARIF consumers."""

from __future__ import annotations

import json
from pathlib import Path

from boundary import __version__
from boundary.engine import load_policy_metadata
from boundary.models import ScanResult

_LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
           "LOW": "note", "INFO": "note"}
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0",
                      "LOW": "3.0", "INFO": "1.0"}


def to_sarif(result: ScanResult) -> str:
    try:
        catalog = {m["id"]: m for m in load_policy_metadata()}
    except Exception:
        catalog = {}
    rule_ids = sorted({f.id for f in result.findings})
    rules = [_rule(rule_id, catalog.get(rule_id), result) for rule_id in rule_ids]
    index = {rule_id: i for i, rule_id in enumerate(rule_ids)}

    results = []
    for f in result.findings:
        message = f.title or f.description or f.id  # SARIF requires non-empty message text
        if f.remediation:
            message = f"{message}\n\nRemediation: {f.remediation.strip()}"
        results.append({
            "ruleId": f.id,
            "ruleIndex": index[f.id],
            "level": _LEVELS.get(f.severity, "warning"),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _rel_uri(f.target.get("file", ""),
                                                         result.scanned_path)},
                    "region": {"startLine": max(int(f.target.get("line") or 1), 1)},
                }
            }],
        })

    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
                   "Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "boundary",
                "informationUri": "https://github.com/andrewblooman/boundary",
                "version": __version__,
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)


def _rule(rule_id: str, meta: dict | None, result: ScanResult) -> dict:
    if meta is None:
        found = next(f for f in result.findings if f.id == rule_id)
        meta = {"title": found.title, "description": found.description,
                "severity": found.severity, "remediation": found.remediation,
                "compliance": found.compliance, "references": found.references}
    tags = ["security"] + [
        f"compliance/{fw}/{control}"
        for fw, controls in sorted((meta.get("compliance") or {}).items())
        for control in controls
    ]
    rule = {
        "id": rule_id,
        "name": rule_id.replace("-", ""),
        "shortDescription": {"text": meta.get("title", rule_id)},
        "fullDescription": {"text": meta.get("description", "")},
        "help": {"text": meta.get("remediation", "")},
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(meta.get("severity", "MEDIUM"), "5.0"),
            "tags": tags,
        },
    }
    references = meta.get("references") or []
    if references:
        rule["helpUri"] = references[0]
    return rule


def _rel_uri(file: str, scanned_path: str) -> str:
    if not file:
        return "unknown"
    try:
        base = Path(scanned_path).resolve()
        if base.is_file():
            base = base.parent
        return Path(file).resolve().relative_to(base).as_posix()
    except ValueError:
        return Path(file).as_posix().lstrip("/")
