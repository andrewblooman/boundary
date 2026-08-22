"""Core data models shared by adapters, engine, and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def severity_rank(severity: str) -> int:
    """Lower rank = more severe. Unknown severities sort last."""
    try:
        return SEVERITIES.index(severity.upper())
    except ValueError:
        return len(SEVERITIES)


@dataclass
class ScanTarget:
    """One normalized unit of input handed to the policy engine."""

    kind: str  # terraform | docker | kubernetes | mcp | skills
    path: str  # file or directory the input was built from
    input_doc: dict[str, Any]  # normalized JSON document for `opa eval`


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str
    target: dict[str, Any]
    observed: Any = None
    remediation: str = ""
    fix_hint: str = "review"
    compliance: dict[str, list[str]] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_rego(cls, raw: dict[str, Any], kind: str, fallback_file: str) -> Finding:
        target = dict(raw.get("target") or {})
        target.setdefault("kind", kind)
        target.setdefault("file", fallback_file)
        return cls(
            id=raw.get("id", "BND-UNKNOWN"),
            severity=str(raw.get("severity", "MEDIUM")).upper(),
            title=raw.get("title", ""),
            description=raw.get("description", ""),
            target=target,
            observed=raw.get("observed"),
            remediation=raw.get("remediation", ""),
            fix_hint=raw.get("fix_hint", "review"),
            compliance=raw.get("compliance") or {},
            references=raw.get("references") or [],
        )


@dataclass
class ScanResult:
    targets: list[ScanTarget]
    findings: list[Finding]
    policy_packs: dict[str, int]  # kind -> number of policies evaluated
    scanned_path: str
    started_at: str
    duration_seconds: float

    @property
    def by_severity(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def violated_controls(self) -> dict[str, list[str]]:
        """Framework -> sorted list of controls violated across all findings."""
        controls: dict[str, set[str]] = {}
        for f in self.findings:
            for framework, refs in f.compliance.items():
                controls.setdefault(framework, set()).update(refs)
        return {fw: sorted(refs) for fw, refs in sorted(controls.items())}

    def worst_severity_rank(self) -> int:
        if not self.findings:
            return len(SEVERITIES)
        return min(severity_rank(f.severity) for f in self.findings)
