"""Canonical Boundary result envelope: the AI-first output format.

The envelope self-describes how an LLM should consume it (ai_context), and
every finding carries its own remediation, fix hint, and compliance mapping
pulled from the policy's # METADATA block — no repo access needed to act on it.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from boundary import __version__
from boundary.models import ScanResult

SCHEMA_URL = (
    "https://raw.githubusercontent.com/andrewblooman/boundary/main/"
    "schemas/boundary-result.schema.json"
)

AI_CONTEXT = {
    "purpose": (
        "This document is a security scan result from Boundary, a policy-as-code "
        "engine built on Open Policy Agent. It is designed to be analysed by an AI "
        "assistant. Each finding is self-contained: severity, the exact file/resource, "
        "what was observed, why it matters (description), how to fix it (remediation), "
        "and which compliance controls it violates (SOC 2, DORA, NIS2, HIPAA)."
    ),
    "suggested_workflow": [
        "Group findings by severity; lead with CRITICAL and HIGH.",
        "For each finding, explain the risk in plain language for a non-security reader.",
        "Use fix_hint to decide the shape of the fix: add_block (insert missing "
        "configuration), change_value (correct an attribute), remove_block (delete "
        "dangerous configuration), review (needs human judgment).",
        "Open target.file at target.line and propose a concrete diff implementing "
        "the remediation text.",
        "After applying fixes, re-run `boundary scan` and confirm the finding ids "
        "no longer appear.",
        "Summarise residual compliance exposure using summary.compliance.",
    ],
    "severity_order": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
}


def build_envelope(result: ScanResult) -> dict:
    return {
        "boundary_version": __version__,
        "schema": SCHEMA_URL,
        "scan": {
            "timestamp": result.started_at,
            "duration_seconds": result.duration_seconds,
            "path": result.scanned_path,
            "targets_scanned": [
                {"kind": t.kind, "path": t.path} for t in result.targets
            ],
            "policy_packs": result.policy_packs,
        },
        "summary": {
            "total": len(result.findings),
            "by_severity": result.by_severity,
            "compliance": {
                fw: {"violated_controls": controls}
                for fw, controls in result.violated_controls().items()
            },
        },
        "findings": [asdict(f) for f in result.findings],
        "ai_context": AI_CONTEXT,
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(build_envelope(result), indent=2)
