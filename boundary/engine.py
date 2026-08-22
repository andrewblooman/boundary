"""Runs the OPA binary against normalized inputs and collects findings.

The engine is deliberately thin: adapters normalize files into JSON, Rego
policies own all assessment logic and carry their own metadata (# METADATA
annotations), and this module just orchestrates `opa eval` / `opa inspect`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from boundary.models import Finding, ScanResult, ScanTarget


def _default_policy_root() -> Path:
    """Built-in policies: $BOUNDARY_POLICY_ROOT wins, else the repo checkout layout."""
    env_root = os.environ.get("BOUNDARY_POLICY_ROOT")
    if env_root:
        return Path(env_root)
    return Path(__file__).resolve().parent.parent / "policies"


DEFAULT_POLICY_ROOT = _default_policy_root()


class EngineError(RuntimeError):
    """Raised when OPA is missing or a policy evaluation fails."""


def find_opa() -> str:
    """Locate the opa binary: $BOUNDARY_OPA wins, then PATH, then ~/.local/bin.

    The candidate is normalized with shutil.which so only an existing,
    executable regular file is accepted, and the resolved absolute path (never
    the raw environment value) is what gets executed — always argv-style, no
    shell.
    """
    candidates = [os.environ.get("BOUNDARY_OPA"), "opa",
                  str(Path.home() / ".local" / "bin" / "opa")]
    for candidate in candidates:
        resolved = shutil.which(candidate) if candidate else None
        if resolved and Path(resolved).is_file():
            return str(Path(resolved).resolve())
    raise EngineError(
        "opa binary not found. Install it (https://www.openpolicyagent.org/docs/#running-opa) "
        "or point BOUNDARY_OPA at the binary."
    )


def _run_opa(args: list[str], stdin: str | None = None) -> str:
    opa = find_opa()
    proc = subprocess.run(
        [opa, *args], input=stdin, capture_output=True, text=True, timeout=120
    )
    if proc.returncode != 0:
        raise EngineError(f"opa {args[0]} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout


def policy_dirs_for_kind(kind: str, policy_roots: list[Path]) -> list[Path]:
    """The pack for `kind` plus the shared lib, from every policy root that has them."""
    dirs = []
    for root in policy_roots:
        for sub in (kind, "lib"):
            d = root / sub
            if d.is_dir():
                dirs.append(d)
    return dirs


def load_policy_metadata(policy_roots: list[Path] | None = None) -> list[dict[str, Any]]:
    """All policy annotations via `opa inspect -a`, one entry per annotated package."""
    roots = policy_roots or [DEFAULT_POLICY_ROOT]
    entries: list[dict[str, Any]] = []
    for root in roots:
        if not root.is_dir():
            continue
        out = _run_opa(["inspect", "-a", "--format", "json", str(root)])
        for ann in json.loads(out).get("annotations", []):
            annotations = ann.get("annotations", {})
            custom = annotations.get("custom") or {}
            if not custom.get("id"):
                continue  # lib helpers and unannotated modules
            entries.append({
                "id": custom["id"],
                "title": annotations.get("title", ""),
                "description": annotations.get("description", ""),
                "severity": str(custom.get("severity", "MEDIUM")).upper(),
                "target": custom.get("target", ""),
                "compliance": custom.get("compliance") or {},
                "remediation": custom.get("remediation", ""),
                "fix_hint": custom.get("fix_hint", "review"),
                "references": custom.get("references") or [],
                "package": _package_path(ann.get("path")),
                "file": ann.get("location", {}).get("file", ""),
            })
    return sorted(entries, key=lambda e: e["id"])


def _package_path(path: Any) -> str:
    """opa inspect encodes the package path as term objects; flatten to dotted form."""
    if isinstance(path, str):
        return path.removeprefix("data.")
    if isinstance(path, list):
        parts = [str(p.get("value", "")) for p in path if isinstance(p, dict)]
        return ".".join(p for p in parts if p and p != "data")
    return ""


def _collect_deny(node: Any, out: list[dict[str, Any]]) -> None:
    """Walk the evaluated data.boundary.<kind> tree collecting every deny set."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "deny" and isinstance(value, list):
                out.extend(v for v in value if isinstance(v, dict))
            else:
                _collect_deny(value, out)


def evaluate_target(target: ScanTarget, policy_roots: list[Path]) -> list[Finding]:
    dirs = policy_dirs_for_kind(target.kind, policy_roots)
    if not dirs:
        return []
    args = ["eval", "--format", "json", "--stdin-input"]
    for d in dirs:
        args += ["--data", str(d)]
    args.append(f"data.boundary.{target.kind}")
    out = _run_opa(args, stdin=json.dumps(target.input_doc))
    result = json.loads(out)
    try:
        tree = result["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError):
        return []
    raw_findings: list[dict[str, Any]] = []
    _collect_deny(tree, raw_findings)
    return [Finding.from_rego(raw, target.kind, target.path) for raw in raw_findings]


def scan(targets: list[ScanTarget], scanned_path: str,
         policy_roots: list[Path] | None = None) -> ScanResult:
    roots = policy_roots or [DEFAULT_POLICY_ROOT]
    started = time.monotonic()
    started_at = datetime.now(UTC).isoformat(timespec="seconds")

    findings: list[Finding] = []
    for target in targets:
        findings.extend(evaluate_target(target, roots))

    packs: dict[str, int] = {}
    for meta in load_policy_metadata(roots):
        packs[meta["target"]] = packs.get(meta["target"], 0) + 1

    findings.sort(key=lambda f: (f.target.get("file", ""), f.target.get("line", 0) or 0, f.id))
    return ScanResult(
        targets=targets,
        findings=findings,
        policy_packs=packs,
        scanned_path=scanned_path,
        started_at=started_at,
        duration_seconds=round(time.monotonic() - started, 2),
    )
