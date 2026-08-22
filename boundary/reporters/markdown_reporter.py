"""Human-facing outputs: Markdown summary (CI job summaries) and terminal table."""

from __future__ import annotations

from boundary.models import SEVERITIES, ScanResult, severity_rank

_ICONS = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}


def _sorted_findings(result: ScanResult):
    return sorted(result.findings, key=lambda f: (severity_rank(f.severity), f.id))


def to_markdown(result: ScanResult) -> str:
    lines = ["# Boundary scan results", ""]
    counts = result.by_severity
    summary = " · ".join(
        f"{_ICONS[s]} {s.title()}: **{counts[s]}**" for s in SEVERITIES if counts.get(s)
    )
    lines.append(f"**{len(result.findings)} finding(s)** in `{result.scanned_path}`"
                 + (f" — {summary}" if summary else ""))
    lines.append("")
    if not result.findings:
        lines.append("✅ No policy violations found.")
        return "\n".join(lines)

    lines += ["| Severity | Rule | Finding | Location |", "|---|---|---|---|"]
    for f in _sorted_findings(result):
        location = f.target.get("file", "")
        if f.target.get("line"):
            location += f":{f.target['line']}"
        resource = f.target.get("resource", "")
        if resource:
            location += f"<br>`{resource}`"
        lines.append(
            f"| {_ICONS.get(f.severity, '')} {f.severity} | `{f.id}` "
            f"| {f.title} | {location} |"
        )

    controls = result.violated_controls()
    if controls:
        lines += ["", "## Compliance controls affected", ""]
        for framework, refs in controls.items():
            lines.append(f"- **{framework.upper()}**: {', '.join(refs)}")
    lines += ["", "_Run `boundary explain <RULE-ID>` for remediation details._"]
    return "\n".join(lines)


def to_table(result: ScanResult) -> str:
    if not result.findings:
        return (f"boundary: no policy violations in {result.scanned_path} "
                f"({sum(result.policy_packs.values())} policies, "
                f"{result.duration_seconds}s)")
    lines = []
    for f in _sorted_findings(result):
        location = f.target.get("file", "")
        if f.target.get("line"):
            location += f":{f.target['line']}"
        resource = f.target.get("resource", "")
        lines.append(f"{f.severity:<8} {f.id:<12} {f.title}")
        lines.append(f"         {location}" + (f"  ({resource})" if resource else ""))
    counts = result.by_severity
    tally = ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITIES if counts.get(s))
    lines.append(f"\n{len(result.findings)} finding(s): {tally}")
    return "\n".join(lines)
