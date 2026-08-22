"""Boundary CLI: scan / policies / explain / version.

Exit codes from `scan`: 0 = clean (or below --fail-on threshold),
1 = findings at/above threshold, 2 = engine/usage error.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from boundary import __version__, engine
from boundary.adapters import discover_targets
from boundary.models import SEVERITIES, severity_rank
from boundary.reporters import FORMATS

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="AI-first policy-as-code security scanner built on OPA.")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="File or directory to scan."),
    target: str = typer.Option("", "--target", "-t",
                               help="Comma-separated kinds: terraform,docker,kubernetes,mcp,skills."
                                    " Default: all."),
    fmt: str = typer.Option("table", "--format", "-f",
                            help="Output format: json | sarif | md | table."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write output to file."),
    fail_on: str = typer.Option("LOW", "--fail-on",
                                help="Exit 1 if findings at/above this severity exist "
                                     "(CRITICAL|HIGH|MEDIUM|LOW|INFO|NEVER)."),
    policy_dir: list[Path] = typer.Option([], "--policy-dir",
                                          help="Extra policy root(s) merged with built-ins."),
):
    """Scan PATH for security policy violations."""
    if fmt not in FORMATS:
        typer.echo(f"error: unknown format {fmt!r} (choose from {sorted(FORMATS)})", err=True)
        raise typer.Exit(2)
    threshold = fail_on.upper()
    if threshold != "NEVER" and threshold not in SEVERITIES:
        typer.echo(
            f"error: unknown --fail-on value {fail_on!r} "
            f"(choose from {SEVERITIES + ['NEVER']})", err=True)
        raise typer.Exit(2)
    if not path.exists():
        typer.echo(f"error: path not found: {path}", err=True)
        raise typer.Exit(2)
    kinds = [k.strip() for k in target.split(",") if k.strip()] or None
    roots = [engine.DEFAULT_POLICY_ROOT, *policy_dir]
    try:
        targets = discover_targets(path, kinds)
        result = engine.scan(targets, str(path), roots)
    except (engine.EngineError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    rendered = FORMATS[fmt](result)
    if output:
        output.write_text(rendered + "\n")
        typer.echo(f"boundary: wrote {fmt} results to {output}", err=True)
    else:
        typer.echo(rendered)

    if threshold != "NEVER" and result.findings:
        if result.worst_severity_rank() <= severity_rank(threshold):
            raise typer.Exit(1)


@app.command()
def policies(
    target: str = typer.Option("", "--target", "-t", help="Filter by target kind."),
    compliance: str = typer.Option("", "--compliance", "-c",
                                   help="Filter by framework (soc2|dora|nis2|hipaa)."),
    policy_dir: list[Path] = typer.Option([], "--policy-dir",
                                          help="Extra policy root(s) merged with built-ins."),
):
    """List available policies and their metadata."""
    entries = _load_metadata(policy_dir)
    if target:
        entries = [e for e in entries if e["target"] == target]
    if compliance:
        entries = [e for e in entries if compliance.lower() in e["compliance"]]
    if not entries:
        typer.echo("no policies matched")
        raise typer.Exit(0)
    for e in entries:
        frameworks = ", ".join(sorted(e["compliance"])) or "-"
        typer.echo(f"{e['id']:<12} {e['severity']:<8} {e['target']:<11} "
                   f"{e['title']}  [{frameworks}]")
    typer.echo(f"\n{len(entries)} policies")


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Policy id, e.g. BND-TF-001."),
    policy_dir: list[Path] = typer.Option([], "--policy-dir",
                                          help="Extra policy root(s) merged with built-ins."),
):
    """Show one policy's full metadata: description, remediation, compliance mapping."""
    entries = _load_metadata(policy_dir)
    match = next((e for e in entries if e["id"].lower() == rule_id.lower()), None)
    if match is None:
        typer.echo(f"error: no policy with id {rule_id!r}", err=True)
        raise typer.Exit(2)
    typer.echo(f"{match['id']} — {match['title']}")
    typer.echo(f"severity: {match['severity']}   target: {match['target']}   "
               f"package: {match['package']}")
    typer.echo(f"\n{match['description']}")
    if match["remediation"]:
        typer.echo(f"\nremediation:\n{match['remediation'].rstrip()}")
    if match["compliance"]:
        typer.echo("\ncompliance:")
        for framework, controls in sorted(match["compliance"].items()):
            typer.echo(f"  {framework}: {', '.join(controls)}")
    for ref in match["references"]:
        typer.echo(f"ref: {ref}")


@app.command()
def version():
    """Print boundary and opa versions."""
    typer.echo(f"boundary {__version__}")
    try:
        typer.echo(f"opa binary: {engine.find_opa()}")
    except engine.EngineError as exc:
        typer.echo(str(exc), err=True)


def _load_metadata(extra_dirs: list[Path]):
    try:
        return engine.load_policy_metadata([engine.DEFAULT_POLICY_ROOT, *extra_dirs])
    except engine.EngineError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc


def main() -> None:  # console_scripts entry
    sys.exit(app())


if __name__ == "__main__":
    main()
