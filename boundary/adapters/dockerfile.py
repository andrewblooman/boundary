"""Dockerfile adapter: parses instructions with line numbers, no dependencies.

Normalized input:

    {"kind": "docker", "file": "Dockerfile", "instructions": [
        {"cmd": "FROM", "value": "python:3.14-slim", "line": 1},
        {"cmd": "RUN", "value": "pip install .", "line": 3}
    ], "stages": ["build", ...]}
"""

from __future__ import annotations

import re
from pathlib import Path

from boundary.models import ScanTarget

_NAME_RE = re.compile(r"^(Dockerfile|Containerfile)([._-].+)?$", re.IGNORECASE)
_AS_RE = re.compile(r"\s+AS\s+(\S+)\s*$", re.IGNORECASE)


def discover(root: Path):
    from boundary.adapters import walk_files

    targets = []
    for path in walk_files(root):
        if _NAME_RE.match(path.name) or path.suffix.lower() == ".dockerfile":
            target = parse_file(path)
            if target is not None:
                targets.append(target)
    return targets


def parse_file(path: Path) -> ScanTarget | None:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    instructions = []
    stages = []
    pending: list[str] = []
    pending_line = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if not pending:
            pending_line = lineno
        if stripped.endswith("\\"):
            pending.append(stripped[:-1].strip())
            continue
        pending.append(stripped)
        full = " ".join(p for p in pending if p)
        pending = []
        match = re.match(r"^([A-Za-z]+)\s+(.*)$", full) or re.match(r"^([A-Za-z]+)$", full)
        if not match:
            continue
        cmd = match.group(1).upper()
        value = match.group(2).strip() if match.lastindex and match.lastindex >= 2 else ""
        instructions.append({"cmd": cmd, "value": value, "line": pending_line})
        if cmd == "FROM":
            alias = _AS_RE.search(value)
            if alias:
                stages.append(alias.group(1))
    if not instructions:
        return None
    return ScanTarget(
        kind="docker",
        path=str(path),
        input_doc={"kind": "docker", "file": str(path),
                   "instructions": instructions, "stages": stages},
    )
