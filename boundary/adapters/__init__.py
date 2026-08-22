"""Adapters turn raw target files into normalized JSON inputs for OPA.

Each adapter module exposes `discover(root: Path) -> list[ScanTarget]`.
"""

from __future__ import annotations

from pathlib import Path

from boundary.adapters import dockerfile, kubernetes, mcp, skills, terraform
from boundary.models import ScanTarget

ADAPTERS = {
    "terraform": terraform,
    "docker": dockerfile,
    "kubernetes": kubernetes,
    "mcp": mcp,
    "skills": skills,
}

# Directories that never contain user IaC worth scanning.
SKIP_DIRS = {".git", ".terraform", "node_modules", ".venv", "venv", "__pycache__"}


def discover_targets(root: Path, kinds: list[str] | None = None) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    for kind in kinds or list(ADAPTERS):
        adapter = ADAPTERS.get(kind)
        if adapter is None:
            raise ValueError(f"unknown target kind: {kind!r} (choose from {sorted(ADAPTERS)})")
        targets.extend(adapter.discover(root))
    return targets


def walk_files(root: Path) -> list[Path]:
    """All files under root, skipping vendored/VCS directories. Accepts a file too."""
    if root.is_file():
        return [root]
    found = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not (SKIP_DIRS & set(p.name for p in path.parents)):
            found.append(path)
    return found
