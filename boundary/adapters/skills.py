"""Agent-skill adapter: SKILL.md frontmatter, body, and bundled scripts.

Each directory containing a SKILL.md becomes one scan target. Bundled
scripts travel with their content (capped) so Rego policies can inspect the
skill's real execution surface, not just its self-description. Normalized:

    {"kind": "skills", "dir": "skills/deploy", "frontmatter": {...},
     "body": "...", "scripts": [{"path": "run.sh", "ext": ".sh",
     "content": "...", "_src": {...}}]}
"""

from __future__ import annotations

from pathlib import Path

import yaml

from boundary.models import ScanTarget

SCRIPT_EXTS = {".sh", ".bash", ".py", ".js", ".mjs", ".ts", ".rb", ".ps1"}
MAX_SCRIPT_BYTES = 65536


def discover(root: Path):
    from boundary.adapters import walk_files

    targets = []
    for path in walk_files(root):
        if path.name == "SKILL.md":
            target = parse_skill(path)
            if target is not None:
                targets.append(target)
    return targets


def parse_skill(skill_md: Path) -> ScanTarget | None:
    try:
        text = skill_md.read_text(errors="replace")
    except OSError:
        return None
    frontmatter, body = _split_frontmatter(text)
    scripts = []
    for path in sorted(skill_md.parent.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SCRIPT_EXTS:
            continue
        try:
            content = path.read_text(errors="replace")[:MAX_SCRIPT_BYTES]
        except OSError:
            continue
        scripts.append({
            "path": str(path.relative_to(skill_md.parent)),
            "ext": path.suffix.lower(),
            "content": content,
            "_src": {"file": str(path), "line": 0},
        })
    return ScanTarget(
        kind="skills",
        path=str(skill_md.parent),
        input_doc={
            "kind": "skills",
            "dir": str(skill_md.parent),
            "file": str(skill_md),
            "frontmatter": frontmatter,
            "body": body,
            "scripts": scripts,
        },
    )


def _split_frontmatter(text: str) -> tuple[dict, str]:
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            try:
                fm = yaml.safe_load(parts[1]) or {}
                if isinstance(fm, dict):
                    return fm, parts[2].strip()
            except yaml.YAMLError:
                pass
    return {}, text.strip()
