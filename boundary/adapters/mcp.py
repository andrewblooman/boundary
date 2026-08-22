"""MCP adapter: server definitions from MCP config files.

Recognizes any .json file whose content contains an mcpServers/servers
mapping -- by content, not filename, the same approach the kubernetes
adapter uses for YAML. Filename-only detection missed real-world configs
like Claude Code's own ~/.claude.json, which carries an mcpServers key but
whose name matches neither ".mcp.json" nor "claude_desktop_config.json".
Normalized input:

    {"kind": "mcp", "file": ".mcp.json", "servers": [
        {"name": "github", "command": "npx", "args": [...], "env": {...},
         "url": "", "headers": {}, "transport": "stdio", "_src": {...}}
    ]}
"""

from __future__ import annotations

import json
from pathlib import Path

from boundary.models import ScanTarget

_SERVER_KEYS = ("mcpServers", "mcp_servers", "servers")


def discover(root: Path):
    from boundary.adapters import walk_files

    targets = []
    for path in walk_files(root):
        if path.suffix != ".json":
            continue
        target = parse_file(path)
        if target is not None:
            targets.append(target)
    return targets


def parse_file(path: Path) -> ScanTarget | None:
    try:
        doc = json.loads(path.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(doc, dict):
        return None
    server_map = None
    for key in _SERVER_KEYS:
        if isinstance(doc.get(key), dict):
            server_map = doc[key]
            break
    if server_map is None:
        return None
    servers = []
    for name, spec in server_map.items():
        if not isinstance(spec, dict):
            continue
        url = spec.get("url", "") or spec.get("serverUrl", "")
        transport = spec.get("type", "") or spec.get("transport", "") or (
            "http" if url else "stdio")
        servers.append({
            "name": name,
            "command": spec.get("command", ""),
            "args": [str(a) for a in spec.get("args", []) or []],
            "env": {k: str(v) for k, v in (spec.get("env") or {}).items()},
            "url": url,
            "headers": {k: str(v) for k, v in (spec.get("headers") or {}).items()},
            "transport": transport,
            "_src": {"file": str(path), "line": 0},
        })
    if not servers:
        return None
    return ScanTarget(kind="mcp", path=str(path),
                      input_doc={"kind": "mcp", "file": str(path), "servers": servers})
