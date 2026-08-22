"""Kubernetes adapter: multi-doc YAML manifests -> objects with doc start lines.

A YAML file is treated as a manifest only when every non-empty document has
both apiVersion and kind, so unrelated YAML (CI configs, values files) is
left alone. Normalized input:

    {"kind": "kubernetes", "file": "deploy.yaml", "objects": [
        {"apiVersion": "apps/v1", "kind": "Deployment", "manifest": {...},
         "_src": {"file": "deploy.yaml", "line": 1}}
    ]}
"""

from __future__ import annotations

from pathlib import Path

import yaml

from boundary.models import ScanTarget

_HELM_MARKERS = ("{{", "{%")


def discover(root: Path):
    from boundary.adapters import walk_files

    targets = []
    for path in walk_files(root):
        if path.suffix.lower() not in (".yaml", ".yml"):
            continue
        target = parse_file(path)
        if target is not None:
            targets.append(target)
    return targets


def parse_file(path: Path) -> ScanTarget | None:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    if any(marker in text for marker in _HELM_MARKERS):
        return None  # templated manifests need rendering first
    try:
        nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return None
    objects = []
    for node, doc in zip(nodes, docs, strict=False):
        if not isinstance(doc, dict):
            return None
        if "apiVersion" not in doc or "kind" not in doc:
            return None  # not a k8s manifest file
        line = node.start_mark.line + 1 if node is not None else 1
        objects.append({
            "apiVersion": doc.get("apiVersion", ""),
            "kind": doc.get("kind", ""),
            "name": (doc.get("metadata") or {}).get("name", ""),
            "manifest": doc,
            "_src": {"file": str(path), "line": line},
        })
    if not objects:
        return None
    return ScanTarget(kind="kubernetes", path=str(path),
                      input_doc={"kind": "kubernetes", "file": str(path), "objects": objects})
