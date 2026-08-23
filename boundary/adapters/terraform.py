"""Terraform adapter: plan JSON first, raw HCL fallback.

Plan JSON (`terraform show -json plan.out`) has variables/modules resolved so
it is the accurate path; raw .tf parsing (python-hcl2) works credential-free
for pre-commit style scans. HCL parsing also supplies provider and Terraform
configuration metadata because plans do not include it. Targets normalize to:

    {"kind": "terraform", "resources": [
        {"type": "aws_s3_bucket", "name": "data", "address": "aws_s3_bucket.data",
         "values": {...}, "_src": {"file": "main.tf", "line": 12}}
    ], "providers": [...], "terraform": {"configurations": [...]}}
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import hcl2

from boundary.models import ScanTarget

PLAN_MARKERS = {"resource_changes", "planned_values"}


def discover(root: Path):
    from boundary.adapters import walk_files

    targets = []
    tf_files: list[Path] = []
    for path in walk_files(root):
        if path.suffix == ".json" and _is_plan(path):
            targets.append(_from_plan(path))
        elif path.suffix == ".tf":
            tf_files.append(path)
    if tf_files:
        if targets:
            # Plans omit provider and Terraform configuration metadata. Keep
            # the plan target for resolved resources and add an HCL-only target
            # so configuration policies still run without duplicate resources.
            targets.append(_from_hcl(tf_files, root, include_resources=False))
        else:
            targets.append(_from_hcl(tf_files, root))
    return [t for t in targets if t is not None]


def _is_plan(path: Path) -> bool:
    try:
        with path.open() as fh:
            head = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return False
    return isinstance(head, dict) and bool(PLAN_MARKERS & head.keys())


def _from_plan(path: Path) -> ScanTarget | None:
    with path.open() as fh:
        plan = json.load(fh)
    resources = []
    for change in plan.get("resource_changes", []):
        actions = change.get("change", {}).get("actions", [])
        if actions in (["delete"], ["no-op"]):
            continue
        values = change.get("change", {}).get("after") or {}
        resources.append({
            "type": change.get("type", ""),
            "name": change.get("name", ""),
            "address": change.get("address", ""),
            "mode": change.get("mode", "managed"),
            "values": values,
            "_src": {"file": str(path), "line": 0},
        })
    if not resources:  # fall back to planned_values for `terraform show -json` of state
        for res in _walk_planned(plan.get("planned_values", {}).get("root_module", {})):
            res["_src"] = {"file": str(path), "line": 0}
            resources.append(res)
    if not resources:
        return None
    return ScanTarget(kind="terraform", path=str(path),
                      input_doc={"kind": "terraform", "source": "plan", "resources": resources})


def _walk_planned(module: dict[str, Any]) -> list[dict[str, Any]]:
    resources = [
        {"type": r.get("type", ""), "name": r.get("name", ""), "address": r.get("address", ""),
         "mode": r.get("mode", "managed"), "values": r.get("values") or {}}
        for r in module.get("resources", [])
    ]
    for child in module.get("child_modules", []):
        resources.extend(_walk_planned(child))
    return resources


def _from_hcl(
    tf_files: list[Path], root: Path, *, include_resources: bool = True
) -> ScanTarget | None:
    resources = []
    module_documents: dict[Path, list[tuple[Path, dict[str, Any]]]] = {}
    root_module = root.parent if root.is_file() else root
    root_module = root_module.resolve()
    for path in tf_files:
        try:
            with path.open() as fh:
                doc = _load_hcl(fh)
        except Exception as exc:  # noqa: S112 - reported, then remaining files scanned
            print(f"boundary: warning: skipping unparseable {path}: {exc}", file=sys.stderr)
            continue
        module_documents.setdefault(path.parent.resolve(), []).append((path, doc))
        if not include_resources:
            continue
        lines = _block_lines(path)
        for block in doc.get("resource", []):
            for rtype, instances in block.items():
                if rtype.startswith("__"):
                    continue
                for name, values in instances.items():
                    if name.startswith("__"):
                        continue
                    values = values or {}
                    line = lines.get((rtype, name), 0)
                    clean = _strip_meta(values)
                    resources.append({
                        "type": rtype,
                        "name": name,
                        "address": f"{rtype}.{name}",
                        "mode": "managed",
                        "values": clean,
                        "_src": {"file": str(path), "line": line},
                    })
    providers = []
    terraform_configurations = []
    for module, docs in module_documents.items():
        module_providers, configuration = _configuration(docs, module == root_module)
        providers.extend(module_providers)
        terraform_configurations.append(configuration)
    terraform_config = {"configurations": terraform_configurations}
    has_configuration = providers or terraform_configurations
    if not resources and not has_configuration:
        return None
    return ScanTarget(kind="terraform", path=str(root),
                      input_doc={
                          "kind": "terraform",
                          "source": "hcl",
                          "resources": resources,
                          "providers": providers,
                          "terraform": terraform_config,
                      })


_BLOCK_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"')
_PROVIDER_RE = re.compile(r'^\s*provider\s+"([^"]+)"')
_TERRAFORM_RE = re.compile(r"^\s*terraform\s*\{")
_BACKEND_RE = re.compile(r'^\s*backend\s+"([^"]+)"')


def _block_lines(path: Path) -> dict[tuple[str, str], int]:
    """(type, name) -> 1-based line of the resource block header."""
    lines = {}
    try:
        for lineno, text in enumerate(path.read_text(errors="replace").splitlines(), 1):
            match = _BLOCK_RE.match(text)
            if match:
                lines.setdefault((match.group(1), match.group(2)), lineno)
    except OSError:
        pass
    return lines


def _configuration_lines(
    tf_files: list[Path],
) -> tuple[dict[tuple[str, str], list[tuple[str, int]]], tuple[str, int]]:
    """Locations for provider/backend blocks and the first Terraform configuration."""
    blocks: dict[tuple[str, str], list[tuple[str, int]]] = {}
    default = (str(tf_files[0]), 1)
    for path in tf_files:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for lineno, text in enumerate(lines, 1):
            provider = _PROVIDER_RE.match(text)
            if provider:
                blocks.setdefault(("provider", provider.group(1)), []).append((str(path), lineno))
            backend = _BACKEND_RE.match(text)
            if backend:
                blocks.setdefault(("backend", backend.group(1)), []).append((str(path), lineno))
            if _TERRAFORM_RE.match(text):
                default = (str(path), lineno)
    return blocks, default


def _configuration(
    documents: list[tuple[Path, dict[str, Any]]], is_root: bool
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Normalize one module's merged provider and Terraform configuration."""
    paths = [path for path, _ in documents]
    block_lines, terraform_location = _configuration_lines(paths)
    block_offsets: dict[tuple[str, str], int] = {}

    def block_location(kind: str, name: str) -> tuple[str, int]:
        key = (kind, name)
        locations = block_lines.get(key, [])
        offset = block_offsets.get(key, 0)
        block_offsets[key] = offset + 1
        if offset < len(locations):
            return locations[offset]
        return terraform_location

    providers = []
    version_constraints = []
    backends = []
    config_source = terraform_location
    for _, doc in documents:
        for block in doc.get("provider", []):
            for name, values in block.items():
                if name.startswith("__"):
                    continue
                file, line = block_location("provider", name)
                providers.append({
                    "name": name,
                    "values": _strip_meta(values or {}),
                    "_src": {"file": file, "line": line},
                })
        for block in doc.get("terraform", []):
            if block.get("required_version"):
                version_constraints.append(str(block["required_version"]))
                config_source = terraform_location
            for backend in block.get("backend", []):
                for name, values in backend.items():
                    if name.startswith("__"):
                        continue
                    file, line = block_location("backend", name)
                    backends.append({
                        "name": name,
                        "values": _strip_meta(values or {}),
                        "_src": {"file": file, "line": line},
                    })

    config = {
        "name": "terraform",
        "is_root": is_root,
        "required_version": ", ".join(version_constraints),
        "backends": backends,
        "_src": {"file": config_source[0], "line": config_source[1]},
    }
    return providers, config


def _load_hcl(fh) -> dict[str, Any]:
    try:  # python-hcl2 >= 5: raw tokens by default, options restore clean values
        from hcl2.utils import SerializationOptions

        return hcl2.load(fh, serialization_options=SerializationOptions(
            with_meta=True, strip_string_quotes=True))
    except (ImportError, TypeError):  # python-hcl2 4.x already strips quotes
        fh.seek(0)
        try:
            return hcl2.load(fh, with_meta=True)
        except TypeError:
            fh.seek(0)
            return hcl2.load(fh)


_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}


def _strip_meta(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_meta(v) for k, v in value.items() if not k.startswith("__")}
    if isinstance(value, list):
        return [_strip_meta(v) for v in value]
    if isinstance(value, str) and "\\" in value:
        # python-hcl2 v8 leaves HCL escape sequences intact in string tokens
        return re.sub(r"\\(.)", lambda m: _ESCAPES.get(m.group(1), m.group(0)), value)
    return value
