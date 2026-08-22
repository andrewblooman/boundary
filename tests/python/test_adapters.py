"""Adapter tests: each fixture parses into the normalized shape policies expect."""

import json

from boundary.adapters import discover_targets, dockerfile, kubernetes, mcp, skills, terraform


def test_terraform_hcl_parses_resources(fixtures):
    targets = terraform.discover(fixtures / "terraform" / "bad")
    assert len(targets) == 1
    doc = targets[0].input_doc
    assert doc["source"] == "hcl"
    types = {r["type"] for r in doc["resources"]}
    assert "aws_s3_bucket" in types and "aws_iam_policy" in types
    bucket = next(r for r in doc["resources"] if r["type"] == "aws_s3_bucket")
    assert bucket["address"] == "aws_s3_bucket.data"
    assert bucket["values"]["acl"] == "public-read"
    assert bucket["_src"]["line"] == 1


def test_terraform_hcl_unescapes_strings(fixtures):
    targets = terraform.discover(fixtures / "terraform" / "bad")
    policy = next(r for r in targets[0].input_doc["resources"] if r["type"] == "aws_iam_policy")
    doc = json.loads(policy["values"]["policy"])
    assert doc["Statement"][0]["Action"] == "*"


def test_terraform_plan_json(tmp_path):
    plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.data",
                "type": "aws_s3_bucket",
                "name": "data",
                "change": {"actions": ["create"], "after": {"bucket": "corp-data"}},
            },
            {
                "address": "aws_s3_bucket.gone",
                "type": "aws_s3_bucket",
                "name": "gone",
                "change": {"actions": ["delete"], "after": None},
            },
        ]
    }
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(plan))
    targets = terraform.discover(tmp_path)
    assert len(targets) == 1
    doc = targets[0].input_doc
    assert doc["source"] == "plan"
    assert [r["address"] for r in doc["resources"]] == ["aws_s3_bucket.data"]


def test_terraform_plan_suppresses_hcl_double_scan(tmp_path):
    plan = {"resource_changes": [{
        "address": "aws_s3_bucket.data", "type": "aws_s3_bucket", "name": "data",
        "change": {"actions": ["create"], "after": {"bucket": "corp-data"}},
    }]}
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n  bucket = "corp-data"\n}\n')
    targets = terraform.discover(tmp_path)
    assert [t.input_doc["source"] for t in targets] == ["plan"]


def test_dockerfile_instructions_and_lines(fixtures):
    targets = dockerfile.discover(fixtures / "docker" / "bad")
    assert len(targets) == 1
    instructions = targets[0].input_doc["instructions"]
    assert instructions[0] == {"cmd": "FROM", "value": "node:latest", "line": 1}
    assert any(i["cmd"] == "EXPOSE" and i["value"] == "22" for i in instructions)


def test_dockerfile_continuations(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.21\nRUN apk add --no-cache \\\n    curl\n")
    targets = dockerfile.discover(tmp_path)
    run = targets[0].input_doc["instructions"][1]
    assert run["cmd"] == "RUN"
    assert "curl" in run["value"]
    assert run["line"] == 2


def test_dockerfile_multistage_stages(fixtures):
    targets = dockerfile.discover(fixtures / "docker" / "good")
    assert targets[0].input_doc["stages"] == ["build"]


def test_kubernetes_objects_with_lines(fixtures):
    targets = kubernetes.discover(fixtures / "kubernetes" / "bad")
    assert len(targets) == 1
    obj = targets[0].input_doc["objects"][0]
    assert obj["kind"] == "Deployment"
    assert obj["name"] == "legacy-app"
    assert obj["_src"]["line"] == 1


def test_kubernetes_ignores_non_manifest_yaml(tmp_path):
    (tmp_path / "ci.yml").write_text("stages:\n  - build\n")
    assert kubernetes.discover(tmp_path) == []


def test_kubernetes_ignores_helm_templates(tmp_path):
    (tmp_path / "t.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Release.Name }}\n")
    assert kubernetes.discover(tmp_path) == []


def test_mcp_servers_parsed(fixtures):
    targets = mcp.discover(fixtures / "mcp" / "bad")
    assert len(targets) == 1
    servers = {s["name"]: s for s in targets[0].input_doc["servers"]}
    assert servers["github"]["env"]["GITHUB_TOKEN"].startswith("FAKE-TOKEN")
    assert servers["tracker"]["url"].startswith("http://")
    assert servers["tracker"]["transport"] == "http"


def test_mcp_ignores_unrelated_json(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x"}')
    (tmp_path / "app.mcp.json").write_text('{"notServers": {}}')
    assert mcp.discover(tmp_path) == []


def test_mcp_detects_by_content_not_filename(tmp_path):
    # Claude Code's own config (~/.claude.json) carries mcpServers but its
    # name matches no filename heuristic -- detection must be content-based.
    (tmp_path / ".claude.json").write_text(json.dumps({
        "mcpServers": {"snyk": {"command": "snyk-mcp", "args": []}},
        "unrelatedState": {"lots": "of other stuff"},
    }))
    targets = mcp.discover(tmp_path)
    assert len(targets) == 1
    assert targets[0].input_doc["servers"][0]["name"] == "snyk"


def test_skills_frontmatter_body_scripts(fixtures):
    targets = skills.discover(fixtures / "skills" / "bad")
    assert len(targets) == 1
    doc = targets[0].input_doc
    assert doc["frontmatter"]["name"] == "helpful-formatter"
    assert "Ignore previous instructions" in doc["body"]
    assert [s["path"] for s in doc["scripts"]] == ["setup.sh"]
    assert "curl" in doc["scripts"][0]["content"]


def test_discover_targets_all_kinds(fixtures):
    targets = discover_targets(fixtures)
    kinds = {t.kind for t in targets}
    assert kinds == {"terraform", "docker", "kubernetes", "mcp", "skills"}
