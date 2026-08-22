"""Reporter tests: envelope validates against the schema, SARIF is well-formed."""

import json

import pytest
from jsonschema import validate

from boundary import engine
from boundary.adapters import discover_targets
from boundary.reporters import to_json, to_markdown, to_sarif, to_table


@pytest.fixture(scope="module")
def result():
    from tests.python.conftest import FIXTURES

    targets = discover_targets(FIXTURES / "terraform" / "bad", ["terraform"])
    return engine.scan(targets, str(FIXTURES / "terraform" / "bad"))


def test_json_envelope_matches_schema(result, repo):
    schema = json.loads((repo / "schemas" / "boundary-result.schema.json").read_text())
    envelope = json.loads(to_json(result))
    validate(envelope, schema)
    assert envelope["summary"]["total"] == len(result.findings)
    assert envelope["ai_context"]["suggested_workflow"]
    assert "CC6.1" in envelope["summary"]["compliance"]["soc2"]["violated_controls"]


def test_sarif_structure(result):
    sarif = json.loads(to_sarif(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} == rules
    sample = run["results"][0]
    assert sample["level"] in {"error", "warning", "note"}
    location = sample["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "main.tf"
    assert location["region"]["startLine"] >= 1
    rule = run["tool"]["driver"]["rules"][0]
    assert "security-severity" in rule["properties"]
    assert any(t.startswith("compliance/") for t in rule["properties"]["tags"])


def test_markdown_summary(result):
    md = to_markdown(result)
    assert "# Boundary scan results" in md
    assert "BND-TF-002" in md
    assert "Compliance controls affected" in md


def test_markdown_clean_scan(result):
    from boundary.models import ScanResult

    clean = ScanResult(
        targets=[], findings=[], policy_packs={"terraform": 10},
        scanned_path="x", started_at="now", duration_seconds=0.1,
    )
    assert "No policy violations" in to_markdown(clean)
    assert "no policy violations" in to_table(clean)


def test_table_output(result):
    table = to_table(result)
    assert "CRITICAL" in table
    assert "finding(s)" in table
