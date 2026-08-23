"""End-to-end engine tests: fixtures through opa to findings.

Requires the opa binary (BOUNDARY_OPA or on PATH); the whole product does.
"""

import pytest

from boundary import engine
from boundary.adapters import discover_targets

EXPECTED = {
    "terraform": {
        "BND-TF-001", "BND-TF-002", "BND-TF-003", "BND-TF-004", "BND-TF-005",
        "BND-TF-006", "BND-TF-007", "BND-TF-008", "BND-TF-009", "BND-TF-010",
        "BND-TF-011", "BND-TF-012", "BND-TF-013", "BND-TF-014", "BND-TF-015",
        "BND-TF-016", "BND-TF-017", "BND-TF-018", "BND-TF-020", "BND-TF-021",
        "BND-TF-022", "BND-TF-023", "BND-TF-024",
    },
    "docker": {
        "BND-DK-001", "BND-DK-002", "BND-DK-003", "BND-DK-004", "BND-DK-005",
        "BND-DK-006", "BND-DK-007", "BND-DK-008", "BND-DK-009",
    },
    "kubernetes": {
        "BND-K8-001", "BND-K8-002", "BND-K8-003", "BND-K8-004", "BND-K8-005",
        "BND-K8-006", "BND-K8-007", "BND-K8-008", "BND-K8-009", "BND-K8-010",
    },
    "mcp": {
        "BND-MCP-001", "BND-MCP-002", "BND-MCP-003", "BND-MCP-004",
        "BND-MCP-005", "BND-MCP-006",
    },
    "skills": {
        "BND-SK-001", "BND-SK-002", "BND-SK-004", "BND-SK-005", "BND-SK-006",
    },
}


@pytest.mark.parametrize("kind", sorted(EXPECTED))
def test_bad_fixture_triggers_expected_rules(kind, fixtures):
    targets = discover_targets(fixtures / kind / "bad", [kind])
    result = engine.scan(targets, str(fixtures / kind / "bad"))
    assert {f.id for f in result.findings} == EXPECTED[kind]


@pytest.mark.parametrize("kind", sorted(EXPECTED))
def test_good_fixture_is_clean(kind, fixtures):
    targets = discover_targets(fixtures / kind / "good", [kind])
    result = engine.scan(targets, str(fixtures / kind / "good"))
    assert result.findings == []


def test_findings_carry_metadata(fixtures):
    targets = discover_targets(fixtures / "terraform" / "bad", ["terraform"])
    result = engine.scan(targets, str(fixtures / "terraform" / "bad"))
    finding = next(f for f in result.findings if f.id == "BND-TF-002")
    assert finding.severity == "CRITICAL"
    assert finding.fix_hint == "change_value"
    assert finding.compliance["soc2"]
    assert finding.remediation
    assert finding.target["kind"] == "terraform"
    assert finding.target["file"].endswith("main.tf")
    assert finding.target["line"] == 1


def test_policy_metadata_complete():
    entries = engine.load_policy_metadata()
    assert len(entries) >= 55
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids)), "duplicate policy ids"
    for entry in entries:
        assert entry["title"], entry["id"]
        assert entry["description"], entry["id"]
        assert entry["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, entry["id"]
        kinds = {"terraform", "docker", "kubernetes", "mcp", "skills"}
        assert entry["target"] in kinds, entry["id"]
        assert entry["remediation"], entry["id"]
        assert entry["compliance"], entry["id"]
        hints = {"add_block", "change_value", "remove_block", "review"}
        assert entry["fix_hint"] in hints, entry["id"]


def test_worst_severity_gates_exit(fixtures):
    targets = discover_targets(fixtures / "docker" / "bad", ["docker"])
    result = engine.scan(targets, str(fixtures / "docker" / "bad"))
    assert result.worst_severity_rank() == 0  # CRITICAL present
