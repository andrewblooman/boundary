"""CLI argument validation and exit-code behavior."""

from typer.testing import CliRunner

from boundary.cli import app
from tests.python.conftest import FIXTURES

runner = CliRunner()


def test_invalid_fail_on_exits_2():
    result = runner.invoke(app, ["scan", str(FIXTURES / "terraform" / "good"),
                                 "--fail-on", "HGIH"])
    assert result.exit_code == 2
    assert "unknown --fail-on" in result.output


def test_invalid_format_exits_2():
    result = runner.invoke(app, ["scan", str(FIXTURES / "terraform" / "good"),
                                 "--format", "xml"])
    assert result.exit_code == 2


def test_missing_path_exits_2():
    result = runner.invoke(app, ["scan", "does/not/exist"])
    assert result.exit_code == 2


def test_fail_on_never_exits_0_with_findings():
    result = runner.invoke(app, ["scan", str(FIXTURES / "terraform" / "bad"),
                                 "--fail-on", "NEVER"])
    assert result.exit_code == 0


def test_findings_gate_exit_1():
    result = runner.invoke(app, ["scan", str(FIXTURES / "terraform" / "bad"),
                                 "--fail-on", "HIGH"])
    assert result.exit_code == 1
