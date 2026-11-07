# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Integration tests for lh-payload CLI application."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_payload_guard.cli import app

runner = CliRunner()
ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_version() -> None:
    """Verify version flag output."""
    res = runner.invoke(app, ["--version"], env=ENV)
    assert res.exit_code == 0
    assert "lh-payload-guard v0.1.0" in res.stdout


def test_cli_rules() -> None:
    """Verify listing of detection rules catalog."""
    res = runner.invoke(app, ["rules"], env=ENV)
    assert res.exit_code == 0
    assert "LH-PAY-001" in res.stdout
    assert "LH-PAY-010" in res.stdout
    assert "SQL Injection (SQLi) Payload" in res.stdout


def test_cli_scan_clean(sample_clean_json: Path) -> None:
    """Verify clean payloads scan exits with 0 and shows clean panel."""
    res = runner.invoke(app, ["scan", str(sample_clean_json)], env=ENV)
    assert res.exit_code == 0
    assert "Payloads Clean" in res.stdout


def test_cli_scan_malicious_fails_by_default(sample_malicious_json: Path) -> None:
    """Verify malicious payloads trigger non-zero exit code on default high threshold."""
    res = runner.invoke(app, ["scan", str(sample_malicious_json)], env=ENV)
    assert res.exit_code == 1
    assert "LH-PAY-001" in res.stdout


def test_cli_scan_json_format(sample_clean_json: Path) -> None:
    """Verify scan with JSON output formatting to stdout."""
    res = runner.invoke(app, ["scan", str(sample_clean_json), "--format", "json"], env=ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["scanner"] == "lh-payload-guard"
    assert data["findings_count"] == 0


def test_cli_scan_sarif_format(sample_clean_json: Path) -> None:
    """Verify scan with SARIF output formatting to stdout."""
    res = runner.invoke(app, ["scan", str(sample_clean_json), "--format", "sarif"], env=ENV)
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "lh-payload-guard"


def test_cli_scan_file_output(sample_clean_json: Path, tmp_path: Path) -> None:
    """Verify writing report to external file."""
    out_file = tmp_path / "report.txt"
    res = runner.invoke(
        app,
        ["scan", str(sample_clean_json), "--output", str(out_file)],
        env=ENV,
    )
    assert res.exit_code == 0
    assert out_file.exists()
    assert "Payloads Clean" in out_file.read_text(encoding="utf-8")


def test_cli_scan_json_file_output(sample_clean_json: Path, tmp_path: Path) -> None:
    """Verify writing JSON report to external file."""
    out_json = tmp_path / "report.json"
    res = runner.invoke(
        app,
        ["scan", str(sample_clean_json), "--format", "json", "--output", str(out_json)],
        env=ENV,
    )
    assert res.exit_code == 0
    assert out_json.exists()
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["findings_count"] == 0


def test_cli_scan_sarif_file_output(sample_clean_json: Path, tmp_path: Path) -> None:
    """Verify writing SARIF report to external file."""
    out_sarif = tmp_path / "report.sarif"
    res = runner.invoke(
        app,
        ["scan", str(sample_clean_json), "--format", "sarif", "--output", str(out_sarif)],
        env=ENV,
    )
    assert res.exit_code == 0
    assert out_sarif.exists()
    data = json.loads(out_sarif.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


def test_cli_scan_min_severity_filter(sample_malicious_json: Path) -> None:
    """Verify min-severity filtering."""
    res = runner.invoke(
        app,
        ["scan", str(sample_malicious_json), "--min-severity", "critical", "--format", "json"],
        env=ENV,
    )
    data = json.loads(res.stdout)
    for finding in data["findings"]:
        assert finding["severity"] == "CRITICAL"
