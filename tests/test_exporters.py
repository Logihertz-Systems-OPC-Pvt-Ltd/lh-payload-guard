# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for report exporters (Rich Table, JSON, SARIF)."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from lh_payload_guard.exporters import (
    export_json,
    export_sarif,
    render_table_report,
    severity_to_sarif_level,
    severity_to_style,
)
from lh_payload_guard.models import (
    AuditFinding,
    AuditReport,
    FindingSeverity,
)


def test_severity_mappings() -> None:
    """Verify severity styling and SARIF level mappings."""
    assert severity_to_style(FindingSeverity.CRITICAL) == "bold red"
    assert severity_to_style(FindingSeverity.HIGH) == "red"
    assert severity_to_style(FindingSeverity.MEDIUM) == "yellow"
    assert severity_to_style(FindingSeverity.LOW) == "blue"

    assert severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert severity_to_sarif_level(FindingSeverity.HIGH) == "error"
    assert severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert severity_to_sarif_level(FindingSeverity.LOW) == "note"


def test_render_table_clean_report() -> None:
    """Verify table rendering when no findings exist."""
    report = AuditReport(
        target="clean.json",
        files_scanned=1,
        requests_analyzed=5,
        findings_count=0,
        findings=[],
        summary={},
        risk_score=0,
    )
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=120)
    render_table_report(report, console=con)
    output = buf.getvalue()
    assert "Payloads Clean" in output
    assert "No payload injection vectors" in output


def test_render_table_with_findings() -> None:
    """Verify table rendering with active security findings."""
    finding = AuditFinding(
        rule_id="LH-PAY-001",
        severity=FindingSeverity.CRITICAL,
        category="Injection",
        request_id="req-123",
        location="query: q",
        title="SQL Injection",
        description="UNION SELECT detected",
        remediation="Use prepared statements",
        evidence="Matched: UNION SELECT",
    )
    report = AuditReport(
        target="dump.json",
        files_scanned=1,
        requests_analyzed=1,
        findings_count=1,
        findings=[finding],
        summary={"critical": 1, "high": 0, "medium": 0, "low": 0},
        risk_score=25,
    )
    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=120)
    render_table_report(report, console=con)
    output = buf.getvalue()
    assert "LH-PAY-001" in output
    assert "CRITICAL" in output
    assert "req-123" in output
    assert "Risk Score: 25/100" in output


def test_export_json() -> None:
    """Verify JSON exporter output validity and schema structure."""
    finding = AuditFinding(
        rule_id="LH-PAY-002",
        severity=FindingSeverity.CRITICAL,
        category="Injection",
        request_id="req-456",
        location="body: comment",
        title="XSS Payload",
        description="<script> detected",
        remediation="Sanitize input",
        evidence="<script>alert(1)</script>",
    )
    report = AuditReport(
        target="payloads.json",
        files_scanned=1,
        requests_analyzed=1,
        findings_count=1,
        findings=[finding],
        summary={"critical": 1, "high": 0, "medium": 0, "low": 0},
        risk_score=25,
    )
    json_str = export_json(report)
    parsed = json.loads(json_str)

    assert parsed["schema_version"] == "1.0.0"
    assert parsed["scanner"] == "lh-payload-guard"
    assert parsed["findings_count"] == 1
    assert parsed["risk_score"] == 25
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["rule_id"] == "LH-PAY-002"
    assert parsed["findings"][0]["severity"] == "CRITICAL"


def test_export_sarif() -> None:
    """Verify OASIS SARIF v2.1.0 exporter format and compliance."""
    finding = AuditFinding(
        rule_id="LH-PAY-006",
        severity=FindingSeverity.CRITICAL,
        category="Deserialization",
        request_id="req-789",
        location="header: User-Agent",
        title="JNDI / Log4Shell",
        description="JNDI lookup string",
        remediation="Upgrade log4j",
        evidence="${jndi:ldap://...}",
    )
    report = AuditReport(
        target="waf.json",
        files_scanned=1,
        requests_analyzed=10,
        findings_count=1,
        findings=[finding],
        summary={"critical": 1, "high": 0, "medium": 0, "low": 0},
        risk_score=25,
    )
    sarif_str = export_sarif(report)
    parsed = json.loads(sarif_str)

    assert parsed["version"] == "2.1.0"
    assert len(parsed["runs"]) == 1
    driver = parsed["runs"][0]["tool"]["driver"]
    assert driver["name"] == "lh-payload-guard"
    assert len(driver["rules"]) == 10

    results = parsed["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "LH-PAY-006"
    assert results[0]["level"] == "error"
