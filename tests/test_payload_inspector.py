# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        tests.test_payload_inspector
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for payload security inspection engine and attack detection rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lh_payload_guard.models import (
    CapturedRequest,
    FindingSeverity,
)
from lh_payload_guard.payload_inspector import (
    PayloadInspector,
    audit_payload_target,
    calculate_risk_score,
)


def test_severity_thresholds() -> None:
    """Verify FindingSeverity hierarchy and comparison methods."""
    assert FindingSeverity.CRITICAL.level == 4
    assert FindingSeverity.HIGH.level == 3
    assert FindingSeverity.MEDIUM.level == 2
    assert FindingSeverity.LOW.level == 1

    assert FindingSeverity.CRITICAL.meets_threshold(FindingSeverity.HIGH)
    assert FindingSeverity.HIGH.meets_threshold(FindingSeverity.HIGH)
    assert not FindingSeverity.MEDIUM.meets_threshold(FindingSeverity.HIGH)

    assert FindingSeverity.from_string("critical") == FindingSeverity.CRITICAL
    assert FindingSeverity.from_string("HIGH") == FindingSeverity.HIGH
    assert FindingSeverity.from_string("medium") == FindingSeverity.MEDIUM
    assert FindingSeverity.from_string("unknown") == FindingSeverity.LOW


def test_clean_payloads_produces_no_findings(sample_clean_json: Path) -> None:
    """Verify clean requests yield zero findings and risk score zero."""
    report = audit_payload_target(sample_clean_json)
    assert report.findings_count == 0
    assert report.risk_score == 0
    assert report.requests_analyzed == 2
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-001: SQL Injection (SQLi) Payload Detected (CRITICAL) ---
    # Evaluates security posture against sql injection (sqli) payload detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_001_sqli() -> None:
    """Verify LH-PAY-001 detects SQL injection payloads."""
    req = CapturedRequest(
        request_id="sqli-test",
        path="/items",
        query_params={"id": "1' UNION ALL SELECT null, null-- "},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-001" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-001")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-002: Cross-Site Scripting (XSS) Payload Detected (HIGH) ---
    # Evaluates security posture against cross-site scripting (xss) payload
    # detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_002_xss() -> None:
    """Verify LH-PAY-002 detects Cross-Site Scripting vectors."""
    req = CapturedRequest(
        request_id="xss-test",
        path="/search",
        query_params={"q": "<img src=x onerror=alert('xss')>"},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-002" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-002")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-003: OS Command Injection Payload Detected (CRITICAL) ---
    # Evaluates security posture against os command injection payload detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_003_rce() -> None:
    """Verify LH-PAY-003 detects command injection and shell executions."""
    req = CapturedRequest(
        request_id="rce-test",
        path="/api/check",
        body={"target": "google.com && id"},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-003" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-003")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-004: Server-Side Request Forgery (SSRF) Payload (CRITICAL) ---
    # Evaluates security posture against server-side request forgery (ssrf) payload.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_004_ssti() -> None:
    """Verify LH-PAY-004 detects template injection expressions."""
    req = CapturedRequest(
        request_id="ssti-test",
        path="/view",
        query_params={"name": "test {{7*7}}"},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-004" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-004")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-005: XML External Entity (XXE) Injection Detected (CRITICAL) ---
    # Evaluates security posture against xml external entity (xxe) injection
    # detected.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_005_path_traversal() -> None:
    """Verify LH-PAY-005 detects directory traversal attempts."""
    req = CapturedRequest(
        request_id="lfi-test",
        path="/file",
        query_params={"path": "%2e%2e%2f%2e%2e%2fetc/passwd"},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-005" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-005")
    assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-006: Path Traversal & Arbitrary File Read Payload (HIGH) ---
    # Evaluates security posture against path traversal & arbitrary file read
    # payload.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_006_jndi_deserialization() -> None:
    """Verify LH-PAY-006 detects Log4Shell and deserialization payloads."""
    req = CapturedRequest(
        request_id="jndi-test",
        path="/login",
        headers={"X-Api-Version": "${jndi:ldap://127.0.0.1:1389/Exploit}"},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-006" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-006")
    assert f.severity == FindingSeverity.CRITICAL
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-007: Insecure Object Deserialization Payload (CRITICAL) ---
    # Evaluates security posture against insecure object deserialization payload.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_007_xxe_nosqli() -> None:
    """Verify LH-PAY-007 detects XXE declarations and NoSQL operators."""
    req = CapturedRequest(
        request_id="xxe-test",
        path="/soap",
        body='<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>',
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-007" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-007")
    assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-008: Server-Side Template Injection (SSTI) Payload (MEDIUM) ---
    # Evaluates security posture against server-side template injection (ssti)
    # payload.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_008_ssrf() -> None:
    """Verify LH-PAY-008 detects SSRF loopback and metadata probes."""
    req = CapturedRequest(
        request_id="ssrf-test",
        path="/fetch",
        query_params={"url": "http://169.254.169.254/latest/user-data"},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-008" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-008")
    assert f.severity == FindingSeverity.HIGH
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-009: LDAP / NoSQL Injection Payload (HIGH) ---
    # Evaluates security posture against ldap / nosql injection payload.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_009_crlf_host_poisoning() -> None:
    """Verify LH-PAY-009 detects CRLF splitting and poisoned Host headers."""
    req = CapturedRequest(
        request_id="crlf-test",
        path="/set",
        headers={"Host": "victim.com,attacker.com"},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-009" for f in findings)
    f = next(f for f in findings if f.rule_id == "LH-PAY-009")
    assert f.severity == FindingSeverity.MEDIUM
    # --------------------------------------------------------------------------
    # --- Rule LH-PAY-010: Malformed Encoding or Oversized Payload Anomaly (LOW) ---
    # Evaluates security posture against malformed encoding or oversized payload
    # anomaly.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_rule_lh_pay_010_prototype_pollution_and_oversized() -> None:
    """Verify LH-PAY-010 detects prototype pollution and payload size anomalies."""
    req = CapturedRequest(
        request_id="proto-test",
        path="/profile",
        body={"__proto__": {"role": "superadmin"}},
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-010" for f in findings)

    # Oversized body anomaly test (> 100KB)
    oversized_req = CapturedRequest(
        request_id="oversized-test",
        path="/upload",
        body="A" * 150_000,
    )
    inspector2 = PayloadInspector([oversized_req])
    findings2 = inspector2.audit()
    assert any(f.rule_id == "LH-PAY-010" for f in findings2)


def test_rule_lh_pay_010_deep_nesting() -> None:
    """Verify LH-PAY-010 flags deeply nested JSON payload structures."""
    nested: dict[str, Any] = {"level": 1}
    curr = nested
    for i in range(2, 25):
        curr["child"] = {"level": i}
        curr = curr["child"]

    req = CapturedRequest(
        request_id="deep-nest-test",
        path="/parse",
        body=nested,
    )
    inspector = PayloadInspector([req])
    findings = inspector.audit()
    assert any(f.rule_id == "LH-PAY-010" for f in findings)


def test_malicious_fixture_comprehensive(sample_malicious_json: Path) -> None:
    """Verify all 10 detection rules trigger on comprehensive malicious test fixture."""
    report = audit_payload_target(sample_malicious_json)
    assert report.findings_count >= 10
    assert report.risk_score > 50

    triggered_rules = {f.rule_id for f in report.findings}
    for rule_num in range(1, 11):
        rule_key = f"LH-PAY-{rule_num:03d}"
        assert rule_key in triggered_rules, f"Expected {rule_key} to be triggered"


def test_calculate_risk_score() -> None:
    """Verify risk score bounded calculation."""
    assert calculate_risk_score([]) == 0
