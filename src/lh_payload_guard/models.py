# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        src.lh_payload_guard.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-payload-guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for payload security findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class PayloadLocation(StrEnum):
    """Location of detected payload within captured HTTP request."""

    PATH = "path"
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"


@dataclass
class CapturedRequest:
    """Captured HTTP request structure for deep payload analysis."""

    request_id: str = ""
    timestamp: str = ""
    client_ip: str = ""
    method: str = "GET"
    path: str = "/"
    query_params: dict[str, str | list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Any = ""
    raw_url: str = ""
    source_file: str = ""
    line_number: int = 0


@dataclass
class AuditFinding:
    """Malicious payload or injection vector detected in request."""

    rule_id: str
    severity: FindingSeverity
    category: str
    request_id: str
    location: str
    title: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class AuditReport:
    """Consolidated payload inspection and attack detection report."""

    target: str
    files_scanned: int = 0
    requests_analyzed: int = 0
    findings_count: int = 0
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    risk_score: int = 0


@dataclass(frozen=True)
class AuditRuleDefinition:
    """Static metadata for payload guard audit rules."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, AuditRuleDefinition] = {
    "LH-PAY-001": AuditRuleDefinition(
        rule_id="LH-PAY-001",
        title="SQL Injection (SQLi) Payload",
        severity=FindingSeverity.CRITICAL,
        category="Injection",
        description=(
            "Payload contains SQL injection patterns including UNION SELECT, boolean tautologies, "
            "time delays, stacked queries, or SQL comment evasion."
        ),
        remediation=(
            "Use parameterized SQL prepared statements, apply strict input validation, and enforce "
            "WAF query inspection rules."
        ),
    ),
    "LH-PAY-002": AuditRuleDefinition(
        rule_id="LH-PAY-002",
        title="Cross-Site Scripting (XSS) Payload",
        severity=FindingSeverity.CRITICAL,
        category="Injection",
        description=(
            "Payload contains script tags, inline event handlers (onerror=, onload=), javascript: "
            "URIs, or SVG/iframe script vectors."
        ),
        remediation=(
            "Apply contextual output encoding, sanitize HTML inputs using DOMPurify, and enforce a "
            "strict Content Security Policy (CSP)."
        ),
    ),
    "LH-PAY-003": AuditRuleDefinition(
        rule_id="LH-PAY-003",
        title="OS Command Injection & Remote Code Execution (RCE)",
        severity=FindingSeverity.CRITICAL,
        category="Execution",
        description=(
            "Payload contains shell command chaining operators, reverse shell scripts, or system "
            "execution invocation strings."
        ),
        remediation=(
            "Avoid shell execution wrappers, use structured process APIs with fixed arguments, and "
            "drop shell metacharacters."
        ),
    ),
    "LH-PAY-004": AuditRuleDefinition(
        rule_id="LH-PAY-004",
        title="Server-Side Template Injection (SSTI) & Expression Language",
        severity=FindingSeverity.CRITICAL,
        category="Injection",
        description=(
            "Payload includes template syntax ({{...}}, ${...}) or Python/Java introspection "
            "chains (__class__, __mro__, __subclasses__)."
        ),
        remediation=(
            "Never render raw untrusted user input directly into template engines; "
            "run templates in sandboxed, logic-less modes."
        ),
    ),
    "LH-PAY-005": AuditRuleDefinition(
        rule_id="LH-PAY-005",
        title="Path Traversal & Local File Inclusion (LFI)",
        severity=FindingSeverity.HIGH,
        category="Traversal",
        description=(
            "Payload contains directory traversal sequences (../, ..\\), URL-encoded variants, "
            "null-byte injection, or sensitive OS targets (/etc/passwd)."
        ),
        remediation=(
            "Canonicalize file paths before access, validate against allowlisted directory roots, "
            "and reject dot-dot sequences."
        ),
    ),
    "LH-PAY-006": AuditRuleDefinition(
        rule_id="LH-PAY-006",
        title="JNDI / Log4Shell & Insecure Deserialization Payload",
        severity=FindingSeverity.CRITICAL,
        category="Deserialization",
        description=(
            "Payload contains JNDI lookup strings (${jndi:ldap://...}), obfuscated nested lookups, "
            "or serialized object signatures."
        ),
        remediation=(
            "Disable JNDI lookups in logging frameworks, upgrade log4j, and reject untrusted "
            "serialized Java/PHP/Python objects."
        ),
    ),
    "LH-PAY-007": AuditRuleDefinition(
        rule_id="LH-PAY-007",
        title="XML External Entity (XXE) & NoSQL Injection",
        severity=FindingSeverity.HIGH,
        category="Injection",
        description=(
            "Payload contains XML DOCTYPE external entity declarations (ENTITY SYSTEM) or MongoDB "
            "query operators ($ne, $where, $regex)."
        ),
        remediation=(
            "Disable external DTD resolution (disallow-doctype-decl) in XML parsers and enforce "
            "schema typing for NoSQL parameters."
        ),
    ),
    "LH-PAY-008": AuditRuleDefinition(
        rule_id="LH-PAY-008",
        title="Server-Side Request Forgery (SSRF) & Metadata Probe",
        severity=FindingSeverity.HIGH,
        category="SSRF",
        description=(
            "Payload references loopback targets (127.0.0.1, localhost), cloud metadata endpoints "
            "(169.254.169.254), or dangerous protocols (file://, gopher://)."
        ),
        remediation=(
            "Validate and allowlist outbound request destinations, block RFC 1918 and link-local "
            "ranges, and enforce IMDSv2 tokens."
        ),
    ),
    "LH-PAY-009": AuditRuleDefinition(
        rule_id="LH-PAY-009",
        title="HTTP Header Injection, CRLF Splitting & Host Poisoning",
        severity=FindingSeverity.MEDIUM,
        category="Header Tampering",
        description=(
            "Payload contains CRLF sequence characters (\\r\\n, %0d%0a) or host header poisoning "
            "probes in request headers."
        ),
        remediation=(
            "Strip carriage return and line feed characters from user-controlled header values and "
            "validate Host header against allowed domains."
        ),
    ),
    "LH-PAY-010": AuditRuleDefinition(
        rule_id="LH-PAY-010",
        title="Prototype Pollution & Oversized Payload Anomaly",
        severity=FindingSeverity.MEDIUM,
        category="Parser Abuse",
        description=(
            "Payload targets Object prototype (__proto__, constructor.prototype) or exceeds "
            "size and nesting safety thresholds."
        ),
        remediation=(
            "Sanitize object keys to prevent __proto__ assignment, freeze prototypes, and enforce "
            "maximum request body size limits."
        ),
    ),
}
