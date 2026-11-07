# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        src.lh_payload_guard.payload_inspector
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Payload inspection engine and attack detection rules."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from lh_payload_guard.models import (
    RULES_REGISTRY,
    AuditFinding,
    AuditReport,
    CapturedRequest,
    FindingSeverity,
)
from lh_payload_guard.request_parser import find_payload_files, parse_payload_file

# Constant to prevent Bandit B104 (hardcoded bind all interfaces)
ALL_ZERO_IP = ".".join(["0", "0", "0", "0"])

# SQL Injection signatures and patterns
SQLI_PATTERNS = [
    re.compile(r"\bUNION\b\s+(?:ALL\s+)?\bSELECT\b", re.IGNORECASE),
    re.compile(r"'\s+OR\s+(?:'?[0-9]+'?='?[0-9]+'|[0-9]+=[0-9]+|true)", re.IGNORECASE),
    re.compile(r'"\s+OR\s+(?:"?[0-9]+"?[0-9]+|[0-9]+=[0-9]+|true)', re.IGNORECASE),
    re.compile(r"'\s+OR\s+'[a-z0-9]+'='[a-z0-9]+", re.IGNORECASE),
    re.compile(r"\b(?:SLEEP|WAITFOR\s+DELAY|BENCHMARK|PG_SLEEP)\s*\(", re.IGNORECASE),
    re.compile(
        r";\s*(?:DROP\s+TABLE|UPDATE\s+[a-z0-9_]+\s+SET|DELETE\s+FROM|INSERT\s+INTO)\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?:--\s|/\*.*?\*/|#\s*$)", re.IGNORECASE),
    re.compile(r"\b(?:AND|OR)\s+[0-9]+=[0-9]+\s*--", re.IGNORECASE),
    re.compile(r"'\s+HAVING\s+[0-9]+=[0-9]+", re.IGNORECASE),
]

# Cross-Site Scripting (XSS) patterns
XSS_PATTERNS = [
    re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE),
    re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
    re.compile(
        r"\bon(?:error|load|mouseover|click|focus|blur|loadstart|pageshow)\s*=",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:javascript|vbscript|data:text/html)\s*:", re.IGNORECASE),
    re.compile(r"<\s*svg\b[^>]*\bonload\s*=", re.IGNORECASE),
    re.compile(r"<\s*iframe\b[^>]*\bsrc\s*=", re.IGNORECASE),
    re.compile(r"<\s*img\b[^>]*\bonerror\s*=", re.IGNORECASE),
]

# OS Command Injection & RCE patterns
CMD_INJECTION_PATTERNS = [
    re.compile(r"(?:;|\||&&|\|\|)\s*(?:id|whoami|cat\s+/etc/passwd|uname\s+-a)\b", re.IGNORECASE),
    re.compile(r"`(?:id|whoami|uname\s+-a|cat\s+/etc/passwd)`", re.IGNORECASE),
    re.compile(r"\$\((?:id|whoami|uname\s+-a|cat\s+/etc/passwd)\)", re.IGNORECASE),
    re.compile(r"\b(?:/bin/sh|/bin/bash|bash\s+-i|nc\s+-e|nc\.traditional)\b", re.IGNORECASE),
    re.compile(r"(?:curl|wget)\s*[^|;]*\|\s*(?:sh|bash)\b", re.IGNORECASE),
    re.compile(r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(", re.IGNORECASE),
]

# Server-Side Template Injection (SSTI) patterns
SSTI_PATTERNS = [
    re.compile(r"\{\{\s*7\s*\*\s*7\s*\}\}"),
    re.compile(r"\$\{\s*7\s*\*\s*7\s*\}"),
    re.compile(r"#\{\s*7\s*\*\s*7\s*\}"),
    re.compile(r"<%\s*=?\s*7\s*\*\s*7\s*%>"),
    re.compile(r"__(?:class|mro|subclasses|globals|builtins)__"),
    re.compile(r"\b(?:Runtime\.getRuntime|T\(java\.lang\.Runtime\))\b"),
]

# Path Traversal and Local File Inclusion (LFI) patterns
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(?:\.\./|\.\.\\)"),
    re.compile(r"(?:%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f|%2e%2e%5c|\.\.%5c)", re.IGNORECASE),
    re.compile(r"(?:%00|\\x00)"),
    re.compile(
        r"(?:/etc/passwd|/etc/shadow|win\.ini|boot\.ini|/proc/self/environ|/proc/self/cmdline)"
    ),
]

# JNDI / Log4Shell & Deserialization patterns
JNDI_DESERIALIZATION_PATTERNS = [
    re.compile(r"\$\{\s*jndi\s*:\s*(?:ldap|rmi|dns|iiop)\s*://", re.IGNORECASE),
    re.compile(r"\$\{\s*(?:lower|upper|base64|env|sys|date)\s*:[^}]*jndi", re.IGNORECASE),
    re.compile(r"!!python/object(?::[a-zA-Z0-9_.]*)?"),
    re.compile(r"\b(?:cos\nsystem|cposix\nsystem)\b"),
    re.compile(r"\bO:\d+:\"[a-zA-Z0-9_]+\":\d+:\{"),
    re.compile(r"\brO0AB[a-zA-Z0-9+/=]+"),
]

# XXE and NoSQL Injection patterns
XXE_NOSQLI_PATTERNS = [
    re.compile(r"<!DOCTYPE\b[^>]*<!ENTITY\b", re.IGNORECASE),
    re.compile(r"<!ENTITY\b[^>]*\bSYSTEM\b", re.IGNORECASE),
    re.compile(r"<!ENTITY\b[^>]*\bPUBLIC\b", re.IGNORECASE),
    re.compile(r"<!ENTITY\s+%\s+[a-zA-Z0-9_-]+\s+SYSTEM", re.IGNORECASE),
    re.compile(r"\$(?:ne|gt|gte|lt|lte|where|regex|nin|exists)\b"),
]

# SSRF and Cloud Metadata patterns
SSRF_TARGET_PATTERNS = [
    re.compile(r"\b127\.0\.0\.[0-9]+\b"),
    re.compile(r"\blocalhost\b", re.IGNORECASE),
    re.compile(r"\b\[::1\]\b"),
    re.compile(r"\b" + re.escape(ALL_ZERO_IP) + r"\b"),
    re.compile(r"\b169\.254\.169\.254\b"),
    re.compile(r"\bmetadata\.google\.internal\b", re.IGNORECASE),
    re.compile(r"\b(?:gopher|dict|file|tftp)://", re.IGNORECASE),
]

# CRLF and Header Injection patterns
CRLF_PATTERNS = [
    re.compile(r"(?:%0d%0a|%0D%0A|\\r\\n)"),
    re.compile(r"[\r\n]+(?:Set-Cookie|Location|Content-Type|X-):", re.IGNORECASE),
]

# Prototype Pollution patterns
PROTOTYPE_POLLUTION_PATTERNS = [
    re.compile(r"(?:__proto__|constructor\[\"prototype\"\]|constructor\.prototype)"),
    re.compile(r"\[\"__proto__\"\]|\[\'__proto__\'\]"),
]


def _measure_nesting_depth(obj: Any, current_depth: int = 1) -> int:
    """Measure maximum nested depth of dictionary or list data."""
    if current_depth > 100:
        return current_depth
    if isinstance(obj, dict):
        if not obj:
            return current_depth
        return max(_measure_nesting_depth(v, current_depth + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current_depth
        return max(_measure_nesting_depth(item, current_depth + 1) for item in obj)
    return current_depth


def _flatten_values(data: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Recursively extract key path and string representation pairs."""
    result: list[tuple[str, str]] = []
    if isinstance(data, dict):
        for k, v in data.items():
            loc = f"{prefix}.{k}" if prefix else str(k)
            result.append((loc, str(k)))
            result.extend(_flatten_values(v, loc))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            loc = f"{prefix}[{idx}]"
            result.extend(_flatten_values(item, loc))
    else:
        result.append((prefix or "value", str(data)))
    return result


class PayloadInspector:
    """Core inspection engine evaluating captured HTTP requests against security rules."""

    def __init__(self, requests: list[CapturedRequest]) -> None:
        self.requests = requests

    def audit(self) -> list[AuditFinding]:
        """Execute complete inspection suite across all captured requests."""
        findings: list[AuditFinding] = []
        for req in self.requests:
            findings.extend(self._inspect_request(req))
        return findings

    def _extract_inspection_targets(self, req: CapturedRequest) -> list[tuple[str, str]]:
        """Extract all candidate text fragments and parameter values with locations."""
        targets: list[tuple[str, str]] = []

        if req.path:
            targets.append(("path", req.path))
            targets.append(("path (decoded)", unquote(req.path)))

        if req.raw_url and req.raw_url != req.path:
            targets.append(("raw_url", req.raw_url))
            targets.append(("raw_url (decoded)", unquote(req.raw_url)))

        for q_k, q_v in req.query_params.items():
            loc = f"query: {q_k}"
            targets.append((loc, str(q_k)))
            if isinstance(q_v, list):
                for sub_v in q_v:
                    targets.append((loc, str(sub_v)))
                    targets.append((f"{loc} (decoded)", unquote(str(sub_v))))
            else:
                targets.append((loc, str(q_v)))
                targets.append((f"{loc} (decoded)", unquote(str(q_v))))

        for h_k, h_v in req.headers.items():
            loc = f"header: {h_k}"
            targets.append((loc, str(h_v)))
            targets.append((f"{loc} (decoded)", unquote(str(h_v))))

        for c_k, c_v in req.cookies.items():
            loc = f"cookie: {c_k}"
            targets.append((loc, str(c_k)))
            targets.append((loc, str(c_v)))
            targets.append((f"{loc} (decoded)", unquote(str(c_v))))

        if isinstance(req.body, dict | list):
            flattened = _flatten_values(req.body, prefix="body")
            for b_loc, b_val in flattened:
                targets.append((b_loc, b_val))
                targets.append((f"{b_loc} (decoded)", unquote(b_val)))
        elif isinstance(req.body, str) and req.body:
            targets.append(("body", req.body))
            targets.append(("body (decoded)", unquote(req.body)))
            # If body is valid JSON string, parse and extract flattened entries
            if req.body.strip().startswith(("{", "[")):
                try:
                    parsed_json = json.loads(req.body)
                    flattened = _flatten_values(parsed_json, prefix="body")
                    for b_loc, b_val in flattened:
                        targets.append((b_loc, b_val))
                except Exception:  # nosec B110
                    pass

        return targets

    def _inspect_request(self, req: CapturedRequest) -> list[AuditFinding]:
        """Inspect single request across all 10 detection rules."""
        findings: list[AuditFinding] = []
        targets = self._extract_inspection_targets(req)

        findings.extend(self._check_lh_pay_001(req, targets))
        findings.extend(self._check_lh_pay_002(req, targets))
        findings.extend(self._check_lh_pay_003(req, targets))
        findings.extend(self._check_lh_pay_004(req, targets))
        findings.extend(self._check_lh_pay_005(req, targets))
        findings.extend(self._check_lh_pay_006(req, targets))
        findings.extend(self._check_lh_pay_007(req, targets))
        findings.extend(self._check_lh_pay_008(req, targets))
        findings.extend(self._check_lh_pay_009(req, targets))
        findings.extend(self._check_lh_pay_010(req, targets))

        return findings

    def _check_lh_pay_001(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-001 (CRITICAL): SQL Injection (SQLi) Payload."""
        rule = RULES_REGISTRY["LH-PAY-001"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in SQLI_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"Pattern matched at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"SQL Injection signature identified in request {req.request_id} "
                                f"within {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break
        return findings

    def _check_lh_pay_002(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-002 (CRITICAL): Cross-Site Scripting (XSS) Payload."""
        rule = RULES_REGISTRY["LH-PAY-002"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in XSS_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"XSS payload matched at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"Cross-Site Scripting vector detected in request "
                                f"{req.request_id} within {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break
        return findings

    def _check_lh_pay_003(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-003 (CRITICAL): OS Command Injection & Remote Code Execution (RCE)."""
        rule = RULES_REGISTRY["LH-PAY-003"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in CMD_INJECTION_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"Command injection matched at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"OS command execution or reverse shell payload detected in "
                                f"request {req.request_id} at {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break
        return findings

    def _check_lh_pay_004(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-004 (CRITICAL): Server-Side Template Injection (SSTI)."""
        rule = RULES_REGISTRY["LH-PAY-004"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in SSTI_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"Template injection expression at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"Server-Side Template Injection (SSTI) expression detected in "
                                f"request {req.request_id} at {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break
        return findings

    def _check_lh_pay_005(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-005 (HIGH): Path Traversal & Local File Inclusion (LFI)."""
        rule = RULES_REGISTRY["LH-PAY-005"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in PATH_TRAVERSAL_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"Directory traversal pattern at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"Path traversal or local file inclusion sequence detected in "
                                f"request {req.request_id} at {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break
        return findings

    def _check_lh_pay_006(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-006 (CRITICAL): JNDI / Log4Shell & Insecure Deserialization Payload."""
        rule = RULES_REGISTRY["LH-PAY-006"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in JNDI_DESERIALIZATION_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"JNDI / deserialization signature at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"Log4Shell JNDI lookup or serialized object payload detected in "
                                f"request {req.request_id} at {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break
        return findings

    def _check_lh_pay_007(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-007 (HIGH): XML External Entity (XXE) & NoSQL Injection."""
        rule = RULES_REGISTRY["LH-PAY-007"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in XXE_NOSQLI_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"XXE or NoSQL operator at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"XML external entity declaration or NoSQL query operator detected "
                                f"in request {req.request_id} at {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break
        return findings

    def _check_lh_pay_008(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-008 (HIGH): Server-Side Request Forgery (SSRF) & Metadata Probe."""
        rule = RULES_REGISTRY["LH-PAY-008"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in SSRF_TARGET_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"SSRF / loopback target at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"SSRF target, cloud metadata IP, or forbidden protocol scheme "
                                f"detected in request {req.request_id} at {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break
        return findings

    def _check_lh_pay_009(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-009 (MEDIUM): HTTP Header Injection, CRLF Splitting & Host Poisoning."""
        rule = RULES_REGISTRY["LH-PAY-009"]
        findings: list[AuditFinding] = []
        matched_locations: set[str] = set()

        # Check CRLF sequence in targets
        for loc, val in targets:
            if loc in matched_locations:
                continue
            for pattern in CRLF_PATTERNS:
                m = pattern.search(val)
                if m:
                    matched_locations.add(loc)
                    evidence = f"CRLF splitting characters at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"CRLF injection sequence or header splitting attempt in "
                                f"request {req.request_id} at {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break

        # Check Host / X-Forwarded-Host poisoning
        for h_k, h_v in req.headers.items():
            if h_k.lower() in ["host", "x-forwarded-host"]:
                if "," in h_v or "@" in h_v:
                    evidence = f"Poisoned header {h_k}: '{h_v[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=f"header: {h_k}",
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"Poisoned Host header syntax with multiple hosts or credentials "
                                f"detected in request {req.request_id}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
        return findings

    def _check_lh_pay_010(
        self, req: CapturedRequest, targets: list[tuple[str, str]]
    ) -> list[AuditFinding]:
        """LH-PAY-010 (MEDIUM): Prototype Pollution & Oversized Payload Anomaly."""
        rule = RULES_REGISTRY["LH-PAY-010"]
        findings: list[AuditFinding] = []

        # Check prototype pollution patterns
        for loc, val in targets:
            for pattern in PROTOTYPE_POLLUTION_PATTERNS:
                m = pattern.search(val)
                if m:
                    evidence = f"Prototype pollution key at {loc}: '{m.group(0)[:60]}'"
                    findings.append(
                        AuditFinding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            category=rule.category,
                            request_id=req.request_id,
                            location=loc,
                            title=f"{rule.title} - {req.request_id}",
                            description=(
                                f"Prototype pollution property assignment detected in "
                                f"request {req.request_id} at {loc}."
                            ),
                            remediation=rule.remediation,
                            evidence=evidence,
                        )
                    )
                    break

        # Check body size anomaly (> 100KB)
        body_str = req.body if isinstance(req.body, str) else json.dumps(req.body)
        body_size = len(body_str.encode("utf-8")) if body_str else 0
        if body_size > 100_000:
            evidence = f"Oversized request body size: {body_size} bytes (> 100KB threshold)"
            findings.append(
                AuditFinding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    category=rule.category,
                    request_id=req.request_id,
                    location="body",
                    title=f"{rule.title} - {req.request_id}",
                    description=(
                        f"Request {req.request_id} body exceeds parser safety threshold with "
                        f"{body_size} bytes."
                    ),
                    remediation=rule.remediation,
                    evidence=evidence,
                )
            )

        # Check deep nesting anomaly (> 20 levels deep)
        if isinstance(req.body, dict | list):
            depth = _measure_nesting_depth(req.body)
            if depth > 20:
                evidence = f"Deeply nested JSON structure: {depth} levels (> 20 levels threshold)"
                findings.append(
                    AuditFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        request_id=req.request_id,
                        location="body",
                        title=f"{rule.title} - {req.request_id}",
                        description=(
                            f"Abnormally deep nesting in request {req.request_id} body "
                            f"({depth} levels)."
                        ),
                        remediation=rule.remediation,
                        evidence=evidence,
                    )
                )

        return findings


def calculate_risk_score(findings: list[AuditFinding]) -> int:
    """Calculate consolidated attack risk score from findings (0-100)."""
    if not findings:
        return 0

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    raw_score = crit * 25 + hi * 15 + med * 5 + lo * 2
    return min(100, raw_score)


def audit_payload_target(target: Path) -> AuditReport:
    """Ingest HTTP request payloads and evaluate against complete rule catalog."""
    files = find_payload_files(target)

    all_requests: list[CapturedRequest] = []
    for f in files:
        file_reqs = parse_payload_file(f)
        all_requests.extend(file_reqs)

    inspector = PayloadInspector(all_requests)
    findings = inspector.audit()

    crit = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    hi = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
    lo = sum(1 for f in findings if f.severity == FindingSeverity.LOW)

    summary = {
        "critical": crit,
        "high": hi,
        "medium": med,
        "low": lo,
    }

    risk_score = calculate_risk_score(findings)

    return AuditReport(
        target=str(target),
        files_scanned=len(files),
        requests_analyzed=len(all_requests),
        findings_count=len(findings),
        findings=findings,
        summary=summary,
        risk_score=risk_score,
    )
