# lh-payload-guard

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-payload-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-payload-guard/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise deep http payload & injection inspector developed by **Logihertz Systems (OPC) Private Limited**.

Inspects captured HTTP request bodies, query strings, headers, and webhook payloads using multi-pass de-obfuscation to detect SQL injection (SQLi), XSS, Server-Side Template Injection (SSTI), XXE, and command injection.

---

## Key Features

- **Multi-Encoding Deep Inspection**: Recursively decodes URL-encoding, Base64, HTML entities, and Unicode escapes before evaluation.
- **Comprehensive Injection Coverage**: Specialized pattern matchers for SQLi (union, boolean, error-based), XSS (stored, reflected, SVG/DOM), and Command Injection.
- **SSRF & Internal Cloud Metadata Probing**: Flags requests targeting AWS/GCP instance metadata (`169.254.169.254`), localhost, or private subnets.
- **XXE & Malicious XML Entity Auditing**: Detects `DOCTYPE`, `ENTITY SYSTEM`, and parameter entity injection in XML payloads.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-PAY-001` | `CRITICAL` | SQL Injection (SQLi) Payload Detected — UNION SELECT, boolean injection, or tautology attacks |
| `LH-PAY-002` | `HIGH` | Cross-Site Scripting (XSS) Payload Detected — script tags, event handlers (onerror/onload), or JS URIs |
| `LH-PAY-003` | `CRITICAL` | OS Command Injection Payload Detected — shell metacharacters (; | & ` $()) chaining system commands |
| `LH-PAY-004` | `CRITICAL` | Server-Side Request Forgery (SSRF) Payload — internal metadata (169.254.169.254) or private CIDR probes |
| `LH-PAY-005` | `CRITICAL` | XML External Entity (XXE) Injection — DOCTYPE entity references targeting /etc/passwd or file:// URIs |
| `LH-PAY-006` | `HIGH` | Path Traversal & Arbitrary File Read Payload — directory traversal sequences (../, %2e%2e%2f) |
| `LH-PAY-007` | `CRITICAL` | Insecure Object Deserialization Payload — serialized Java, Python pickle, or PHP object gadgets |
| `LH-PAY-008` | `MEDIUM` | Server-Side Template Injection (SSTI) Payload — template expression syntax (${{...}}, <%=...%>, {{...}}) |
| `LH-PAY-009` | `HIGH` | LDAP / NoSQL Injection Payload — LDAP filter escapes or MongoDB operators ($where, $ne, $regex) |
| `LH-PAY-010` | `LOW` | Malformed Encoding or Oversized Payload Anomaly — excessive nesting depth or invalid UTF-8 sequences |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-payload-guard.git
cd lh-payload-guard

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-payload` (also accessible via `lh-payload`, `lh-payload-guard`).

```bash
# Scan a captured HTTP request payload file
lh-payload scan payload.json

# Scan an XML body for XXE and injection attacks
lh-payload scan request.xml --format json

# Export findings to OASIS SARIF v2.1.0
lh-payload scan ./traffic/ --format sarif --output payload-results.sarif

# List all payload detection rules
lh-payload rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
