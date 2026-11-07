# Security Rules Reference: lh-payload-guard

An enterprise http payload security inspection & sanitization engine developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-payload-guard`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-PAY-001` | `CRITICAL` | Injection | SQL Injection (SQLi) Payload Detected |
| `LH-PAY-002` | `HIGH` | Injection | Cross-Site Scripting (XSS) Payload Detected |
| `LH-PAY-003` | `CRITICAL` | Injection | OS Command Injection Payload Detected |
| `LH-PAY-004` | `CRITICAL` | SSRF | Server-Side Request Forgery (SSRF) Payload |
| `LH-PAY-005` | `CRITICAL` | XXE | XML External Entity (XXE) Injection Detected |
| `LH-PAY-006` | `HIGH` | Path Traversal | Path Traversal & Arbitrary File Read Payload |
| `LH-PAY-007` | `CRITICAL` | Deserialization | Insecure Object Deserialization Payload |
| `LH-PAY-008` | `MEDIUM` | Injection | Server-Side Template Injection (SSTI) Payload |
| `LH-PAY-009` | `HIGH` | Injection | LDAP / NoSQL Injection Payload |
| `LH-PAY-010` | `LOW` | Payload Hygiene | Malformed Encoding or Oversized Payload Anomaly |

---

## Granular Rule Specifications

### `LH-PAY-001`: SQL Injection (SQLi) Payload Detected

- **Severity**: `CRITICAL`
- **Category**: `Injection`
- **Description**: UNION SELECT, boolean injection, or tautology patterns detected in HTTP payload.
- **Remediation**: Use parameterized database queries and ORMs; reject unvalidated dynamic SQL statements.

---

### `LH-PAY-002`: Cross-Site Scripting (XSS) Payload Detected

- **Severity**: `HIGH`
- **Category**: `Injection`
- **Description**: Script tags, event handlers (onerror/onload), or javascript: URIs detected in input.
- **Remediation**: Contextually encode output and enforce strict Content-Security-Policy headers.

---

### `LH-PAY-003`: OS Command Injection Payload Detected

- **Severity**: `CRITICAL`
- **Category**: `Injection`
- **Description**: Shell metacharacters (; | & ` $()) chaining system execution in input string.
- **Remediation**: Avoid passing user input to shell commands; use subprocess.run with argument lists.

---

### `LH-PAY-004`: Server-Side Request Forgery (SSRF) Payload

- **Severity**: `CRITICAL`
- **Category**: `SSRF`
- **Description**: Internal metadata IP (169.254.169.254) or private CIDR range targeted in URL payload.
- **Remediation**: Validate destination URLs against domain allowlists and block private RFC 1918 IPs.

---

### `LH-PAY-005`: XML External Entity (XXE) Injection Detected

- **Severity**: `CRITICAL`
- **Category**: `XXE`
- **Description**: DOCTYPE entity references targeting /etc/passwd or file:// URIs in XML payload.
- **Remediation**: Disable external entity resolution (resolve_entities=False) in XML parsers.

---

### `LH-PAY-006`: Path Traversal & Arbitrary File Read Payload

- **Severity**: `HIGH`
- **Category**: `Path Traversal`
- **Description**: Directory traversal sequences (../, %2e%2e%2f) attempting unauthorized file access.
- **Remediation**: Sanitize filenames using os.path.basename and validate paths against strict base directories.

---

### `LH-PAY-007`: Insecure Object Deserialization Payload

- **Severity**: `CRITICAL`
- **Category**: `Deserialization`
- **Description**: Serialized Java objects, Python pickle streams, or PHP serialized objects in payload.
- **Remediation**: Never deserialize untrusted input with pickle/unserialize; use safe formats like JSON.

---

### `LH-PAY-008`: Server-Side Template Injection (SSTI) Payload

- **Severity**: `MEDIUM`
- **Category**: `Injection`
- **Description**: Template syntax expressions (${{...}}, <%=...%>, {{...}}) detected in user input.
- **Remediation**: Treat user input as data rather than executable template logic in template engines.

---

### `LH-PAY-009`: LDAP / NoSQL Injection Payload

- **Severity**: `HIGH`
- **Category**: `Injection`
- **Description**: LDAP filter escapes or MongoDB operators ($where, $ne, $regex) in input fields.
- **Remediation**: Use type-safe schemas and sanitize input using query builder parameterization.

---

### `LH-PAY-010`: Malformed Encoding or Oversized Payload Anomaly

- **Severity**: `LOW`
- **Category**: `Payload Hygiene`
- **Description**: Excessive object nesting depth or invalid UTF-8 sequences risking parser crash.
- **Remediation**: Enforce request body size limits and validate UTF-8 encoding prior to parsing.

---
