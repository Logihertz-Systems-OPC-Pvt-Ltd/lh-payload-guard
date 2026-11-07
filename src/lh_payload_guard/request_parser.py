# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        src.lh_payload_guard.request_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Parsers for HTTP requests, WAF exports, logs, and payload dumps."""

from __future__ import annotations

import csv
import json
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import yaml

from lh_payload_guard.models import CapturedRequest

# Regex pattern for Apache/Nginx Combined Log Format
COMBINED_LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+HTTP/[0-9.]+)?\"'
    r'\s+(\d{3})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"'
)

# Regex pattern for Apache/Nginx Common Log Format
COMMON_LOG_PATTERN = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)(?:\s+HTTP/[0-9.]+)?\"'
    r"\s+(\d{3})\s+(\S+)"
)


def _extract_field(row: dict[str, Any], aliases: list[str], default: Any = None) -> Any:
    """Case-insensitively retrieve field value by checking multiple alias names."""
    normalized_keys = {k.strip().lower().replace("_", " "): k for k in row.keys() if k is not None}
    for alias in aliases:
        norm_alias = alias.strip().lower().replace("_", " ")
        if norm_alias in normalized_keys:
            orig_key = normalized_keys[norm_alias]
            val = row[orig_key]
            if val is not None:
                return val
    return default


def _parse_url_path_and_query(raw_url: str) -> tuple[str, dict[str, str | list[str]]]:
    """Extract path and query parameters from raw URL string."""
    clean = raw_url.strip()
    if not clean:
        return "/", {}

    parsed = urlparse(clean)
    path = parsed.path or "/"
    query_dict: dict[str, str | list[str]] = {}
    if parsed.query:
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for k, v in qs.items():
            query_dict[k] = v[0] if len(v) == 1 else v
    return path, query_dict


def _parse_cookies_string(cookie_header: str) -> dict[str, str]:
    """Parse HTTP Cookie header into key-value dictionary."""
    cookies: dict[str, str] = {}
    parts = cookie_header.split(";")
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def _dict_to_captured_request(
    data: dict[str, Any], source_file: str, line_no: int
) -> CapturedRequest:
    """Convert parsed dictionary entry into CapturedRequest object."""
    req_id = str(
        _extract_field(data, ["id", "request_id", "req_id", "uuid"])
        or f"req-{uuid.uuid4().hex[:8]}"
    )
    ts = str(_extract_field(data, ["timestamp", "time", "date", "datetime"], ""))
    ip = str(_extract_field(data, ["client_ip", "ip", "ip_address", "remote_addr"], ""))
    method = str(_extract_field(data, ["method", "http_method"], "GET")).upper()
    raw_url = str(_extract_field(data, ["url", "path", "uri", "endpoint", "page"], "/"))

    path, query_from_url = _parse_url_path_and_query(raw_url)

    # Check explicit query params
    explicit_query = _extract_field(data, ["query", "query_params", "params", "args"], None)
    query_params: dict[str, str | list[str]] = dict(query_from_url)
    if isinstance(explicit_query, dict):
        query_params.update({str(k): v for k, v in explicit_query.items()})
    elif isinstance(explicit_query, str) and explicit_query:
        qs = parse_qs(explicit_query.lstrip("?"), keep_blank_values=True)
        for k, v in qs.items():
            query_params[k] = v[0] if len(v) == 1 else v

    # Headers
    explicit_headers = _extract_field(data, ["headers", "request_headers"], {})
    headers: dict[str, str] = {}
    if isinstance(explicit_headers, dict):
        headers = {str(k): str(v) for k, v in explicit_headers.items()}

    # Cookies
    explicit_cookies = _extract_field(data, ["cookies", "cookie"], {})
    cookies: dict[str, str] = {}
    if isinstance(explicit_cookies, dict):
        cookies = {str(k): str(v) for k, v in explicit_cookies.items()}
    elif isinstance(explicit_cookies, str) and explicit_cookies:
        cookies = _parse_cookies_string(explicit_cookies)
    elif "cookie" in (k.lower() for k in headers):
        for h_k, h_v in headers.items():
            if h_k.lower() == "cookie":
                cookies = _parse_cookies_string(h_v)
                break

    # Body / payload
    body = _extract_field(data, ["body", "payload", "data", "content", "post_data"], "")

    return CapturedRequest(
        request_id=req_id,
        timestamp=ts,
        client_ip=ip,
        method=method,
        path=path,
        query_params=query_params,
        headers=headers,
        cookies=cookies,
        body=body,
        raw_url=raw_url,
        source_file=source_file,
        line_number=line_no,
    )


def parse_json_payloads(path: Path) -> list[CapturedRequest]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Parse JSON or NDJSON captured request payloads."""
    requests: list[CapturedRequest] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace").strip()
        if not content:
            return []

        if content.startswith("["):
            loaded = json.loads(content)
            if isinstance(loaded, list):
                for idx, item in enumerate(loaded, start=1):
                    if isinstance(item, dict):
                        requests.append(_dict_to_captured_request(item, str(path), idx))
                return requests
        elif content.startswith("{"):
            try:
                loaded = json.loads(content)
                if isinstance(loaded, dict):
                    # Check if wrapper with list of requests
                    if "requests" in loaded and isinstance(loaded["requests"], list):
                        for idx, item in enumerate(loaded["requests"], start=1):
                            if isinstance(item, dict):
                                requests.append(_dict_to_captured_request(item, str(path), idx))
                        return requests
                    else:
                        return [_dict_to_captured_request(loaded, str(path), 1)]
            except json.JSONDecodeError:
                pass

        for idx, line in enumerate(content.splitlines(), start=1):
            clean = line.strip()
            if not clean:
                continue
            try:
                obj = json.loads(clean)
                if isinstance(obj, dict):
                    requests.append(_dict_to_captured_request(obj, str(path), idx))
            except json.JSONDecodeError:
                continue
    except Exception:
        return []
    return requests


def parse_yaml_payloads(path: Path) -> list[CapturedRequest]:
    """Parse YAML captured request payloads."""
    requests: list[CapturedRequest] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        loaded = yaml.safe_load(content)
        if isinstance(loaded, list):
            for idx, item in enumerate(loaded, start=1):
                if isinstance(item, dict):
                    requests.append(_dict_to_captured_request(item, str(path), idx))
        elif isinstance(loaded, dict):
            if "requests" in loaded and isinstance(loaded["requests"], list):
                for idx, item in enumerate(loaded["requests"], start=1):
                    if isinstance(item, dict):
                        requests.append(_dict_to_captured_request(item, str(path), idx))
            else:
                requests.append(_dict_to_captured_request(loaded, str(path), 1))
    except Exception:
        return []
    return requests


def parse_csv_payloads(path: Path) -> list[CapturedRequest]:
    """Parse CSV exports of visitor/request traffic."""
    requests: list[CapturedRequest] = []
    try:
        with path.open(mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=2):
                if not row:
                    continue
                req_dict: dict[str, Any] = dict(row)
                ref = _extract_field(row, ["referrer", "referer", "http_referer"])
                ua = _extract_field(
                    row, ["user agent", "user_agent", "useragent", "http_user_agent", "ua"]
                )
                headers: dict[str, str] = {}
                if ref:
                    headers["Referer"] = str(ref)
                if ua:
                    headers["User-Agent"] = str(ua)

                req_dict["headers"] = headers
                requests.append(_dict_to_captured_request(req_dict, str(path), idx))
    except Exception:
        return []
    return requests


def parse_log_payloads(path: Path) -> list[CapturedRequest]:
    """Parse access logs in Combined or Common Log Format."""
    requests: list[CapturedRequest] = []
    try:
        with path.open(mode="r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                m_comb = COMBINED_LOG_PATTERN.match(clean_line)
                if m_comb:
                    ip = m_comb.group(1)
                    ts = m_comb.group(2)
                    method = m_comb.group(3)
                    raw_url = m_comb.group(4)
                    ref = m_comb.group(7)
                    ua = m_comb.group(8)

                    headers: dict[str, str] = {}
                    if ref and ref != "-":
                        headers["Referer"] = ref
                    if ua and ua != "-":
                        headers["User-Agent"] = ua

                    path_val, query_val = _parse_url_path_and_query(raw_url)

                    requests.append(
                        CapturedRequest(
                            request_id=f"log-{line_no}",
                            timestamp=ts,
                            client_ip=ip,
                            method=method,
                            path=path_val,
                            query_params=query_val,
                            headers=headers,
                            cookies={},
                            body="",
                            raw_url=raw_url,
                            source_file=str(path),
                            line_number=line_no,
                        )
                    )
                    continue

                m_comm = COMMON_LOG_PATTERN.match(clean_line)
                if m_comm:
                    ip = m_comm.group(1)
                    ts = m_comm.group(2)
                    method = m_comm.group(3)
                    raw_url = m_comm.group(4)
                    path_val, query_val = _parse_url_path_and_query(raw_url)

                    requests.append(
                        CapturedRequest(
                            request_id=f"log-{line_no}",
                            timestamp=ts,
                            client_ip=ip,
                            method=method,
                            path=path_val,
                            query_params=query_val,
                            headers={},
                            cookies={},
                            body="",
                            raw_url=raw_url,
                            source_file=str(path),
                            line_number=line_no,
                        )
                    )
    except Exception:
        return []
    return requests


def parse_payload_file(path: Path) -> list[CapturedRequest]:
    """Parse HTTP payload file according to extension and file signatures."""
    suffix = path.suffix.lower()
    if suffix in [".json", ".jsonl"]:
        return parse_json_payloads(path)
    if suffix in [".yaml", ".yml"]:
        return parse_yaml_payloads(path)
    if suffix == ".csv":
        return parse_csv_payloads(path)
    if suffix in [".log", ".txt", ".access"]:
        return parse_log_payloads(path)

    # Heuristic fallback
    json_reqs = parse_json_payloads(path)
    if json_reqs:
        return json_reqs
    yaml_reqs = parse_yaml_payloads(path)
    if yaml_reqs:
        return yaml_reqs
    csv_reqs = parse_csv_payloads(path)
    if csv_reqs:
        return csv_reqs
    return parse_log_payloads(path)


def find_payload_files(root: Path) -> list[Path]:
    """Locate all supported request and payload dump files under root path."""
    if not root.exists():
        return []

    if root.is_file():
        return [root]

    supported_suffixes = {".json", ".jsonl", ".yaml", ".yml", ".csv", ".log", ".txt"}
    files: list[Path] = []
    for item in root.rglob("*"):
        if item.is_file() and item.suffix.lower() in supported_suffixes:
            files.append(item)
    return sorted(files)
