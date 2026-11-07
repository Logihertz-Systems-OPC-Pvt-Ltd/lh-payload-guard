# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        tests.test_request_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for payload file parsers and HTTP request extractors."""

from __future__ import annotations

import json
from pathlib import Path

from lh_payload_guard.request_parser import (
    _parse_cookies_string,
    _parse_url_path_and_query,
    find_payload_files,
    parse_csv_payloads,
    parse_json_payloads,
    parse_log_payloads,
    parse_payload_file,
    parse_yaml_payloads,
)


def test_parse_url_path_and_query() -> None:
    """Verify URL path and query string separation."""
    path, query = _parse_url_path_and_query("/search?q=security&page=1")
    assert path == "/search"
    assert query["q"] == "security"
    assert query["page"] == "1"

    p_empty, q_empty = _parse_url_path_and_query("")
    assert p_empty == "/"
    assert q_empty == {}


def test_parse_cookies_string() -> None:
    """Verify cookie header decomposition into dictionary."""
    cookie_hdr = "session_id=xyz123; theme=dark; token=abc"
    parsed = _parse_cookies_string(cookie_hdr)
    assert parsed["session_id"] == "xyz123"
    assert parsed["theme"] == "dark"
    assert parsed["token"] == "abc"


def test_parse_json_payloads(sample_clean_json: Path) -> None:
    """Verify parsing JSON array of captured HTTP requests."""
    requests = parse_json_payloads(sample_clean_json)
    assert len(requests) == 2
    assert requests[0].request_id == "req-101"
    assert requests[0].method == "GET"
    assert requests[0].path == "/products/search"
    assert requests[0].query_params["q"] == "wireless keyboard"
    assert requests[0].headers["User-Agent"] == "Mozilla/5.0 Chrome/125.0"
    assert requests[0].cookies["session_id"] == "sess_abc123"

    assert requests[1].request_id == "req-102"
    assert requests[1].method == "POST"
    assert isinstance(requests[1].body, dict)
    assert requests[1].body["rating"] == 5


def test_parse_json_wrapper(tmp_path: Path) -> None:
    """Verify parsing single JSON object with requests wrapper."""
    file_path = tmp_path / "wrapper.json"
    data = {
        "source": "gateway",
        "requests": [
            {"id": "wrap-1", "path": "/api", "method": "GET"},
            {"id": "wrap-2", "path": "/auth", "method": "POST"},
        ],
    }
    file_path.write_text(json.dumps(data), encoding="utf-8")
    requests = parse_json_payloads(file_path)
    assert len(requests) == 2
    assert requests[0].request_id == "wrap-1"
    assert requests[1].request_id == "wrap-2"


def test_parse_ndjson_payloads(tmp_path: Path) -> None:
    """Verify parsing newline-delimited JSON request streams."""
    file_path = tmp_path / "stream.jsonl"
    lines = [
        json.dumps({"id": "line-1", "path": "/one"}),
        json.dumps({"id": "line-2", "path": "/two"}),
    ]
    file_path.write_text("\n".join(lines), encoding="utf-8")
    requests = parse_json_payloads(file_path)
    assert len(requests) == 2
    assert requests[0].request_id == "line-1"
    assert requests[1].path == "/two"


def test_parse_yaml_payloads(sample_clean_yaml: Path) -> None:
    """Verify parsing YAML captured requests."""
    requests = parse_yaml_payloads(sample_clean_yaml)
    assert len(requests) == 1
    assert requests[0].request_id == "yaml-01"
    assert requests[0].path == "/healthz"
    assert requests[0].headers["Host"] == "example.com"


def test_parse_csv_payloads(tmp_path: Path) -> None:
    """Verify parsing CSV traffic dumps."""
    csv_file = tmp_path / "traffic.csv"
    content = (
        "Time,IP Address,Page,Referrer,User Agent\n"
        "2026-11-01T10:00:00Z,1.2.3.4,/test?user=admin,https://evil.com,Mozilla/5.0\n"
    )
    csv_file.write_text(content, encoding="utf-8")
    requests = parse_csv_payloads(csv_file)
    assert len(requests) == 1
    assert requests[0].client_ip == "1.2.3.4"
    assert requests[0].path == "/test"
    assert requests[0].query_params["user"] == "admin"
    assert requests[0].headers["Referer"] == "https://evil.com"


def test_parse_log_payloads(sample_access_log: Path) -> None:
    """Verify parsing Nginx access logs."""
    requests = parse_log_payloads(sample_access_log)
    assert len(requests) == 2
    assert requests[0].client_ip == "192.0.2.1"
    assert requests[0].path == "/items"
    assert requests[0].query_params["cat"] == "tech"
    assert requests[1].client_ip == "192.0.2.2"
    assert requests[1].path == "/search"


def test_find_payload_files(tmp_path: Path) -> None:
    """Verify recursive file discovery across supported extensions."""
    (tmp_path / "one.json").write_text("[]\n", encoding="utf-8")
    (tmp_path / "two.yaml").write_text("[]\n", encoding="utf-8")
    (tmp_path / "three.csv").write_text("head\n", encoding="utf-8")
    (tmp_path / "ignore.bin").write_text("bin\n", encoding="utf-8")

    found = find_payload_files(tmp_path)
    names = [f.name for f in found]
    assert "one.json" in names
    assert "two.yaml" in names
    assert "three.csv" in names
    assert "ignore.bin" not in names


def test_parse_payload_file_dispatch(sample_clean_json: Path, tmp_path: Path) -> None:
    """Verify parse_payload_file dispatches correctly."""
    reqs = parse_payload_file(sample_clean_json)
    assert len(reqs) == 2

    # Fallback with unknown extension
    unk = tmp_path / "payload.raw"
    unk.write_text(sample_clean_json.read_text(encoding="utf-8"), encoding="utf-8")
    reqs_unk = parse_payload_file(unk)
    assert len(reqs_unk) == 2
