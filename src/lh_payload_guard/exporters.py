# ==============================================================================
# Product:       lh-payload-guard (lh-payload)
# Module:        src.lh_payload_guard.exporters
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Report exporters for lh-payload-guard: Rich Table, JSON, and OASIS SARIF v2.1.0."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lh_payload_guard.models import (
    RULES_REGISTRY,
    AuditReport,
    FindingSeverity,
)


def severity_to_style(severity: FindingSeverity) -> str:
    """Return Rich markup style for severity rating."""
    mapping = {
        FindingSeverity.CRITICAL: "bold red",
        FindingSeverity.HIGH: "red",
        FindingSeverity.MEDIUM: "yellow",
        FindingSeverity.LOW: "blue",
    }
    return mapping.get(severity, "white")


def severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to OASIS SARIF 2.1.0 level."""
    mapping = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
    }
    return mapping.get(severity, "note")


def render_table_report(report: AuditReport, console: Console | None = None) -> None:
    # --- Rich Terminal Table Presentation Layout ---
    # Renders structured security findings with ANSI color highlights,
    # severity-coded badges, file locations, and executive posture summaries.
    """Render an enterprise Rich table report of payload audit findings."""
    con = console or Console()

    if not report.findings:
        con.print(
            Panel(
                f"[bold green]No payload injection vectors or malicious input anomalies detected "
                f"across {report.requests_analyzed} request(s) in '{report.target}'.[/]",
                title="[bold green]Payloads Clean[/]",
                border_style="green",
            )
        )
        return

    table = Table(
        title=(
            f"lh-payload-guard Audit Report "
            f"({report.findings_count} Findings | Risk Score: {report.risk_score}/100)"
        ),
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", width=18)
    table.add_column("Request / Target", width=24)
    table.add_column("Description & Evidence", width=46)

    for f in report.findings:
        sev_style = severity_to_style(f.severity)
        desc_text = f.description
        if f.evidence:
            desc_text += f"\n[dim]{f.evidence}[/dim]"
        req_loc = f"{f.request_id} ({f.location})"
        table.add_row(
            f.rule_id,
            f"[{sev_style}]{f.severity.value}[/]",
            f.category,
            req_loc,
            desc_text,
        )

    con.print(table)

    summary_text = (
        f"[bold red]Critical:[/] {report.summary.get('critical', 0)} | "
        f"[red]High:[/] {report.summary.get('high', 0)} | "
        f"[yellow]Medium:[/] {report.summary.get('medium', 0)} | "
        f"[blue]Low:[/] {report.summary.get('low', 0)} | "
        f"[bold]Risk Score:[/] {report.risk_score}/100 | "
        f"[bold]Requests Analyzed:[/] {report.requests_analyzed}"
    )
    con.print(Panel(summary_text, title="[bold]Payload Audit Summary[/]", border_style="cyan"))


def export_json(report: AuditReport, indent: int = 2) -> str:
    """Export payload audit report as structured JSON document."""
    data: dict[str, Any] = {
        "schema_version": "1.0.0",
        "scanner": "lh-payload-guard",
        "target": report.target,
        "files_scanned": report.files_scanned,
        "requests_analyzed": report.requests_analyzed,
        "findings_count": report.findings_count,
        "risk_score": report.risk_score,
        "summary": report.summary,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "category": f.category,
                "request_id": f.request_id,
                "location": f.location,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=indent)


def export_sarif(report: AuditReport, indent: int = 2) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export payload audit report complying with OASIS SARIF v2.1.0 standard."""
    rules_list: list[dict[str, Any]] = []
    for rule_id, rule_def in RULES_REGISTRY.items():
        rules_list.append(
            {
                "id": rule_id,
                "name": rule_def.title.replace(" ", ""),
                "shortDescription": {"text": rule_def.title},
                "fullDescription": {"text": rule_def.description},
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(rule_def.severity),
                },
                "help": {
                    "text": (
                        f"Rule {rule_id}: {rule_def.title}\n"
                        f"Category: {rule_def.category}\n"
                        f"Remediation: {rule_def.remediation}"
                    )
                },
                "properties": {
                    "category": rule_def.category,
                    "severity": rule_def.severity.value,
                },
            }
        )

    results_list: list[dict[str, Any]] = []
    for f in report.findings:
        level = severity_to_sarif_level(f.severity)
        msg_text = f.description
        if f.evidence:
            msg_text += f" Evidence: {f.evidence}"

        results_list.append(
            {
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": msg_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": report.target,
                            },
                        }
                    }
                ],
            }
        )

    sarif_data: dict[str, Any] = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-payload-guard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-payload-guard",
                        "rules": rules_list,
                    }
                },
                "results": results_list,
            }
        ],
    }
    return json.dumps(sarif_data, indent=indent)
