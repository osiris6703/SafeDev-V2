"""SafeDev V2 — Output formatting."""

from __future__ import annotations

import json
from typing import Optional

from safedev.core.models import AnalysisResult, Verdict


# ANSI color codes
_COLORS = {
    Verdict.SAFE:           "\033[92m",  # Green
    Verdict.SUSPICIOUS:     "\033[93m",  # Yellow
    Verdict.MALICIOUS:      "\033[91m",  # Red
    Verdict.UNKNOWN:        "\033[90m",  # Gray
    Verdict.ANALYSIS_ERROR: "\033[91m",  # Red
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def format_json(result: AnalysisResult) -> str:
    """Format analysis result as JSON string."""
    return json.dumps(result.to_dict(), indent=2)


def format_text(result: AnalysisResult) -> str:
    """Format analysis result as human-readable text."""
    color = _COLORS.get(result.verdict, "")
    lines = []

    lines.append("")
    lines.append(f"{'=' * 60}")
    lines.append(f"{_BOLD}SafeDev V2 — Package Analysis Report{_RESET}")
    lines.append(f"{'=' * 60}")
    lines.append("")

    lines.append(f"  Package    : {result.package_name}")

    if result.version:
        lines.append(f"  Version    : {result.version}")

    lines.append(f"  Ecosystem  : {result.ecosystem.value}")
    lines.append("")

    lines.append(f"  {_BOLD}Verdict    : {color}{result.verdict.value}{_RESET}")

    if result.verdict not in (Verdict.UNKNOWN, Verdict.ANALYSIS_ERROR):
        lines.append(
            f"  Probability: {result.malicious_probability:.4f}"
        )
        lines.append(
            f"  Threshold  : {result.threshold:.4f}"
        )

    if result.error_message:
        lines.append(f"  Error      : {result.error_message}")

    if result.evidence:
        lines.append("")
        lines.append(f"  {'─' * 50}")
        lines.append(f"  Evidence:")
        for ev in result.evidence:
            severity_color = {
                "critical": "\033[91m",
                "high": "\033[91m",
                "medium": "\033[93m",
                "low": "\033[96m",
                "info": "\033[90m",
            }.get(ev.severity, "")
            lines.append(
                f"    {severity_color}[{ev.severity.upper()}]{_RESET} "
                f"{ev.description}"
            )

    lines.append("")
    lines.append(f"{'=' * 60}")
    lines.append("")

    return "\n".join(lines)
