"""Reporting helpers for JSON and Markdown fuzzing outputs."""

from __future__ import annotations

import json
from pathlib import Path

from fuzzer.models import Finding, RequestTemplate
from fuzzer.utils import now_iso


def write_reports(
    report_dir: Path,
    mode: str,
    total_requests_sent: int,
    templates: list[RequestTemplate],
    coverage_ids: set[str],
    status_codes: set[int | None],
    findings: list[Finding],
) -> tuple[Path, Path]:
    """Write JSON and Markdown reports for a fuzz run."""
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "findings.json"
    md_path = report_dir / "summary.md"

    payload = {
        "timestamp": now_iso(),
        "mode": mode,
        "total_requests_sent": total_requests_sent,
        "templates_discovered": [
            {
                "method": t.method,
                "path": t.path,
                "params": t.params,
                "source": t.source,
                "input_names": t.input_names,
            }
            for t in sorted(templates, key=lambda x: (x.path, x.method, tuple(x.input_names)))
        ],
        "coverage_ids_found": sorted(coverage_ids),
        "unique_status_codes": sorted(status_codes, key=lambda x: (-1 if x is None else x)),
        "total_findings": len(findings),
        "findings": [
            {
                "request": finding.request,
                "reasons": finding.reasons,
                "score": finding.score,
                "status_code": finding.status_code,
                "response_hash": finding.response_hash,
                "coverage_ids": finding.coverage_ids,
                "response_snippet": finding.response_snippet,
            }
            for finding in findings
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    top_findings = sorted(findings, key=lambda f: f.score, reverse=True)[:10]
    lines = [
        "# MiniGreyWebFuzz Run Summary",
        "",
        f"- Timestamp: {payload['timestamp']}",
        f"- Mode: `{mode}`",
        f"- Requests sent: **{total_requests_sent}**",
        f"- Templates discovered: **{len(templates)}**",
        f"- Unique status codes: **{len(status_codes)}** -> {sorted(status_codes, key=lambda x: (-1 if x is None else x))}",
        f"- Unique coverage IDs: **{len(coverage_ids)}**",
        f"- Total findings: **{len(findings)}**",
        "",
        "## Endpoints Discovered",
    ]

    for tmpl in sorted(templates, key=lambda x: (x.path, x.method)):
        param_list = ", ".join(tmpl.input_names) if tmpl.input_names else "(none)"
        lines.append(f"- `{tmpl.method} {tmpl.path}` from `{tmpl.source}` params: {param_list}")

    lines.extend(["", "## Top Findings"])
    if not top_findings:
        lines.append("- No high-signal findings were captured in this run.")
    else:
        for idx, finding in enumerate(top_findings, start=1):
            reason_text = "; ".join(finding.reasons) if finding.reasons else "No explicit reasons"
            lines.append(
                f"{idx}. Score={finding.score}, status={finding.status_code}, reasons={reason_text}, request={finding.request}"
            )

    lines.extend(
        [
            "",
            "## Interpretation",
            "Feedback-guided mode generally prioritizes requests that unlock new coverage IDs, new response patterns, reflection, or error-like behavior.",
            "Random mode explores without memory and may require more requests to hit rare branches in branch-heavy endpoints.",
        ]
    )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path


def write_coverage_history(report_dir: Path, coverage_history: list[dict[str, int]]) -> Path:
    """Write compact coverage growth points to JSON."""
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / "coverage_history.json"
    path.write_text(json.dumps(coverage_history, indent=2), encoding="utf-8")
    return path
