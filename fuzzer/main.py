"""CLI entry point for MiniGreyWebFuzz."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path

import requests
from rich.console import Console
from rich.table import Table

from fuzzer.crawler import WebCrawler
from fuzzer.executor import RequestExecutor
from fuzzer.feedback import FeedbackAnalyzer
from fuzzer.models import Finding
from fuzzer.mutator import generate_mutations
from fuzzer.reporter import write_coverage_history, write_reports
from fuzzer.scheduler import RequestScheduler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MiniGreyWebFuzz: lightweight feedback-guided web fuzzer for Flask apps")
    parser.add_argument("--base-url", type=str, required=True, help="Base target URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--max-requests", type=int, default=300, help="Maximum requests to send")
    parser.add_argument("--timeout", type=float, default=2.0, help="Request timeout in seconds")
    parser.add_argument("--mode", type=str, choices=["random", "feedback"], default="feedback")
    parser.add_argument("--crawl-depth", type=int, default=2)
    parser.add_argument("--crawl-pages", type=int, default=30)
    parser.add_argument("--budget-per-param", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    console = Console()
    session = requests.Session()

    crawler = WebCrawler(session=session, timeout=args.timeout)
    executor = RequestExecutor(session=session, base_url=args.base_url, timeout=args.timeout)
    analyzer = FeedbackAnalyzer()
    scheduler = RequestScheduler(mode=args.mode)

    console.print(f"[bold]MiniGreyWebFuzz[/bold] mode={args.mode} target={args.base_url}")
    executor.reset_coverage()

    templates = crawler.crawl(
        base_url=args.base_url,
        start_path="/",
        max_depth=args.crawl_depth,
        max_pages=args.crawl_pages,
    )
    console.print(f"Discovered {len(templates)} request templates")

    initial_requests = []
    for template in templates:
        initial_requests.extend(generate_mutations(template, base_url=args.base_url, budget_per_param=args.budget_per_param))
    scheduler.add_initial(initial_requests)
    console.print(f"Generated {len(initial_requests)} initial fuzzed requests (queue={scheduler.size()})")

    findings: list[Finding] = []
    sent = 0
    unique_status: set[int | None] = set()
    all_coverage: set[str] = set()
    coverage_history: list[dict[str, int]] = []
    last_coverage_count = 0

    while sent < args.max_requests:
        req = scheduler.pop_next()
        if req is None:
            break

        result = executor.execute(req)
        sent += 1
        unique_status.add(result.status_code)
        all_coverage.update(result.coverage_ids)
        current_coverage_count = len(all_coverage)
        if current_coverage_count > last_coverage_count:
            coverage_history.append(
                {
                    "request_index": sent,
                    "coverage_count": current_coverage_count,
                }
            )
            last_coverage_count = current_coverage_count

        interesting, score, reasons = analyzer.analyze(result)
        scheduler.record_result(req, interesting=interesting, score=score)

        if interesting:
            findings.append(
                Finding(
                    request=asdict(result.request),
                    reasons=reasons,
                    score=score,
                    status_code=result.status_code,
                    response_hash=result.response_hash,
                    coverage_ids=result.coverage_ids,
                    response_snippet=result.response_snippet,
                )
            )

    json_path, md_path = write_reports(
        report_dir=Path("reports"),
        mode=args.mode,
        total_requests_sent=sent,
        templates=templates,
        coverage_ids=all_coverage,
        status_codes=unique_status,
        findings=findings,
    )
    coverage_history_path = write_coverage_history(Path("reports"), coverage_history)

    table = Table(title="Run Summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Mode", args.mode)
    table.add_row("Requests sent", str(sent))
    table.add_row("Templates discovered", str(len(templates)))
    table.add_row("Unique status codes", ", ".join(str(x) for x in sorted(unique_status, key=lambda x: (-1 if x is None else x))))
    table.add_row("Coverage IDs", str(len(all_coverage)))
    table.add_row("Findings", str(len(findings)))
    table.add_row("JSON report", str(json_path))
    table.add_row("Markdown report", str(md_path))
    table.add_row("Coverage history", str(coverage_history_path))
    console.print(table)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
