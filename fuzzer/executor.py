"""Execution engine for sending fuzzed requests and collecting response feedback."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable

import requests

from fuzzer.models import ExecutionResult, FuzzedRequest
from fuzzer.utils import clean_snippet

ERROR_KEYWORDS = [
    "exception",
    "traceback",
    "internal server error",
    "syntax error",
    "warning",
    "invalid",
]


class RequestExecutor:
    """Execute fuzzed requests and collect observability signals."""

    def __init__(self, session: requests.Session, base_url: str, timeout: float = 2.0) -> None:
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def reset_coverage(self) -> None:
        """Reset target coverage tracker; ignore errors to keep fuzzing resilient."""
        for method in (self.session.post, self.session.get):
            try:
                method(f"{self.base_url}/__reset_coverage", timeout=self.timeout)
                return
            except requests.RequestException:
                continue

    def fetch_coverage(self) -> list[str]:
        """Retrieve coverage IDs from target app, if available."""
        try:
            response = self.session.get(f"{self.base_url}/__coverage", timeout=self.timeout)
            payload = response.json()
            coverage = payload.get("coverage", [])
            if isinstance(coverage, list):
                return sorted(str(x) for x in coverage)
        except (requests.RequestException, ValueError, TypeError):
            return []
        return []

    def execute(self, request: FuzzedRequest) -> ExecutionResult:
        """Send a single request and capture response and feedback signals."""
        self.reset_coverage()

        start = time.perf_counter()
        try:
            if request.method.upper() == "POST":
                response = self.session.post(request.url, data=request.params, timeout=self.timeout)
            else:
                response = self.session.get(request.url, params=request.params, timeout=self.timeout)

            text = response.text
            status_code = response.status_code
            response_len = len(text)
            response_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
            reflected = self._find_reflections(request.params.values(), text)
            error_hits = self._find_error_keywords(text)
            coverage = self.fetch_coverage()
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            snippet = clean_snippet(text)

            return ExecutionResult(
                request=request,
                status_code=status_code,
                response_len=response_len,
                response_hash=response_hash,
                elapsed_ms=elapsed_ms,
                reflected_inputs=reflected,
                error_keywords=error_hits,
                coverage_ids=coverage,
                exception_text=None,
                response_snippet=snippet,
            )

        except requests.RequestException as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return ExecutionResult(
                request=request,
                status_code=None,
                response_len=0,
                response_hash="",
                elapsed_ms=elapsed_ms,
                reflected_inputs=[],
                error_keywords=[],
                coverage_ids=self.fetch_coverage(),
                exception_text=str(exc),
                response_snippet="",
            )

    @staticmethod
    def _find_reflections(values: Iterable[object], response_text: str) -> list[str]:
        detected: list[str] = []
        for value in (str(v) for v in values):
            trimmed = value.strip()
            if not trimmed:
                continue
            if len(trimmed) < 2:
                continue
            if trimmed in response_text and trimmed not in detected:
                detected.append(trimmed)
        return detected

    @staticmethod
    def _find_error_keywords(response_text: str) -> list[str]:
        lower = response_text.lower()
        return [kw for kw in ERROR_KEYWORDS if kw in lower]
