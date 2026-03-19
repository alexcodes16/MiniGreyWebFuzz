"""Feedback analyzer that scores execution results for interestingness."""

from __future__ import annotations

from dataclasses import dataclass, field

from fuzzer.models import ExecutionResult


@dataclass
class FeedbackAnalyzer:
    """Track seen behavior and score new/interesting execution outcomes."""

    seen_status_codes: set[int | None] = field(default_factory=set)
    seen_response_hashes: set[str] = field(default_factory=set)
    seen_coverage_ids: set[str] = field(default_factory=set)
    seen_signatures: set[tuple[int | None, str]] = field(default_factory=set)
    baseline_response_len: int | None = None

    def analyze(self, result: ExecutionResult) -> tuple[bool, int, list[str]]:
        """Score a result and return whether it is worth prioritizing."""
        score = 0
        reasons: list[str] = []

        if result.status_code not in self.seen_status_codes:
            score += 14
            reasons.append(f"new status code {result.status_code}")
            self.seen_status_codes.add(result.status_code)

        if result.response_hash and result.response_hash not in self.seen_response_hashes:
            score += 6
            reasons.append("new response body hash")
            self.seen_response_hashes.add(result.response_hash)

        new_cov = sorted(set(result.coverage_ids) - self.seen_coverage_ids)
        if new_cov:
            score += 55 + min(25, len(new_cov) * 5)
            reasons.append(f"new coverage ids: {', '.join(new_cov[:5])}")
            self.seen_coverage_ids.update(new_cov)

        if result.reflected_inputs:
            score += 10
            reasons.append("input reflection observed")

        if result.error_keywords:
            score += 18
            reasons.append(f"error keywords: {', '.join(result.error_keywords)}")

        if result.exception_text:
            score += 28
            reasons.append("request exception occurred")

        signature = (result.status_code, result.response_hash)
        if signature not in self.seen_signatures:
            self.seen_signatures.add(signature)
        else:
            score = max(0, score - 15)
            if not reasons:
                reasons.append("repeated behavior signature")

        if self.baseline_response_len is None and result.response_len > 0:
            self.baseline_response_len = result.response_len
        elif self.baseline_response_len:
            diff_ratio = abs(result.response_len - self.baseline_response_len) / max(self.baseline_response_len, 1)
            if diff_ratio > 0.8:
                score += 8
                reasons.append("large response length deviation")

        interesting = bool(new_cov) or bool(result.exception_text) or score >= 35
        return interesting, score, reasons
