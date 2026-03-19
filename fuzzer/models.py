"""Dataclass models used across the fuzzer pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class RequestTemplate:
    method: str
    path: str
    params: dict[str, str]
    source: str
    input_names: list[str]


@dataclass(slots=True)
class FuzzedRequest:
    method: str
    url: str
    params: dict[str, str]
    source_template: str
    mutation_notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExecutionResult:
    request: FuzzedRequest
    status_code: int | None
    response_len: int
    response_hash: str
    elapsed_ms: float
    reflected_inputs: list[str]
    error_keywords: list[str]
    coverage_ids: list[str]
    exception_text: str | None
    response_snippet: str


@dataclass(slots=True)
class Finding:
    request: dict
    reasons: list[str]
    score: int
    status_code: int | None
    response_hash: str
    coverage_ids: list[str]
    response_snippet: str
