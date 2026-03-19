"""Shared helper utilities for MiniGreyWebFuzz."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlparse


def now_iso() -> str:
    """Return UTC timestamp in compact ISO format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_path(path: str) -> str:
    """Normalize path to a stable form for template deduplication."""
    if not path:
        return "/"
    parsed = urlparse(path)
    value = parsed.path or "/"
    if not value.startswith("/"):
        value = "/" + value
    if len(value) > 1 and value.endswith("/"):
        value = value[:-1]
    return value


def stable_param_items(params: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Return params as sorted tuple pairs for deterministic keys."""
    return tuple(sorted((k, str(v)) for k, v in params.items()))


def template_key(method: str, path: str, params: dict[str, str]) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    """Build a template deduplication key."""
    return method.upper(), normalize_path(path), stable_param_items(params)


def request_key(method: str, url: str, params: dict[str, str]) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    """Build a request deduplication key."""
    parsed = urlparse(url)
    path = normalize_path(parsed.path)
    return method.upper(), path, stable_param_items(params)


def query_params_from_url(url: str) -> dict[str, str]:
    """Extract first-value query params from URL."""
    parsed = urlparse(url)
    return {k: v for k, v in parse_qsl(parsed.query, keep_blank_values=True)}


def clean_snippet(text: str, limit: int = 220) -> str:
    """Create compact one-line response snippet."""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
