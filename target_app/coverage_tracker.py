"""Lightweight in-process coverage tracker for the demo Flask target app."""

from __future__ import annotations

from threading import Lock

_COVERAGE_POINTS: set[str] = set()
_LOCK = Lock()


def mark(point: str) -> None:
    """Record a coverage point identifier."""
    if not point:
        return
    with _LOCK:
        _COVERAGE_POINTS.add(point)


def get_coverage() -> list[str]:
    """Return sorted coverage IDs for deterministic output."""
    with _LOCK:
        return sorted(_COVERAGE_POINTS)


def reset_coverage() -> None:
    """Clear all recorded coverage IDs."""
    with _LOCK:
        _COVERAGE_POINTS.clear()
