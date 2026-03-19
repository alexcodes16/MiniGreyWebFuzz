"""Mutation helpers for generating fuzzed web requests."""

from __future__ import annotations

from urllib.parse import urljoin

from fuzzer.models import FuzzedRequest, RequestTemplate
from fuzzer.utils import request_key


def basic_payloads() -> list[str]:
    """Return a reusable payload corpus for mutation-based fuzzing."""
    return [
        "",
        " ",
        "   ",
        "a",
        "abc123",
        "A" * 128,
        "B" * 512,
        "0",
        "-1",
        "1",
        "2147483647",
        "-2147483648",
        "'",
        '"',
        "<",
        ">",
        "&",
        "/",
        "\\",
        "../",
        "../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "%s%s%s%s",
        "admin",
        "admin'--",
        "null",
        "true",
        "false",
        "0x41414141",
        "line1\nline2",
        "\t\t",
        "😀",
        "Ω≈ç√∫˜µ≤≥÷",
    ]


def mutate_value(original: str) -> list[tuple[str, str]]:
    """Mutate a single value and return (mutated_value, note) pairs."""
    original_safe = original or ""
    candidates: list[tuple[str, str]] = [(payload, "payload-library") for payload in basic_payloads()]

    if original_safe:
        candidates.extend(
            [
                (original_safe[::-1], "reversed-original"),
                (original_safe.upper(), "uppercase-original"),
                (original_safe.lower(), "lowercase-original"),
                (original_safe + original_safe, "duplicated-original"),
                (original_safe + "_test", "suffix-appended"),
                (f"{original_safe}123", "numeric-suffix"),
            ]
        )
    else:
        candidates.append(("seed", "empty-to-seed"))

    deduped: list[tuple[str, str]] = []
    seen: set[str] = set()
    for value, note in candidates:
        if value in seen:
            continue
        seen.add(value)
        deduped.append((value, note))
    return deduped


def generate_mutations(
    template: RequestTemplate,
    base_url: str,
    budget_per_param: int = 10,
) -> list[FuzzedRequest]:
    """Generate conservative, deduplicated request mutations from a template."""
    method = template.method.upper()
    target_url = urljoin(base_url.rstrip("/") + "/", template.path.lstrip("/"))
    names = sorted(template.params.keys())

    if not names:
        return [
            FuzzedRequest(
                method=method,
                url=target_url,
                params={},
                source_template=f"{template.method} {template.path}",
                mutation_notes=["no-params-template"],
            )
        ]

    generated: list[FuzzedRequest] = []
    seen_keys: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()

    for name in names:
        original = template.params.get(name, "")
        mutations = mutate_value(original)[:budget_per_param]
        for mutated_value, note in mutations:
            params = dict(template.params)
            params[name] = mutated_value
            req = FuzzedRequest(
                method=method,
                url=target_url,
                params=params,
                source_template=f"{template.method} {template.path}",
                mutation_notes=[f"param={name}", note],
            )
            key = request_key(req.method, req.url, req.params)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            generated.append(req)

    if len(names) > 1:
        params = dict(template.params)
        notes = ["multi-param-combo"]
        for idx, name in enumerate(names[:2]):
            mutated, note = mutate_value(template.params.get(name, ""))[idx % 3]
            params[name] = mutated
            notes.append(f"{name}:{note}")
        req = FuzzedRequest(
            method=method,
            url=target_url,
            params=params,
            source_template=f"{template.method} {template.path}",
            mutation_notes=notes,
        )
        key = request_key(req.method, req.url, req.params)
        if key not in seen_keys:
            seen_keys.add(key)
            generated.append(req)

    return generated
