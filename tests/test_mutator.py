from fuzzer.models import RequestTemplate
from fuzzer.mutator import basic_payloads, generate_mutations


def test_basic_payloads_not_empty() -> None:
    payloads = basic_payloads()
    assert payloads


def test_long_payload_exists() -> None:
    payloads = basic_payloads()
    assert any(len(p) >= 100 for p in payloads)


def test_generate_mutations_preserve_param_names() -> None:
    template = RequestTemplate(
        method="GET",
        path="/search",
        params={"q": "hello", "page": "1"},
        source="unit-test",
        input_names=["q", "page"],
    )
    mutations = generate_mutations(template, base_url="http://127.0.0.1:5000", budget_per_param=5)
    assert mutations
    for req in mutations:
        assert set(req.params.keys()) == {"q", "page"}


def test_generate_mutations_are_deduplicated_sufficiently() -> None:
    template = RequestTemplate(
        method="POST",
        path="/login",
        params={"username": "admin", "password": "admin"},
        source="unit-test",
        input_names=["username", "password"],
    )
    mutations = generate_mutations(template, base_url="http://127.0.0.1:5000", budget_per_param=20)
    unique = {(m.method, m.url, tuple(sorted(m.params.items()))) for m in mutations}
    assert len(unique) == len(mutations)
    assert len(mutations) <= 50
