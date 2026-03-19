from fuzzer.feedback import FeedbackAnalyzer
from fuzzer.models import ExecutionResult, FuzzedRequest


def _result(
    *,
    status: int | None = 200,
    response_hash: str = "h1",
    response_len: int = 100,
    reflected: list[str] | None = None,
    errors: list[str] | None = None,
    coverage: list[str] | None = None,
    exc: str | None = None,
) -> ExecutionResult:
    req = FuzzedRequest(
        method="GET",
        url="http://127.0.0.1:5000/search",
        params={"q": "x"},
        source_template="GET /search",
        mutation_notes=[],
    )
    return ExecutionResult(
        request=req,
        status_code=status,
        response_len=response_len,
        response_hash=response_hash,
        elapsed_ms=1.5,
        reflected_inputs=reflected or [],
        error_keywords=errors or [],
        coverage_ids=coverage or [],
        exception_text=exc,
        response_snippet="snippet",
    )


def test_new_coverage_is_interesting() -> None:
    analyzer = FeedbackAnalyzer()
    interesting, score, reasons = analyzer.analyze(_result(coverage=["search:normal"]))
    assert interesting
    assert score >= 25
    assert any("coverage" in reason for reason in reasons)


def test_reflection_increases_interestingness() -> None:
    analyzer = FeedbackAnalyzer()
    _, score_plain, _ = analyzer.analyze(_result(response_hash="x1"))
    _, score_reflect, reasons = analyzer.analyze(_result(response_hash="x2", reflected=["payload"]))
    assert score_reflect > score_plain
    assert any("reflection" in reason for reason in reasons)


def test_repeated_result_becomes_less_interesting() -> None:
    analyzer = FeedbackAnalyzer()
    _, score_first, _ = analyzer.analyze(_result(status=200, response_hash="same"))
    _, score_second, reasons_second = analyzer.analyze(_result(status=200, response_hash="same"))
    assert score_second <= score_first
    assert reasons_second == ["repeated behavior signature"] or score_second < score_first


def test_error_or_exception_boosts_score() -> None:
    analyzer = FeedbackAnalyzer()
    _, score_error, _ = analyzer.analyze(_result(response_hash="err1", errors=["exception"]))
    _, score_exc, reasons = analyzer.analyze(_result(response_hash="err2", exc="timeout"))
    assert score_error > 0
    assert score_exc >= score_error - 10
    assert any("exception" in reason for reason in reasons)
