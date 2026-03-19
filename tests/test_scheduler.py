from fuzzer.models import FuzzedRequest
from fuzzer.scheduler import RequestScheduler


def _req(value: str = "abc") -> FuzzedRequest:
    return FuzzedRequest(
        method="GET",
        url="http://127.0.0.1:5000/search",
        params={"q": value},
        source_template="GET /search",
        mutation_notes=[],
    )


def test_feedback_mode_requeues_interesting_request() -> None:
    scheduler = RequestScheduler(mode="feedback", max_requeues_per_request=1, enable_child_mutations=False)
    req = _req("seed")
    scheduler.add_request(req, score_hint=1)

    picked = scheduler.pop_next()
    assert picked is not None
    assert scheduler.size() == 0

    scheduler.record_result(picked, interesting=True, score=50)
    assert scheduler.size() == 1

    boosted = scheduler.pop_next()
    assert boosted is not None
    assert boosted.url == req.url
    assert boosted.params == req.params


def test_random_mode_record_result_does_not_requeue() -> None:
    scheduler = RequestScheduler(mode="random")
    req = _req("seed")
    scheduler.add_request(req, score_hint=1)

    picked = scheduler.pop_next()
    assert picked is not None
    assert scheduler.size() == 0

    scheduler.record_result(picked, interesting=True, score=100)
    assert scheduler.size() == 0


def test_feedback_mode_can_emit_one_bounded_child_request() -> None:
    scheduler = RequestScheduler(mode="feedback", max_requeues_per_request=1, enable_child_mutations=True)
    req = _req("hello")
    scheduler.add_request(req, score_hint=1)

    picked = scheduler.pop_next()
    assert picked is not None
    scheduler.record_result(picked, interesting=True, score=60)

    boosted = scheduler.pop_next()
    assert boosted is not None
    assert boosted.params == {"q": "hello"}

    child = scheduler.pop_next()
    assert child is not None
    assert child.params != {"q": "hello"}
    assert "seed-mutation" in child.mutation_notes
    assert "scheduler-child" in child.mutation_notes
