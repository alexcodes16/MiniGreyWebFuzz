"""Request scheduling for random and lightweight feedback-guided modes."""

from __future__ import annotations

import heapq
import random
from dataclasses import dataclass, field
from collections import deque

from fuzzer.models import FuzzedRequest
from fuzzer.mutator import mutate_value
from fuzzer.utils import request_key


@dataclass(order=True)
class _PrioritizedItem:
    priority: int
    index: int
    request: FuzzedRequest = field(compare=False)


class RequestScheduler:
    """Bounded scheduler that supports random and feedback-guided execution."""

    def __init__(
        self,
        mode: str,
        max_queue: int = 5000,
        seed: int = 1337,
        max_requeues_per_request: int = 2,
        enable_child_mutations: bool = True,
        max_seed_corpus: int = 100,
        max_children_per_seed: int = 5,
    ) -> None:
        if mode not in {"random", "feedback"}:
            raise ValueError("mode must be 'random' or 'feedback'")
        self.mode = mode
        self.max_queue = max_queue
        self.max_requeues_per_request = max_requeues_per_request
        self.enable_child_mutations = enable_child_mutations
        self.max_seed_corpus = max_seed_corpus
        self.max_children_per_seed = max_children_per_seed
        self._random = random.Random(seed)

        self._queue_random: list[FuzzedRequest] = []
        self._queue_feedback: list[_PrioritizedItem] = []
        self._boost_feedback: list[_PrioritizedItem] = []

        self._seen: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
        self._requeue_counts: dict[tuple[str, str, tuple[tuple[str, str], ...]], int] = {}
        self._counter = 0

        self._seed_corpus: deque[FuzzedRequest] = deque()
        self._seed_keys: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
        self._expanded_seed_keys: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()

    def add_initial(self, requests: list[FuzzedRequest]) -> None:
        for request in requests:
            self.add_request(request, score_hint=1)

    def add_request(self, request: FuzzedRequest, score_hint: int) -> bool:
        """Add a new unique request template to the main queue."""
        key = request_key(request.method, request.url, request.params)
        if key in self._seen:
            return False
        if self.size() >= self.max_queue:
            return False

        self._seen.add(key)
        self._counter += 1
        if self.mode == "random":
            self._queue_random.append(request)
        else:
            heapq.heappush(
                self._queue_feedback,
                _PrioritizedItem(priority=-max(1, score_hint), index=self._counter, request=request),
            )
        return True

    def pop_next(self) -> FuzzedRequest | None:
        if self.mode == "random":
            if not self._queue_random:
                return None
            idx = self._random.randrange(len(self._queue_random))
            return self._queue_random.pop(idx)

        if self._boost_feedback:
            return heapq.heappop(self._boost_feedback).request

        if not self._queue_feedback and self.enable_child_mutations:
            self._enqueue_children_from_seed()

        if self._queue_feedback:
            return heapq.heappop(self._queue_feedback).request
        return None

    def record_result(self, request: FuzzedRequest, interesting: bool, score: int) -> None:
        """In feedback mode, interesting requests are boosted and added to seed corpus."""
        if self.mode != "feedback" or not interesting:
            return

        key = request_key(request.method, request.url, request.params)
        used = self._requeue_counts.get(key, 0)
        if used < self.max_requeues_per_request and self.size() < self.max_queue:
            self._requeue_counts[key] = used + 1
            self._counter += 1
            heapq.heappush(
                self._boost_feedback,
                _PrioritizedItem(priority=-max(1, score), index=self._counter, request=request),
            )

        self._add_seed(request)

    def size(self) -> int:
        if self.mode == "random":
            return len(self._queue_random)
        return len(self._queue_feedback) + len(self._boost_feedback)

    def _add_seed(self, request: FuzzedRequest) -> None:
        """Store unique interesting requests in a bounded seed corpus."""
        key = request_key(request.method, request.url, request.params)
        if key in self._seed_keys:
            return

        if len(self._seed_corpus) >= self.max_seed_corpus:
            evicted = self._seed_corpus.popleft()
            evicted_key = request_key(evicted.method, evicted.url, evicted.params)
            self._seed_keys.discard(evicted_key)
            self._expanded_seed_keys.discard(evicted_key)

        self._seed_corpus.append(request)
        self._seed_keys.add(key)

    def _enqueue_children_from_seed(self) -> None:
        """Select one seed and generate up to max_children_per_seed mutator-based children."""
        if not self._seed_corpus or self.size() >= self.max_queue:
            return

        seed_request = self._seed_corpus[0]
        self._seed_corpus.rotate(-1)

        seed_key = request_key(seed_request.method, seed_request.url, seed_request.params)
        if seed_key in self._expanded_seed_keys:
            return

        children = self._generate_children_from_seed(seed_request, self.max_children_per_seed)
        added = 0
        for child in children:
            if self.add_request(child, score_hint=2):
                added += 1
            if added >= self.max_children_per_seed or self.size() >= self.max_queue:
                break

        self._expanded_seed_keys.add(seed_key)

    def _generate_children_from_seed(self, seed_request: FuzzedRequest, limit: int) -> list[FuzzedRequest]:
        """Generate bounded child requests by mutating one parameter at a time from a seed."""
        if limit <= 0 or not seed_request.params:
            return []

        children: list[FuzzedRequest] = []
        names = sorted(seed_request.params.keys())

        for name in names:
            original = str(seed_request.params.get(name, ""))
            for mutated_value, _note in mutate_value(original):
                if mutated_value == original:
                    continue
                child_params = dict(seed_request.params)
                child_params[name] = mutated_value
                child = FuzzedRequest(
                    method=seed_request.method,
                    url=seed_request.url,
                    params=child_params,
                    source_template=seed_request.source_template,
                    mutation_notes=[*seed_request.mutation_notes, "seed-mutation", "scheduler-child", f"param={name}"],
                )
                children.append(child)
                if len(children) >= limit:
                    return children

        return children
