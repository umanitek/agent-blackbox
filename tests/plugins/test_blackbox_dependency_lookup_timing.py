"""A 2,000-package lockfile is judged within the hot-path budget: its store queries run side by side.

Security round 4 (bb-sec-r4, 4-CPU VM, REAL ruleset): a cold check of a 2,000-package
package-lock.json took 67 ms (target < 50 ms); asked again with the file cached it still took 40 ms
— the live lookup, four 1,000-candidate questions of about ten 200-value queries each, asked one
after another (9–13 ms per question). Now one question carries every candidate (the lookup's own
4,000-value cap) and its queries run on a small shared pool, in query order for the answer.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

from plugins.blackbox.detection.manifests import verdicts
from plugins.blackbox.kernel.store.client import StoreAnswer
from plugins.blackbox.ruleset.live import lookup as live_lookup
from plugins.blackbox.ruleset.live.health import LookupHealth

class _Store:
    """A store whose first query waits until a second one is being asked beside it (bounded): a
    lookup asking one query after another never gets there."""

    def __init__(self):
        self.asked = 0
        self.most_at_once = 0
        self._now = 0
        self._lock = threading.Lock()
        self._together = threading.Event()

    def select(self, sparql, *, timeout=None):
        with self._lock:
            self.asked += 1
            self._now += 1
            self.most_at_once = max(self.most_at_once, self._now)
            if self._now > 1:
                self._together.set()
        self._together.wait(timeout=0.5)
        with self._lock:
            self._now -= 1
        return StoreAnswer([])


def _lookup(tmp_path, store):
    scope = SimpleNamespace(ready=True, spellings=lambda eco, name: [name], assertion_graphs=set(), suppressed_subjects=set())
    return live_lookup.VerifiedLookup(scope, store, LookupHealth(tmp_path / "state.json"))


def test_a_2000_package_lockfiles_lookup_runs_its_queries_side_by_side(tmp_path):
    store = _Store()
    candidates = [("npm", f"r4-filler-{i:05d}", version) for i in range(2000) for version in ("1.0.0", "*")]
    answer = _lookup(tmp_path, store).dependencies(candidates)
    assert answer.outcome == live_lookup.CLEAN and store.asked == len(candidates) // live_lookup.CHUNK
    assert store.most_at_once > 1, "the queries were asked one after another"


def test_the_first_query_that_could_not_tell_is_still_the_answer(tmp_path):
    answers = iter([StoreAnswer([]), StoreAnswer(None, "timeout")] + [StoreAnswer([])] * 30)
    lock = threading.Lock()

    def select(sparql, *, timeout=None):
        with lock:
            return next(answers)
    store = SimpleNamespace(select=select)
    answer = _lookup(tmp_path, store).dependencies([("npm", f"p{i}", "1") for i in range(1000)])
    assert answer.outcome == live_lookup.COULD_NOT_TELL


def test_one_lockfile_is_one_question_of_the_ruleset():
    assert verdicts.LOOKUP_CHUNK == live_lookup.MAX_VALUES
