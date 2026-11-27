"""The agent-instances routes read only finite numbers from a query (review 2026-11-26, HIGH).

``float("nan")`` and ``float("inf")`` parse, so ``wait=nan`` on the live long-poll reached the
tracker's wait as NaN — a deadline that never passes, a thread spinning at full CPU, reachable by a
plain GET from any page — and ``offset=inf`` on ``/detail`` raised a 500. A number that is not
finite now reads as the route's default:

- ``/live`` with ``wait=nan`` / ``inf`` never waits on a non-finite or over-long time;
- ``/detail`` and ``/history`` with ``inf`` / ``nan`` answer normally, never 500;
- the same audit of the notification routes: a non-finite lease is refused (400) and an
  overflowing cursor reads as the default, never a 500.
"""

from __future__ import annotations

import math

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from plugins.blackbox.agent_hooks import tracking
from plugins.blackbox.dashboard import notify_routes
from plugins.blackbox.dashboard.agent_hooks_routes import instances


@pytest.fixture
def client(monkeypatch):
    waits: list[float] = []
    monkeypatch.setattr(tracking, "wait", lambda cursor, seconds: waits.append(seconds) or cursor)
    monkeypatch.setattr(tracking, "live", lambda: {"cursor": 1})
    monkeypatch.setattr(tracking, "detail", lambda key, **page: {"key": key, **page})
    monkeypatch.setattr(tracking, "history", lambda **query: {"query": query})
    app = FastAPI()
    instances.register(app)
    return TestClient(app), waits


@pytest.mark.parametrize("wait", ["nan", "NaN", "inf", "-inf", "1e999"])
def test_the_live_long_poll_never_waits_on_a_non_finite_time(client, wait):
    test_client, waits = client
    assert test_client.get(f"/api/agent-instances/live?cursor=1&wait={wait}").status_code == 200
    assert all(math.isfinite(seconds) and 0 <= seconds <= instances.MAX_WAIT_SECONDS for seconds in waits)


@pytest.mark.parametrize("value", ["inf", "nan", "-inf"])
def test_detail_and_history_answer_non_finite_numbers_normally(client, value):
    test_client, _ = client
    detail = test_client.get(f"/api/agent-instances/detail?key=k&offset={value}&limit={value}")
    assert detail.status_code == 200 and detail.json()["offset"] == 0
    history = test_client.get(f"/api/agent-instances/history?since={value}&until={value}&before={value}&limit={value}")
    assert history.status_code == 200
    assert all(math.isfinite(number) for number in history.json()["query"].values() if isinstance(number, float))


def test_the_notification_routes_refuse_non_finite_numbers():
    app = FastAPI()
    notify_routes.register(app, lambda *_args, **_kwargs: None)
    test_client = TestClient(app)
    for seconds in ("NaN", "Infinity", "1e400"):
        answer = test_client.post("/api/notifications/lease", content=f'{{"holder": "app", "seconds": {seconds}}}',
                                  headers={"content-type": "application/json"})
        assert answer.status_code == 400
    answer = test_client.post("/api/notifications/delivered", content='{"seq": 1e400}', headers={"content-type": "application/json"})
    assert answer.status_code == 200
