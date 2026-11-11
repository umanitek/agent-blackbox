"""Delivery — where this node's announcements, alarms and metrics go (trust-and-threat-lab W3, §03.1).

The one module of ``curate.watch`` that does outward I/O: the sinks POST to
the node's own monitor. ``curate.intake``'s watchers decide WHAT is new and
call a sink; this module only carries it.

Pattern: Strategy — any object with ``notify`` / ``notify_alarm`` /
``notify_metrics`` is a sink (:class:`IntakeSink`; tests use a list).
:class:`WebhookSink` (a JSON webhook, or a Slack incoming webhook) and
:class:`TelegramSink` POST with a 3 s timeout and never raise.

Each node's sink credential is its OWN: :func:`node_sink`
reads ``<curate home>/alarm_sink.json`` of THIS node only (mode 600), so one node's credential can never
silence or spoof another node's alarms.

Usage::

    sink = node_sink()                                     # or WebhookSink(url)
    sink.notify_alarm(item)                                # a HealthItem
    sink.notify_metrics(console.collect_metrics(...))      # C4's PipelineMetrics
    items = manifest_items(ctx.manifest, now)              # W1: the manifest watcher's items
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional, Protocol

from ...kernel.health import HealthClass, HealthItem
from ...kernel.health import manifest_watch
from .. import keys

logger = logging.getLogger(__name__)

_WEBHOOK_TIMEOUT = 3.0
#: This node's own alarm-sink credential, under ITS curate home (never another node's).
NODE_SINK_FILE = "alarm_sink.json"
_TELEGRAM_SEND = "https://api.telegram.org/bot{token}/sendMessage"
_TELEGRAM_TOKEN = re.compile(r"\d{5,}:[A-Za-z0-9_-]{30,}")
_TELEGRAM_CHAT = re.compile(r"-?\d{1,20}|@[A-Za-z0-9_]{5,32}")


@dataclass(frozen=True)
class IntakeEvent:
    """What the webhook receives for one new threat: the item's facts only."""

    identifier: str
    stage: str
    enforcement: str
    reporters: int
    lane: int


class MetricsRecord(Protocol):
    """The F-035 metrics record a sink posts — ``curate.console.PipelineMetrics``
    (C4), the ONE record for the key console and the Slack monitor. Named by
    shape here because ``console`` itself reads ``curate.watch``."""

    def as_payload(self) -> dict[str, object]: ...   # {"kind": "metrics", "metrics": {name: value}}

    def lines(self) -> list[str]: ...                # "name: value" per metric


class IntakeSink(Protocol):
    """Where announcements go. Each method returns False when the notification
    was NOT delivered (the watcher then tries again next round); True or None
    counts as delivered."""

    def notify(self, event: IntakeEvent) -> Optional[bool]: ...

    def notify_alarm(self, item: Any) -> Optional[bool]: ...

    def notify_metrics(self, record: MetricsRecord) -> Optional[bool]: ...


class SinkCredentialError(ValueError):
    """This node's alarm-sink credential is missing, exposed or damaged (the watcher must not run deaf)."""


class WebhookSink:
    """POSTs JSON to *url*. ``chat=True`` (a Slack incoming webhook) sends ``{"text": …}``;
    otherwise the structured body. Fail-open: a failed delivery is logged, never raised."""

    def __init__(self, url: str, *, chat: bool = False) -> None:
        self._url = url
        self._chat = chat

    def notify(self, event: IntakeEvent) -> bool:
        return self._send(asdict(event), _event_text(event), event.identifier)

    def notify_alarm(self, item: Any) -> bool:
        """R10b: a curator-audience alarm ({audience, class, message, what_to_do})."""
        return self._send({"kind": "alarm", **item.as_dict()}, alarm_text(item), item.message)

    def notify_metrics(self, record: MetricsRecord) -> bool:
        """F-035: the metrics record ({"kind": "metrics", "metrics": {name: value}})."""
        return self._send(record.as_payload(), metrics_text(record), "metrics")

    def _send(self, body: dict, text: str, what: str) -> bool:
        return _post(self._url, {"text": text} if self._chat else body, what)

    def __repr__(self) -> str:
        return f"WebhookSink(chat={self._chat})"   # the URL is a credential


class TelegramSink:
    """Sends each notification as a Telegram message from this node's own bot."""

    def __init__(self, bot_token: str, chat_id: str) -> None:
        self._url = _TELEGRAM_SEND.format(token=bot_token)
        self._chat_id = chat_id

    def notify(self, event: IntakeEvent) -> bool:
        return self._send(_event_text(event), event.identifier)

    def notify_alarm(self, item: Any) -> bool:
        return self._send(alarm_text(item), item.message)

    def notify_metrics(self, record: MetricsRecord) -> bool:
        return self._send(metrics_text(record), "metrics")

    def _send(self, text: str, what: str) -> bool:
        return _post(self._url, {"chat_id": self._chat_id, "text": text}, what)

    def __repr__(self) -> str:
        return "TelegramSink()"   # the token is a credential


def _post(url: str, body: dict, what: str) -> bool:
    """True when the endpoint accepted the POST (a failed delivery is logged — never the URL,
    which holds the credential — and retried next round)."""
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=_WEBHOOK_TIMEOUT):
            return True
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning("blackbox curate: webhook failed for %s: %s", what, type(exc).__name__)
        return False


def alarm_text(item: Any) -> str:
    """One chat line for an alarm: class, message, what to do."""
    return f"[{item.klass.value.upper()}] {item.message} — {item.what_to_do}"


def metrics_text(record: MetricsRecord) -> str:
    return "\n".join(["Blackbox curation metrics"] + record.lines())


def _event_text(event: IntakeEvent) -> str:
    return (f"New threat {event.identifier} · stage {event.stage} · {event.enforcement} · "
            f"{event.reporters} reporter(s) · lane {event.lane}")


def node_sink(home: Optional[Path] = None) -> IntakeSink:
    """This node's own alarm sink, read from ``<home>/alarm_sink.json`` (default: this
    node's curate home) and from nowhere else. The file (mode 600) holds one of::

        {"kind": "slack", "url": "https://hooks.slack.com/services/…"}
        {"kind": "webhook", "url": "https://…"}
        {"kind": "telegram", "bot_token": "123456:…", "chat_id": "-100…"}

    Raises :class:`SinkCredentialError` when it is missing, readable by other
    users, or damaged — fail closed: a watcher with no channel must say so."""
    path = (home or keys.curate_home()) / NODE_SINK_FILE
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise SinkCredentialError(f"no readable {NODE_SINK_FILE} in this node's curate home; write it (mode 600) "
                                  "or pass --webhook") from exc
    if os.name == "posix" and mode & 0o077:
        raise SinkCredentialError(f"{NODE_SINK_FILE} is readable by other users; run chmod 600 on it")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        kind = str(data["kind"])
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise SinkCredentialError(f"{NODE_SINK_FILE} is damaged") from exc
    if kind == "telegram":
        token, chat = str(data.get("bot_token", "")), str(data.get("chat_id", ""))
        if _TELEGRAM_TOKEN.fullmatch(token) and _TELEGRAM_CHAT.fullmatch(chat):
            return TelegramSink(token, chat)
        raise SinkCredentialError(f"{NODE_SINK_FILE}: telegram needs a bot_token and a chat_id")
    url = str(data.get("url", ""))
    if kind in ("slack", "webhook") and url.startswith("https://"):
        return WebhookSink(url, chat=kind == "slack")
    raise SinkCredentialError(f"{NODE_SINK_FILE}: kind must be slack, webhook or telegram, with an https url")


def manifest_items(manifest: Optional[Any], now: float, home: Optional[Path] = None) -> list[HealthItem]:
    """The manifest watcher's items (W1) for the trusted *manifest* (``ctx.manifest``),
    built only through ``manifest_watch.watch_inputs`` over this node's seen-order
    record: a trusted list newer than the record → SECURITY, renewal reminders.
    Per-beat heartbeat times and lists still inside their time-lock are the
    beat's facts (SVC4), which polls its own items into the same watcher."""
    order = manifest.order if manifest is not None else None
    record = manifest_watch.SeenOrderRecord((home or keys.curate_home()) / manifest_watch.SEEN_ORDER_FILE)
    inputs = manifest_watch.watch_inputs(record, [order] if order else [], heartbeats={}, beat_interval_s=0.0,
                                         manifest_order=order, issued_day=getattr(manifest, "issued_day", ""), now=now)
    return [HealthItem("curator", HealthClass(klass), message, what_to_do)
            for klass, message, what_to_do in manifest_watch.alarms(inputs)]

