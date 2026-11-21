"""Network Shield's events report: what it refused, told in plain words.

A story is HTML with a few bold spans; every value put in it — a domain, a host, an agent's
name, all from outside Blackbox — is escaped first.

Three sources, newest first:

* the enforcer's refusals of the verified graph's malicious domains (``enforcement.recent_blocks``;
  ads and trackers are counted, not told one by one);
* what the enforcer watched: SSH sessions into this machine, changes to the login files, the
  malicious connections it cut (``watch.events``);
The guard's lockdown and block-list findings stay in the public shield's own report; these are
added to it (``ShieldExtension.events``) and merged newest first.
"""

from __future__ import annotations

from html import escape
from typing import Any

from ....shields.contract import EventFact, ShieldEvent
from ....shields.network.events import NO_SESSION as _NO_SESSION
from ..protect import enforcement
from ..monitor import watch

MAX_EVENTS = 100


def _dns_event(block: dict[str, Any]) -> ShieldEvent:
    domain = str(block.get("domain") or "")
    return ShieldEvent(
        ts=float(block.get("ts") or 0), identifier=f"ioc:domain:{domain}",
        title=f"Blocked a malicious domain: {domain}", severity="high", outcome="blocked", tool="dns",
        command="", asked="", logo="", session=_NO_SESSION,
        story=f"Something on this Mac looked up <b>{escape(domain)}</b>, which Blackbox's verified threat graph lists "
              "as malicious. DNS Shield refused the lookup, so nothing connected to it.",
        what_to_do=("If you did not expect this, check which app was running at that time (Network page).",),
        facts=(EventFact("Domain", domain, mono=True), EventFact("List", "Verified threat graph")),
    )


#: What a person should do about each kind of watch event.
_WATCH_ADVICE = {
    "ssh-session-new": "If you did not expect it, switch Remote Login off (System Settings → General → Sharing) "
                       "or turn on SSH lockdown in Network Shield.",
    "ssh-session-ended": "Nothing to do; it is shown so the session's end is on record.",
    "file-changed": "If you did not change it, look at the file now: a new key in authorized_keys lets someone log in.",
    "connection-cut": "Nothing to do. Check the Network page for which app made the connection.",
    "remote-login-changed": "If you did not change it, check System Settings → General → Sharing.",
}


def _watch_event(event: dict[str, Any]) -> ShieldEvent:
    kind = str(event.get("kind"))
    text = watch.text_of(event)
    subject = str(event.get("remote_ip") or event.get("path") or "")
    identifier = f"ioc:ip:{subject}" if kind == "connection-cut" else f"network:{kind}"
    facts = [EventFact("Address", subject, mono=True)] if event.get("remote_ip") else []
    if event.get("path"):
        facts = [EventFact("File", subject, mono=True), EventFact("Change", str(event.get("change") or ""))]
    return ShieldEvent(
        ts=float(event.get("ts") or 0), identifier=identifier, title=text.rstrip("."),
        severity=watch.SEVERITY.get(kind, "info"), outcome="blocked" if kind == "connection-cut" else "flagged",
        tool="network", command="", asked="", logo="", session=_NO_SESSION,
        story=escape(text), what_to_do=(_WATCH_ADVICE.get(kind, ""),), facts=tuple(facts),
    )


def report() -> list[ShieldEvent]:
    """Desktop's events of the shield, newest first: the helper's refusals and what it watched."""
    events = [_dns_event(block) for block in enforcement.recent_blocks(MAX_EVENTS) if block.get("list") == "verified"]
    events += [_watch_event(event) for event in watch.events(MAX_EVENTS)]
    return sorted(events, key=lambda event: -event.ts)[:MAX_EVENTS]
