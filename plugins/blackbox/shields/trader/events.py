"""Trader Shield's full events report: every event it claims, with the session around it (local only).

``TRADER.events`` answers the dashboard's full-screen events window with
:class:`~..contract.ShieldEvent` records. Each event is one time the agent reached for a
wallet vault, a seed phrase, a key, an exchange key, a token approval or the keychain,
told the way a person reads it:

* ``outcome`` (blocked / flagged), ``title``, ``identifier``, ``severity``, ``ts``;
* ``tool`` and ``command`` — the exact tool call (redacted, size-capped);
* ``asked`` — the request in the conversation just before the agent acted (redacted);
* ``logo`` — the wallet's logo URL for a vault event whose pack ships one, else "";
* ``story`` — what happened, in sentences: HTML-safe text with a few ``<b>`` / ``<q>``
  spans (every value from the logs is HTML-escaped into it);
* ``what_to_do`` — plain sentences; ``facts`` — labelled values (``mono`` for a command);
* ``session`` — agent, model, start/end, how it ended;
* ``timeline`` — that session's steps in order (model calls, tool calls, file reads,
  installs, threats met on the way — e.g. a prompt injection in what the agent read),
  each naming the threats it raised, the step that triggered the event marked ``this``.

The prose (story, what to do, "Why it matters", "Reached for") was the dashboard's
JavaScript (``WALLET_WHY``, ``wevStory``, ``wevTodo``, ``wevFacts``, ``walletRows``) and
moved here verbatim so it is tested and the window can draw any shield's events.

PRIVATE BY CONSTRUCTION: everything is read from this machine's own audit logs through
the one session reconstruction the local graph also uses (:func:`audit.read_local_activity`).
Trader findings carry ``source: "secret"``, which the community share gate never sends,
so none of this ever reaches the community graph. Text is clamped here with
``kernel.display_safety.log_safe``; the dashboard sanitises every record once more where
it serves them — this module never imports the dashboard.

Usage::

    events.report(trader.claims, blocking=True)   # -> [ShieldEvent, ...] newest first
"""

from __future__ import annotations

import html
import logging
import re
from dataclasses import replace
from typing import Any, Callable, Mapping, Optional

from ... import audit

logger = logging.getLogger(__name__)
from ...kernel.display_safety import log_safe
from ..contract import EventFact, SessionSummary, ShieldEvent, TimelineStep
from . import kinds, mode as trader_mode

MAX_REPORT_EVENTS = 100
#: Steps shown per session; a long session keeps the steps nearest the event.
MAX_TIMELINE_STEPS = 40
SESSIONS_SCANNED = 200
#: The ingest cap on an identifier (the dashboard's ``safe_payloads.MAX_IDENTIFIER_CHARS``).
MAX_IDENTIFIER_CHARS = 512
#: Earlier threats named in the story and the facts ("Warning signs before it").
MAX_WARNINGS = 3

#: "Is this finding mine?" — the shield's own ``claims``.
Claims = Callable[[Mapping[str, Any]], bool]

#: Why each kind of event matters ("Why it matters" in the facts).
WALLET_WHY = {
    "vault": "The vault holds your seed phrase and private keys, encrypted with your wallet password. Copied off this machine it can be cracked offline, and whoever cracks it can empty the wallet.",
    "seed": "A seed phrase IS the wallet: anyone who has the words controls every account in it, on any device, forever.",
    "key": "A private key signs transactions for its account. Whoever holds it can move the funds.",
    "keychain": "The keychain holds every password macOS saved and the key each browser uses to lock its saved passwords and cookies — including your exchange logins.",
    "approval": "A token approval lets the spender move your tokens whenever it likes, without asking again. An unlimited one covers every token you will ever hold of that kind — it is how most wallets are drained.",
    "exchange": "An exchange API key trades — and, if withdrawals are allowed, withdraws — as your account. A key sent anywhere but its own exchange has been handed to someone else.",
}
#: What a wallet event is after, for events recorded before threat profiles named it.
GOAL = {"vault": "the wallet's keys — to empty the wallet",
        "seed": "the wallet itself — the recovery words control every account in it",
        "key": "the account's signing key — to move its funds"}
#: The plain key identifiers, each with what "Reached for" says about it.
_KEYS = {"secret:wallet-private-key": "a wallet private key, written next to a key label",
         "secret:solana-private-key": "a Solana secret key (what Phantom's \"Export private key\" shows, or a Solana CLI key file)",
         "secret:bitcoin-private-key": "a Bitcoin private key (a WIF key, or an xprv / yprv / zprv extended key that opens the whole wallet)"}
_APPROVALS = {"secret:token-approval-drainer": "a token approval to an address listed as a wallet drainer",
              "secret:token-approval-unlimited": "an unlimited token approval (approve MAX or approve-all)",
              "secret:token-approval-unchecked-spender": "a token approval to a spender Blackbox cannot check "
                                                         "(an ENS name, or an exchange router on a chain the call does not name)"}
#: A finding's title or evidence names its wallet or exchange in brackets: "… (MetaMask)".
_NAMED = re.compile(r"\(([^)]+)\)")
#: The facts a threat profile adds, in order: (label, its two key spellings, mono). The profile's
#: outcome and tool are left out — the facts already say both.
_PROFILE_FACTS = (("What it's after", ("threatGoal", "threat_goal"), False),
                  ("At risk", ("resourceAtRisk", "resource_at_risk"), False),
                  ("Technique", ("attackTechnique", "attack_technique"), True),
                  ("Agent action", ("agentAction", "agent_action"), False),
                  ("Found in", ("injectionContext", "context", "iocContext", "ioc_context"), False),
                  ("Matched by", ("matchedBy", "matched_by"), False),
                  ("Verified rule", ("verifiedSubject", "verified_subject"), True),
                  ("Blackbox version", ("blackboxVersion", "blackbox_version"), True))
_WORDED = {"What it's after", "At risk", "Agent action", "Found in"}   # hyphens read as spaces


def local_text(value: Any, limit: int) -> str:
    """Text from this machine's own logs, for the page: controls stripped and clamped.

    Not :func:`..safe_payloads.safe_text`: that one defangs indicators for community-written
    text, and would show the operator's own ``backup.tgz`` as ``backup[.]tgz``. These values
    were redacted when they were logged, and the page escapes them when it inserts them."""
    return log_safe(value if value is not None else "", limit)


def _escaped(text: str) -> str:
    """*text* safe inside the story's HTML: escaped exactly as the page's ``esc()`` does."""
    return html.escape(text, quote=True).replace("&#x27;", "&#39;")


def _named(text: str, default: str) -> str:
    match = _NAMED.search(text)
    return match.group(1) if match else default


def _last_request(context: Optional[dict[str, Any]]) -> str:
    """The latest user turn before the action (already redacted by the audit reader)."""
    turns = (context or {}).get("turns") or []
    for turn in reversed(turns):
        if str(turn.get("role") or "").lower() == "user" and turn.get("text"):
            return local_text(turn["text"], 600)
    return ""


def _step(event: dict[str, Any], is_this: bool) -> dict[str, Any]:
    """One timeline step: what kind, when, and a short readable label."""
    kind = event.get("type") or "event"
    if kind == "api":
        label = "Asked the model " + str(event.get("model") or "")
    elif kind == "file":
        label = "{} {}".format(event.get("mode") or "read", event.get("path") or "")
    elif kind == "dependency":
        label = "install {}:{}@{}".format(event.get("ecosystem"), event.get("name"), event.get("version"))
    elif kind == "threat":   # met outside a tool call, e.g. an injection in a model request
        label = "Threat found in what the agent was given"
    else:
        label = str(event.get("action") or "")   # redacted when it was logged (audit.record)
    threats = event.get("threats") or []
    outcomes = sorted({"blocked" if t.get("decision") == "block" else "flagged" for t in threats})
    return {"type": local_text(kind, 16), "ts": event.get("ts") or 0, "tool": local_text(event.get("tool"), 40),
            "label": local_text(label, 240), "result": local_text(event.get("resultStatus"), 16),
            "threats": outcomes, "threat_titles": [local_text(t.get("title"), 120) for t in threats][:4],
            "this": is_this}


def _timeline(events: list[dict[str, Any]], index: int) -> list[dict[str, Any]]:
    """The session's steps, at most :data:`MAX_TIMELINE_STEPS`, centred on step *index*."""
    start = max(0, min(index - MAX_TIMELINE_STEPS // 2, len(events) - MAX_TIMELINE_STEPS))
    window = events[start:start + MAX_TIMELINE_STEPS]
    return [_step(event, start + offset == index) for offset, event in enumerate(window)]


def _session_summary(session: dict[str, Any]) -> dict[str, Any]:
    return {"id": local_text(session.get("shortId"), 16), "agent": local_text(session.get("agent"), 24),
            "model": local_text(session.get("model"), 64), "start": session.get("start"), "end": session.get("end"),
            "status": local_text(session.get("status"), 16), "steps": len(session.get("events") or [])}


def _warnings(timeline: tuple[TimelineStep, ...]) -> list[str]:
    """Threats met earlier in the same session (e.g. a prompt injection in a page the agent
    read): the warning signs that explain why the agent reached for the wallet."""
    titles: list[str] = []
    for step in timeline:
        if step.this:
            break
        titles.extend(title for title in step.threat_titles if title and title not in titles)
    return titles[:MAX_WARNINGS]


def _story(event: ShieldEvent, kind: str, evidence: str, blocking: bool, warned: list[str]) -> str:
    """What happened, in sentences (HTML-safe: every logged value is escaped into it)."""
    wallet = _escaped(_named(event.title, "a wallet"))
    if kind == "vault":
        did = (f"copied {wallet}'s vault (the encrypted file that holds its keys) by archiving or copying a folder that contains it"
               if evidence.startswith("copy") else f"opened {wallet}'s vault (the encrypted file that holds its keys)")
    elif kind == "seed":
        did = "handled a seed phrase — the recovery words that control a whole wallet"
    else:
        did = "handled a wallet private key — the key that signs for an account"
    where = "In a conversation with " + _escaped(event.session.model) if event.session.model else "In an agent session"
    asked = f"{where}, your agent was asked: <q>{_escaped(event.asked)}</q> " if event.asked else where + ", "
    # A blocked action never ran, so the agent "tried to"; a flagged one did run.
    verb = "tried to " if event.outcome == "blocked" else ""
    using = ((("run" if verb else "ran") + " a terminal command that would have ") if event.tool == "terminal" else
             (("use" if verb else "used") + f" its {_escaped(event.tool or 'tool')} tool in a way that would have "))
    acted = ("It then " if event.asked else "your agent ") + verb + using + did + "."
    if event.outcome == "blocked":
        outcome = " <b>Blackbox stopped it before it ran</b> — nothing was read, copied or sent, and the agent was told why."
    elif not blocking:
        outcome = " <b>Blackbox let it run and recorded it</b>, because it is set to watch only (audit mode)."
    else:
        outcome = (" <b>Blackbox flagged it and let it run</b>: handling a key on this machine is allowed (trading tools "
                   "need it); sending it off the machine is what gets blocked.")
    before = (f" Just before, Blackbox had flagged <b>{_escaped('; '.join(warned))}</b> in what the agent was given — "
              "a sign the agent was being steered there.") if warned else ""
    return asked + acted + outcome + before


def _what_to_do(kind: str, blocked: bool, asked: bool) -> tuple[str, ...]:
    """What the operator should do about the event, most important first."""
    out = []
    if blocked:
        out.append("Nothing left this machine. No action is needed for this event.")
    if kind == "vault" and blocked:
        out.append("If you asked for this on purpose (a browser backup, say), do it yourself outside the agent — Blackbox will keep agents away from the vault.")
    if kind == "vault" and not blocked:
        out.append("The action ran. Look for the copy it made (an archive or folder) and delete it, then turn on Block in Settings so it is stopped next time.")
    if kind != "vault" and not blocked:
        out.append("If this " + ("seed phrase" if kind == "seed" else "key") + " was ever pasted or sent somewhere you don't control, move the funds to a new wallet.")
    out.append("If you did not ask for this, check what the agent read just before (a web page, file or message) — it may have been told to."
               if asked else "Check what the agent read just before (a web page, file or message) — it may have been told to do this.")
    return tuple(out)


def _reached_for(kind: str, identifier: str, title: str, evidence: str) -> str:
    """What the agent reached for, in words ("" for an identifier of no known kind)."""
    how = "by copying or archiving a folder that contains it" if evidence.startswith("copy") else "by reading it directly"
    if kind == "vault":
        return _named(title or evidence, "a wallet") + "'s vault (the wallet's key store), " + how
    if kind == "seed":
        return "a seed phrase (wallet recovery words) in what the agent was handling or sending"
    if kind == "keychain":
        return "the macOS keychain (" + how.replace("it directly", "it directly, or with the security tool") + ")"
    if kind == "approval":
        return _APPROVALS[identifier]
    if kind == "exchange":
        return ("an exchange API key, in the header only that exchange uses, sent to a different site ("
                + _named(title, "an exchange") + ")")
    return _KEYS.get(identifier, "")


def _profile_facts(profile: Mapping[str, Any]) -> list[EventFact]:
    """The threat profile's closed words as facts (an "unknown" or empty value is left out)."""
    out = []
    for label, keys, mono in _PROFILE_FACTS:
        value = next((str(profile[key]) for key in keys if profile.get(key)), "")
        if label == "At risk" and value == "none-identified":
            value = ""
        if label in _WORDED:
            value = value.replace("-", " ")
        if value and value != "unknown":
            out.append(EventFact(label, value, mono))
    return out


def _facts(event: ShieldEvent, kind: str, evidence: str, profile: Mapping[str, Any],
           warned: list[str]) -> tuple[EventFact, ...]:
    """The details, in the window's order: what it reached for and why it matters, the call,
    the decision, the threat profile, the rule and the session."""
    reached = _reached_for(kind, event.identifier, event.title, evidence)
    rows = [EventFact("Reached for", reached), EventFact("Why it matters", WALLET_WHY[kind])] if reached and kind else []
    if event.command:
        rows.append(EventFact("Command", event.command, True))
    rows += [EventFact("Tool", event.tool or "—"),
             EventFact("Decision", "Blocked before it ran" if event.outcome == "blocked" else "Flagged (it ran)"),
             EventFact("Severity", event.severity or "—")]
    named = _profile_facts(profile)
    rows += named
    if not any(fact.label == "What it's after" for fact in named) and kind in GOAL:
        rows.insert(2, EventFact("What it's after", GOAL[kind]))
    if warned:
        rows.insert(2, EventFact("Warning signs before it", "; ".join(warned)))
    rows.append(EventFact("Rule", event.identifier, True))
    session = event.session
    rows.append(EventFact("Session", " · ".join(part for part in (
        session.agent, session.model, session.status, f"{session.steps or 0} steps",
        "#" + session.id if session.id else "") if part)))
    return tuple(rows)


def _logo(kind: str, title: str, evidence: str) -> str:
    """The wallet's logo URL for a vault event whose pack ships a logo, else ""."""
    if kind != "vault":
        return ""
    name = _named(title or evidence, "").strip().lower()   # the display name the finding carries
    pack_id = next((pack_id for pack_id, display in trader_mode.supported_wallets().items()
                    if display.lower() == name), "")   # by name: ids are hyphenated ("coinbase-wallet")
    return trader_mode.logo_url(pack_id)


def _event(threat: dict[str, Any], step: dict[str, Any], session: dict[str, Any], index: int,
           blocking: bool) -> ShieldEvent:
    """One event as the report window shows it (see the module doc)."""
    identifier = local_text(threat.get("identifier"), MAX_IDENTIFIER_CHARS)
    title, evidence = local_text(threat.get("title"), 160), local_text(threat.get("evidence"), 160)
    kind = kinds.event_kind(identifier)
    profile = {key: local_text(value, 48) for key, value in (threat.get("profile") or {}).items()
               if isinstance(value, str)}
    bare = ShieldEvent(
        ts=threat.get("ts") or step.get("ts") or 0, identifier=identifier, title=title,
        severity=local_text(threat.get("severity"), 16),
        outcome="blocked" if threat.get("decision") == "block" else "flagged",
        tool=local_text(threat.get("tool") or step.get("tool"), 40), command=local_text(step.get("action"), 400),
        asked=_last_request(threat.get("context")), logo=_logo(kind, title, evidence), story="",
        session=SessionSummary(**_session_summary(session)),
        timeline=tuple(TimelineStep(**fields) for fields in _timeline(session.get("events") or [], index)))
    warned = _warnings(bare.timeline)
    return replace(bare, story=_story(bare, kind, evidence, blocking, warned),
                   what_to_do=_what_to_do(kind, bare.outcome == "blocked", bool(bare.asked)),
                   facts=_facts(bare, kind, evidence, profile, warned))


def report(claims: Claims, blocking: bool) -> list[ShieldEvent]:
    """Every event *claims* says is the shield's, newest first; *blocking* is Blackbox's
    block mode (the story says "watch only" when it is off). Fail-open: empty when the
    logs are unreadable."""
    try:
        sessions = audit.read_local_activity(max_sessions=SESSIONS_SCANNED).get("sessions") or []
    except Exception:   # an unreadable log means "no events", never a broken window
        logger.warning("blackbox: Trader Shield events: the audit log could not be read", exc_info=True)
        sessions = []
    events: list[ShieldEvent] = []
    for session in sessions:
        for index, step in enumerate(session.get("events") or []):
            for threat in step.get("threats") or []:
                if claims({"identifier": str(threat.get("identifier") or "")}):
                    events.append(_event(threat, step, session, index, blocking))
    events.sort(key=lambda event: event.ts, reverse=True)
    return events[:MAX_REPORT_EVENTS]
