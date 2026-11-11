"""The site a verified prompt injection was found on, as its own finding (threat-profiles D8).

When a VERIFIED injection pattern turns up in a page a web tool fetched during
this turn, the page's site is a threat indicator too: it is raised as an IOC
finding ``ioc:domain:<registrable domain>`` with reason ``injection-host``, so
the operator sees which site carried it and other nodes flag that site. Only
verified matches trigger this (LES-018: an untrusted pattern never makes this
node publish anything), only the registrable domain is used, and popular or
user-content platforms are never named (:func:`..community.injection_host_identifier`).

Usage (from the pre-API hook)::

    findings += injection_site_findings(findings, request_messages, rs)
"""

from __future__ import annotations

import json
from typing import Any, Iterator, Mapping

from .. import community, detection
from . import api_request, session_context

_URL_KEYS = ("url", "uri", "href", "link")


def _fetch_calls(messages: list[Any]) -> Iterator[tuple[str, str, Any]]:
    """``(call id, tool name, arguments)`` for every tool call in *messages*, in both wire
    shapes: Chat Completions (``tool_calls`` on an assistant turn) and the Responses API
    (``{"type": "function_call", "call_id", "name", "arguments"}`` items)."""
    for msg in messages:
        if not isinstance(msg, Mapping):
            continue
        if msg.get("type") == "function_call" and msg.get("call_id"):
            yield str(msg["call_id"]), str(msg.get("name") or ""), msg.get("arguments")
        calls = msg.get("tool_calls")
        for call in calls if isinstance(calls, list) else []:
            function = call.get("function") if isinstance(call, Mapping) else None
            if isinstance(function, Mapping) and call.get("id"):
                yield str(call["id"]), str(function.get("name") or ""), function.get("arguments")


def _call_urls(messages: list[Any]) -> dict[str, tuple[str, str]]:
    """``tool_call_id`` -> (fetch tool name, the URL it was given)."""
    urls: dict[str, tuple[str, str]] = {}
    for call_id, name, args in _fetch_calls(messages):
        tool = name.lower()
        if not tool.startswith(detection.FETCH_TOOL_PREFIXES):
            continue
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (ValueError, RecursionError):
                args = {}
        url = next((str(args[k]) for k in _URL_KEYS if isinstance(args, Mapping) and args.get(k)), "")
        if url:
            urls[call_id] = (tool, url)
    return urls


def _fetched_pages(messages: list[Any]) -> list[tuple[str, str, str]]:
    """(fetch tool, url, page text) for every fetched page returned since the last user turn.
    A tool's result is recognised by the request scanner's own reader (``api_request._tool_result``),
    so both wire shapes are read here exactly as they are scanned there (KI-365)."""
    start = max((i for i, m in enumerate(messages) if isinstance(m, Mapping) and m.get("role") == "user"), default=0)
    urls = _call_urls(messages)
    pages = []
    for msg in messages[start:]:
        result = api_request._tool_result(msg)
        if result is not None and result[0] in urls:
            pages.append((*urls[result[0]], session_context._message_text(result[1])))
    return pages


def injection_site_findings(findings: list[detection.Finding], request_messages: Any, rs: Any) -> list[detection.Finding]:
    """One ``injection-host`` IOC finding per site that carried a VERIFIED
    injection found in a fetched page this turn (deduplicated)."""
    verified = {f.identifier: f for f in findings
                if f.category == "injection" and f.source == "public" and f.fields.get("context") == "in-fetched-page"}
    if not verified:
        return []
    messages = request_messages if isinstance(request_messages, list) else []
    out: dict[str, detection.Finding] = {}
    for tool, url, text in _fetched_pages(messages):
        matched = [f for f in detection.detect_injection(text, rs, "in-fetched-page") if f.identifier in verified]
        site = community.injection_host_identifier(url) if matched else None
        if not site or site in out:
            continue
        injection = verified[matched[0].identifier]
        domain = site.split(":", 2)[2]
        out[site] = detection.Finding(
            identifier=site, category="ioc", severity=injection.severity, tool_name=tool,
            title=f"Site carried a prompt injection ({injection.title})", matched=domain,
            evidence=f"domain {domain} served {injection.identifier}", confirmed=False, source="heuristic",
            kind="injection-host",
            fields={"ioc_type": "domain", "ioc_context": "fetched-by-tool", "reason": "injection-host"})
    return list(out.values())
