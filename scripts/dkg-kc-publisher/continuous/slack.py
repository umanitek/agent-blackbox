"""Slack report and Socket Mode approval helpers."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Dict, Mapping

from .core import State, read_secret
from .pipeline import (
    bundle_export_bytes,
    decide_bundle,
    issue_approval_nonce,
    prepare_approval_preflight,
    request_publish,
    verify_bundle,
)


def _slack_api(token: str, method: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    request = urllib.request.Request(
        f"https://slack.com/api/{method}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"authorization": f"Bearer {token}", "content-type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Slack API HTTP {exc.code}") from exc
    if not result.get("ok"):
        raise RuntimeError(f"Slack API {method} failed: {result.get('error', 'unknown_error')}")
    return result


def _slack_webhook(url: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8", errors="replace").strip()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Slack incoming webhook returned HTTP {exc.code}") from exc
    if body != "ok":
        raise RuntimeError("Slack incoming webhook returned an unexpected response")
    return {"ok": True, "transport": "incoming_webhook"}


def _post_message(slack: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
    if any(slack.get(f"webhook_url_{kind}") for kind in ("credential", "file", "env")):
        return _slack_webhook(read_secret(slack, "webhook_url"), payload)
    result = _slack_api(read_secret(slack, "bot_token"), "chat.postMessage", payload)
    return {**result, "transport": "web_api"}


def _upload_bundle_json(
    slack: Mapping[str, Any], bundle_id: str, title: str, payload: bytes, thread_ts: str,
) -> Dict[str, Any]:
    """Upload the immutable approval payload into the approval message thread."""
    try:
        from slack_sdk import WebClient
    except ImportError as exc:  # pragma: no cover - deployment-only dependency
        raise RuntimeError("Slack JSON attachments require slack-sdk") from exc

    response = WebClient(token=read_secret(slack, "bot_token"), timeout=30).files_upload_v2(
        content=payload,
        filename=f"{bundle_id}.json",
        title=f"{title} — approval JSON",
        channel=str(slack["channel_id"]),
        thread_ts=thread_ts,
        initial_comment="Exact JSON covered by this approval.",
    )
    # slack_sdk's SlackResponse exposes the decoded JSON through ``.data``.
    # Iterating the response itself yields field names in some SDK releases,
    # so ``dict(response)`` can fail after an otherwise successful upload.
    response_data = getattr(response, "data", None)
    if not isinstance(response_data, Mapping):
        raise RuntimeError("Slack JSON attachment returned an invalid response")
    result = dict(response_data)
    if not result.get("ok"):
        raise RuntimeError(f"Slack JSON attachment failed: {result.get('error', 'unknown_error')}")
    return result


def _plain(text: str) -> Dict[str, Any]:
    return {"type": "plain_text", "text": text[:3000], "emoji": False}


def _labels(counter: Mapping[str, Any]) -> str:
    return ", ".join(str(key).replace("_", " ") for key in counter) or "uncategorized"


def _summary_text(summary: Mapping[str, Any]) -> tuple[str, str]:
    records = int(summary["records"])
    assets = int(summary["assets"])
    categories = _labels(summary.get("categories") or {})
    sources = _labels(summary.get("sources") or {})
    lifecycle = _labels(summary.get("lifecycle") or {})
    confidence = (summary.get("confidence") or {}).get("average", "?")
    return (
        f"{records:,} {categories} {'threat' if records == 1 else 'threats'}",
        f"{sources} · {assets} {'asset' if assets == 1 else 'assets'} · {lifecycle} · {confidence}% confidence",
    )


def _count_phrase(counter: Mapping[str, Any]) -> str:
    labels = {
        "domain": ("domain", "domains"),
        "ip": ("IP", "IPs"),
        "url": ("URL", "URLs"),
        "endpoint": ("endpoint", "endpoints"),
        "hash": ("hash", "hashes"),
    }
    ordered = sorted(counter.items(), key=lambda item: (-int(item[1]), str(item[0])))
    parts = []
    for kind, count_value in ordered:
        count = int(count_value)
        singular, plural = labels.get(str(kind), (str(kind).replace("_", " "), f"{str(kind).replace('_', ' ')}s"))
        parts.append(f"{count:,} {singular if count == 1 else plural}")
    if len(parts) > 2:
        return f"{parts[0]}, {parts[1]}, and {sum(int(value) for _, value in ordered[2:]):,} others"
    return " and ".join(parts)


def _description(summary: Mapping[str, Any]) -> str:
    records = int(summary["records"])
    category = _labels(summary.get("categories") or {})
    lifecycle = _labels(summary.get("lifecycle") or {})
    source_ids = list((summary.get("sources") or {}).keys())
    source = (
        str(source_ids[0]).replace("_", " ").title()
        if len(source_ids) == 1
        else f"{len(source_ids)} reviewed sources"
    )
    kinds = _count_phrase(summary.get("canonical_types") or {})
    if kinds:
        return f"{records:,} {lifecycle} {category} indicators: {kinds} from {source}."
    return f"{records:,} {lifecycle} {category} indicators from {source}."


def _defang_preview(kind: str, value: str) -> str:
    text = "".join(char if char >= " " else " " for char in str(value)).strip()
    text = text.replace("<", "[").replace(">", "]").replace("&", " and ")
    if kind == "url":
        text = re.sub(r"^https://", "hxxps://", text, flags=re.IGNORECASE)
        text = re.sub(r"^http://", "hxxp://", text, flags=re.IGNORECASE)
    if kind in {"domain", "ip", "url", "endpoint"}:
        text = text.replace(".", "[.]")
    if kind == "hash" and len(text) > 20:
        text = f"{text[:16]}…"
    return text[:72] + ("…" if len(text) > 72 else "")


def _preview(state: State, summary: Mapping[str, Any], limit: int = 3) -> str:
    sample_ids = [
        str(item.get("observation_id"))
        for item in (summary.get("samples") or [])
        if item.get("observation_id")
    ]
    observations = state.get_observations(sample_ids[:limit])
    values = [_defang_preview(item.canonical_type, item.canonical_value) for item in observations]
    return " · ".join(value for value in values if value)[:400] or "Preview unavailable"


def post_bundle(
    config: Mapping[str, Any], state: State, bundle_id: str, *, approval_required: bool = True,
) -> Dict[str, Any]:
    slack = config["slack"]
    if not slack.get("enabled", False):
        return {"status": "disabled"}
    row = state.bundle_row(bundle_id)
    review = verify_bundle(config, row)
    preflight = prepare_approval_preflight(config, state, bundle_id)
    row = state.bundle_row(bundle_id)
    action_value = ""
    if approval_required:
        nonce = issue_approval_nonce(config, state, bundle_id)
        action_value = json.dumps(
            {
                "bundle": bundle_id,
                "manifest": row["manifest_sha256"],
                "preflight": preflight["sha256"],
                "nonce": nonce,
            },
            separators=(",", ":"),
        )
    summary = review["summary"]
    title, detail = _summary_text(summary)
    description = _description(summary)
    preview = _preview(state, summary)
    summary_blocks = [
        {"type": "header", "text": _plain(title)},
        {"type": "section", "text": _plain(description)},
        {"type": "context", "elements": [_plain(detail)]},
        {"type": "context", "elements": [_plain(f"Preview: {preview}")]},
    ]
    pending_blocks = [
        *summary_blocks,
        {"type": "context", "elements": [_plain("Uploading approval JSON…")]},
    ]
    ready_blocks = [*summary_blocks]
    if approval_required:
        ready_blocks.extend(
            [
                {"type": "context", "elements": [_plain("JSON attached in thread.")]},
                {
                    "type": "actions",
                    "elements": [
                        {"type": "button", "action_id": "blackbox_approve", "text": _plain("Approve"), "style": "primary", "value": action_value},
                        {"type": "button", "action_id": "blackbox_decline", "text": _plain("Decline"), "style": "danger", "value": action_value},
                    ],
                },
            ]
        )
    else:
        ready_blocks.append(
            {
                "type": "context",
                "elements": [_plain("Auto-publish enabled · JSON attached for review; no manual approval required.")],
            }
        )
    token = read_secret(slack, "bot_token")
    result = _slack_api(
        token, "chat.postMessage",
        {"channel": slack["channel_id"], "text": title, "blocks": pending_blocks},
    )
    message_ts = str(result.get("ts") or "")
    if not message_ts:
        raise RuntimeError("Slack approval message did not return a timestamp")
    try:
        attachment = _upload_bundle_json(
            slack, bundle_id, title, bundle_export_bytes(config, state, bundle_id), message_ts,
        )
    except Exception:
        _slack_api(
            token, "chat.update",
            {
                "channel": slack["channel_id"], "ts": message_ts, "text": title,
                "blocks": [
                    *summary_blocks,
                    {
                        "type": "context",
                        "elements": [_plain(
                            "JSON attachment failed; this card cannot be approved."
                            if approval_required
                            else "JSON attachment failed; auto-publishing was not started."
                        )],
                    },
                ],
            },
        )
        raise
    _slack_api(
        token, "chat.update",
        {
            "channel": slack["channel_id"], "ts": message_ts, "text": title,
            "blocks": ready_blocks,
        },
    )
    state.db.execute(
        "UPDATE bundles SET slack_workspace=?,slack_channel=?,slack_ts=? WHERE bundle_id=?",
        (slack.get("workspace_id"), slack["channel_id"], message_ts, bundle_id),
    )
    return {
        "status": "posted", "channel": result.get("channel") or slack["channel_id"],
        "ts": message_ts, "transport": "web_api",
        "attachment_ids": [str(item.get("id")) for item in attachment.get("files") or [] if item.get("id")],
    }


def post_publish_success(config: Mapping[str, Any], state: State, bundle_id: str) -> Dict[str, Any]:
    slack = config["slack"]
    if not slack.get("enabled", False):
        return {"status": "disabled"}
    row = state.bundle_row(bundle_id)
    if row["state"] != "published":
        raise RuntimeError(f"cannot announce unpublished bundle {bundle_id}")
    title, _detail = _summary_text(verify_bundle(config, row)["summary"])
    assets = int(row["asset_count"])
    text = f"✅ Published {title} as {assets} knowledge {'asset' if assets == 1 else 'assets'}."
    result = _post_message(slack, {"channel": slack["channel_id"], "text": text})
    return {
        "status": "posted", "channel": result.get("channel") or slack["channel_id"],
        "ts": result.get("ts"), "transport": result["transport"],
    }


def post_publish_progress(
    config: Mapping[str, Any], state: State, bundle_id: str, finalized: int, total: int,
) -> Dict[str, Any]:
    slack = config["slack"]
    if not slack.get("enabled", False):
        return {"status": "disabled"}
    row = state.bundle_row(bundle_id)
    summary = verify_bundle(config, row)["summary"]
    title, _detail = _summary_text(summary)
    if finalized <= 0:
        text = f"🚀 Publishing {title} · 0/{total} knowledge assets."
    else:
        text = f"⏳ Publishing {title} · {finalized}/{total} knowledge assets verified."
    result = _post_message(slack, {"channel": slack["channel_id"], "text": text})
    return {
        "status": "posted", "channel": result.get("channel") or slack["channel_id"],
        "ts": result.get("ts"), "transport": result["transport"],
    }


def post_publish_failure(config: Mapping[str, Any], state: State, bundle_id: str) -> Dict[str, Any]:
    slack = config["slack"]
    if not slack.get("enabled", False):
        return {"status": "disabled"}
    row = state.bundle_row(bundle_id)
    total = int(row["asset_count"])
    finalized = int(state.db.execute(
        "SELECT COUNT(*) AS n FROM assets WHERE bundle_id=? AND status='finalized'",
        (bundle_id,),
    ).fetchone()["n"])
    error = str(row["last_error"] or "")
    match = re.search(r"storage_ack_insufficient: got (\d+)/(\d+)", error)
    reason = (
        f"DKG storage quorum returned {match.group(1)}/{match.group(2)} acknowledgements before blockchain submission"
        if match
        else "the DKG publisher returned an error"
    )
    text = f"❌ Publishing stopped: {reason} · {finalized}/{total} assets verified · no automatic retry."
    result = _post_message(slack, {"channel": slack["channel_id"], "text": text})
    return {
        "status": "posted", "channel": result.get("channel") or slack["channel_id"],
        "ts": result.get("ts"), "transport": result["transport"],
    }


def post_run_summary(config: Mapping[str, Any], summary: Mapping[str, Any]) -> Dict[str, Any]:
    slack = config["slack"]
    if not slack.get("enabled", False):
        return {"status": "disabled"}
    observations = summary.get("observations") or {}
    pending = int(observations.get("candidate", 0))
    bundled = int(observations.get("bundled", 0))
    text = f"Scan {summary.get('status', 'complete')} · {pending:,} pending · {bundled:,} awaiting decision"
    result = _post_message(
        slack,
        {
            "channel": slack["channel_id"],
            "text": text,
        },
    )
    return {
        "status": "posted", "channel": result.get("channel") or slack["channel_id"],
        "ts": result.get("ts"), "transport": result["transport"],
    }


def run_socket_listener(config: Mapping[str, Any], state_path: str) -> None:
    """Run authenticated outbound-only Slack Socket Mode actions."""
    try:
        from slack_bolt import App
        from slack_bolt.adapter.socket_mode import SocketModeHandler
    except ImportError as exc:  # pragma: no cover - deployment-only dependency
        raise RuntimeError("Slack approvals require the Hermes slack extra (slack-bolt/slack-sdk)") from exc

    slack = config["slack"]
    bot_token = read_secret(slack, "bot_token")
    app_token = read_secret(slack, "app_token")
    app = App(token=bot_token)

    def unpack(body: Mapping[str, Any]) -> tuple[Dict[str, Any], str, str, str, str]:
        action = (body.get("actions") or [{}])[0]
        payload = json.loads(action.get("value") or "{}")
        actor = str((body.get("user") or {}).get("id") or "")
        workspace = str((body.get("team") or {}).get("id") or "")
        channel = str((body.get("channel") or body.get("container") or {}).get("id") or (body.get("container") or {}).get("channel_id") or "")
        action_timestamp = str(action.get("action_ts") or body.get("action_ts") or "")
        return payload, actor, workspace, channel, action_timestamp

    @app.action("blackbox_approve")
    def approve(ack, body, respond):  # type: ignore[no-untyped-def]
        ack()
        local = State(__import__("pathlib").Path(state_path))
        try:
            try:
                payload, actor, workspace, channel, action_timestamp = unpack(body)
                result = decide_bundle(
                    config, local, payload["bundle"], "approve", actor=actor, source="slack",
                    manifest_sha256=payload["manifest"], nonce=payload["nonce"], workspace=workspace,
                    channel=channel, action_timestamp=action_timestamp,
                    approval_preflight_sha256=payload["preflight"],
                )
                if config["publisher"].get("enabled", False):
                    request_publish(config, local, result["bundle_id"])
                    text = "Approved — publishing started."
                else:
                    text = "Approved — rehearsal only."
            except Exception:
                respond(
                    text="This batch is no longer publishable. A fresh review card is required.",
                    replace_original=True,
                )
                raise
            respond(text=text, replace_original=True)
        finally:
            local.close()

    @app.action("blackbox_decline")
    def decline(ack, body, respond):  # type: ignore[no-untyped-def]
        ack()
        local = State(__import__("pathlib").Path(state_path))
        try:
            payload, actor, workspace, channel, action_timestamp = unpack(body)
            result = decide_bundle(
                config, local, payload["bundle"], "decline", actor=actor, source="slack",
                manifest_sha256=payload["manifest"], nonce=payload["nonce"], workspace=workspace,
                channel=channel, action_timestamp=action_timestamp,
                approval_preflight_sha256=payload["preflight"],
            )
            review = verify_bundle(config, local.bundle_row(result["bundle_id"]))
            title, _detail = _summary_text(review["summary"])
            respond(text=f"Declined {title}.", replace_original=True)
        finally:
            local.close()

    SocketModeHandler(app, app_token).start()
