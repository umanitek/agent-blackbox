# The helper ↔ plugin contract

`blackbox-netd` (this crate) applies what the plugin's Network Shield decides. It decides nothing.
This file is the ONE place the JSON shapes and the authentication are written down; the plugin
side lives in `plugins/blackbox/shields/network/`. Additive changes only: a field the other side
does not know is ignored.

## Authentication (security wave 2, finding 1)

`blackbox-netd install` creates a per-install key: 32 random bytes in
`/Library/Application Support/Blackbox/netd/plan.key` (root, 0600) and a copy handed to the
plugin's own state folder at `<BLACKBOX_HOME>/helper/plan.key` (owner: the person, 0600).

* **Plans.** Every plan request carries a fresh `nonce` (32 hex characters) as a query parameter.
  The plugin answers with the header
  `X-Blackbox-Signature: hex(HMAC-SHA256(key, nonce + "\n" + <the exact response body bytes>))`.
  The helper refuses a plan that is unsigned, signed with another key, or signed for another nonce,
  keeps its last verified plan, and reports the refusal in `last_error`.
* **Reports.** The helper POSTs a report only to a server that proved the key within the last
  120 s, with `X-Blackbox-Token` (the dashboard's session token, as before) AND
  `X-Blackbox-Helper-Signature: hex(HMAC-SHA256(key, <the exact request body bytes>))`. The
  plugin should refuse an unsigned or wrongly signed report once it has a key.
* **Legacy.** A helper installed before keys existed has no key file: it accepts unsigned plans
  and says `"auth": "legacy"` in every report, so the plugin can ask the person to reinstall it.
  A key file of the wrong size is `"auth": "broken"`: every plan is refused (fail closed).
* Losing the plugin never undoes anything: the last verified plan stays applied.

## Plan — `GET /api/shields/network-shield/api/enforcement?have=<version>&nonce=<hex>`

```json
{"version": "<sha>", "unchanged": false,
 "dns": {"enabled": true, "verified": ["evil.example"], "lists": [], "block": []},
 "firewall": {"enabled": true, "ips": ["203.0.113.9"]},
 "cut": {"enabled": false, "ips": []},
 "ssh": {"lockdown": false, "allow": []},
 "remote": {"lock": false, "block": [], "end": [{"session_id": "...", "pid": 1, "started": 0, "how": "ssh"}]},
 "watch": true, "allow": ["example.org"]}
```

`{"version": "<sha>", "unchanged": true}` when `have` matches. The helper validates every
address before pf sees it (`plan.rs`).

## System plan — `GET /api/shields/network-shield/api/system-plan?nonce=<hex>`

`{"watch": bool, "posture_fixes": ["firewall-on", …], "tamper_guard": bool, "posture_refresh": n}`
— all off when absent.

## Reports

`POST /api/shields/network-shield/api/enforcer-report` — running, `dns_active`, `firewall_active`,
`cut_active`, `ssh_lockdown_active`, `version`, `queries`, `firewall_dropped`, `blocks`, `watch`,
`events`, `remote`, plus (wave 2) `auth` ("signed" | "legacy" | "broken"), `last_error`,
`pf_enabled`, `resolver_ok`, `dns_error`, `filter_error`.

`POST /api/shields/network-shield/api/system-report` — `watching`, `at`, `exposure`,
`persistence`, `tamper` (wave 2 adds `pf_enabled`), `posture`, `fixes`, `events`.
