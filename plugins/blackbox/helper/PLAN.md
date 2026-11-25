# The helper ↔ plugin contract

`blackbox-netd` (this crate) applies what the plugin's Network Shield decides. It decides nothing.
This file is the ONE place the JSON shapes and the authentication are written down; the plugin
side lives in `plugins/blackbox/shields/network/`. Additive changes only: a field the other side
does not know is ignored.

## Authentication (security wave 2, finding 1)

`blackbox-netd install` creates a per-install key: 32 random bytes in
`/Library/Application Support/Blackbox/netd/plan.key` (root, 0600) and a copy for the person
who installed it at `~/Library/Application Support/Blackbox/helper/plan.key` (owner: that
person, 0600, written as them). ONE place per person, not per `BLACKBOX_HOME`: the installer's
Blackbox and any companion app both read it, so either can drive a helper the other
installed. Another account on the Mac has no key and cannot drive it (by design).
A later install (an upgrade) keeps the key, so pairing survives it. An upgrade that fails puts
the previous helper back and starts it again; a successful install writes the public receipt
`/Library/Application Support/Blackbox/netd-installed` (`sha256 <hex>`, 0644), which the
installer compares with the helper it carries to upgrade only one that differs.

* **Plans.** Every plan request carries a fresh `nonce` (32 hex characters) as a query parameter.
  The plugin answers with the header
  `X-Blackbox-Signature: hex(HMAC-SHA256(key, nonce + "\n" + <the exact response body bytes>))`.
  The helper refuses a plan that is unsigned, signed with another key, or signed for another nonce,
  keeps its last verified plan, and reports the refusal in `last_error`.
* **Reports.** The helper POSTs a report only to a server that proved the key within the last
  120 s, with `X-Blackbox-Token` (the dashboard's session token, as before) AND
  `X-Blackbox-Helper-Signature: hex(HMAC-SHA256(key, <the exact request body bytes>))`. The
  plugin refuses (401) an unsigned or wrongly signed report once it has a key.
* **Plugin side:** `plugins/blackbox/shields/helper_link.py` reads the key, signs the
  `enforcement` and `system-plan` answers (exact bytes, sent through `shields.RawAnswer`) and
  checks reports; the card says "not paired" when the helper is installed but this person has
  no key. Both sides check one shared vector (key 32×0x07, nonce `abc`, body
  `{"version":"v1"}` → `556ad530…85eafa`).
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
 "watch": true, "allow": ["example.org"], "keep_verified": false}
```

`{"version": "<sha>", "unchanged": true}` when `have` matches. The helper validates every
address before pf sees it (`plan.rs`).

`keep_verified: true` — the verified graph's lists in this plan are not the whole truth (its store
is down, not read yet, or only partly read). The helper keeps the verified domains and firewall
addresses it last applied and adds these (`plan.rs` `Kept`), and does not save the plan as its
last one. A list is cleared only by switching its protection off, or by a complete plan
(`keep_verified: false`). Absent (an older plugin) means false.

## System plan — `GET /api/shields/network-shield/api/system-plan?nonce=<hex>`

`{"watch": bool, "posture_fixes": ["firewall-on", …], "tamper_guard": bool, "posture_refresh": n}`
— all off when absent.

## File Shield's watch plan — `GET /api/shields/file-shield/api/watch-plan?nonce=<hex>`

Signed like every plan. `{"watch": bool, "paths": ["/abs/path", …]}` — every item the person
protected and every watched folder, absolute. The helper watches those that exist (at most 256)
with the operating system's file events (FSEvents on macOS, `platform/macos/file_shield.rs`) and
starts again when the set changes; `"watch": false` (or an old plugin's empty answer) stops it; an
unreachable plugin keeps the last plan.

Linux adds `"agents": [{"digest": "<12 hex>", "local_ports": bool, "allow": [port, …], "docker_tcp": bool}, …]`
(only when an agent is sandboxed there): each sandboxed agent's network rules, keyed by its
policy's digest — the start of its cgroup scope's name (`blackbox-agent-<digest>-<id>.scope`).
The helper's agent guard (`platform/linux/agent_guard.rs`) keeps one nftables table,
`inet blackbox_agents`, with a chain per running scope: ssh to this computer refused always, Docker's
TCP ports while `docker_tcp`, every local TCP port but `allow` and DNS while `local_ports`; then it
writes `/run/blackbox-netd/agents/<scope>.ready`, which the launcher waits for (at most 500 ms).

Report — `POST /api/shields/file-shield/api/file-report`, signed like every report, within about a
second of a change (changes are gathered for 300 ms): `{"at": <unix s>, "events": [{"path": "/abs",
"kind": "created|removed|renamed|modified|changed|denied", "ts": <unix s>, "program": "<name>"}, …]}`,
at most 200 events. `denied` is the kernel sandbox refusing a program (File Shield Layer 2): the
helper reads the sandbox's deny messages for the same paths from the system log
(`observe/sandbox_denials.rs`), and only a denial carries `program` (≤ 64 characters, the name the
log gives). The plugin keeps only changes inside its current items and folders (a denial only inside
a protected item). FSEvents cannot say which program made a change, and the helper never reads a file.

## Reports

`POST /api/shields/network-shield/api/enforcer-report` — running, `dns_active`, `firewall_active`,
`cut_active`, `ssh_lockdown_active`, `version`, `queries`, `firewall_dropped`, `blocks`, `watch`,
`events`, `remote`, plus (wave 2) `auth` ("signed" | "legacy" | "broken"), `last_error`,
`pf_enabled`, `resolver_ok`, `dns_error`, `filter_error`, and `resolved` (KI-588:
`[{"ip", "domain", "ts"}]`, at most 500 — which name each address DNS Shield relayed an answer for
was asked as; the plugin keeps it in memory only, never on disk).
`protections` = `{"dns"|"firewall"|"cut"|"ssh_lockdown"|"remote_lock": {"applied": bool,
"error": string|null}}` — the screen shows a protection "on" only when `applied` is true.

`POST /api/shields/network-shield/api/system-report` — `watching`, `at`, `exposure`,
`persistence`, `tamper` (wave 2 adds `pf_enabled`), `posture`, `fixes`, `events`.

## After a restart

The helper saves the exact bytes of each new plan it applies (verified first when paired) in its
root-only folder as `last-plan.json`, and applies that plan again the moment it starts — before
the first poll — so a restart or an upgrade leaves no gap without DNS Shield or the firewall.
End requests (`remote.end`) are never carried over a restart.

An upgrade is a hand-over (`src/handover.rs`, KI-537): `blackbox-netd install` writes a short-lived
`handover` mark in the root-only folder before it stops the old helper, and the old helper then
leaves DNS and the pf rules in place instead of putting them back; the new helper clears the mark
once it has applied its saved plan. An upgrade that ends with no helper running at all puts DNS and
the firewall back, so the Mac is never left pointing at a resolver that is gone.
