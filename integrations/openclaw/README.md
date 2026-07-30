# Agent Blackbox — OpenClaw plugin

Mirrors the Hermes Blackbox plugin's local detection inside an OpenClaw agent.
It reads the same curated Verifiable Memory graph; findings stay local.

When OpenClaw is attached by `blackbox attach`, it points at the
Blackbox-managed DKG node (`http://127.0.0.1:9320`) and home
(`~/.hermes/blackbox/dkg`). That keeps it separate from any user-owned DKG node
on the DKG CLI defaults (`~/.dkg` / `9200`).

The default context graph is public. The shared local node subscribes and
catches up without curator approval; `blackbox sync --wait` reports that state.

- **Detection rules come only from the threat graph.** The plugin syncs a
  ruleset from your local DKG node's Verifiable Memory. On an empty
  graph it detects nothing until synced — by design.
- **Audit-only by default.** Blocking is opt-in (`mode: block`).
- **Fail-open.** Any error in a hook is swallowed; the agent loop is never
  broken. Threat pushes are deterministic HTTP calls, never LLM/MCP-driven.
- **Findings stay local.** Community sharing is coming soon.

## Trust model

Every sync reads the verified public graph. Built-in heuristics remain local:

| Tier | Memory view | `source` | Behavior |
|------|-------------|----------|----------|
| **Public** | `verifiable-memory` (Umanitek-verified public threat graph) | `public` | The source of truth: a match is `confirmed`, and blockable in block mode. |
| **Heuristic** | built-in discovery candidates | `heuristic` | Local nominations only. Never block. |

Community Shared Working Memory support is coming soon.

## What it detects

| Category | Where | Identifier |
|----------|-------|------------|
| Prompt injection | tool params, the incoming run prompt, inbound messages | `injection:{sha256(pattern)[:24]}` |
| Privilege escalation | tool call shape (compares **both** tool name and arg shape) | `escalation:{tool}:{argShape}` (literal shape slug, e.g. `escalation:shell:remote-script-pipe`) |
| Vulnerable dependency | install commands (`pip`/`uv`/`npm`/`pnpm`/`yarn`/`bun`/`cargo`/`gem`/`brew`), plus off-path OSV auto-discovery | `dep:{ecosystem}:{name}@{version}` |
| Sensitive file access | file-tool calls whose path falls in a sensitive category (SSH keys, `.env`, credentials, …); only the category + tool leave the box | `fileaccess:{tool}:{category}` |
| Suspicious skill | skill/plugin install or modify: graph known-bad `skill:{name}@{version}`, dangerous-code shapes, over-broad permission grants | `skill:{name}@{version}` / `skill:{name}:{dangerShape}` |

## Hooks

| Hook | Behavior |
|------|----------|
| `before_tool_call` | record the tool call plus routine file/download/package activity; detect escalation + dependency + injection over params; **block** (block mode, ≥ `blockSeverity`) or observe + report |
| `after_tool_call` | observe result (redacted); never blocks |
| `before_agent_run` | prompt-injection scan of the incoming prompt + history — **requires `allowConversationAccess`** |
| `message_received` | observe inbound content for injection sightings |
| `session_start` / `session_end` | lifecycle; `session_start` warms the ruleset |

## Install

### Option A — `openclaw plugins install`

```bash
openclaw plugins install ./integrations/openclaw
openclaw plugins enable blackbox
```

### Option B — config merge (dkg-adapter pattern)

Point OpenClaw at the plugin directory and set its config in
`~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "load": { "paths": ["/absolute/path/to/agent-blackbox/integrations/openclaw"] },
    "enabled": ["blackbox"],
    "entries": {
      "blackbox": {
        "hooks": { "allowConversationAccess": true },
        "config": {
          "mode": "audit",
          "contextGraphId": "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm",
          "dkgUrl": "http://127.0.0.1:9320",
          "dkgHome": "~/.hermes/blackbox/dkg",
          "syncInterval": 300,
          "report": true,
          "dailyReportLimit": 9999,
          "reportMinSeverity": "high",
          "blockSeverity": "critical",
          "discover": true,
          "osvLookup": true,
          "detection": {
            "dependency": { "minSeverity": "critical" },
            "skill": { "enabled": false }
          },
          "protectedPaths": ["~/.ssh", "~/secrets/**", "*.pem"]
        }
      }
    }
  }
}
```

> **`allowConversationAccess` is required for `before_agent_run`.** It is a
> conversation hook; without
> `plugins.entries.blackbox.hooks.allowConversationAccess=true` OpenClaw will
> not deliver the prompt/history to the plugin and the incoming-run
> prompt-injection scan is silently skipped. Tool-call, message, and session
> detection still work without it.

## Configuration

Set under `plugins.entries.blackbox.config`; every key has an environment
override (env wins).

| Key | Default | Env | Meaning |
|-----|---------|-----|---------|
| `mode` | `audit` | `BLACKBOX_MODE` | `audit` \| `block` |
| `contextGraphId` | `0x37b1Fdfd…/agent-blackbox-vm` | `BLACKBOX_CONTEXT_GRAPH_ID` | Public verified threat graph id |
| `dkgUrl` | `http://127.0.0.1:9320` | `BLACKBOX_DKG_DAEMON_URL` / `BLACKBOX_DKG_URL` | Blackbox-managed local node |
| `dkgHome` | `~/.hermes/blackbox/dkg` | `BLACKBOX_DKG_HOME` | isolated DKG config, API token, pid, and cache |
| `syncInterval` | `300` | `BLACKBOX_SYNC_INTERVAL` | seconds between ruleset refresh |
| `report` | `false` | — | coming soon; findings stay local |
| `dailyReportLimit` | `0` | — | coming soon; outbound reporting is disabled |
| `reportMinSeverity` | `high` | `BLACKBOX_REPORT_MIN_SEVERITY` | min severity for a built-in **heuristic** candidate to flag/report (graph-backed findings always flag) |
| `blockSeverity` | `critical` | `BLACKBOX_BLOCK_SEVERITY` | min severity blocked in block mode (public-graph findings only) |
| `discover` | `true` | `BLACKBOX_DISCOVER` | run the built-in discovery nomination layer |
| `osvLookup` | `true` | `BLACKBOX_OSV_LOOKUP` | OSV dependency auto-discovery off the blocking path |
| `detection` | `{}` | — | per-category policy (see below) |
| `protectedPaths` | `[]` | — | user protected-path patterns (see below) |

Snake_case config keys (`report_min_severity`, `daily_report_limit`, …) are
accepted as aliases of the camelCase keys.

### Per-category tuning

Each of the six detection categories — `injection`, `escalation`,
`dependency`, `fileaccess`, `skill`, `ioc` — can be individually disabled or
given a minimum-severity floor under `detection.<category>`. **Defaults: every
category is enabled at `minSeverity: info`** (flag everything the threat graph
knows), so you only need to add a category when you want to quiet it down.

IOC matches and historical skill reports without an affected version always
alert; they never auto-block.

- `enabled: false` drops **every** finding in that category.
- `minSeverity: <info|low|medium|high|critical>` drops anything below the floor
  (e.g. "only critical dependency vulns").

The floor applies to graph-backed findings too — it is a stricter user policy on
top of the trust tiers. Built-in heuristic candidates must *also* clear
`reportMinSeverity` (they are nominations, not confirmed threats).
`min_severity` is accepted as a snake_case alias of `minSeverity`.

```jsonc
"detection": {
  "dependency": { "minSeverity": "critical" },  // only critical dep vulns
  "skill":      { "enabled": false },            // ignore skill threats entirely
  "injection":  { "min_severity": "medium" }     // snake_case alias also works
}
```

The equivalent YAML (hermes-style `config.yaml`) — the OpenClaw plugin reads the
**same** `plugins.entries.blackbox.detection.*` keys as the Python plugin:

```yaml
plugins:
  entries:
    blackbox:
      detection:
        dependency:
          min_severity: critical
        skill:
          enabled: false
      protected_paths:
        - "~/.ssh"
        - "~/secrets/**"
        - "*.pem"
```

### Protected paths

`protectedPaths` is a list of **your own** path patterns. When a file tool
(`read_file`, `write_file`, `edit_file`, …) touches a matching path, Blackbox
raises a `critical`, `source: "custom"` finding that:

- **always flags** (it bypasses the per-category policy — you asked for it),
- **blocks in block mode** (at/above `blockSeverity`), and
- is **never shared** to the community graph — the pattern is your private
  config, not shared threat intel (audited locally only).

Patterns match three ways (mirroring the Python plugin), with `~` expanded to
your home directory:

| Pattern | Matches |
|---------|---------|
| Full-path glob — `~/secrets/**`, `/etc/*.conf` | the whole accessed path |
| Basename glob — `*.pem`, `id_rsa` | the file's basename anywhere |
| Directory prefix (glob-free) — `~/.ssh`, `/etc/ssl` | that path and everything under it |

Accepted under `protectedPaths` or the snake_case `protected_paths`; the list is
de-duplicated and capped at 100 patterns.

Outbound sightings are also deduplicated per identifier with a 6-hour cooldown
(mirroring the hermes plugin's `audit.REPORT_COOLDOWN_SECS`): a re-fire of the
same identifier within the window is not re-reported.

The DKG bearer token is resolved from `$BLACKBOX_DKG_API_TOKEN` /
`$BLACKBOX_DKG_AUTH_TOKEN`, then `<dkgHome>/auth.token`. Generic DKG CLI
variables are intentionally ignored so OpenClaw does not accidentally talk to a
user's default DKG node.

Ruleset cache is stored under the OpenClaw state dir
(`$OPENCLAW_STATE_DIR/blackbox/ruleset.json`, default `~/.openclaw/blackbox/`).

## Requirements

- OpenClaw ≥ 2026.6.11. Earlier releases do not expose the stable Plugin SDK
  hooks Blackbox uses.
- Node ≥ 22.19 (OpenClaw runtime). Zero runtime dependencies — uses global
  `fetch`, `node:crypto`, and `node:fs`.
- A running local DKG v10 node. Without one, the plugin loads and fails open
  (detects nothing, reports nothing).

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
```

Detection semantics and threat identifiers are kept byte-identical to the Python
`plugins/blackbox/` side and the reference `dkg/packages/node-ui/src/blackbox.ts`.
Do not change identifier construction (`quads.ts`) or arg-shape normalization
(`detection.ts`) on one side without mirroring the other.
