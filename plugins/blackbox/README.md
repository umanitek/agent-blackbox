# Agent Blackbox

Real-time threat protection for AI agents.

Agent Blackbox checks prompts, tool calls, shell commands, file access, package
installs, and skills against a shared threat graph on the OriginTrail DKG. It
works with Hermes and OpenClaw, runs in audit mode by default, and can block
confirmed threats before they execute.

## Install

Run the installer:

```bash
curl -fsSL blackbox.umanitek.ai | bash
```

The installer sets up an isolated node from the latest official
`@origintrail-official/dkg` npm package and protects detected Hermes and OpenClaw
agents. Docker must be installed and running for its Blazegraph store. The
installer does not replace or modify an existing DKG node.

The default context graph is public, so every Agent Blackbox install can sync
verified threat data immediately. Publishing remains curated so only trusted
data becomes blocking Verifiable Memory. Local working memory and the dashboard
remain available during the initial sync.

## Compatibility

- Hermes builds dated 2026-04-13 or later are supported. The installer uses a
  compatible Hermes build.
- OpenClaw 2026.6.11 or later is supported. Older releases do not provide the
  stable plugin hooks Blackbox requires.

Standard Hermes profiles and OpenClaw profiles are attached automatically. A
running OpenClaw Gateway must be restarted once after its plugin config changes.
For a remote or containerized agent, install Blackbox on the Gateway host.

## Use

```bash
blackbox status       # check Blackbox and DKG health
blackbox sync --wait  # pull the latest threat data now
blackbox dashboard    # open http://127.0.0.1:9700
blackbox attach       # protect all detected local agents
blackbox detach       # remove protection
blackbox chat         # open the Blackbox assistant
```

The installer adds the `blackbox` command to your per-user PATH. It forwards
to `hermes blackbox`, so the longer form remains fully supported.

Blackbox detects:

- prompt injection
- dangerous commands
- vulnerable or malicious dependencies
- sensitive file and secret access
- suspicious skills

Findings are logged locally and shown in the dashboard. In the default `audit`
mode, Blackbox warns without stopping the action. To block confirmed threats,
set the mode to `block` in the dashboard or in `config.yaml`:

```yaml
plugins:
  entries:
    blackbox:
      mode: block
```

## Community graph (sharing is opt-in)

Nothing leaves your machine until you read the reporter terms and consent;
withdrawing is one command and stops sharing on the next action.

```bash
blackbox report --consent               # read the terms, record consent (sharing stays off)
blackbox report --enable-sharing        # turn sharing on (needs consent); --disable-sharing turns it off
blackbox report --withdraw-consent      # sharing stops
blackbox report --type ioc --ioc-type domain --value evil.example --context fetched-by-tool
blackbox report --status                # what happened to each report, and its community stage
blackbox report --standing              # counted or probation, with a co-sighting estimate
blackbox report --retract IDENTIFIER    # withdraw your own report
blackbox report --false-positive IDENTIFIER --reason tolerable
blackbox report --export FILE           # your key backup + ledger (portable)
blackbox report --erase-identity --confirm
```

A verified rule that blocks here can be demoted to FLAG on this machine only
(audited, never shared; there is no way to raise enforcement locally):

```bash
blackbox rules unblock IDENTIFIER --reason "false positive in our CI"
blackbox rules reblock IDENTIFIER
blackbox rules list
```

Curators run `blackbox curate` (queue, dossier, two-key `propose` /
`approve` / `publish`, `--attest`, `--kill-list`, `outcome`, `graduate`,
`metrics`, `watch`). Community settings in `config.yaml`:
`community_poll_interval` (seconds between pulse probes, 0 off),
`community_keepalive_epoch_days` (re-publish cadence for your own reports,
0 off) and `community_shadow` (compute and log stages, enforce only
monitor). `$BLACKBOX_HOME/allowlist.json` extends the shipped allowlist and
warninglist; `$BLACKBOX_HOME/public_suffix_list.dat` refreshes the vendored
Public Suffix List. The reporter terms, DPIA and controller map ship in
`plugins/blackbox/docs/`.

## How threat data works

Blackbox currently uses one shared graph:

- The **public graph** contains Umanitek-verified threats. These can be blocked
  in block mode. Anyone can read and sync it, while publishing remains curated.
  The UI expands collection contents and lists each threat entity, not one row
  per collection.
- The **community graph** is the open collective-defense layer: any protected
  agent contributes privacy-safe threat reports and learns from other agents'
  reports (aggregated with honest distinct-reporter counts). Community rules
  FLAG only — they can never block. Active when a community graph address is
  configured; sharing additionally requires `report: true` (`blackbox report --enable-sharing`).

Raw prompts, commands, file contents, secrets, and your local audit trail are
never published — reports carry only deterministic threat names and the
signature fields a reviewer needs, and secret/LLM/custom findings are
hard-excluded from sharing in code. Reports are pseudonymous under your
node's persistent address.

## Configuration

Settings are under `plugins.entries.blackbox` in `config.yaml`. The easiest way
to change them is through the dashboard settings page.

| Setting | Default | Purpose |
|---|---:|---|
| `mode` | `audit` | Warn only (`audit`) or stop confirmed threats (`block`) |
| `block_severity` | `critical` | Minimum severity blocked in block mode |
| `report` | `false` | Share privacy-safe threat reports with the community graph |
| `report_min_severity` | `high` | Minimum severity for heuristic candidates to flag/share |
| `detection.<category>.enabled` | `true` | Enable or disable a detection category |
| `detection.<category>.min_severity` | `info` | Minimum visible severity for a category |
| `protected_paths` | `[]` | Local file globs that always block and are never shared |
| `context_graph_id` | `0x37b1Fdfd…/agent-blackbox-vm` | Public verified threat graph |
| `community_graph_id` | *(empty until launch)* | Community graph address; empty keeps sharing dormant |
| `daily_report_limit` | `20` | Daily cap on outbound community reports (cannot be switched off; 0 means the default) |
| `graph_peer_id` | bundled publisher peer | Authoritative threat-data sync source |

Categories are `injection`, `escalation`, `dependency`, `fileaccess`, and
`skill`.

Example:

```yaml
plugins:
  entries:
    blackbox:
      detection:
        dependency:
          enabled: true
          min_severity: critical
        skill:
          enabled: false
      protected_paths:
        - "~/.ssh/*"
        - "**/.env"
```

### Optional AI reviewer

Blackbox can use your configured model for a second opinion on prompt
injection:

```bash
blackbox setup-llm
```

This feature is off by default. It sends reviewed text to the selected model
provider, only warns, and never shares its verdict with the threat graphs.
Disable it with `blackbox setup-llm --disable`.

## Troubleshooting sync

First check the node and retry the sync:

```bash
blackbox status
blackbox sync --wait
```

A first sync can continue in the background for several minutes. If it does not
finish, rerun the command below and include the displayed peer ID and DKG log
when reporting the problem:

```bash
blackbox sync --wait --timeout 180
```

## Direct local graph queries (opt-in)

See [Direct graph reads](docs/DIRECT_GRAPH_READS.md) for the paired DKG capability,
configuration, compatibility limits and validation gates. The default remains
`legacy-cache` until that migration is explicitly selected.
