# Changelog

Every change to Agent Blackbox that a user or operator would notice, newest first.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the
version numbers follow [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** — something a user, an operator or another Blackbox node must change to keep working.
- **MINOR** — new behaviour that works with everything the previous version did.
- **PATCH** — fixes only.

What counts as Blackbox's public surface (a change to any of these that is not backward
compatible is a MAJOR release):

- the `blackbox:` keys in Hermes's `config.yaml` and the `BLACKBOX_*` environment variables;
- the `blackbox` / `hermes blackbox` commands and their options;
- what audit mode records and what block mode refuses;
- the local dashboard's address (127.0.0.1:9700) and its pages;
- the threat identifiers, report statements and graph vocabulary other Blackbox nodes read and
  write — a node on this version must still understand nodes on the previous MINOR version.

## How a release is made

1. While building: every change a user would notice adds a line under **Unreleased** in the same
   pull request, in plain words — what changed for the user, not how the code changed.
2. To release: move the Unreleased lines under a new version heading with today's date, set the
   same version in `plugin.yaml` (`version:`) and `kernel/constants.py` (`__version__`), and merge
   that pull request into umanitek/agent-blackbox `main`.
3. Tag the merge commit `blackbox-vX.Y.Z` (the `blackbox-` prefix keeps clear of Hermes's own
   `vX.Y.Z` tags in this repository) and publish a GitHub release with this version's section.
4. Update the Hermes plugin catalog: a pull request to NousResearch/hermes-agent changing
   `plugin-catalog/blackbox.yaml` — `sha` and `docs_url` to the merge commit, `version` to the
   new version. Users get the release through `hermes plugins update blackbox` once it merges.

A released section is never edited afterwards; a correction is a new release.
`tests/plugins/test_blackbox_versioning.py` checks the version, this file's order and dates, and
that the two version fields agree.

## [Unreleased]

### Added

- **Set up Blackbox from Hermes Desktop.** After a plugin-catalog install the Blackbox page no
  longer shows empty cards: it says the built-in rules already protect, lists what setup will do,
  and runs `hermes blackbox setup` with one button, showing each step live (check this Mac, connect
  to Hermes, install the threat-graph node, turn on protection, start the dashboard, keep the node
  running, final checks) with the log one click away. Setup is refused while a run is going or once
  it is done.
- **The sync, live.** While Umanitek's verified threat graph arrives, the Overview opens with its
  phase, percentage and asset counts, refreshed every few seconds: "First sync in progress" before
  any rule, then "Still syncing" with how many verified rules already protect, or "Sync stopped
  making progress" with what to do. The empty verified map says why it is empty.

### Changed

- The Desktop page refreshes every 4 seconds, as the dashboard does (was 10 to 30).
- The Desktop page opens with your connected agents, then the stats, then Trader Shield as the
  dashboard's "Engage Trader Shield" card (one line once it is on). A new **Shields** tab turns each
  shield on or off (turning off asks first) and holds what it protects, its events and its settings.
- Clicking a threat (on the map, in search or in Threats detected) or an Agent activity row opens a
  pop-up with the same details as the dashboard's, over the page, instead of leaving it.

### Fixed

- A fresh dashboard no longer says "UNPROTECTED: run `blackbox sync --wait`" while setup's own first
  sync is running: its health check reads the sync meter before judging the first sync.
- On a fresh install the first sync of the verified threat graph starts within seconds of setup
  finishing. It could wait an hour: setup's own compile left an empty ruleset that the dashboard
  took for a finished one.

## [1.3.0] - 2026-11-06

### Added

- **The Blackbox dashboard inside Hermes Desktop.** Switch it on once under Capabilities →
  Plugins, then open Blackbox in the sidebar:
  - **Overview:** open findings, verified threats synced, last sync, the community graph and
    threat sharing at a glance; your connected agents, with Attach agent to protect another one;
    and Trader Shield — the wallets found on this machine, what it always watches, recent events.
  - **Threat graph:** the verified, community and local graphs as a live bubble map you can drag
    and zoom (dependencies split by ecosystem, threats coloured by severity, click to open one),
    the verified graph's sync progress, a search over all verified threats, and Threats detected
    and Agent activity as sortable, paged tables.
  - **Settings:** the mode (Audit or Block; switching to Audit asks you to confirm), what
    Blackbox checks and from which severity, protected paths, Trader Shield (wallets, your
    addresses) and community sharing (with its consent step).
- **A shield in Desktop's status bar** shows the mode — Audit in amber, Block in green — and what
  was caught today; Desktop says once, with a Turn on blocking button, when Blackbox is recording
  but not blocking.
- **Live alerts in Desktop** the moment Blackbox flags or blocks something an agent tried to do:
  the finding, its severity, the tool and whether it was blocked — never the command or file
  contents. An action that matches several rules is one alert.

### Security

- **An agent can no longer change Blackbox's settings or switch it off.** Edits by an agent's
  tools to Hermes's `config.yaml` that touch Blackbox (its mode, its entry, the plugin list),
  writes into Blackbox's own folders, and commands such as `hermes plugins disable blackbox` are
  flagged, and refused in block mode. You still change settings as before: the dashboard, the
  `blackbox` commands you type, or your own editor.
- **Protected files stay protected on more routes:** code run through Hermes's code tool, a
  wildcard that would match a protected file, and a link pointing at one are now checked the same
  way as a direct read.

## [1.2.0] - 2026-11-04

### Added

- **Hermes Desktop support.** The one-line installer puts Blackbox into the Hermes that is already
  on the machine (such as Hermes Desktop's) instead of installing a second Hermes. When Blackbox
  was installed first and Hermes Desktop afterwards, re-running the installer moves Blackbox onto
  Desktop's Hermes — the DKG node, its keys and its synced graph move with it — and retires the
  Hermes it installed earlier.
- **`blackbox uninstall`** removes Blackbox and nothing else: its services, its DKG node, its data
  and the plugin. Node and wallet keys are kept in a private backup folder unless `--purge` is
  given; logs are removed unless `--keep-logs` is given; `--dry-run` shows the plan first.
- **One graph.** Community reports now live in the verified threat graph, in their own area,
  instead of a separate community graph. A fresh install asks to join the graph within seconds,
  and the dashboard's Community card shows when the node is connected and approved, or when the
  graph owner's approval has not reached this node yet.
- **The Playground and sandbox mode.** Send test threats (malicious packages, domains, prompt
  injections, wallet access) through the real check and watch them appear as findings, alerts and
  Recent events, kept apart from real findings.
- **Curator tools** for graph owners: promote a community report into the verified graph as
  itself, with the curators' approvals.
- **Opt-in direct graph detection and semantic review**, which read evidence straight from the
  local DKG node for the optional second-opinion reviewer.
- The first threat-graph sync says what it is doing, and only a sync that is really stuck raises
  an alarm.

### Changed

- The DKG node gets its sync slots and memory sized for the machine, and syncs verified and
  community data side by side with its own default slots.
- A restarting DKG node is given up to 300 seconds to answer (set
  `BLACKBOX_DKG_RUNTIME_WAIT_SECONDS` to change it); a node holding the whole graph needs about
  100 seconds to reopen its store.
- The installer is all or nothing: if any step fails, the machine is put back as it was. It picks
  free ports for Blackbox's node and store, and works without Docker.
- Blackbox keeps the comments in your Hermes `config.yaml` when it writes its settings.

### Removed

- The separate community-graph settings `community_graph_id` and `community_graph_peer_id` (and
  `BLACKBOX_COMMUNITY_GRAPH_ID` / `BLACKBOX_COMMUNITY_GRAPH_PEER_ID`). There is one graph now;
  a config that still sets them keeps working, and Blackbox says once that they are ignored.

### Fixed

- Installing with npm 12 (Hermes's bundled npm) runs the DKG package's install scripts again.
- `hermes blackbox setup` no longer opens a stopped Docker Desktop.
- Reinstalling after the Blackbox folder was deleted no longer leaves Hermes unable to start.
- A sync that fell due while the computer slept starts right after it wakes.
- A slow or degraded graph store is checked every 10 seconds instead of slowing every tool call.
- `blackbox dashboard` stops only a Blackbox dashboard on its port, never another program.
- The installer works under macOS's bash 3.2, and never gives Blackbox's node the DKG default
  store port.

### Security

- The DKG package is pinned by its tarball's own sha512 checksum.
- When a Blackbox check fails and lets an action through (fail-open), it now says so in the log.

## [1.0.0] - 2026-10-17

The first version in the Hermes plugin catalog (commit `7d697683`, added by Hermes's maintainers
in NousResearch/hermes-agent#140529). Its `plugin.yaml` said 1.0.0 while Blackbox's own code and
dashboard reported 1.1.0; 1.1.0 is therefore skipped, so no two different builds share a number.

[Unreleased]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.3.0...main
[1.3.0]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.2.0...blackbox-v1.3.0
[1.2.0]: https://github.com/umanitek/agent-blackbox/compare/7d697683e0d56608cfe3fee374d6a6866702058a...blackbox-v1.2.0
[1.0.0]: https://github.com/umanitek/agent-blackbox/tree/7d697683e0d56608cfe3fee374d6a6866702058a/plugins/blackbox
