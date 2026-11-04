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

[Unreleased]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.2.0...main
[1.2.0]: https://github.com/umanitek/agent-blackbox/compare/7d697683e0d56608cfe3fee374d6a6866702058a...blackbox-v1.2.0
[1.0.0]: https://github.com/umanitek/agent-blackbox/tree/7d697683e0d56608cfe3fee374d6a6866702058a/plugins/blackbox
