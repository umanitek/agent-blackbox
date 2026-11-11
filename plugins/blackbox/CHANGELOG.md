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

### Fixed

- **One check that fails no longer ends the others.** If a single detector hits an error on a
  call (for example on a number thousands of digits long), the rest of the checks still run and
  can still block; the failure is logged. Arguments nested too deep to read are checked as text
  instead of raising an error to Hermes.
- **A typo in `snapshot_sync` no longer switches protection off.** A saved `snapshot_sync` block
  that cannot be used is reported (`blackbox status` says so, sync refuses to start) while every
  check keeps running. Saving such a block is refused.
- **The guard-settings rule follows `cd`.** A command that reaches Blackbox's own settings through
  several `cd` steps is recognised like one that names the file directly.
- **A `config.yaml` that cannot be read is never written over.** Attach, the assistant's profile
  setup, settings saves and uninstall leave an unreadable file alone and say so, instead of
  replacing it with a nearly empty one. Blackbox's own changes to a `config.yaml` also wait for
  each other, so a settings save and an automatic attach in the dashboard cannot undo one another.
- **`blackbox dashboard` honours `auto_attach`.** Starting the dashboard no longer attaches every
  agent on the machine when automatic attach is off.
- **The agent's action no longer waits for the node after a finding.** The finding is recorded
  and the block is returned at once; the private audit record and the community share follow in
  the background. A slow or stopped node could hold a blocked action for minutes.
- **Community rules stay in force while they are refreshed.** Between full syncs the community
  rules were briefly missing each time they were re-read from the node. They are now replaced in
  one step.
- **Large file writes are checked quickly.** Writing a large file with few spaces (a minified
  file, an encoded blob) could hold the agent for several seconds per call.
- **Blackbox talks to its own node and dashboard directly.** Requests to the local node and the
  local dashboard no longer go through a proxy set in the environment, and do not follow
  redirects.
- **Uninstall stops only Blackbox's node.** The process number saved by the node is checked to be
  the Blackbox node before it is stopped. Uninstall and the dashboard's assistant also use the
  Hermes they are running in, not another `hermes` found on the PATH.
- **The audit logs lose no record under load.** When several agents write while one trims a full
  log, every record is kept.
- **A dashboard page left open keeps working after the dashboard restarts** (it used to answer
  "403" until reloaded), and the first page after a start is no longer slow because the start-up
  reads did not run.
- **A manual report made in sandbox mode stays in the sandbox.** `blackbox report` with Sandbox
  mode on now goes to the sandbox lane only, like automatic reports, and is not re-published.
- **Curator commands.** `blackbox curate approve` exits with an error when nothing was published;
  `curate inbox` admits only proposals a curator signed; a sighting digest dated in a week that
  does not exist is ignored instead of emptying the heat map.
- **Advisories OSV labels "moderate" are shown.** Dependency discovery dropped them without a
  word; they now appear as medium. A package looked up while offline is checked again later
  instead of being remembered as clean.
- **The site that carried a prompt injection is named for OpenAI-direct and Codex agents too.**
  The injection itself was already found for them; the site finding was missing.
- **`blackbox status` lists every attached OpenClaw agent.** One whose config has comments, or
  is named by `OPENCLAW_CONFIG_PATH`, was attached but missing from the list.
- **Secrets in logged settings.** The words that mark a setting as secret are now one list for
  every place Blackbox redacts, so a name redacted in one log is redacted in all of them.

### Changed

- A mode or severity written with stray spaces or capitals in `config.yaml` (`mode: " Block "`)
  is read as that value. It used to fall back to the default.

## [1.4.0] - 2026-11-08

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
- **The Blackbox assistant in Desktop.** The chat button in the page header opens the dashboard's
  assistant beside the page: its three example questions, a running conversation kept on this
  computer (New chat starts over), and progress messages while it works.
- **Docs and the Playground in Desktop.** The book button opens the dashboard's documentation in
  your browser. With Sandbox mode on, the Overview holds the Playground: send a listed threat of
  each kind through the real check, and run every wallet test Trader Shield has for this machine
  (one at a time or Run all), each with its result.

### Changed

- A seed phrase or wallet private key on its way off the machine (posted, put in a web
  address, sent by a script or a messaging tool) is blocked even with Trader Shield off — a
  wallet secret has no right destination. Writing or reading one on the machine stays Trader
  Shield's to watch.
- The Desktop page refreshes every 4 seconds, as the dashboard does (was 10 to 30).
- The Desktop page opens with your connected agents, then the stats, then Trader Shield as the
  dashboard's "Engage Trader Shield" card (one line once it is on). A new **Shields** tab turns each
  shield on or off (turning off asks first) and holds what it protects, its events and its settings.
- A shield's recent events are clickable, as on the dashboard: each opens the shield's events window
  with the full local record (what happened, what to do, the details, what happened in that session),
  private to this machine and refreshed live; View all lists every event.
- Clicking a threat (on the map, in search or in Threats detected) or an Agent activity row opens a
  pop-up with the same details as the dashboard's, over the page, instead of leaving it.

### Fixed

- The Desktop page's "Open findings" card opens Threats detected, as the bell does (it was
  a count you could not click through).
- An agent can no longer stop Blackbox's own services: unloading or stopping its login
  services, killing its dashboard or node by name, or killing whatever holds their ports is
  treated like editing Blackbox's settings (ordinary process commands stay allowed).
- The Desktop Shields tab no longer ticks Trader Shield's checks while the shield is off — each
  shows "off — engage Trader Shield to watch this".
- The Desktop "Threats detected" table fits beside the sidebar: the outcome sits under the
  severity and long reasons wrap instead of squeezing every column.
- On a Mac the installer hands the dashboard to its login service at once, so a crashed
  dashboard is restarted from the first day (it used to run unsupervised until the next login).
- A Python package rule matches every spelling of the same release: a rule for version 1 now also
  stops `pip install <name>==1.0` and `==1.0.0` (PEP 440 treats them as one release).
- The check never fails on an odd tool input (a tool name that is not text, arguments sent as JSON
  text): such a failure used to let the action through unchecked.
- After a restart or reboot the page no longer says half the threat graph is missing: the node
  re-checks the assets it already holds, and that re-check is no longer counted as data still to
  download (a fresh Mac fell from 100% to 51% of a "1,842-asset" graph that has 971).
- In the minute after a reboot, while the DKG node reopens its store, the page says "the DKG node is
  starting" (and Desktop's header "Node starting") instead of a red "my node is stale — run
  `blackbox sync --wait`".
- The Blackbox assistant looks threats up instead of reading a whole graph tier into the model: its
  answers are faster, and its own request no longer trips Blackbox's prompt-injection alert on the
  attack phrases quoted in threat names.
- Turning on Trader Shield, or saving its settings, no longer tells you to restart your agent: a
  running agent picks the change up at once (README and the Trader Shield page updated too).
- Desktop: a long package name in Threats detected, or the graph on a Retina screen, no longer
  pushes the page sideways past the window; the tabs line up with the header once the first sync
  is done; the first-sync note is not shown twice; the "recording, not blocking" notice waits until
  setup has finished instead of covering the setup page; "Watching" (audit mode) is amber like the
  Shields tab; the Attach agent tile shows a close icon while it is open.
- "Attach agent" on the dashboard opens its window again from a click on its icon or label (only
  a click on the button's edge did anything), and Escape closes that window.
- The Trader Shield page no longer says "Not engaged" for the first moments after the dashboard
  starts: it shows "Checking this machine…" until the dashboard knows, then the real state.
- Threat graph labels stay readable in the dashboard and in Desktop: hub names and threat counts
  sit on a small plate above the dots, two labels never land on each other, and on a phone they
  keep a readable size instead of shrinking to a few pixels.
- Layout and sizing: the umanitek logo at the foot of the dashboard shows on the light theme; the
  tier tabs show "970,000" like the cards; the Trader Shield card has no empty fourth column and
  its header wraps on a phone; the Trader Shield page's headline fits in four lines on a laptop
  and its picture no longer runs into the status box on a phone; the docs search box and figure
  labels fit on a phone; Desktop's five summary cards sit 3 + 2 beside Hermes' sidebar instead of
  five squeezed columns, and its wordmark reads BLACKB●X.
- A fresh dashboard no longer says "UNPROTECTED: run `blackbox sync --wait`" while setup's own first
  sync is running: its health check reads the sync meter before judging the first sync.
- On a fresh install the first sync of the verified threat graph starts within seconds of setup
  finishing. It could wait an hour: setup's own compile left an empty ruleset that the dashboard
  took for a finished one.
- The Blackbox assistant answers again, in the dashboard and in Desktop. On Hermes 0.23 every
  question failed with "No such file or directory: '/usr/local/sbin/-c'": it re-ran Hermes by the
  name of the running program, which Hermes' new launcher reports as `-c`.
- The assistant's own Hermes profile no longer appears in Connected agents as an idle agent.
- One slow request (an assistant answer) no longer freezes the Desktop page: it used to empty
  every card until the answer came back.
- A question to the assistant that starts with a dash ("-v", "--why") is asked as written
  instead of failing, and when the assistant cannot start, the page says so in plain words
  instead of showing the system's error text.
- Desktop's assistant shows `code` and **bold** in its answers as formatting, not as symbols.
- Desktop no longer says "0 connected agents" above an agent it protects: like the dashboard, it
  counts only agents active right now and shows nothing when none is.
- Desktop's assistant: "New chat" while an answer is on its way really starts a new chat (the old
  answer no longer comes back), closing and reopening the assistant mid-answer keeps that answer,
  and answers keep their paragraph breaks.
- A long Desktop request (an assistant answer, a Playground test) no longer gives up after one
  failed check while it is still running, and Playground "Run all" stops when you leave the page.
- Desktop's threat bell counts the same threats the findings list shows, and clicking it before
  the list has loaded no longer marks every threat as new again.
- A Shield's list setting in Desktop (addresses, names) can be typed one entry per line; Enter and
  commas no longer vanish as you type them.

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

[Unreleased]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.4.0...main
[1.4.0]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.3.0...blackbox-v1.4.0
[1.3.0]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.2.0...blackbox-v1.3.0
[1.2.0]: https://github.com/umanitek/agent-blackbox/compare/7d697683e0d56608cfe3fee374d6a6866702058a...blackbox-v1.2.0
[1.0.0]: https://github.com/umanitek/agent-blackbox/tree/7d697683e0d56608cfe3fee374d6a6866702058a/plugins/blackbox
