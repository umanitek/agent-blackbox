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

## [1.6.0] - 2026-11-25

### Added

- **Linux gets the same deep protection as macOS.** On Linux (tested on Ubuntu 24.04 and 22.04)
  Blackbox now runs agents inside its own sandbox (your private keys, Blackbox's settings,
  startup places and the system stay closed to them), the Threat Firewall (nftables: listed
  addresses are refused at once), DNS Shield (systemd-resolved, NetworkManager or
  `/etc/resolv.conf`, put back exactly on uninstall), the startup watch and the system protection
  helper as a systemd service. `blackbox approve` confirms a weakening change with your own
  password, as on macOS. Docker and stopping one of your programs ask you, as on macOS.
- **The Protection page.** One page shows every refused attempt to switch Blackbox off or get
  around it, counted by kind; a protection log whose entries are chained, so an edit, a cut or a
  rewind of the record shows; and watch-first rules — watch a host or a package, see how often
  agents reach for it, then block it with one click (taking a block off asks you first). A
  finding offers "Watch this". `docs/THREAT_MODEL.md` says what Blackbox defends against and how.
- **Blackbox's own hooks are watched.** If one of Blackbox's hooks or plugins in an agent's folders
  is removed or changed outside a Blackbox install, Blackbox raises a high-severity alert and puts
  it back within seconds; a file found in its place is kept aside, never deleted. A new hook or
  plugin that is not Blackbox's in those folders is reported too. "Stop protecting" an agent turns
  this off for it.

- **Sandbox permissions.** What an AI agent inside Blackbox's sandbox may do beyond your files is
  now a list you control — block, ask each time, or allow, for every agent, one agent, one project
  folder or one agent in one project: Homebrew and global installs (`npm i -g`, `pipx`, `pip
  --user`, `cargo`, `gem`, `uv tool`, done by Blackbox, names only and threat-checked), opening web
  links and opening files in apps, one AppleScript you read first, stopping a stray program, Docker,
  services on this Mac and the clipboard. On "ask" you answer Allow once / Always for this agent
  here / Keep blocked. Turning one up asks you first. File Shield's page lists them, the rules you
  set and what is never unlocked, and names a running agent that still needs a restart.

- **Native notifications from Blackbox itself.** Blackbox now tells you through your system's own
  notifications which AI agent did what and whether it was allowed, flagged or stopped — safe to
  read on a locked screen. Security notices are on; agents starting and ending, and a one-line
  session summary, are opt-in. Mute an agent, set quiet hours, cap how many a minute. On macOS
  they appear under Blackbox's own name once its notifier is installed; a companion app, while it
  runs, delivers instead. See `docs/notifications.md` and the dashboard's Notifications page.
- **An agent asking for root, and a program it started running as root, are flagged and shown.**
  `sudo` is not refused; it is made visible on the agent's instance, in the findings and in a
  notification.
- Turning protection down needs your confirmation: Audit instead of Block, a shield, detection or agent switched off, a protected path removed, an address unblocked or remote access unlocked waits until you confirm it, with your computer's password prompt on the dashboard or in a paired companion app's dialog. Strengthening applies at once.
- Coding-agent protection is in the core: Claude Code, Codex, Cursor, Gemini CLI, GitHub Copilot CLI, Windsurf (Devin), Cline and OpenCode are protected through their own hooks (`agent_hooks`; `/api/agent-hooks`), with prompt-injection checks on prompts and tool outputs and self-protection of each agent's hook config — with the plugin alone.
- `guard.text_verdict`: a prompt or a tool's output checked for prompt injection with the same rules as a tool call (only a verified pattern blocks, in Block mode) — for runtimes that are not Hermes, such as a coding agent's own hooks.

- **Network Shield, the second shield.** Switch it on (Settings → Shields) and Blackbox keeps AI
  agents to the hosts you allow (agent network lockdown) and away from the ones you block, shows
  this machine's system status (CPU on every core, memory, disks, each network interface) and
  what talks to the internet right now (download and upload — this machine's own local traffic
  kept apart — the apps online and their connections, each checked against the verified threat
  graph). With the **system protection helper** (a small root helper the installer offers, or a
  companion app installs) it also runs DNS Shield, the Threat Firewall, cutting malicious
  connections, SSH lockdown and watch, Lock remote access, the exposure and posture checks — each
  shown active only while the helper reports it; without the helper they say "needs the system
  protection helper". An add-on may add richer views on top.
- Add-ons: a package installed beside the plugin that declares itself with a `blackbox-addon.json`
  manifest can add shields and more to a shield through one documented extension point; a broken
  add-on never stops Blackbox.

- **Every agent protected, now and later, on one yes.** The installer asks once (Enter is yes):
  "Protect every agent, now and later, automatically?" — every Hermes profile and OpenClaw
  workspace on the machine is protected, and so is each one added later, within a minute, with the
  same rules and settings and its findings labelled with its name on the dashboard. Hermes Desktop's
  setup page has the same switch (on), `blackbox setup --protect-new-agents` / `--no-…` answer it
  for scripts, and `blackbox attach --all --auto` / `--no-auto` is the command behind all of them.
  An agent you switch off stays off. Change it any time: Settings → Agents.
- The dashboard says "New agent protected: Hermes · coder" when one is protected by itself, and
  shows one slim line naming any agent on the machine that is not protected, with Protect and
  "Protect every agent, now and later".

### Fixed

- **Setup no longer loses the store's settings when Blackbox sits in a folder whose name has a
  space.** The installer split such a path, could not read the existing node's store settings,
  and went on with an empty store name.

- **No false "running without Blackbox" alert when the sandbox starts an agent.** An agent started
  through Blackbox's sandbox launcher can take longer than 20 s to send its first hook event on a
  busy machine. Such a run now gets up to 90 s. A run whose hooks are switched off is still
  reported at once, and the launcher's mark can only delay an alert, never remove it.
- **The first threat-graph sync gives way to your own work.** The sync runs at a lower CPU and disk
  priority, and the dashboard no longer copies the whole Hermes config on every settings read. The
  DKG node gets more time to start on a busy machine, so it no longer restart-loops. The node
  itself keeps its priority: it answers the hooks' threat-graph lookups.
- **The Linux sandbox's network rules are in place before the agent starts.** On a busy machine,
  the helper's agent rules waited on a slow dashboard. The agent started without them ("did not
  apply this agent's network rules in time"). The helper now binds a new agent at once, and a
  start waits up to 2 s for it.
- **Linux: a stop Blackbox refuses names the right system.** The reason it never stops a system
  process said "it is part of macOS" on Linux too. The Blackbox tests also no longer depend on the
  machine that runs them (29 failed on a Linux runner).
- `blackbox uninstall` also removes the system protection helper, first — your DNS and firewall
  go back to how they were before it (macOS asks for your admin password once).
- Self-protection covers add-ons: each add-on folder beside the plugin (one that carries the `blackbox-addon.json` manifest, `kernel.addons.MANIFEST`) is guarded in every Hermes home like the plugin's own, and an add-on can declare its other places (`Registrar.protect_places`) — before, an agent could delete an add-on and silently remove the protection it brings.

- **OpenClaw 2026.11.6 and later load Blackbox again.** That OpenClaw release could fail to load
  the Blackbox plugin on a busy machine ("Plugin preparation callback timed out") and then refused
  to run the agent at all. The OpenClaw plugin now ships as one bundled file, which loads.
- **OpenClaw: protected files are protected in shell commands too.** A protected file read, copied
  or archived through OpenClaw's `exec` tool (`cat ~/.ssh/id_rsa`, `cp -r ~/.ssh …`, `tar … ~`,
  a one-line script, `find … -exec cat`) is now flagged, and blocked in Block mode, as it is in
  Hermes. Before, only OpenClaw's file tools were checked.
- **OpenClaw: your protected-path list and block level now apply there.** Under OpenClaw the
  built-in protected paths (`~/.ssh/*`, `.env`, `*.pem`, …) were switched off by an empty default,
  and the list and block level you set in the dashboard never reached OpenClaw agents. Both now
  follow your Blackbox settings.
- **OpenClaw agents are now judged by the same checks as Hermes agents.** Before each tool call
  the OpenClaw plugin asks the Blackbox on your machine for its verdict, so packages and addresses
  from the verified threat graph, Trader Shield's wallet key stores and your local overrides apply
  to OpenClaw too (a verified malicious package installed through OpenClaw used to go through).
  If Blackbox's service is not running, the plugin's own built-in checks still decide.
- **A protected file reached as `$HOME/…` is protected like `~/…`.** `cat $HOME/.ssh/id_rsa`
  (also `${HOME}` and `%USERPROFILE%`) went through where `cat ~/.ssh/id_rsa` was blocked — in
  Hermes and OpenClaw alike. The home folder is now read the same however a command spells it.
- **A refused action retried another way is still caught.** After a protected file was refused,
  an agent could reach it by a bare name after `cd`, with `dd`, `awk`, `sed`, `sort`, `vim` or
  `open`, through `< file`, `echo file | xargs cat`, a variable holding the folder, an upload
  (`curl -d @file`, `-F`, `-T`), `file://`, or by wrapping the command in `sh -c '…'`, `bash -c`
  or `eval`. A package fetched with `npx`, `bunx`, `pnpm dlx`, `yarn dlx` or `pipx run`, or
  installed inside `sh -c`, is now checked like any install.
- OpenClaw findings on the dashboard say whether the action was blocked or flagged, and which
  OpenClaw profile and agent it came from ("OpenClaw · work / research").

### Changed

- **Agents run inside Blackbox's sandbox by default.** On install, upgrade and `blackbox attach`
  every agent Blackbox finds is picked for the agent sandbox (macOS, and Linux where the system
  protection helper's `blackbox-sandbox` is installed), File Shield engaged. An agent
  you took out of the sandbox stays out, upgrades included; taking one out still asks you first; a
  File Shield you turned off stays off.
- **Uninstall asks whether to remove the Hermes host Blackbox's installer set up.** On a machine
  that had no Hermes before, `blackbox uninstall` asks once (`--remove-host` when not at a terminal)
  and removes exactly what the installer put there — your own lines in `~/.zshrc` stay byte for
  byte. Kept, the host no longer loads Blackbox. A second uninstall says Blackbox is not installed
  and changes nothing; an add-on's companion app can name the caches, Keychain item and preferences
  it leaves, and they go too.
- **The persistence watch reports each change once, and names an agent only with evidence.** The
  same entry seen through a linked home folder, or `at`'s own bookkeeping files, no longer raise
  extra alerts; an agent is named as the writer only when the file was written while its command
  ran ("writer unknown" otherwise). A new program on your PATH is titled as one.
- The installer says what macOS really answered about Blackbox's notifications (allowed, waiting for
  your OK in the banner, or off — with where to turn them on).
- Installs Blackbox makes for a sandboxed agent keep your own `HOMEBREW_NO_AUTO_UPDATE`,
  `HOMEBREW_NO_INSTALL_CLEANUP` and similar "turn it off" Homebrew settings.
- Trader Shield protects a wallet type added in a later Blackbox version without a new save:
  a saved wallet list keeps the wallets you left unticked off, and guards every wallet it was
  never offered (before, those stayed off until you saved Settings again).


### Security

- **The bundled Node.js is 26.13.1, which carries Node's October and November 2026 security
  releases.** Builds that bundle their own runtime shipped Node 26.7.0, and setup warned that it
  should be upgraded. Every platform's pin now names 26.13.1 with nodejs.org's published checksums,
  so the runtime comes in through the package manager's normal checks.
- **Hermes no longer runs without Blackbox on a busy machine.** Hermes drops a plugin whose start
  takes longer than its 10 s limit, and Blackbox's took 10-15 s on a loaded 4-CPU machine, so
  Hermes ran unguarded and nothing said so. Blackbox now hands Hermes its hooks at once and loads
  the rest beside them. A tool call made before that is finished waits for it, and is refused
  ("not checked yet, try again") rather than let through. If Hermes still starts without Blackbox,
  that is a HIGH "running without Blackbox" finding, read from Hermes's own log.
- **A coding agent's hook answers before the agent stops waiting.** When the dashboard was slow,
  Blackbox's own check could take longer than the 10 s an agent waits, and the agent then ran the
  call: a graph-listed package installed. The hook now answers within its time: the dashboard
  first, then the same check (with the same threat-graph lookup) made locally. A tool call that
  could not be checked in time is refused, never passed. Recording happens after the answer.
- **Codex is shown as NOT protected until you trust Blackbox's hooks in Codex.** Codex runs a
  hook only after you approve it with `/hooks`. Blackbox reads Codex's own trust record and says
  so in `blackbox status`, the dashboard and `blackbox attach`, with the one step to fix it. A
  Codex run while its hooks are untrusted is a HIGH finding. Blackbox never approves them for you.
- **An agent cannot switch off its own hooks.** A write that would turn hooks off or remove
  Blackbox's hook entries in an agent's settings — Claude Code's user or project
  `settings.json` / `settings.local.json`, another project's, Codex's or Gemini CLI's project
  settings — is refused by every route (edit, shell, copy, script). Ordinary edits of those files
  still work. A Claude Code session that starts without Blackbox is reported as high severity,
  naming the folder.
- **The folders that hold the agents' hooks cannot be moved away inside the sandbox.** Every folder
  above a hook or plugin place, up to your home folder, is locked, on macOS and Linux.
- **DNS Shield and the Threat Firewall repair themselves.** They are checked every few seconds;
  if they were switched off, flushed or lost at a restart they come back within seconds with a
  high-severity alert, and the dashboard shows what is really in effect, not what was saved.
- **Signals to Blackbox's own processes are refused by number as well as by name** (`sudo kill
  -9 <pid>` of the helper).

- **The Docker socket is closed inside the agent sandbox** unless you allow Docker for that agent:
  a container runs outside the sandbox, so `docker run -v <protected folder>:/x` could read a
  protected item (KI-622). Mounting a protected item into a container is refused by the hooks too.
- **Your own program folders (`~/.local/bin`, `~/.cargo/bin`, `~/bin` …) are closed to writes inside
  the sandbox** by default: a program an agent left there would run outside it the next time you
  typed its name. Global installs now go through Blackbox.

- **No AI agent can leave something that starts by itself later — sandboxed or not.** An agent
  checked only by its hooks could add a key to `~/.ssh/authorized_keys`, write a launchd job, a
  cron or `at` job, a line in your shell startup files or a program in Homebrew's folders. Blackbox
  now refuses those writes for every agent in every mode, by any route, from the same list the agent
  sandbox closes; reading them stays allowed. Programs an agent writes into your own PATH folders
  (`~/.local/bin`, npm's global prefix, pipx) stay allowed and raise a critical alert naming the agent.
- **The agent sandbox keeps Blackbox's settings closed.** Inside the sandbox nothing can change,
  rename or remove Hermes's `config.yaml` and `.env` (every profile), where Blackbox's settings live,
  nor move Blackbox's home away.
- **Installs from lockfiles and manifests, and transitive dependencies, are checked (KI-595).**
  Blackbox used to check only the package names written in an install command, so `npm ci`,
  `npm install`, `uv sync`, `pip install -r`, `poetry install`, `cargo build`, `bundle install` and
  the packages a named install pulls in were never checked against the threat graph. Now the files
  they install from (npm/pnpm/yarn/bun lockfiles, package.json, requirements files, uv.lock,
  poetry.lock, Pipfile(.lock), pyproject.toml, Cargo.lock, Gemfile.lock) are read — bounded,
  offline, cached — and every package is judged in the usual tiers: verified blocks naming the
  package, version, file and chain, community flags. After a named install, the packages it added
  to its lockfile are checked; a verified one that landed is a critical alert with the removal
  command. Writes that add a listed package to these files are judged at the write. A file that
  cannot be read lets the install through with a note on the session. See "What Blackbox checks
  for packages" in the README and the dashboard's Docs page.
- **The agent sandbox reaches more launches and cannot be turned against Blackbox.** The sandbox
  launchers are now first on PATH for zsh started without a terminal too (`zsh -c`, a zsh script,
  an SSH command); File Shield's page lists which ways of starting an agent are covered and says
  for each agent whether it is "sandboxed (kernel-enforced)" or "hooks only". Inside the sandbox an
  agent can no longer change any agent's hook config or signal a process outside it. The Hermes
  agent can be picked: its terminal tool's shells then run inside the sandbox. A refusal the
  sandbox made now shows on the agent's session as refused.
- **A script an agent writes is judged by what it says.** File Shield now reads a script an agent
  writes (through a file tool, a heredoc or `echo … >`) and refuses it when it names a protected
  item — also when its path is joined from pieces such as `Path.home().joinpath(…)` — and reads it
  again when the agent runs it. A program that hides what it opens still needs the sandbox.
- **File Shield judges the command an interpreter is told to run.** A protected file read through
  inline code (`python3 -c`, `node -e`, `ruby -e`, `perl -e`, `osascript -e`), a command
  substitution, a decode spelled out on the command line, `eval`, or a wrapper such as `env`,
  `nohup` or `timeout` is now refused like the plain read. A command beside a protected item that
  builds what it opens while it runs is flagged and says why; every flagged action now shows its
  reason.
- **Gemini CLI's hooks now really run.** Blackbox wrote each hook's time limit in seconds, but
  Gemini CLI reads it in milliseconds, so every hook was cut off and Gemini ran without Blackbox.
  Each agent now gets its limit in its own unit, the sweep rewrites a config written the old way,
  and the Agents page and the agent's profile say so when a hook is written but would not run.
- **An agent cannot switch Blackbox off, in any mode.** An action that would change Blackbox's
  settings, rules, logs or program files, stop its services, use its control page, or start an
  agent with Blackbox's own variables changed is now refused in Audit mode too (before, Audit mode
  only flagged it, so an agent could turn the guard off and carry on). Everything else in Audit
  mode is still only flagged. You change Blackbox as before: the dashboard, the `blackbox`
  commands you type, or your own editor.
- The rule that protects Blackbox itself was rebuilt after an attack pass of 240 attempts: it now
  covers OpenClaw's config and plugin files, the service definitions, the `blackbox` command,
  wildcards, parent folders, other tools that run commands, scripts written first and run later,
  base64-wrapped commands, and a change hidden in the middle of a very long command. Reading
  Blackbox's files and status stays allowed.
- While Blackbox's service is not answering, an OpenClaw agent is refused anything that touches
  Blackbox itself until the service is back.
- **The system protection helper is hardened and lives in the core** (`plugins/blackbox/helper`,
  one helper for Blackbox and any companion app). It obeys only plans signed with its own install
  key (another program on port 9700 cannot drive it) and reports only to Blackbox; the firewall is
  checked really on after every change and after a restart; DNS Shield switches only to a resolver
  that answers, puts your DNS back if it stops, follows the network you are on and never sends your
  lookups to a public resolver you did not choose; it never follows links or hangs on special
  files in your folders; it installs only a binary whose checksum was verified first; its records
  are private to the system; and stopping, repairing or removing it never turns your Mac's own
  hardening back off unless you choose that. The installer offers it at the end (`--system-protection`,
  `--no-system-protection`, `--remove-system-protection [--undo-hardening]`); no means nothing is installed.
- **Blackbox signs the helper's plans and checks its reports.** With the key the helper gives
  the person who installed it, Network Shield signs every plan for that one request and refuses a
  report that the helper did not sign. Network Shield's card shows the helper's health: whether
  it is paired (and how to fix it if not), an older helper, the macOS packet filter off, DNS
  Shield's resolver not answering, and the last problem it reported.

## [1.5.0] - 2026-11-19

### Added

- The dashboard now says when your agent has no AI model connected (a fresh install has none:
  the agent cannot chat, so no prompt reaches Blackbox to check) and connects one right there —
  a free Nous account (you approve on Nous's site; the dashboard shows the link and code) or your
  own API key (OpenRouter, Anthropic, OpenAI, Google AI Studio), handed straight to Hermes and
  never kept or logged by Blackbox. The panel goes away once the agent has a model.
- The installer ends with that same step when the agent has no model, and offers to open the
  dashboard.
- The installer asks once whether to turn on Block mode (Audit stays the default; no terminal or
  no answer keeps Audit).
- A status dot in the top bar shows the agent's AI model at a glance: green connected, amber
  refused recently, red none — with one slim line on the page until it is connected. Click it for
  the account and model, the model recommended for your account (a free Nous account gets a free
  model), another model, or to switch account / sign out; every change says what it did. While
  you sign in it shows a small spinner — waiting for your approval on Nous's page, then connecting
  the account — and a short note says when it is done.

### Fixed

- A global install of a package you only watch is no longer refused as a threat.
- A program an agent puts on your PATH with `npm -g` is reported naming the agent.
- A new DNS block applies within seconds (was up to three minutes), without a "plan could not be
  read" message meanwhile.
- A refusal by the sandbox is counted for the agent that tried, not for "agent-sandbox".
- A script deleting under Blackbox's folder is no longer also counted as a startup-item attempt.
- An agent you removed no longer shows as available; Linux says "this machine", not "this Mac".
- An upgrade over a running install no longer fails with "File exists".
- Uninstall removes the empty folders the installer created, and nothing of yours.
- Before the first threat-graph sync, the dashboard no longer says the graph is complete.

- **Codex can edit a package.json with its own patch tool again.** A Codex `apply_patch` of any
  package.json was refused as a change to Blackbox's own settings; a listed package added that way is
  now refused for what it is.
- **Cline's first message is checked.** Cline's start event carries no task text; Blackbox's Cline
  plugin now reads the task from the first run (CLI, SDK, Kanban). In the IDE extensions, which run
  hook scripts only, the first message is still not checked.
- **Refusals the sandbox makes are counted where they were missed:** a launchd job, an SSH key or a
  program in Homebrew's folders refused inside the sandbox, and a protected file the Hermes agent's
  `execute_code` was refused, now show on the session as refused.
- A 2,000-package lockfile is checked with half the store queries it took before.

- **Each agent session tells the truth about itself.** Claude Code and Gemini CLI sessions now show
  their model (from the command line, then from the session's transcript — the model's name only);
  one prompt is counted once even when sub-agents report back; a sub-agent's task no longer counts
  as a prompt of its session; a headless Cline run shows as headless; a session whose hooks a
  `--settings` flag or a project setting switched off says exactly which; OpenCode sub-agents end
  when their task returns or their session's process leaves.
- **The Hermes agent's sessions show where they run.** Each session now shows its project folder
  (not the Hermes home), its process, whether it was started headless, its model and how many
  prompts it was given; two projects are two lanes, every child of one delegated task is that
  session's sub-agent, and the history can be filtered to the Hermes agent.
- Every Hermes profile is protected the same way. A profile other than the main one — Blackbox's
  own assistant included — used to keep its own Blackbox folder: no verified threat rules (only
  the general patterns), its own copy of the settings (dashboard changes and Block mode never
  reached it), and logs the dashboard never showed. Now one Blackbox serves every profile: the
  same rules, the same settings, one log, and each finding is labelled with its profile
  ("Blackbox assistant" for the assistant). Old per-profile logs join the shared log when the
  dashboard starts, and an agent in any profile can no longer edit the main Hermes config.
- The "Test Blackbox" card no longer asks you to paste the test prompt into a chat that cannot
  run: with no model connected it says to connect one first.
- The Blackbox assistant answers "connect a model first" (with a button to the panel) instead of
  Hermes' raw setup text, and always uses the same model as your agent (it used to keep the
  settings it was first made with).
- After a free Nous sign-in the agent now lands on a free model; it used to land on a paid one
  and every chat was refused for credits.
- The assistant no longer shows Hermes' "Resumed session" notice or an out-of-credits message as
  if it were its answer: it says the model gave no answer and offers to fix the connection.
- The assistant starts a new conversation by itself when the one it remembered is gone (after a
  reinstall), instead of answering "Session not found".
- The assistant gets a short, current summary of Blackbox's state with every question (mode, rules,
  last refresh, protected agents, newest findings), so it answers common questions straight away
  instead of searching — and a finding's flagged text is never in it. When the assistant reads
  Blackbox's own findings back, an old finding is no longer flagged a second time; anything new in
  what it read, or in what you type, still is, and your own agents still flag every repeat. With a free model the AI model card says it is
  a small model and how to get sharper answers.
- The Playground's four send-a-threat tests no longer show as buttons that never respond while
  Community sharing is off: it says why and opens the setting.

## [1.4.1] - 2026-11-13

### Fixed

- **One check that fails no longer ends the others.** If a single detector hits an error on a
  call (for example on a number thousands of digits long), the rest of the checks still run and
  can still block; the failure is logged. Arguments nested too deep to read are checked as text
  instead of raising an error to Hermes.
- **A typo in `snapshot_sync` no longer switches protection off.** A saved `snapshot_sync` block
  that cannot be used is reported (`blackbox status` says so, sync refuses to start) while every
  check keeps running. Saving such a block is refused.
- **A long command is checked like a short one.** The protected-path, keychain, guard-settings
  and dangerous-command checks read a command whole up to 100,000 characters, and a longer one
  by its first and last 50,000. They used to read only its first 8,000.
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
- **Uninstall also removes Blackbox from its own chat profile.** The plugin copy that
  `blackbox chat` puts in `~/.hermes/profiles/agent-blackbox` was left behind. Uninstall also no
  longer crashes on a config.yaml whose `plugins:` section is not a mapping, and `blackbox detach`
  exits with an error when a target could not be detached.
- **Uninstall stops only Blackbox's node.** The process number saved by the node is checked to be
  the Blackbox node before it is stopped. Uninstall and the dashboard's assistant also use the
  Hermes they are running in, not another `hermes` found on the PATH.
- **The audit logs lose no record under load.** When several agents write while one trims a full
  log, every record is kept.
- **A dashboard page left open keeps working after the dashboard restarts** (it used to answer
  "403" until reloaded), and the first page after a start is no longer slow because the start-up
  reads did not run.
- **Nothing is shared while sharing is off, whichever part of Blackbox sends it.** The check that
  sharing is switched on and your consent is in force now sits at the one place reports leave
  the machine, not only in each feature that sends. Disputes and retractions still go through,
  because they only withdraw.
- **A refused manual report is recorded once.** `blackbox report` wrote two "reports" rows for a
  report the node refused for now (one "failed", one "retrying"); it now writes the one
  "retrying" row, as automatic reports do.
- **The dashboard no longer calls a graph "open" while the node is still waiting to learn
  its policy.** When the graph's on-chain record had arrived empty, the community card could
  say "open graph: no approval needed" while Blackbox itself was still waiting to decide; both
  now say it could not check yet.
- **A manual report made in sandbox mode stays in the sandbox.** `blackbox report` with Sandbox
  mode on now goes to the sandbox lane only, like automatic reports, and is not re-published.
- **Curator consent codes expire and are single-use, as documented.** `curate publish` restarted
  a code's 10-minute life on every attempt, and two publishes of one code at the same moment could
  both go through. A code now expires 10 minutes after it was shown and is used once.
- **A curator's second publish to Verified Memory does not pay again.** When the first attempt
  could not read its statement back yet, the next attempt published (and paid) again instead of
  looking first. A publish that timed out now says it could not tell whether it was published,
  not that nothing was.
- **`blackbox curate watch` raises the same alarms as the curator service.** It left out the
  self-test's alarm, so a curator suspended by a failing self-test was silent through it.
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
- **Trader Shield names the right browser.** A wallet is shown under the browser whose folder it
  is in; a user folder such as "marc" or "operator" no longer makes a Chrome wallet read Arc or Opera.
- **An approval to a spender Blackbox cannot check is told like any other approval.** Its event
  in Trader Shield's report now says what the agent reached for and why it matters.
- **An empty `APPDATA` no longer points Trader Shield at the top of the disk.** Like an empty
  `XDG_CONFIG_HOME`, it now counts as unset when Trader Shield works out where a wallet app keeps its files.
- **A crash while recording a report can no longer reset the report limits.** The file that holds the
  per-threat cooldowns and the daily cap is replaced whole, never rewritten in place.
- **Detaching an OpenClaw agent keeps a copy of its config.** `blackbox detach` saves
  `openclaw.json.before-blackbox-detach.bak` before it rewrites the file, as attach does. Both now
  say when a config's comments could not be kept, and name the copy that still has them.
- **Switching an agent off through a link to its folder sticks.** An agent switched off (or back on)
  through a symlink or another spelling of its folder is the same agent to the automatic re-attach.
- **`blackbox uninstall` asks at your terminal when it is run from a pipe.** Like `blackbox attach`, it
  asks the terminal itself instead of refusing outright; with no terminal it still needs `--yes`.
- **`blackbox uninstall` finishes on a hand-edited Hermes config.** A `plugins:` written as text or a
  list no longer stops the removal half-way, after the services were already stopped.
- **One damaged line in a log no longer empties the dashboard's findings.** A findings line that is
  not a JSON object is skipped like any other damaged line; the activity total counts only rows it shows.
- **The Playground's sandbox lane shows other members' tests safely.** Their text is cleaned and
  defanged like the Community graph's, a threat's category comes from its identifier, and a test can no
  longer break the threat window by filling its sources with text.
- **Hermes Desktop's status bar counts every action of the day.** On a day with more than 100 findings the
  count stopped at the newest 100; it now counts everything from the last 24 hours.
- **An older finding shows the same trust everywhere.** A recorded finding that does not say whether it
  came from a verified rule now reads the same in the findings list and the Local activity view.
- **The dashboard links a threat's references only when they are web addresses.** Anything else is
  shown as plain text, as Hermes Desktop already did.
- **Hermes Desktop says the first sync is done only when verified rules have arrived.** Community reports that
  Blackbox can match against were counted as verified rules, so the setup page could call the first sync
  finished too early.
- **A sync failure is no longer hidden by an older catch-up job.** The dashboard's sync activity read a
  job time written in milliseconds as newer than the failure and dropped the failure's reason.

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
- **The Blackbox assistant in Hermes Desktop.** The chat button in the page header opens the dashboard's
  assistant beside the page: its three example questions, a running conversation kept on this
  computer (New chat starts over), and progress messages while it works.
- **Docs and the Playground in Hermes Desktop.** The book button opens the dashboard's documentation in
  your browser. With Sandbox mode on, the Overview holds the Playground: send a listed threat of
  each kind through the real check, and run every wallet test Trader Shield has for this machine
  (one at a time or Run all), each with its result.

### Changed

- A seed phrase or wallet private key on its way off the machine (posted, put in a web
  address, sent by a script or a messaging tool) is blocked even with Trader Shield off — a
  wallet secret has no right destination. Writing or reading one on the machine stays Trader
  Shield's to watch.
- The Hermes Desktop page refreshes every 4 seconds, as the dashboard does (was 10 to 30).
- The Hermes Desktop page opens with your connected agents, then the stats, then Trader Shield as the
  dashboard's "Engage Trader Shield" card (one line once it is on). A new **Shields** tab turns each
  shield on or off (turning off asks first) and holds what it protects, its events and its settings.
- A shield's recent events are clickable, as on the dashboard: each opens the shield's events window
  with the full local record (what happened, what to do, the details, what happened in that session),
  private to this machine and refreshed live; View all lists every event.
- Clicking a threat (on the map, in search or in Threats detected) or an Agent activity row opens a
  pop-up with the same details as the dashboard's, over the page, instead of leaving it.

### Fixed

- The Hermes Desktop page's "Open findings" card opens Threats detected, as the bell does (it was
  a count you could not click through).
- An agent can no longer stop Blackbox's own services: unloading or stopping its login
  services, killing its dashboard or node by name, or killing whatever holds their ports is
  treated like editing Blackbox's settings (ordinary process commands stay allowed).
- The Hermes Desktop Shields tab no longer ticks Trader Shield's checks while the shield is off — each
  shows "off — engage Trader Shield to watch this".
- The Hermes Desktop "Threats detected" table fits beside the sidebar: the outcome sits under the
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
  starting" (and Hermes Desktop's header "Node starting") instead of a red "my node is stale — run
  `blackbox sync --wait`".
- The Blackbox assistant looks threats up instead of reading a whole graph tier into the model: its
  answers are faster, and its own request no longer trips Blackbox's prompt-injection alert on the
  attack phrases quoted in threat names.
- Turning on Trader Shield, or saving its settings, no longer tells you to restart your agent: a
  running agent picks the change up at once (README and the Trader Shield page updated too).
- Hermes Desktop: a long package name in Threats detected, or the graph on a Retina screen, no longer
  pushes the page sideways past the window; the tabs line up with the header once the first sync
  is done; the first-sync note is not shown twice; the "recording, not blocking" notice waits until
  setup has finished instead of covering the setup page; "Watching" (audit mode) is amber like the
  Shields tab; the Attach agent tile shows a close icon while it is open.
- "Attach agent" on the dashboard opens its window again from a click on its icon or label (only
  a click on the button's edge did anything), and Escape closes that window.
- The Trader Shield page no longer says "Not engaged" for the first moments after the dashboard
  starts: it shows "Checking this machine…" until the dashboard knows, then the real state.
- Threat graph labels stay readable in the dashboard and in Hermes Desktop: hub names and threat counts
  sit on a small plate above the dots, two labels never land on each other, and on a phone they
  keep a readable size instead of shrinking to a few pixels.
- Layout and sizing: the umanitek logo at the foot of the dashboard shows on the light theme; the
  tier tabs show "970,000" like the cards; the Trader Shield card has no empty fourth column and
  its header wraps on a phone; the Trader Shield page's headline fits in four lines on a laptop
  and its picture no longer runs into the status box on a phone; the docs search box and figure
  labels fit on a phone; Hermes Desktop's five summary cards sit 3 + 2 beside Hermes' sidebar instead of
  five squeezed columns, and its wordmark reads BLACKB●X.
- A fresh dashboard no longer says "UNPROTECTED: run `blackbox sync --wait`" while setup's own first
  sync is running: its health check reads the sync meter before judging the first sync.
- On a fresh install the first sync of the verified threat graph starts within seconds of setup
  finishing. It could wait an hour: setup's own compile left an empty ruleset that the dashboard
  took for a finished one.
- The Blackbox assistant answers again, in the dashboard and in Hermes Desktop. On Hermes 0.23 every
  question failed with "No such file or directory: '/usr/local/sbin/-c'": it re-ran Hermes by the
  name of the running program, which Hermes' new launcher reports as `-c`.
- The assistant's own Hermes profile no longer appears in Connected agents as an idle agent.
- One slow request (an assistant answer) no longer freezes the Hermes Desktop page: it used to empty
  every card until the answer came back.
- A question to the assistant that starts with a dash ("-v", "--why") is asked as written
  instead of failing, and when the assistant cannot start, the page says so in plain words
  instead of showing the system's error text.
- Hermes Desktop's assistant shows `code` and **bold** in its answers as formatting, not as symbols.
- Hermes Desktop no longer says "0 connected agents" above an agent it protects: like the dashboard, it
  counts only agents active right now and shows nothing when none is.
- Hermes Desktop's assistant: "New chat" while an answer is on its way really starts a new chat (the old
  answer no longer comes back), closing and reopening the assistant mid-answer keeps that answer,
  and answers keep their paragraph breaks.
- A long Hermes Desktop request (an assistant answer, a Playground test) no longer gives up after one
  failed check while it is still running, and Playground "Run all" stops when you leave the page.
- Hermes Desktop's threat bell counts the same threats the findings list shows, and clicking it before
  the list has loaded no longer marks every threat as new again.
- A Shield's list setting in Hermes Desktop (addresses, names) can be typed one entry per line; Enter and
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
- **A shield in Hermes Desktop's status bar** shows the mode — Audit in amber, Block in green — and what
  was caught today; Hermes Desktop says once, with a Turn on blocking button, when Blackbox is recording
  but not blocking.
- **Live alerts in Hermes Desktop** the moment Blackbox flags or blocks something an agent tried to do:
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
  Hermes Desktop's Hermes — the DKG node, its keys and its synced graph move with it — and retires the
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

[Unreleased]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.6.0...main
[1.6.0]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.5.0...blackbox-v1.6.0
[1.5.0]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.4.1...blackbox-v1.5.0
[1.4.1]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.4.0...blackbox-v1.4.1
[1.4.0]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.3.0...blackbox-v1.4.0
[1.3.0]: https://github.com/umanitek/agent-blackbox/compare/blackbox-v1.2.0...blackbox-v1.3.0
[1.2.0]: https://github.com/umanitek/agent-blackbox/compare/7d697683e0d56608cfe3fee374d6a6866702058a...blackbox-v1.2.0
[1.0.0]: https://github.com/umanitek/agent-blackbox/tree/7d697683e0d56608cfe3fee374d6a6866702058a/plugins/blackbox
