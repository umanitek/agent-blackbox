# Agent Blackbox threat model

This document says what Agent Blackbox protects, against whom, where each protection is
enforced, and what it does not protect. It is written for the people who run Blackbox and for
anyone reviewing it.

Blackbox is a plugin (`plugins/blackbox/`). It sits between an AI agent and each action the agent
takes: a tool call, a model request, a package install, a file read or write, a command. It names
the action, checks it against local rules, and then records, flags or blocks it.

Every claim below points to a test in this repository. Where a claim is not checked by a test,
this document says so and says why.

For the Hermes host's own trust model (isolation postures, credential scoping, external
surfaces), see the root `SECURITY.md`. This document covers Blackbox only.

## How protection is layered

- **Layer 1, the hooks.** Every tool call an agent makes passes Blackbox's guard first. The guard
  reads the text of the call (the command, the path, the code) and judges it. It runs locally and
  offline, with no network call on the hot path. It covers the Hermes agent, Blackbox's own
  assistant and the supported coding agents (see `plugins/blackbox/docs/agent-compat/`).
- **Layer 2, the agent sandbox.** For the coding agents the person picks, Blackbox starts the
  agent inside the operating system's own sandbox, built from the protected list. The kernel then
  refuses the open, the write or the job, whatever a program computes at run time. It is on by
  default where it is available.
- **The system protection helper.** An optional root helper watches protected items with the
  operating system's file events and enforces some Network Shield plans. Its reports are signed.

Layer 1 judges what a call says. Layer 2 judges what a process does. Only Layer 2 is a guarantee
against code whose behaviour is decided at run time.

## Goals

- **G1. The agent cannot switch Blackbox off.** It cannot edit Blackbox's settings, remove its
  hooks, stop its programs, move its folders or press its switches. This holds in every mode,
  Audit mode included.
- **G2. Protected files stay closed.** An item the person protects cannot be read, copied, listed,
  changed, moved or deleted by any agent, by any route Blackbox can see.
- **G3. Weakening waits for the person.** Any change that lowers protection is held until the
  person confirms it with a proof an agent cannot produce. Strengthening applies at once.
- **G4. Nothing leaves the machine without opt-in consent.** Community sharing is off by default.
  Reports never carry prompts, commands, file contents or secrets. There is no telemetry.
- **G5. Fail-open.** If Blackbox itself breaks, the agent keeps working, and the trail says that a
  call passed unchecked.
- **G6. Only verified rules may block.** Rules from the verified graph may block. Community rules
  only flag. Local overrides may only reduce severity.
- **G7. Nothing is left to start by itself later.** An agent cannot leave a job, login item or
  login file that would run later, outside Blackbox's view.
- **G8. The record can be trusted.** Local logs are redacted and size-capped, cannot be forged by
  injected text, and tampering with them is detectable.

## Assumptions

- **A1. The person is not the adversary.** Blackbox protects the person from their agent, not the
  machine from its owner. The person's own edits, dashboard actions and typed `blackbox` commands
  do not pass through an agent's tool calls and are not judged.
  (not checked: this is a scope statement, not a behaviour.)
- **A2. The OS kernel and root are trusted.** The sandbox, file permissions and signals rely on the
  kernel. A process running as root can undo any user-level protection.
  (not checked: no test can prove the kernel is sound.)
- **A3. The hooks are attached.** Blackbox can only judge an agent whose hooks are installed and
  whose hook config still carries Blackbox's entry.
  (checked: `tests/plugins/test_blackbox_attach.py`, `tests/plugins/test_blackbox_agent_hook_configs.py`)
- **A4. The dashboard listens on loopback only.** It binds to 127.0.0.1, refuses forged hosts and
  foreign origins, and needs its process token for writes.
  (checked: `tests/plugins/test_blackbox_dashboard_server.py`, `tests/plugins/test_blackbox_browser_boundary.py`)
- **A5. Agents run as the person, not as root.** A sandbox cannot hold a root process, and the
  operating system does not start setuid programs inside one.
  (not checked: it depends on how the person starts the agent.)
- **A6. The installed plugin is the one that was shipped.** Blackbox cannot protect itself from a
  change made before it was installed, or by the person.
  (not checked: the integrity of the shipped code depends on where the person got it.)
- **A7. The hot path stays fast and local.** Rules are compiled locally. A hook waits only for
  the verdict, never for bookkeeping, and a degraded rule store is probed, not waited on.
  (checked in part: `tests/plugins/test_blackbox_agent_hook_latency.py`,
  `tests/plugins/test_blackbox_lookup_breaker.py`)

## Adversaries

| Adversary | In scope? | What Blackbox does |
|---|---|---|
| A misbehaving agent (mistakes, over-eager actions) | Yes | Prevents, through hooks and sandbox. |
| A prompt-injected agent (hostile text in a page, file or tool output) | Yes | Checks prompts and outputs; prevents the actions the injection leads to. |
| Local malware running as the same user | Largely no | Some of it is detected (startup items, DNS changes, changes to protected items). Little is prevented. |
| Root, or anyone with the person's password | No | Out of scope. Root can remove Blackbox. |

Plainly: Blackbox defends against the agent it watches, whether the agent is wrong or has been
turned. It does not defend against a program that never passes through an agent's tool call and
already runs with the person's rights. Against that, Blackbox can detect some effects and tell
the person. It cannot prevent them. Against root it offers nothing.

## Threats

Each threat lists where it is enforced, what the agent sees, how it is counted, which tests cover
it, and what is left.

"Tamper counts" are three counters of refused attempts against Blackbox, kept in Blackbox's own
folder (`audit.tamper_counts`) and shown on the dashboard's Protection page:

- **self-protection**: a hook refused a change to Blackbox, a read of its keys, or a signal to its
  programs;
- **self-protection-kernel**: the operating system's sandbox refused it (on macOS from the kernel's
  denial log, which the helper reads; on Linux from the refusal the sandboxed program printed, which
  the agent's hook reads, `shields/files/changes.py` `record_seen_refusal`);
- **startup-item**: a hook refused something that would start by itself later.

Each refusal counted is also an entry in the protection log (T11). An agent cannot reset either:
both live in Blackbox's folder, which is guarded (T1). "Findings log" is the local findings record
the dashboard shows. Held weakening changes (T10) are not tamper counts; they wait on the
dashboard's approval prompt.

### T1. Editing Blackbox's settings or config

An agent changes Blackbox's mode, turns a shield off, or rewrites the config that holds them.

- **Enforced at:** `plugins/blackbox/detection/paths/guard_settings.py` and `guard_places.py`
  (Layer 1); `plugins/blackbox/shields/files/sandbox/places.py` (Layer 2: Blackbox's places are
  readable, never writable).
- **Refusal:** the call is blocked in every mode with a critical finding, "Change to Blackbox's
  own settings". A read is allowed.
- **Counted by:** tamper counts: self-protection; self-protection-kernel (refused inside the sandbox).
- **Tests:** `tests/plugins/test_blackbox_guard_settings.py`,
  `tests/plugins/test_blackbox_self_protection.py`,
  `tests/plugins/test_blackbox_self_protection_scripts.py`,
  `tests/plugins/test_blackbox_agent_sandbox_own_settings.py`,
  `tests/plugins/test_blackbox_addon_self_protection.py`,
  `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** on hooks only, a change built from pieces the rule cannot join, or made later by a
  program started earlier, is not seen (see U1).

### T2. Removing Blackbox's hooks from a coding agent

An agent edits its own hook settings to drop Blackbox's entry.

- **Enforced at:** `plugins/blackbox/detection/paths/guard_settings.py` (each agent's hook config
  is a guarded place); `plugins/blackbox/kernel/agent_hosts` (the catalogue of hook files).
- **Refusal:** an edit that touches Blackbox's part, or overwrites the whole file, is blocked. The
  agent may still edit the rest of its own settings.
- **Counted by:** tamper counts: self-protection.
- **Tests:** `tests/plugins/test_blackbox_agent_hook_configs.py`,
  `tests/plugins/test_blackbox_agent_security.py`, `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** an agent started without its hooks (for example an IDE that starts its own copy)
  is not judged at all. The dashboard shows which sessions report in.

### T3. Stopping or killing Blackbox's processes or service

An agent signals the dashboard or another Blackbox program, or stops its service.

- **Enforced at:** `plugins/blackbox/detection/paths/guard_settings.py` with
  `plugins/blackbox/kernel/own_processes` (which programs are Blackbox's).
- **Refusal:** a signal or service stop aimed at Blackbox is blocked. Everyday signals to the
  agent's own programs stay allowed. The service restarts however it ends. With the dashboard down,
  the hook runner judges the call itself, locally, so a refused call is still refused.
- **Counted by:** tamper counts: self-protection.
- **Tests:** `tests/plugins/test_blackbox_self_protection_processes.py`,
  `tests/plugins/test_blackbox_guard_settings.py`,
  `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** only genuine breakage (the plugin missing or broken) lets calls through unchecked,
  by design (G5).

### T4. Switching mode through the control API or the dashboard

An agent calls the dashboard's settings routes, drives a browser at it, or reads its session token.

- **Enforced at:** `plugins/blackbox/detection/paths/guard_settings.py` (requests and browser
  tools aimed at Blackbox's switches); `plugins/blackbox/kernel/browser_boundary` (host, origin and
  token checks); `plugins/blackbox/approvals` (weakening is held).
- **Refusal:** the call is blocked. A request without the token is refused before it can raise a
  dialog. A weakening request that does arrive is held (HTTP 428) for the person.
- **Counted by:** tamper counts: self-protection (the refused call). A held request is shown to the
  person, not counted.
- **Tests:** `tests/plugins/test_blackbox_agent_security.py`,
  `tests/plugins/test_blackbox_browser_boundary.py`, `tests/plugins/test_blackbox_approvals.py`,
  `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** if the person exposes the dashboard beyond loopback, A4 no longer holds.

### T5. Startup items and persistence

An agent leaves something that starts later by itself: a launchd job, a login item, a cron or
`at` job, an SSH login file, a shell startup line, a systemd unit, or a program in a folder on the
person's PATH.

- **Enforced at:** `plugins/blackbox/kernel/persistence_places` (the one list),
  `plugins/blackbox/detection/paths/guard_startup.py` (Layer 1, every mode),
  `plugins/blackbox/shields/files/sandbox/places.py` (Layer 2, closed to writes).
- **Refusal:** the write, or the command that schedules a job, is blocked. Inside the sandbox the
  kernel refuses it. The person can still add the item in their own terminal.
- **Counted by:** tamper counts: startup-item. Network Shield's persistence watch also raises a
  finding (critical when an agent wrote it) in the findings log.
- **Tests:** `tests/plugins/test_blackbox_persistence_hooks.py`,
  `tests/plugins/test_blackbox_persistence_scripts.py`,
  `tests/plugins/test_blackbox_persistence_wrappers.py`,
  `tests/plugins/test_blackbox_persistence_linux.py`,
  `tests/plugins/test_blackbox_agent_sandbox_startup_places.py`,
  `tests/plugins/test_blackbox_sandbox_login_preferences.py`,
  `tests/plugins/test_blackbox_network_startup_items.py`,
  `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** on hooks only, a name assembled at run time is not judged (U1). The watch still
  sees the result after the fact.

### T6. Reading Blackbox's keys

An agent reads the key that signs reports or the helper's key folder.

- **Enforced at:** `plugins/blackbox/detection/paths/guard_secrets.py` (Layer 1, any tool, any
  spelling, every mode); `plugins/blackbox/shields/files/sandbox/places.py` (Layer 2, no read).
- **Refusal:** blocked with "Would read Blackbox's key files". Ordinary work near Blackbox's
  folders is left alone.
- **Counted by:** tamper counts: self-protection.
- **Tests:** `tests/plugins/test_blackbox_guard_secrets.py`,
  `tests/plugins/test_blackbox_agent_sandbox_reach.py`,
  `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** same-user malware can read any file the person can read (out of scope).

### T7. Protected-file access by a tool

An agent's file tool, shell command or MCP tool names a protected item, a folder above it, or a
spelling that resolves to it.

- **Enforced at:** `plugins/blackbox/detection/paths/protected.py`, `plugins/blackbox/shields/files`.
- **Refusal:** blocked in every mode with "Access to a user-protected path". A whole-tree command
  over a folder that holds a protected item is refused with advice to name the subfolders instead.
- **Counted by:** findings log (`files:file-hit`, `files:folder-hit`, never with file contents).
- **Tests:** `tests/plugins/test_blackbox_shields_files.py`,
  `tests/plugins/test_blackbox_protected_paths_terminal.py`,
  `tests/plugins/test_blackbox_protected_paths_touches.py`,
  `tests/plugins/test_blackbox_protected_paths_bypass.py`,
  `tests/plugins/test_blackbox_file_shield_escaped_paths.py`,
  `tests/plugins/test_blackbox_file_shield_proc_aliases.py`.
- **Residual:** none for routes the call names. Run-time paths are T8 and U1.

### T8. Protected-file access by a script

An agent writes or runs a script that opens a protected item.

- **Enforced at:** `plugins/blackbox/detection/script_files` and `detection/paths` (the script's
  text is judged when written and when run, with its arguments).
- **Refusal:** blocked when the text shows the path. When it cannot be decided from the text, the
  call is flagged with the reason, not shown as plainly allowed.
- **Counted by:** findings log.
- **Tests:** `tests/plugins/test_blackbox_file_shield_written_scripts.py`,
  `tests/plugins/test_blackbox_file_shield_write_and_run.py`,
  `tests/plugins/test_blackbox_file_shield_wrapped_runs.py`,
  `tests/plugins/test_blackbox_file_shield_hooks_only_routes.py`,
  `tests/plugins/test_blackbox_script_files_stdin.py`.
- **Residual:** a script whose behaviour is decided only at run time is not stopped by hooks
  alone (U1). That is Layer 2's job.

### T9. Protected-file access by a sandboxed program

A program the agent starts inside the sandbox (a compiled binary, an interpreter, a shell) tries
to open, change or rename a protected item, or a folder above it.

- **Enforced at:** `plugins/blackbox/shields/files/sandbox` (Facade over `places.py` and one
  platform Strategy per OS).
- **Refusal:** the kernel refuses the operation. The agent is told "Blackbox's sandbox refused
  this (…)" beside the error. The refusal is recorded on the agent's session.
- **Counted by:** tamper counts: self-protection-kernel (for Blackbox's own places); findings log
  (for File Shield hits).
- **Tests:** `tests/plugins/test_blackbox_shields_files_sandbox.py`,
  `tests/plugins/test_blackbox_shields_files_sandbox_default.py`,
  `tests/plugins/test_blackbox_agent_sandbox_reach.py`,
  `tests/plugins/test_blackbox_agent_sandbox_refusals.py`,
  `tests/plugins/test_blackbox_sandbox_linux_platform.py`,
  `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** an agent started outside Blackbox's launchers keeps Layer 1 only. A running agent
  keeps the profile it started with until restarted.

### T10. Turning protection down

An agent (or a page it drives) asks Blackbox to go to Audit mode, switch a shield off, remove a
protected path, take an agent out of the sandbox, widen an allow-list or loosen a sandbox
permission.

- **Enforced at:** `plugins/blackbox/approvals` (which changes weaken, the held store, the
  confirmation), gated in `plugins/blackbox/dashboard`.
- **Refusal:** the change is held (HTTP 428) until the person confirms it, through a paired
  companion app's dialog that proves the answer with its own key, or the system's password prompt,
  or (on a server with no dialog) their own terminal and sudo password. An approval applies
  exactly that change, once.
- **Counted by:** not a tamper count: the held request is what the person sees.
- **Tests:** `tests/plugins/test_blackbox_approvals.py`,
  `tests/plugins/test_blackbox_approvals_direction.py`,
  `tests/plugins/test_blackbox_approvals_terminal.py`,
  `tests/plugins/test_blackbox_sandbox_permissions_model.py`,
  `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** a person who confirms without reading gives the change away (see Duties).

### T11. Tampering with the audit trail or the protection log

An agent rewrites, truncates or forges Blackbox's local records to hide what it did.

- **Enforced at:** `plugins/blackbox/audit` (redacted, size-capped logs that keep whole lines under
  many writers); Blackbox's data folder is a guarded place (T1). The protection log
  (`audit.protection_log`) is hash-chained: each entry names the hash of the one before it. A
  separate head file records how far the chain reached and its last hash. The check
  (`protection_log.verify`, run by the Protection page) says `ok`, `broken` (with the first bad
  entry: one edited, removed or put in between), `rewound` (put back to an older copy) or `drift`
  (swapped for another log of the same length). An unreadable log, or a link put in its place, is
  `broken` and is never quietly replaced by a fresh one. Entries hold no command, path or file
  contents. An add-on can hand the head to a remote verifier, which can then notice a chain that
  went backwards or vanished.
- **Refusal:** a write to Blackbox's logs by an agent is blocked as self-protection. Text that
  tries to forge a log line is neutralised.
- **Counted by:** tamper counts: self-protection. A check that is not `ok` is shown on the
  Protection page.
- **Tests:** `tests/plugins/test_blackbox_self_protection.py`,
  `tests/plugins/test_blackbox_audit_log_trim.py`, `tests/plugins/test_blackbox_hardening.py`,
  `tests/plugins/test_blackbox_own_logs_hold_no_secrets.py`,
  `tests/plugins/test_blackbox_protection_log.py`, `tests/plugins/test_blackbox_protection_page.py`.
- **Residual:** deleting the whole log together with its head file is not provable on the
  machine itself (U5).

### T12. Outbound data leakage

Blackbox itself sends something the person did not agree to, or a report carries private data.

- **Enforced at:** `plugins/blackbox/community` (consent gate, report schema, sharing switch);
  `plugins/blackbox/kernel/redaction.py` (one redaction implementation).
- **Refusal:** with no consent record bound to the reporter terms, nothing is sent. A report with
  free text or unknown fields cannot be built. Rejected reports never leave the machine.
- **Counted by:** not applicable (nothing is sent).
- **Tests:** `tests/plugins/test_blackbox_consent.py`,
  `tests/plugins/test_blackbox_report_sharing_switch.py`,
  `tests/plugins/test_blackbox_report_schema.py`, `tests/plugins/test_blackbox_privacy_c11.py`,
  `tests/plugins/test_blackbox_kernel_redaction.py`,
  `tests/plugins/test_blackbox_model_request_secrets.py`.
- **Residual:** the agent's own network use is the agent's. Blackbox checks model requests and
  links but does not proxy all traffic.

### T13. A malicious community report

Someone publishes a false report to the open community graph to make Blackbox block a legitimate
package, host or action.

- **Enforced at:** `plugins/blackbox/community` (reader and aggregation);
  `plugins/blackbox/ruleset` (precedence); `plugins/blackbox/overrides`.
- **Refusal:** a community rule only flags. It can never block, even at critical severity in Block
  mode. Verified rules win any collision. Withdrawal and correction need a signed statement.
- **Counted by:** findings log (as a flag).
- **Tests:** `tests/plugins/test_blackbox_community_ruleset.py`, `tests/plugins/test_blackbox_tiers.py`,
  `tests/plugins/test_blackbox_retractions.py`, `tests/plugins/test_blackbox_overrides.py`,
  `tests/plugins/test_blackbox_signed_corrections.py`.
- **Residual:** false flags can still create noise and erode trust in warnings.

### T14. Network tamper

A program changes the machine's DNS away from Blackbox's resolver while DNS Shield is on.

- **Enforced at:** `plugins/blackbox/shields/network/protect/tamper_guard.py` (opt-in, off by
  default), applied by the root helper.
- **Refusal:** the helper puts the DNS setting back. Turning the guard off is a weakening change
  and waits for the person (T10).
- **Counted by:** Network Shield's events (not a tamper count: the change is undone, not refused).
- **Tests:** `tests/plugins/test_blackbox_shields_network_posture.py`,
  `tests/plugins/test_blackbox_shields_network_protect.py`,
  `tests/plugins/test_blackbox_approvals.py`, `tests/plugins/test_blackbox_tamper_counts.py`.
- **Residual:** only with the helper installed and the guard switched on. Root can stop the helper.

### T15. Blackbox breaks

A detector raises, a hook times out, or the dashboard is down.

- **Enforced at:** `plugins/blackbox/guard/hooks.py`.
- **Refusal:** none, by design. One failing detector does not end the other checks. A call that
  passed unchecked is logged as a guard error.
- **Counted by:** findings log (guard error row).
- **Tests:** `tests/plugins/test_blackbox_guard_hook_failed.py`,
  `tests/plugins/test_blackbox_detector_isolation.py`,
  `tests/plugins/test_blackbox_agent_hook_timeouts.py`,
  `tests/plugins/test_blackbox_private_audit_record.py`.
- **Residual:** an attacker who can break the plugin gets an unchecked agent. Self-protection (T1)
  is what keeps the agent from breaking it.

### T16. Reaching a host or package the person wants watched

An agent fetches from a host, or installs a package, that the person has put on their watch list,
or that an organisation's add-on handed in.

- **Enforced at:** `plugins/blackbox/watch` (the person's `watch_rules` section and an
  organisation's rules), checked on every tool call by `plugins/blackbox/guard/hooks.py`.
- **Refusal:** a rule in `watch` never refuses: the call is flagged and counted per rule and agent.
  A rule the person promotes to `enforce` refuses the call in Block mode. Its hits stay with it,
  because a rule's id comes from what it names. An organisation's rules only watch and cannot be
  promoted on the machine; an older set of them cannot replace a newer one. A refusal by a promoted rule says
  it was the person's watch rule, not self-protection. Taking an enforced rule
  off, or moving it back to watch, is a weakening change (T10). The watch list is in Blackbox's
  settings, so an agent cannot edit it (T1).
- **Counted by:** each rule's hits (`$BLACKBOX_HOME/watch/hits.json`), shown on the Protection page.
  A watch finding is the person's own rule and is never shared (T12).
- **Tests:** `tests/plugins/test_blackbox_watch_rules.py`,
  `tests/plugins/test_blackbox_protection_page.py`.
- **Residual:** a host or package named only at run time is not seen on hooks only (U1).

## Residual risks

- **R1.** Hooks read text. Anything decided only at run time is beyond Layer 1 (U1).
- **R2.** An agent not started through Blackbox's launchers is on hooks only.
- **R3.** An agent started without its hooks at all is not judged.
- **R4.** Audit mode only flags threats from rules. Self-protection, File Shield and startup places
  still refuse in Audit mode; other detections do not.
- **R5.** Some sandbox permissions, when allowed, run work outside the sandbox (package install
  scripts, opened apps, AppleScript). The person chooses this trade-off per permission.
- **R6.** A person who approves a weakening prompt without reading it weakens protection.
- **R7.** Community flags can be noisy or wrong. They never block.
- **R8.** Same-user malware and root can bypass most protections (see Adversaries).

## Open gaps

These are known limits, stated plainly. They are not secret; they are why Layer 2 exists.

- **U1. Hooks-only limits.** On hooks only, Blackbox does not stop:
  - a path or command a program builds while it runs (from input, files, the network, or values
    it computes);
  - a compiled program an agent builds and runs, or a script fetched and run without its text
    passing through a tool call;
  - a program started earlier that acts later without a further tool call;
  - a script run by a tool the hook does not know as a runner, or one too large to read (flagged).
  The guard lists these in `KNOWN_LIMITS` (`plugins/blackbox/detection/paths/guard_settings.py`).
  The sandbox closes them for sandboxed agents.
- **U2. macOS sandbox limits.** Setuid programs cannot run inside the sandbox. Programs the agent
  compiles that drive other apps through the system's own frameworks are not fully closed. Keychain
  and camera/microphone permissions are not controllable yet.
- **U3. Linux.** The sandbox's Linux port (`blackbox-sandbox`: namespaces, seccomp, Landlock) is
  newer than macOS's and less proven on real machines. It needs kernel support (Landlock at a
  recent ABI) and falls back to hooks only where that is missing. Some network rules depend on
  the root helper. Tests: `tests/plugins/test_blackbox_sandbox_linux_platform.py`,
  `tests/plugins/test_blackbox_sandbox_linux_network.py`, `tests/plugins/test_blackbox_linux_pages_honest.py`.
- **U4. Windows.** There is no agent sandbox on Windows. Protection there is Layer 1 only.
- **U5. Whole-log deletion.** Deleting the whole protection log together with its head file leaves nothing on the machine to compare against. Only a remote verifier that
  saw an earlier chain head can notice it. Without one, that loss is not detected locally.
- **U6. Real-time watching needs the helper.** Without the system protection helper, changes made
  outside an agent's tool calls are not watched in real time.

## Duties for the person

Blackbox works best when the person does their part.

- Keep the operating system updated. The sandbox and the helper rely on the kernel.
- Do not run agents as root, and do not give agents your password.
- Read approval prompts before you confirm them. An agent cannot answer them; you can give the
  change away.
- Use **Block mode**. Audit mode only flags most threats.
- Keep the sandbox on where it is available. Take an agent out only when a tool you need fails,
  and put it back after.
- Start agents through Blackbox's launchers, so they run inside the sandbox.
- Restart running agents after you change the protected list or a permission.
- Keep the dashboard on loopback. Do not expose it to a network.
- Install the system protection helper if you want real-time watching and network enforcement.
- Leave community sharing off unless you have read the reporter terms and want to share.
- Review findings and tamper counts. A rising count means an agent is trying something.
- Install third-party skills, plugins and add-ons only from sources you trust.

## Reporting a vulnerability

Report security issues privately, as described in `SECURITY.md` §1. Do not open a public issue or
pull request for a finding that lets an agent escape a protection described here.
