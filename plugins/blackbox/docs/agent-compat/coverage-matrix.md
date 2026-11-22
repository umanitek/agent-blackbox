# What Blackbox protects, per coding agent

Generated from `dashboard/docs_routes/agent_registry.json` — edit that file, never this one (a test holds them equal). Last updated 2026-11-22 for Blackbox 1.5.0.

Three layers:

- **hooks** — Layer 1 — the agent's own hooks: every action the agent reports is judged before it runs.
- **sandbox** — Layer 2 — the agent sandbox (macOS): the kernel refuses protected files to the agent and everything it starts.
- **os** — Layer 3 — operating-system file authorisation for every process. Not built yet.

Statuses:

- **Tested** — run on a real machine, with the date and how
- **Built, not yet run in the product** — built and covered by automated tests, not yet run in the real product
- **Not covered** — Blackbox does not protect this, and why

| Agent | Hooks | Sandbox | OS-level |
|---|---|---|---|
| Claude Code | Tested | Tested | Not covered |
| Codex | Tested | Built, not yet run in the product | Not covered |
| Cursor | Built, not yet run in the product | Tested | Not covered |
| Gemini CLI | Tested | Built, not yet run in the product | Not covered |
| GitHub Copilot CLI | Built, not yet run in the product | Not covered | Not covered |
| Windsurf (Devin) | Built, not yet run in the product | Not covered | Not covered |
| Devin | Built, not yet run in the product | Not covered | Not covered |
| Cline | Tested | Not covered | Not covered |
| OpenCode | Tested | Not covered | Not covered |
| Hermes agent | Built, not yet run in the product | Not covered | Not covered |

## Claude Code

One `claude` process per session (a native binary). Sub-agents (the Agent tool), agent-team teammates and skills run INSIDE that process; tools run as child processes. `claude -p` and the Agent SDK start the same binary without a terminal.

**Profiles:** macOS `~/.claude (settings.json, projects/ transcripts) and ~/.claude.json` · Linux `~/.claude` · Windows `%USERPROFILE%\.claude` · moved by `CLAUDE_CONFIG_DIR`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user | `~/.claude/settings.json` | yes |  |
| another config home | `$CLAUDE_CONFIG_DIR/settings.json` | yes | found from a hook event or a running agent process of the same user (its environment is readable; a path with spaces is read whole), then hooked |
| project | `PROJECT/.claude/settings.json and settings.local.json` | no | hooks merge across levels, so the user-level hooks still run; a project's disableAllHooks is reported |
| command line | `--settings FILE-OR-JSON` | no | cannot remove user hooks, but --settings '{"disableAllHooks": true}' switches every hook off for that run: the process then shows as unprotected |
| managed | `managed-settings.json, MDM or server-managed` | no | allowManagedHooksOnly blocks Blackbox's hooks: reported |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| interactive | `claude` | yes |  |
| headless | `claude -p` | yes |  |
| headless, bare | `claude --bare -p` | no | --bare skips every hook by design; Blackbox shows the process as unprotected. The sandbox launcher still applies. |
| sdk | `Claude Agent SDK` | yes | runs the same binary; --bare is recommended by the vendor for SDK calls and skips hooks |
| ide | `VS Code / JetBrains extension, desktop app` | yes | uses the same user settings |
| sub-agent | `Agent tool, agent teams, --agent` | yes | user hooks fire inside sub-agents with agent_id and agent_type |
| cloud | `Claude Code on the web` | no | cloud sessions do not read the local ~/.claude/settings.json |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| SessionStart | session_start | yes |  |
| UserPromptSubmit | prompt | yes |  |
| PreToolUse | pre_tool | yes |  |
| PostToolUse | post_tool | yes |  |
| Stop | turn_end | yes |  |
| SessionEnd | stop | yes |  |
| SubagentStart | subagent_start | yes |  |
| SubagentStop | subagent_stop | yes |  |
| ConfigChange | config_change | yes |  |
| Notification | attention | yes |  |
| PermissionRequest, PermissionDenied, PostToolUseFailure, PostToolBatch, TaskCreated, TaskCompleted, StopFailure, TeammateIdle, PreCompact, PostCompact, CwdChanged, DirectoryAdded, FileChanged, WorktreeCreate, WorktreeRemove, PreModelSwitch, PostModelSwitch, Setup, InstructionsLoaded, UserPromptExpansion, MessageDisplay, Elicitation, ElicitationResult |  | no | not needed to judge an action or follow an instance |

**Sub-agents:** Tracked: SubagentStart/SubagentStop carry agent_id and agent_type, and every tool call a sub-agent makes carries them too. The built-in web-fetch sub-agent runs SubagentStart/Stop hooks from managed settings only; its WebFetch tool call is still judged.

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | interactive | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 2.1.330, macOS 26.6.2: test VM (macOS 26, bb-recheck2): the agent's own configured hook command run with the payloads of its hook reference; refusals in Block and Audit mode — pass |
| macos | sub-agent | hooks | Built, not yet run in the product | covered by tests with the documented payloads; not yet run inside a signed-in session |
| macos | headless | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 2.1.330, macOS 26.6.2: test VM, REAL claude -p with a hosted model (haiku): sessions, two at once, 5 parallel sub-agents with their tasks and exact counts, nested and sequential sub-agents, a 12-call loop and --resume in one instance, --bare and disableAllHooks shown unprotected, File Shield and self-protection refusals on the right session or sub-agent, sudo flagged; the model is not shown (Claude Code's hooks carry none, KI-566) and background sub-agent results count as prompts (KI-567) — partial |
| macos | sdk | hooks | Built, not yet run in the product |  |
| macos | ide | hooks | Built, not yet run in the product |  |
| macos | headless, bare | hooks | Not covered | the agent skips hooks |
| macos | cloud | hooks | Not covered | runs off this machine |
| macos | interactive | sandbox | Tested | 2026-11-22, Blackbox 1.5.0, agent 2.1.330, macOS 26.6.2: test VM: the launcher's Seatbelt sandbox; a script written then run, python, a grandchild, links, osascript and open -a all refused by the kernel — pass |
| macos | interactive | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |
| macos | headless | sandbox | Tested | 2026-11-22, Blackbox 1.5.0, agent 2.1.330, macOS 26.6.2: test VM, REAL claude -p (haiku) through the agent sandbox launcher: a script reading a protected file was refused by the kernel and the session is marked sandboxed; the kernel refusal is not yet recorded in Blackbox (KI-568) — partial |

**Not covered:**
- `claude --bare` and `--settings '{"disableAllHooks": true}'` run without hooks (shown as unprotected; the sandbox layer still applies when the launcher is used).
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://code.claude.com/docs/en/hooks> (read 2026-11-22), <https://code.claude.com/docs/en/settings> (read 2026-11-22), <https://code.claude.com/docs/en/headless> (read 2026-11-22), <https://code.claude.com/docs/en/sub-agents> (read 2026-11-22)

## Codex

One `codex` process per session (CLI or `codex exec`); the desktop app and IDE extension talk to `codex app-server`. Sub-agents run inside the session and report with the PARENT session id plus agent_id.

**Profiles:** macOS `~/.codex (config.toml, hooks.json, sessions)` · Linux `~/.codex` · Windows `%USERPROFILE%\.codex` · moved by `CODEX_HOME`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user | `$CODEX_HOME/hooks.json` | yes | Codex runs a new or changed hook only after the person trusts it once (/hooks): shown as trust-required |
| profile | `--profile NAME → $CODEX_HOME/NAME.config.toml` | yes | a config layer over the same home, so the same hooks.json applies |
| project | `PROJECT/.codex/hooks.json (trusted projects only)` | no | adds hooks; cannot remove the user's |
| system / managed | `/etc/codex/hooks.json, requirements.toml` | no | allow_managed_hooks_only skips Blackbox's hooks; [features].hooks = false switches hooks off: both reported |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| interactive | `codex` | yes |  |
| headless | `codex exec` | yes |  |
| sdk | `codex app-server (desktop app, IDE extension)` | yes |  |
| sub-agent | `spawn_agent` | yes | SubagentStart/SubagentStop; SessionEnd does not run for sub-agents |
| cloud | `Codex Cloud` | no | cloud orchestration runs only an organisation's MCP hooks |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| SessionStart | session_start | yes |  |
| UserPromptSubmit | prompt | yes |  |
| PreToolUse | pre_tool | yes |  |
| PostToolUse | post_tool | yes |  |
| Stop | turn_end | yes |  |
| SessionEnd | stop | yes |  |
| SubagentStart | subagent_start | yes |  |
| SubagentStop | subagent_stop | yes |  |
| PermissionRequest, PreCompact, PostCompact, Interrupt, PreModelRequest, PostModelRequest |  | no | not needed to judge an action or follow an instance |

**Sub-agents:** Tracked: SubagentStart/SubagentStop carry the parent session id, agent_id and agent_type. Seen 2026-11-22 (Codex 0.171.0, codex exec): spawn_agent fired NO sub-agent hook event. A spawned agent whose events carry its own thread id is linked to the session that called spawn_agent by process ancestry (the same codex process) and order (the oldest spawn not yet claimed); one whose events carry the parent's session id and no agent_id cannot be told apart from its session: its actions are checked and counted in the session.

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | interactive | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 0.171.0, macOS 26.6.2: test VM (macOS 26, bb-recheck2): the agent's own configured hook command run with the payloads of its hook reference; refusals in Block and Audit mode — pass |
| macos | headless | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 0.171.0, macOS 26.6.2: test VM, real codex exec --oss with a local model (Ollama qwen2.5:7b): two sessions with model, a 12-call loop, a File Shield read refused; spawn_agent sub-agents are not tracked as sub-agents (KI-557) — partial |
| macos | sdk | hooks | Built, not yet run in the product |  |
| macos | sub-agent | hooks | Built, not yet run in the product |  |
| macos | cloud | hooks | Not covered | runs off this machine |
| macos | interactive | sandbox | Built, not yet run in the product | the launcher is written; refusals were proven with Claude Code's launcher |
| macos | interactive | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |

**Not covered:**
- Hosted tools (for example WebSearch) do not pass through Codex's hook path.
- Until the person trusts Blackbox's hooks in Codex (/hooks), Codex skips them.
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://developers.openai.com/codex/hooks> (read 2026-11-22), <https://developers.openai.com/codex/config-advanced> (read 2026-11-22)

## Cursor

The Cursor app (Electron) runs agent chats inside its own processes; `cursor-agent` is the CLI. Sub-agents (the Task tool) run inside the conversation. Cloud agents run on Cursor's machines.

**Profiles:** macOS `~/.cursor (hooks.json) and ~/Library/Application Support/Cursor` · Linux `~/.cursor` · Windows `%USERPROFILE%\.cursor`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user | `~/.cursor/hooks.json` | yes |  |
| project | `PROJECT/.cursor/hooks.json` | no | all sources run and a deny from any wins, so the user hooks still decide |
| enterprise / team | `/Library/Application Support/Cursor/hooks.json, dashboard` | no | run before the user's; cannot remove them |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| ide | `Cursor app, Agent chat` | yes |  |
| headless | `cursor-agent -p` | yes |  |
| sub-agent | `Task tool` | yes | subagentStart names subagent_id and the parent conversation; subagentStop names only the type |
| background | `background agent on this machine` | yes | sessionStart says is_background_agent |
| cloud | `Cloud agents` | no | user-level hooks are not available in cloud agents; only project, team and enterprise hooks run there |
| tab | `inline Tab completions` | no | beforeTabFileRead / afterTabFileEdit exist; Blackbox does not hook Tab |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| preToolUse | pre_tool | yes |  |
| beforeReadFile | pre_tool | yes |  |
| postToolUse | post_tool | yes |  |
| beforeSubmitPrompt | prompt | yes |  |
| stop | turn_end | yes |  |
| sessionStart | session_start | yes |  |
| sessionEnd | stop | yes |  |
| subagentStart | subagent_start | yes |  |
| subagentStop | subagent_stop | yes |  |
| beforeShellExecution, beforeMCPExecution, afterShellExecution, afterMCPExecution, afterFileEdit, postToolUseFailure, preCompact, afterAgentResponse, afterAgentThought, beforeTabFileRead, afterTabFileEdit, workspaceOpen |  | no | the generic preToolUse / postToolUse already fire for every tool; Tab is not an agent |

**Sub-agents:** Tracked: subagentStart / subagentStop.

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | ide | hooks | Built, not yet run in the product | the shell, MCP and read hooks were run on the test VM (2026-11-21); the generic tool hooks that replace them are not yet |
| macos | sub-agent | hooks | Built, not yet run in the product |  |
| macos | cloud | hooks | Not covered | runs off this machine; user hooks are not loaded |
| macos | ide | sandbox | Tested | 2026-11-22, Blackbox 1.5.0, agent 3.31.15, macOS 26.6.2: test VM: Open Cursor protected starts Cursor inside the sandbox and it stays up; reading a protected file from inside was not exercised (sign-in screen) — partial |
| macos | ide | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |

**Not covered:**
- Cloud agents and Tab completions.
- The generic tool hooks (2026-11-22) are covered by tests with the documented payloads but not yet run inside a signed-in Cursor.
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://cursor.com/docs/agent/hooks> (read 2026-11-22)

## Gemini CLI

One `gemini` process (Node) per session; `gemini -p` runs headless. Sub-agents run inside the session and have no hook events of their own.

**Profiles:** macOS `~/.gemini (settings.json); system: /Library/Application Support/GeminiCli/settings.json` · Linux `~/.gemini; /etc/gemini-cli/settings.json` · Windows `%USERPROFILE%\.gemini` · moved by `GEMINI_CLI_HOME`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user | `~/.gemini/settings.json` | yes |  |
| another home | `$GEMINI_CLI_HOME/.gemini/settings.json` | yes |  |
| project | `PROJECT/.gemini/settings.json` | no | hook lists are joined, not replaced; hooksConfig.enabled = false there switches hooks off: reported |
| system | `system settings.json and system-defaults.json` | no | read-only for Blackbox |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| interactive | `gemini` | yes |  |
| headless | `gemini -p` | yes |  |
| sub-agent | `sub-agents (experimental)` | yes | their tool calls pass BeforeTool like any other; there is no sub-agent start or stop event, so they are not separate instances |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| SessionStart | session_start | yes |  |
| BeforeAgent | prompt | yes |  |
| BeforeTool | pre_tool | yes |  |
| AfterTool | post_tool | yes |  |
| AfterAgent | turn_end | yes |  |
| SessionEnd | stop | yes |  |
| Notification | attention | yes |  |
| BeforeModel, BeforeToolSelection, AfterModel, PreCompress |  | no | not needed to judge an action or follow an instance |

**Sub-agents:** Not separate instances: Gemini CLI documents no sub-agent hook event. Their tool calls are judged inside the session.

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | interactive | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 0.70.0, macOS 26.6.2: test VM (macOS 26, bb-recheck2): the agent's own configured hook command run with the payloads of its hook reference; refusals in Block and Audit mode — pass |
| macos | headless | hooks | Built, not yet run in the product |  |
| macos | interactive | sandbox | Built, not yet run in the product | the launcher is written; refusals were proven with Claude Code's launcher |
| macos | interactive | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |

**Not covered:**
- hooksConfig.enabled = false or a hook named in hooksConfig.disabled switches Blackbox's hooks off (reported).
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://geminicli.com/docs/hooks/reference/> (read 2026-11-22), <https://geminicli.com/docs/reference/configuration/> (read 2026-11-22)

## GitHub Copilot CLI

One `copilot` process per session. Sub-agents run inside it. The Copilot cloud agent runs in GitHub's sandbox.

**Profiles:** macOS `~/.copilot (hooks/*.json, settings.json)` · Linux `~/.copilot` · Windows `%USERPROFILE%\.copilot` · moved by `COPILOT_HOME`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user | `$COPILOT_HOME/hooks/blackbox.json` | yes |  |
| repository | `REPO/.github/hooks/*.json` | no | adds hooks; the only source in a cloud agent job |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| interactive | `copilot` | yes |  |
| headless | `copilot -p` | yes |  |
| sub-agent | `sub-agents` | yes | hooks inside a sub-agent carry agentId and agentType |
| cloud | `Copilot cloud agent` | no | the sandbox has no user-level hook files |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| sessionStart | session_start | yes |  |
| userPromptSubmitted | prompt | yes |  |
| preToolUse | pre_tool | yes |  |
| postToolUse | post_tool | yes |  |
| agentStop | turn_end | yes |  |
| sessionEnd | stop | yes |  |
| subagentStart | subagent_start | yes |  |
| subagentStop | subagent_stop | yes |  |
| permissionRequest, postToolUseFailure, errorOccurred |  | no | not needed to judge an action or follow an instance |

**Sub-agents:** Tracked: subagentStart / subagentStop and agentId on hooks inside a sub-agent.

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | interactive | hooks | Built, not yet run in the product | hooked automatically on the test VM within 6 s; its hook command has not been run with payloads there |
| macos | cloud | hooks | Not covered | runs off this machine |
| macos | interactive | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |

**Not covered:**
- Its prompt hook cannot refuse a prompt (recorded only).
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://docs.github.com/en/copilot/reference/hooks-configuration> (read 2026-11-22)

## Windsurf (Devin)

The Windsurf app (now shipped as Devin.app) runs Cascade inside its own processes.

**Profiles:** macOS `~/.codeium/windsurf (hooks.json)` · Linux `~/.codeium/windsurf` · Windows `%USERPROFILE%\.codeium\windsurf`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user | `~/.codeium/windsurf/hooks.json` | yes | the Cascade hooks file documented before the move to Devin; the current pages describe Devin's own hooks (see Devin) |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| ide | `Windsurf / Devin app` | yes |  |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| pre_run_command | pre_tool | yes |  |
| pre_read_code | pre_tool | yes |  |
| pre_write_code | pre_tool | yes |  |
| pre_mcp_tool_use | pre_tool | yes |  |
| post_run_command | post_tool | yes |  |
| pre_user_prompt | prompt | yes |  |

**Sub-agents:** Not tracked: the Cascade hooks have no session or sub-agent events.

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | ide | hooks | Built, not yet run in the product | written against the Cascade hooks reference; not run in the app |
| macos | ide | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |

**Not covered:**
- The vendor's docs now redirect to Devin Local; whether the app still reads the Cascade hooks file is unverified.
- No session start or end event: an instance ends by going quiet or by its process leaving.
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://docs.windsurf.com/windsurf/cascade/hooks> (read 2026-11-22)

## Devin

One `devin` process per CLI session; Devin Local is the desktop app. Sub-agents run as their own agent sessions (run_subagent), in the foreground or background.

**Profiles:** macOS `~/.config/devin/config.json (hooks key)` · Linux `~/.config/devin/config.json` · Windows `%APPDATA%\devin\config.json`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user | `~/.config/devin/config.json` | yes |  |
| Claude Code's files | `~/.claude/settings.json, ~/.claude.json` | yes | Devin reads them by default (read_config_from.claude); such an event is counted as Devin's, once |
| project | `PROJECT/.devin/hooks.v1.json, .devin/config.json, .claude/settings.json` | no | adds hooks |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| interactive | `devin` | yes |  |
| ide | `Devin Local` | yes | not in Restricted Mode: hooks neither load nor run there |
| sub-agent | `run_subagent` | yes | no sub-agent start or stop event is documented; a sub-agent is its own session |
| cloud | `Devin cloud sessions` | no | SessionEnd is not fired in cloud sessions; this machine's hooks do not run there |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| SessionStart | session_start | yes |  |
| UserPromptSubmit | prompt | yes |  |
| PreToolUse | pre_tool | yes |  |
| PostToolUse | post_tool | yes |  |
| Stop | turn_end | yes |  |
| SessionEnd | stop | yes |  |
| PermissionRequest, PostCompaction |  | no | not needed to judge an action or follow an instance |

**Sub-agents:** Each sub-agent is its own session; no parent link is documented in the hook payload.

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | interactive | hooks | Built, not yet run in the product | written from the reference; Devin is not installed on the test machines |
| macos | interactive | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |

**Not covered:**
- New on 2026-11-22 and never run in Devin: written from the vendor's reference only.
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://docs.devin.ai/cli/extensibility/hooks/overview.md> (read 2026-11-22), <https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks.md> (read 2026-11-22), <https://docs.devin.ai/cli/subagents.md> (read 2026-11-22)

## Cline

The `cline` CLI (TUI, headless, and a background hub), the SDK (`ClineCore`), Kanban and the VS Code / JetBrains extensions. Agents a session spawns (`spawn_agent`, teams) run inside it and name their parent on every hook event. SDK plugins run in a worker thread of the host.

**Profiles:** macOS `~/.cline (data/settings, hooks/, plugins/; moved by CLINE_DIR or --config) and ~/Documents/Cline (Hooks/, Plugins/ — read whatever CLINE_DIR says)` · Linux `~/.cline and ~/Documents/Cline` · Windows `%USERPROFILE%\.cline and Documents\Cline`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user, hook scripts | `~/Documents/Cline/Hooks/EVENT` | yes | run by the IDE extensions and — checked in the SDK 3.0.75 itself — by the CLI and SDK too; a script of the person's own for an event is kept |
| user, SDK plugin | `~/Documents/Cline/Plugins/blackbox.js` | yes | CLI, SDK and Kanban only (the docs say plugins do not apply to the IDE extensions yet); loaded for every profile |
| another profile | `CLINE_DIR/hooks and CLINE_DIR/plugins` | no | not needed: ~/Documents/Cline is searched for every profile |
| project | `PROJECT/.cline/hooks, PROJECT/.clinerules/hooks, PROJECT/.cline/plugins` | no | adds hooks and plugins; cannot remove the user-level ones |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| ide | `VS Code / JetBrains extension` | yes | hook scripts, with Settings → Enable Hooks on |
| interactive | `cline (TUI)` | yes | hook scripts and the SDK plugin |
| headless | `cline "task" / cline --json` | yes | hook scripts and the SDK plugin |
| sdk | `ClineCore / Agent with pluginPaths` | yes | a host that passes its own plugin policy can switch plugins off; the hook scripts still run |
| cloud | `Cline Cloud Agents` | no | runs in the vendor's sandbox |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| TaskStart | session_start | yes |  |
| TaskResume | session_start | yes |  |
| UserPromptSubmit | prompt | yes |  |
| PreToolUse | pre_tool | yes |  |
| PostToolUse | post_tool | yes |  |
| TaskComplete | turn_end | yes |  |
| TaskCancel | turn_end | yes |  |
| SessionShutdown | stop | yes |  |
| TaskError |  | no | carries nothing Blackbox judges |
| PreCompact |  | no | carries nothing Blackbox judges |
| plugin beforeTool / afterTool | pre_tool / post_tool | no | not a hook event of its own: Blackbox's SDK plugin reports the same calls as PreToolUse / PostToolUse, and one call is answered once |

**Sub-agents:** Tracked: every event names agent_id and parent_agent_id, so an agent a session spawned is its own instance under that session.

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | sdk | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 3.0.75, macOS 27.2.1: the Cline SDK's own loader (discoverPluginModulePaths, loadAgentPluginsFromPathsWithDiagnostics, listHookConfigFiles) on Blackbox's installed files: the plugin loaded with no failure, all 8 hook scripts were found, and beforeTool returned skip for a refused call. No model run. — partial |
| macos | interactive | hooks | Built, not yet run in the product | built and loaded by the SDK; not run in a signed-in CLI session |
| macos | ide | hooks | Built, not yet run in the product | hook scripts; not run in the extension |
| macos | cloud | hooks | Not covered | local hooks never run in the vendor's cloud |
| macos | interactive | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |
| macos | headless | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 3.0.75, macOS 26.6.2: test VM, real cline -P ollama with a local model (qwen2.5:7b): two sessions, a 12-call loop, a File Shield read refused, sudo recorded; this mode has no sub-agents — pass |

**Not covered:**
- Not run with a model yet: the CLI needs a sign-in. The SDK's own loader loaded Blackbox's plugin and found its hook scripts; a real session is still to be run.
- The IDE extensions run the hook scripts only, and only with Enable Hooks on — Blackbox cannot see that switch.
- A host built on the SDK can switch plugins off for a session; the hook scripts still report its tool calls.
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://docs.cline.bot/customization/hooks.md> (read 2026-11-22), <https://docs.cline.bot/customization/plugins.md> (read 2026-11-22), <https://docs.cline.bot/sdk/plugins.md> (read 2026-11-22), <https://docs.cline.bot/sdk/guides/writing-plugins.md> (read 2026-11-22), <https://docs.cline.bot/getting-started/config.md> (read 2026-11-22)

## OpenCode

One `opencode` process (TUI) or `opencode serve`; agents and sub-agents run inside it.

**Profiles:** macOS `~/.config/opencode (opencode.jsonc, plugins/)` · Linux `~/.config/opencode` · Windows `%USERPROFILE%\.config\opencode`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| user, version 1 | `~/.config/opencode/plugin/blackbox.js` | yes | a function returning tool.execute.before / after; OpenCode 1.19.6 lists it among its loaded plugins |
| user, version 2 | `~/.config/opencode/plugins/blackbox/index.js` | yes | a default export with id and setup(ctx) registering ctx.tool.hook; version 2 runs no version-1 plugin |
| project | `PROJECT/.opencode/plugins/` | no | adds plugins |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| interactive | `opencode` | yes |  |
| headless | `opencode run` | yes |  |
| sdk | `opencode serve / acp` | yes |  |
| headless, pure | `opencode --pure` | no | --pure runs without external plugins, Blackbox's included |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| tool.execute.before | pre_tool | yes |  |
| tool.execute.after | post_tool | yes |  |

**Sub-agents:** Tracked: a sub-agent (the task tool) runs as a child session. OpenCode 1's plugin names the child's parent (OpenCode's session.created event, or one question to OpenCode per session) with every call, so the child is shown under its session with the task call's description and type. OpenCode 2's plugin names no parent: a new session whose first event is a tool call, in the same opencode process as a session with an unclaimed task call, is linked to that call (by process and order).

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | interactive | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 1.19.6, macOS 27.2.1: OpenCode 1.19.6 with both of Blackbox's plugin files in place: `opencode debug config` lists the version-1 plugin among its loaded plugins and reports no error for the version-2 folder. No model run. — partial |
| macos | interactive, version 2 | hooks | Built, not yet run in the product | the version-2 plugin is run under Node with the documented events; OpenCode 2 itself is not released on npm's latest tag |
| macos | headless, pure | hooks | Not covered | --pure loads no external plugin |
| macos | interactive | os | Not covered | needs Apple's Endpoint Security entitlement (not requested yet) |
| macos | headless | hooks | Tested | 2026-11-22, Blackbox 1.5.0, agent 1.19.6, macOS 26.6.2: test VM, real opencode run with a local model (Ollama qwen2.5:7b): two sessions, a 12-call loop, a File Shield read refused, sudo recorded; a task-tool sub-agent shows as a separate session with no parent (KI-555) — partial |

**Not covered:**
- `opencode --pure` runs without external plugins: nothing Blackbox installs is loaded.
- OpenCode 2 is not on npm's `latest` yet (1.19.6 is): the version-2 plugin is built against @opencode/plugin 2.3.2 and run under Node with its documented events, not in OpenCode 2 itself.
- No prompt or session events.
- A program the agent compiles and runs is seen by the sandbox layer, not by hooks.
- Sessions that run in the vendor's cloud never touch this machine's hooks.

Sources: <https://opencode.ai/docs/plugins/> (read 2026-11-22), <https://opencode.ai/docs/build/plugins/server/> (read 2026-11-22), <https://opencode.ai/docs/build/plugins/migrate-v1/> (read 2026-11-22)

## Hermes agent

One Hermes process per run (CLI, gateway or a profile's service). A task it delegates (delegate_task) runs as a child agent inside that process with a session of its own. Blackbox is a plugin loaded into it: its hooks are called in-process, never through a command Blackbox installs.

**Profiles:** macOS `~/.hermes and each profile's home (hermes -p NAME)` · Linux `~/.hermes and each profile's home` · Windows `%LOCALAPPDATA%\hermes` · moved by `HERMES_HOME`

| Scope | Where | Blackbox's hooks there | Note |
|---|---|---|---|
| every profile | `the Blackbox plugin in each Hermes home (blackbox attach)` | yes | one set of Blackbox settings in the main Hermes home protects every profile |

| Launch mode | How | Hooks run | Note |
|---|---|---|---|
| interactive | `hermes` | yes |  |
| gateway | `hermes gateway (messaging platforms)` | yes |  |

| Hook event | Blackbox reads it as | Hooked | Why not |
|---|---|---|---|
| on_session_start | session_start | yes |  |
| pre_tool_call | pre_tool | yes |  |
| post_tool_call | post_tool | yes |  |
| on_session_end | stop | yes |  |
| pre_api_request |  | no | checked for prompt injection by the guard; not an instance event |

**Sub-agents:** Tracked from the existing hook data: a session that first appears in the same Hermes home within two minutes of a delegate_task call is recorded as that call's sub-agent (its tool calls and its end).

| OS | Launch mode | Layer | Status | Detail |
|---|---|---|---|---|
| macos | interactive | hooks | Built, not yet run in the product | the plugin's own Hermes hooks, recorded in the instance tree, are covered by tests; the real run on the test VM did not complete (the local model was too slow for Hermes' prompt, 2026-11-22) |
| macos | sub-agent | hooks | Built, not yet run in the product | a delegated task is linked to its session by tests with the guard's own hook calls; not yet run with a hosted model |

**Not covered:**
- A plugin that is not loaded (Blackbox removed from a profile) sees nothing of that profile.
- Hermes sessions that run on another machine never touch this machine's plugin.

Sources: <https://github.com/NousResearch/hermes-agent> (read 2026-11-22)
