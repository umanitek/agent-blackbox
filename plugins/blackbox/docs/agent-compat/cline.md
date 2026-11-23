# Cline: how Blackbox protects it

**Docs reviewed:** https://docs.cline.bot (the Hooks pages) and the Cline v3.36 release post on cline.bot, which introduced hooks (accessed 2026-11-21). Sections reviewed: hook types (TaskStart, UserPromptSubmit, PreToolUse, PostToolUse, TaskComplete), hook output (`cancel`, `errorMessage`, `contextModification`), the "Enable Hooks" setting, the hooks folder.

**Hook config:** `~/Documents/Cline/Hooks/` (a script per event). An existing user script for an event is kept. Hooks run only with **Settings → Enable Hooks** on.

## Events

| Cline hook | Blackbox event | Sent | Blackbox can |
|---|---|---|---|
| `TaskStart` / `TaskComplete` | session_start / stop | task | record |
| `UserPromptSubmit` | prompt | `userPromptSubmit.prompt` | **refuse**: `{"cancel":true,"errorMessage"}` (the initial prompt can be blocked) |
| `PreToolUse` | pre_tool | `preToolUse.toolName`, `parameters` | **refuse**: `cancel` |
| `PostToolUse` | post_tool | `postToolUse.result` | **warn the model**: `contextModification` with Blackbox's reason (the tool already ran) |

## Tool mapping
`execute_command` becomes `terminal`. `write_to_file` and `replace_in_file` become `write_file`. `read_file` becomes `read_file`.

## VM test
Cline is a VS Code extension (`code --install-extension saoudrizwan.claude-dev`) and needs a model provider key.
- Turn on Enable Hooks.
- Same checks as the others.

## Re-read 2026-11-22: two hook forms, both installed

Checked against the docs **and the Cline CLI/SDK 3.0.75 itself** (installed from npm, its own loader asked):

- **Hook scripts still run in the CLI and SDK.** <https://docs.cline.bot/customization/hooks.md> now only says "See details under SDK Plugins", but the SDK searches the `Hooks` folder under `~/Documents/Cline`, the `hooks` folder of its own home, and a project's `.clinerules/hooks` and `.cline/hooks` folders (<https://docs.cline.bot/getting-started/config.md>), and its loader found all of Blackbox's scripts. Events now also hooked: `TaskResume` (a session starts again), `TaskCancel` (the turn ended) and `SessionShutdown` (the session ended). `TaskComplete` ends a turn, not the session.
- **SDK plugins** (<https://docs.cline.bot/sdk/plugins.md>): the CLI, SDK and Kanban load `.js` / `.ts` plugins from `~/.cline/plugins` and `~/Documents/Cline/Plugins`; "not applicable on VSCode and JetBrains Extension for now". Blackbox writes `~/Documents/Cline/Plugins/blackbox.js`: `beforeTool` returns `{ skip: true, reason }` for a refused call, and `afterTool` returns `{ result }` to **replace** an output carrying a known injection (a script can only add a warning). The folder is read for every profile, whatever `CLINE_DIR` says. Each plugin hook call has 3 seconds; Blackbox's answers within 2.5 or lets the tool run.
- **One call, one answer.** A CLI session reports each tool call through the script and the plugin. Both carry the call's id (`tool_call.id`), and Blackbox answers and records it once.
- **Instances.** Every payload names `agent_id` and `parent_agent_id`: an agent a session spawned (`spawn_agent`, teams) is its own instance under that session.

### The CLI's tools

The CLI's tools differ from the extension's. Blackbox reads them from the call's own input:

| Cline CLI tool | Input | Blackbox reads it as |
|---|---|---|
| `run_commands` | `commands`: strings or `{command, args}` | `terminal`, one command per line — each is judged |
| `read_files` | `files` / `paths` / `file_paths` / `path` … | `read_file` — every file is judged |
| `editor` | `path`, `old_text`, `new_text` | `write_file`, as an edit when `old_text` is given |
| `apply_patch` | `input` | `apply_patch` — every file in the patch |
| `fetch_web_content` | `requests[].url` | as sent; its output is checked as a fetched page |

### The task Cline starts with (KI-617)

Security round 5 (real Cline 3.0.75 runs) captured what Cline's `TaskStart` hook really sends: `clineVersion`, `timestamp`, `taskId`, `sessionContext`, `workspaceRoots`, `workspaceInfo`, `userId`, `agent_id`, `parent_agent_id`, `hookName: "agent_start"`. It holds **no task text**, and `UserPromptSubmit` fires only for later messages, so a hook script never sees the first message. Blackbox's SDK plugin reads it instead: its `beforeRun` hook takes the first user message from the run's `snapshot.messages` (once, on the run whose snapshot holds one user message) and sends it as a prompt; Cline's own boilerplate (its mode tag and completion nudge) stays set aside. Plainly: in the **IDE extensions**, which run hook scripts only, Cline's first message is **not checked** — its tool calls still are.

### Still open

- No run with a model: the CLI needs a sign-in. What ran: the SDK's loader on Blackbox's installed files (plugin loaded, 8 scripts found, a refused call skipped).
- The IDE extensions run the scripts only, and only with **Enable Hooks** on.
- A host built on the SDK can switch plugins off for a session; the scripts still report its calls.
