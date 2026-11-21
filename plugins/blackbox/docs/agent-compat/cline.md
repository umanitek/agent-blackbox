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
