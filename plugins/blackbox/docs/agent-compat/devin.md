# Devin (CLI and Devin Local)

Added 2026-11-22 from the vendor's reference; never run in the product yet.

Sources: <https://docs.devin.ai/cli/extensibility/hooks/overview.md>, <https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks.md>, <https://docs.devin.ai/cli/subagents.md> (read 2026-11-22).

- **Where:** a `hooks` key in `~/.config/devin/config.json` (user), `.devin/hooks.v1.json` (project). Claude-shaped groups: `{"matcher", "hooks": [{"type": "command", "command"}]}`.
- **Events hooked:** `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop`, `SessionEnd`. Every payload carries `session_id` and `prompt_id`.
- **Refusing:** exit code 2 or a `"decision": "block"` JSON object; Blackbox answers with the Claude-shaped deny.
- **Reads Claude Code's files too** (`read_config_from.claude`, on by default): a Devin session runs the hook Blackbox wrote for Claude Code. The runner recognises that (`DEVIN_PROJECT_DIR`), counts the event as Devin's, and drops it once Devin's own config carries Blackbox's hooks.
- **Sub-agents** (`run_subagent`) are their own agent sessions; the payload names no parent.
- Hooks neither load nor run in Restricted Mode; `SessionEnd` is not fired in cloud sessions.
