# Cursor (editor and `cursor-agent`): how Blackbox protects it

**Docs reviewed:** https://cursor.com/docs/hooks (accessed 2026-11-21; the page states no version). Sections reviewed: hooks.json (`version: 1`), beforeShellExecution / beforeMCPExecution (`permission` allow/deny/ask), beforeReadFile, beforeSubmitPrompt, afterShellExecution / afterMCPExecution, stop, exit codes, `failClosed`.

**Hook config:** `~/.cursor/hooks.json` (flat, `{"version": 1, "hooks": {...}}`).

## Events

| Cursor hook | Blackbox event | Sent | Blackbox can |
|---|---|---|---|
| `beforeSubmitPrompt` | prompt | `prompt` | **refuse the prompt**: `{"continue": false, "user_message"}` |
| `beforeShellExecution` | pre_tool | `command` | **refuse**: `{"permission":"deny"}` |
| `beforeMCPExecution` | pre_tool | tool + input | **refuse** |
| `beforeReadFile` | pre_tool | `file_path` + `content` | **refuse the read** when the file carries a verified injection, or when it is a protected file |
| `afterShellExecution` | post_tool | `output` | record and flag only (Cursor's after-hooks only observe) |
| `stop` | turn_end | session | record |

## Gaps
- The after-hooks cannot change what the model sees. Protection there is `beforeReadFile`, which refuses before the model reads.
- Cursor fails **open** on a hook error unless `failClosed: true`. Blackbox keeps fail-open, so the agent stays usable.
- Community reports describe `ask` and read enforcement gaps in some builds. Verify on the VM.

## Tests
- `cursor` cases in `test_blackbox_agent_security.py`: prompt, output, `delete_file` and `rm -rf` on an add-on folder in the Hermes home.
- `test_cursor_refuses_to_read_a_file_carrying_a_verified_injection`.

## VM test
Cursor needs a sign-in, and so does `cursor-agent` (`curl https://cursor.com/install -fsS | bash`).
- `cat` the injection file → expect beforeReadFile denied.
- Prompt with the injection → expect it refused.
- `rm -rf` Blackbox's plugin → expect it denied.

## Re-read 2026-11-22: generic tool hooks, sessions, sub-agents

Source: <https://cursor.com/docs/agent/hooks>.

- Blackbox now uses the generic **`preToolUse` / `postToolUse`**, which fire for EVERY tool (Shell, Read, Write, MCP, Task…), instead of the shell- and MCP-only hooks — a file written by Cursor's Write tool was not judged before. `beforeReadFile` stays for the file's text.
- **Sessions and sub-agents are tracked:** `sessionStart` (`is_background_agent`), `sessionEnd` (`reason`), `subagentStart` (`subagent_id`, `parent_conversation_id`, `subagent_type`) and `subagentStop` (names only the type and status).
- **Not covered:** cloud agents (user-level hooks are not loaded there) and Tab completions.
- These generic hooks are covered by tests with the documented payloads; they have not been run inside a signed-in Cursor yet.
