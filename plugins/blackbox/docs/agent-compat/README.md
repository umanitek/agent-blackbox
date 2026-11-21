# Coding agents: what Blackbox can do in each

Coding-agent protection lives in the Blackbox plugin (`plugins/blackbox/agent_hooks`, since 2026-11-21): one hook per agent, all sent to the same local guard.

The official docs were read on **2026-11-21**; each file links its sources and the sections
reviewed. Every agent sends the LOCAL guard (127.0.0.1) the full tool call, the prompt and the
tool's output. The text is checked there and never recorded: only its length is kept, plus the
matched phrase as local evidence, exactly as for a Hermes agent.

| Agent | Refuse a tool call | Refuse a prompt with an injection | Tool output with an injection | Refuse reading an injected file | Hook config self-protected |
|---|---|---|---|---|---|
| [Claude Code](claude-code.md) | ✅ PreToolUse deny | ✅ block | ⚠️ reason beside the output | — (output check) | ✅ |
| [Codex CLI](codex.md) | ✅ PreToolUse deny | ✅ block | ✅ **replaced** | — | ✅ |
| [Cursor](cursor.md) | ✅ permission deny | ✅ continue:false | 📝 recorded (after-hooks observe) | ✅ beforeReadFile | ✅ |
| [Gemini CLI](gemini-cli.md) | ✅ BeforeTool deny | ✅ BeforeAgent deny | ✅ **replaced** | — | ✅ |
| [Copilot CLI](copilot-cli.md) | ✅ preToolUse deny | 📝 recorded (output ignored) | 📝 recorded | — | ✅ |
| [Windsurf (Devin)](windsurf.md) | ✅ exit 2 | ✅ exit 2 | 📝 recorded | ✅ pre_read_code | ✅ |
| [Cline](cline.md) | ✅ cancel | ✅ cancel | ⚠️ contextModification warning | — | ✅ |
| [OpenCode](opencode.md) | ✅ throw | — (no prompt hook) | ✅ **replaced** | — | ✅ |

✅ enforced · ⚠️ the model is warned · 📝 recorded only (the agent's hook cannot block it) · — not available.

Blocking needs **Block mode**, and only a **verified** pattern blocks. Audit mode, community
patterns and heuristics only flag.

## Self-protection (every agent, every mode)

An agent's shell and file tools cannot do any of the following:
- edit, delete or move Blackbox's plugin, `BLACKBOX_HOME` or an installed add-on's folder;
- touch the system protection helper's folder (`/Library/Application Support/Blackbox`) or its LaunchDaemon;
- remove Blackbox's entry from its own hook config;
- curl the dashboard's settings, protection or agent-hooks routes, or read its session token;
- stop Blackbox's services.

An add-on declares its own places through the extension point (`Registrar.protect_places`);
the plugin names no add-on.

Tests: `tests/plugins/test_blackbox_agent_security.py`, `test_blackbox_agent_hook_configs.py`,
`test_blackbox_addon_self_protection.py`.

## Turning protection down

Any weakening change, from any screen or caller, waits for the person to confirm it: the
dashboard asks with the operating system's own password prompt (`plugins/blackbox/approvals`).
An agent cannot answer that prompt for them.
