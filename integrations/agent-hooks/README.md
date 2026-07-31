# Agent Blackbox hooks for Claude Code and Codex

This bundle exposes the same Blackbox detection and blocking engine to Claude
Code and Codex through their lifecycle-hook APIs.

The Blackbox installer configures it automatically:

- Claude Code receives user-level hooks in `~/.claude/settings.json`. No manual
  Claude plugin step is required.
- Codex receives the `blackbox@agent-blackbox` plugin automatically. Codex
  deliberately skips new command hooks until the user reviews them once with
  `/hooks`; the installer never bypasses that trust boundary.

The shared events are `SessionStart`, `UserPromptSubmit`, `PreToolUse`,
`PostToolUse`, and `Stop`. Hosted tools that a host does not expose through its
local lifecycle-hook path cannot be observed by this integration.
