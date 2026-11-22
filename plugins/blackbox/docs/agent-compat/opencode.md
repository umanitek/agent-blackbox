# OpenCode: how Blackbox protects it

**Docs reviewed:** https://opencode.ai/docs/plugins (accessed 2026-11-21). Sections reviewed: plugin loading from `~/.config/opencode/plugin/`, `tool.execute.before` (throwing blocks), `tool.execute.after` (may change `output.output`), the v2 `ctx.tool.hook("execute.before")` note (legacy names fail silently on v2).

**Hook config:** `~/.config/opencode/plugin/blackbox.js`, a plugin file of Blackbox's own. It runs the runner with Node's `spawnSync` and fails open.

## Events

| OpenCode hook | Blackbox event | Sent | Blackbox can |
|---|---|---|---|
| `tool.execute.before` | pre_tool | `tool`, `args` | **refuse**: the plugin throws Blackbox's reason |
| `tool.execute.after` | post_tool | `output.output` (bounded 256 KB) | **replace the output**: the plugin sets `output.output` to Blackbox's notice |

## Tool mapping
`bash` becomes `terminal`. `edit` and `write` (`filePath`, `newString` / `content`) become `write_file`. `filePath` was not read before 2026-11-21, so edits to Blackbox's files were allowed. `read` becomes `read_file`.

## Gaps
- No prompt hook is wired. Whether `chat.message` can block is not documented, so prompts are not checked. The tool call an injected prompt leads to is still checked.
- OpenCode **v2** plugins use `ctx.tool.hook(...)`, and the legacy names used here fail silently there. **Verify the installed version on the VM.** If it is v2, the plugin template needs the v2 form.

## VM test
`npm i -g opencode-ai`. It needs a provider key. A free OpenCode Zen model may run without a paid key; verify.
- Edit Blackbox's plugin → expect the throw.
- `cat` the injection file → expect the output replaced.

## Re-read 2026-11-22: a plugin for each OpenCode version

<https://opencode.ai/docs/build/plugins/migrate-v1/>: "V1 plugin implementations do not run in V2". Blackbox now writes both forms; each version reads only its own.

| | OpenCode 1 | OpenCode 2 |
|---|---|---|
| File | `~/.config/opencode/plugin/blackbox.js` | `~/.config/opencode/plugins/blackbox/index.js` |
| Shape | a function returning hooks by name | a default export `{ id: "blackbox", setup(ctx) }` |
| Before a tool | `"tool.execute.before"(input, output)` — throws to refuse | `ctx.tool.hook("execute.before", event)` — throws to refuse |
| After a tool | sets `output.output` | sets `event.result.content` (only for `status: "completed"`) |
| Call fields sent | `tool`, `args`, `sessionID` | `tool`, `input`, `sessionID`, `id` (the call) |

The version-2 file imports nothing from `@opencode/plugin` (`Plugin.define` only returns its argument), so it needs no install step. Event fields are those of `@opencode/plugin` 2.3.2's `ToolHooks`.

### What was run

- OpenCode **1.19.6** (npm `latest` on 2026-11-22) with both files in place: `opencode debug config` lists the version-1 plugin among its loaded plugins and reports no error for the version-2 folder.
- The version-2 plugin under Node with the documented events: a refused call throws Blackbox's reason, a poisoned result's `content` is replaced, a failed call is left alone.

### Still open

- OpenCode 2 itself was not run: it is not npm's `latest` yet.
- `opencode --pure` "runs without external plugins" — Blackbox's included. Such a run shows as unprotected.
- No prompt or session events are wired (version 2 has `ctx.session.hook("prompt")`; not used yet).
