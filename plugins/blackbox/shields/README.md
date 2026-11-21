# Shields

A **shield** is a named, opt-in protection pack: one kind of user (a crypto trader, say) switches
it on and gets a set of extra rules made for them. **Trader Shield** is the first. It keeps an AI
agent away from crypto wallets, seed phrases and keys.

This folder holds everything a shield is. Blackbox's core (the hooks, the dashboard and the
settings) never names a shield or a wallet; it asks the **registry** in `__init__.py`. Adding a
wallet is adding a folder of data. Adding a shield is adding one folder with one `Shield` record.

For what Trader Shield does and how to switch it on, see the plugin
[README](../README.md#trader-shield-crypto-wallets-and-keys). This page is for whoever changes
the code.

## The parts

```
shields/
├── __init__.py        the registry: snapshot · check · allows · statuses · events · settings_validators
├── contract.py        what a shield IS: the Shield record and the typed records it answers with
├── event_records.py   the records of a shield's events report (re-exported by contract.py)
├── json_records.py    how every record becomes plain JSON (JsonValue, as_json helpers)
├── shield_api.py      a shield's own endpoints (ShieldApi) and what the dashboard injects (ShieldContext)
├── packs.py           one loader for any shield's packs and browsers.json (validate, then use)
└── trader/            Trader Shield
    ├── __init__.py    TRADER = Shield(...): wires its parts together
    ├── mode.py        its setting (shields.trader), and the old keys it still reads
    ├── status.py      the dashboard card
    ├── events.py      wallet events, each told as a plain-language story
    ├── detectors/     one detector per KIND of wallet
    │   ├── browser_extension.py   key stores of browser extensions, in any browser
    │   ├── app_folder.py          desktop apps and CLI key files (with the pointer reader)
    │   ├── firefox_map.py         Firefox's per-profile extension folders
    │   └── own_keys.py            a raw private key that opens one of your own addresses
    ├── wallets/       DATA, one folder per wallet: wallet.json (+ logo.svg and NOTICE.md)
    ├── browsers.json  DATA: every browser profile root, per OS and install type
    ├── attacks.json   the page's attack table (what each attack is, and its outcome)
    ├── graph.json     the page's crypto figures from the verified threat graph
    └── page/          trader.html + content.json (the page's prose and "coming next" list)
```

A `Shield` is a **record of plain functions**, not a class to subclass (the Strategy pattern):

| Field | What the core asks it |
|---|---|
| `mode()` | Is it on, and with what options? |
| `validate(payload)` | Check a Settings save for this shield |
| `detect(tool, args, mode)` | What does this action threaten? |
| `claims(finding)` · `allows(finding, mode)` | Is this finding mine? Does it count right now? |
| `status(mode)` · `events()` | The dashboard card, and what happened |
| `settings_fields()` | What the Settings group draws |
| `finding_kinds` · `capabilities` | What it can find, and what it covers beyond packs |
| `packs` · `page` · `attacks` · `browser_roots` | Where its data lives |
| `detectors` | The detectors that serve its pack kinds |
| `api` | Optional named endpoints beyond the card and events, served at `GET`/`POST /api/shields/<id>/api/<name>` with a `ShieldContext` (the verified network lists, the assistant, the mode) the dashboard injects |

## How one action is checked

```
agent wants to run a tool call
        │
        ▼
guard/hooks.on_pre_tool_call
        │  active = shields.snapshot()           every shield's mode, read ONCE for this call
        ▼
core rules (detection/)  +  shields.check(tool, args, active)
                                │  each enabled shield's detect(); every finding is
                                │  made local-only (source "secret"): it never leaves
                                │  the machine, whatever the sharing setting
        ▼
reporting._flag_worthy(…, active)              shields.allows(): a shield's finding counts
        │                                       only while that shield is on, for what you chose
        ▼
block mode + at/above block_severity  ──►  the call is refused; the agent is told why
        │
        ▼
audit log ──► GET /api/shields/<id>/events ──► the dashboard's events window and stories
```

Everything here **fails open**: a broken detector or pack logs a warning and contributes nothing.
It never breaks the agent.

## Rules every shield keeps

- **Local only.** Shield findings are about the user's own secrets and wallets. `shields.check`
  marks every one `source="secret"`, which the sharing gate never sends.
- **One way.** `shields` may use `kernel`, `detection` and `audit`, and never `dashboard`. The
  dashboard cleans what it serves at its own boundary (`dashboard/shields_routes`).
  `tests/plugins/test_blackbox_architecture.py` enforces it.
- **Packs are refused, never half-used.** A pack that breaks any loader rule loads as
  `unavailable`, with its reason on the card and in the log, and protects nothing silently.
  The rules are at the top of `packs.py`: size caps, no symlinks, the id equals its folder
  name, no case-twins, and closed path roots (`~`, `$XDG_CONFIG_HOME`, `%APPDATA%`,
  `%LOCALAPPDATA%`), so a typo can never protect the whole home folder.
- **Personal fields stay personal.** Trader Shield's `addresses` are only shown in Settings
  (`ShieldMode.as_json(include_personal=True)`), never in a status, event, log or report.

## Settings

Each shield owns one section of the `blackbox` config entry, and the kernel merges saves per
shield, so saving one shield never touches another:

```yaml
plugins:
  entries:
    blackbox:
      shields:
        trader:
          enabled: true
          wallets: [metamask, phantom, exodus, electrum, solana-cli]
          addresses: []
```

The dashboard passes `shields.settings_validators()` to `kernel.settings.write_settings`, and
each shield's `validate()` checks its own section. Trader Shield still reads the older keys
(`wallet_protection`, `protected_wallets`, `wallet_addresses`) until the first save, which
writes `shields.trader` and removes them.

## Add a wallet to Trader Shield

1. **Add a folder** `trader/wallets/<id>/` whose name equals the pack's `id` (lower case,
   digits and `-`).
2. **Write `wallet.json`.** The common fields first:

   ```json
   { "id": "rabby", "name": "Rabby", "kind": "browser-extension", "status": "planned", "order": 110 }
   ```

   A `planned` pack is enough to show the wallet as **coming soon** in Settings. To make it
   `supported`, add `verified` (the date you checked it on the real software) and `source`
   (where you checked it), plus the block for its kind:

   | `kind` | Block | Example |
   |---|---|---|
   | `browser-extension` | `stores`: extension ids per engine | `metamask`: `"stores": {"chromium": [...], "firefox": ["webextension@metamask.io"]}` |
   | `desktop-app` | `places`: path templates per OS, and a `label` | `exodus`: `"$XDG_CONFIG_HOME/Exodus/exodus.wallet"`, `~/Library/...`, `%APPDATA%/...` |
   | `cli-key-file` | `places`, plus a `pointer` to the CLI's config that names the key file | `solana-cli`: `"pointer": {"config": "$XDG_CONFIG_HOME/solana/cli/config.yml", "key": "keypair_path"}` |

   A browser extension needs no paths: the detector finds its key store under every root in
   `browsers.json`, in every browser and install type listed there.
3. **Logo (optional).** Add `logo.svg` with its licence terms in `NOTICE.md`, and name both in
   `"logo": {"file": "logo.svg", "terms": "NOTICE.md", "source": "..."}`. Logos must be plain
   shapes: no scripts, no event handlers, and only `#fragment` links.
4. **Prove it.** Add attack rows to `trader/attacks.json`, with their tool calls in
   `tests/plugins/trader_shield_attack_scenarios.json` (keyed by row id; the commands are test
   data and never ship in the plugin). A supported pack must earn it with a `blocked` row
   that reads its key store (`test_every_supported_pack_has_earned_it_with_a_blocked_vault_row`).
   Check it once against the **real** software installed the normal way, because a fake folder
   only confirms what the code already assumes.
5. **Regenerate the OpenClaw list**, which is generated from the packs:
   `uv run python scripts/gen_openclaw_wallets.py`, then commit
   `integrations/openclaw/src/generated/wallets.json` (it is git-ignored, so `git add -f`).
6. **Run the tests** below. If you changed what Settings or the page lists as coming soon,
   update `test_settings_coming_soon_is_unchanged` / `test_page_coming_next_is_unchanged`
   in the same commit, on purpose.

Users who saved their wallet list before the new wallet existed keep their saved list. The card
shows the new wallet under **new since you last saved**, so it is not switched on behind their
back.

## Add a new kind of wallet

Write a detector in `trader/detectors/` that satisfies `contract.PackDetector`: a `KINDS` tuple
and `validate_pack(manifest)`, which returns one problem sentence or `None`. The loader already
checks `places`, `pointer` and `verified`, so the detector checks only its own block. Add it to
`DETECTORS` in `trader/detectors/__init__.py`. Any file path built from pack data or from an
agent's call is read with `kernel.bounded_files.read_small_text(..., nofollow=True)`.

## Add a new shield

1. Create `shields/<id>/` with an `__init__.py` that builds its `Shield(...)` record. Copy
   Trader Shield's shape (`trader/__init__.py`): its mode, validator, detect, claims/allows,
   status, events, settings fields, finding kinds, and its data paths.
2. Register it: add it to `_SHIELDS` in `shields/__init__.py`. The guard, dashboard, settings,
   routes (`/api/shields`, `/shields/<id>`, `/shields/<id>/packs/<pack>/logo.svg`) and the
   generic dashboard renderer (`dashboard/static/shields.js`) pick it up with no further change.
3. Give it a page (`page/<id>.html` + `content.json`), an `attacks.json`, and a scenarios file
   `tests/plugins/<id>_shield_attack_scenarios.json`. The shared attack-table tests join each
   registered shield's table with its scenarios.
4. Classify every `FindingKind` it emits in `community/sighting/classification.py`, and keep its
   findings local-only (the registry enforces it).
5. Update `ARCHITECTURE.md` (the `shields` row) and this page.

## The tests that guard this

| Test | What it holds |
|---|---|
| `test_blackbox_shields_contract.py` | the records, and the pack and browser-root loader rules |
| `test_blackbox_shields_trader_packs.py` | every pack loads; packs give exactly what the old code did; the coming-soon lists |
| `test_blackbox_shields_trader_vault.py` · `_app_folder.py` · `_firefox.py` · `_own_keys.py` | each detector |
| `test_blackbox_shields_gate.py` · `test_blackbox_shields_sharing.py` | the mode gate; findings stay local |
| `test_blackbox_settings_shields.py` · `test_blackbox_shields_trader_mode.py` | settings merge per shield; the old keys |
| `test_blackbox_shields_status.py` · `_events.py` · `_routes.py` · `_panel.py` | the card, events, routes, and the dashboard in a real browser |
| `test_blackbox_trader_shield_attacks.py` | every attack row gives its stated outcome |
| `test_blackbox_shields_boundaries.py` | the core never names a retired wallet identifier again |
| `test_blackbox_package_data.py` | every pack file ships in every install form |
| `test_blackbox_dashboard_browser.py` | every shield's page renders clean at desktop and phone widths |

Run the whole Blackbox suite before a commit:
`uv run pytest tests/plugins/test_blackbox_*.py tests/test_blackbox_*.py`.
