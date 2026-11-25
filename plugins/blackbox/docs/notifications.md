# Notifications

Blackbox tells you what your AI agents are doing through your system's own notifications. The
plugin does this itself, from the moment it is installed; a companion app shows the same feed
when it is running.

## What a notification says

Every notification says **which agent** (its product name and the project folder's name),
**what it did** in plain words, and **Blackbox's verdict**: allowed and recorded, flagged, or
stopped — with the reason in a few words.

- "Blackbox stopped Claude Code — Claude Code in payments tried a dangerous command. Stopped by
  Blackbox: it matches the verified threat graph."
- "Codex asked for administrator rights — Codex in api ran a command that asks for root (sudo).
  Blackbox let it run and recorded it."
- "Gemini CLI is running a program as root — …"
- "Claude Code is running without Blackbox — …"

A notification never shows a path, a command, a prompt, an address or a user name: it can be read
on a locked screen. Turn **Show details in notifications** on to add the finding's own short
description (already stripped of secrets).

## What you are told

| Kind | Default | What |
|---|---|---|
| Security | on | An agent was stopped or flagged; an agent asked for root or a program it started runs as root; an agent runs without Blackbox; a setting switches Blackbox's hooks off; File Shield and Network Shield alerts. |
| Agents starting and ending | off | An agent or sub-agent started, ended, or waits for you. |
| Session summary | off | One line when a session ends (and every N minutes if you set that): actions checked, refused, flagged. |

You can mute one agent, set quiet hours (only critical security notices are shown then) and cap
how many are shown in a minute — the rest are counted into one summary, so there is never a storm.
Turning Security off, turning every notification off, or muting an agent makes Blackbox tell you
less about threats, so it waits for your confirmation like any change that turns protection down.

Settings: the dashboard's **Notifications** page (`/notifications`), a companion app's Settings,
or `notifications:` in the config:

```yaml
notifications:
  enabled: true
  security: true
  lifecycle: false
  digest: false
  digest_minutes: 0
  muted_agents: []
  quiet_hours: "22:00-07:00"
  details: false
  per_minute: 6
```

## Root (sudo)

Agents keep `sudo` (the person's decision D7), with one line drawn (Linux round L1, 2026-11-24:
with passwordless sudo, an agent wrote `/etc/cron.d`, `/etc/sudoers.d`, `/etc/profile.d` and
enabled a root service of its own):

- **A write as root to a place something starts from** (`/etc/cron.d`, `/etc/sudoers.d`,
  `/etc/profile.d`, `/etc/systemd/system`, `/etc/ld.so.preload`, PAM …) or `systemctl enable` /
  `link` of a system service is refused in every mode, like any persistence write.
- **Any other write as root to the machine's own folders** (`/etc`, `/usr`, `/boot`, `/bin`,
  `/lib`, `/var/spool`, root's home) — `sudo tee -a /etc/hosts`, `sudo cp x /usr/local/bin/git` —
  is refused in Block mode and flagged in Audit mode (`fileaccess:<tool>:root-write`).
- **Every other `sudo`** (`sudo apt install`, `sudo systemctl restart nginx`) runs, and is made
  visible twice:


1. **The request.** A command that asks for more than your own rights — `sudo`, `su`, `doas`, an
   administrator prompt, a change to the sudo rules, adding an account to the admin group, a
   setuid bit, a system-wide service — is flagged (`agent:elevation-request`).
2. **The fact.** A program an agent started that is running as root is seen in the process list
   and recorded on that agent's instance (`agent:running-as-root`, critical). The instance shows
   "running as root" while it lasts, and for about five minutes afterwards a note that `sudo`
   usually stays unlocked in that terminal.

Limits: a program that writes as root without naming the place (`sudo make install`, a package
manager) is only flagged. The process list is read about every 1.5 seconds, so a root command shorter than that can
be missed (its request is still flagged); a root program that detaches from the agent's process
tree is no longer attributed to it.

## Who shows them

One deliverer at a time, from one feed, so nothing is shown twice and nothing is lost:

- **A companion app**, while it runs, delivers instead (it already has your permission and opens the agent on a click).
- Otherwise **the plugin's own notifier**:
  - macOS: Blackbox's notifier app, so notifications appear under Blackbox's name and can be
    styled or silenced in System Settings → Notifications. macOS asks once whether to allow it.
    Without the app, macOS's own script notifier is used (the notification then appears under
    "Script Editor" with "Blackbox" as its title).
  - Linux: the desktop's notifier (`notify-send`).
  - Windows: not yet — the dashboard's Notifications page shows every notice.

`blackbox notifications status` says which is in use; `blackbox notifications test` shows one.

## Where it lives

Everything is on this machine: the feed and its history in `$BLACKBOX_HOME/notifications/`, the
notifier app in `$BLACKBOX_HOME/notifier/`. Nothing is sent anywhere. `blackbox uninstall`
removes both with the rest of Blackbox's data.
