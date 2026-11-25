//! The agent sandbox's policy file on Linux, read STRICTLY: the plugin renders it
//! (`shields/files/sandbox/platform/linux/profile.py`), the launcher hands its path to
//! `blackbox-sandbox run --policy`, and anything this parser does not understand refuses the
//! whole file — the agent then starts with Blackbox's hooks only and says so (fail-open, never a
//! half-read policy).
//!
//! The format is line-oriented, one directive per line:
//!
//! ```text
//! # blackbox-sandbox policy 1
//! # Blackbox agent sandbox — generated, do not edit. sha256:0123abcd…
//! hide-dir /home/me/Documents/Taxes
//! hide-file /home/me/.config/blackbox/helper/key
//! hide-glob /home/me/.hermes/blackbox/*.pem
//! canary /home/me/.hermes/blackbox/sandbox/canary
//! ro /home/me/.hermes/blackbox
//! ro-file /home/me/.bashrc
//! ro-glob /home/me/.hermes/plugins/*/blackbox-addon.json
//! pin /home/me/Documents
//! startup-ro /home/me/.config/systemd/user
//! startup-ro-glob /home/me/.local/share/gem/ruby/*/bin
//! hide-socket /run/user/1000/bus
//! hide-socket-glob /tmp/.X11-unix/*
//! display allow
//! bus refuse
//! docker refuse
//! devices refuse
//! local-ports block
//! allow-port 5432
//! dashboard-port 9700
//! ```
//!
//! Line 1 names the format and its version; line 2 carries the digest the launcher exports
//! (`BLACKBOX_SANDBOX_PROFILE=<file>#<digest>`, the same line the macOS profile has). Paths are
//! absolute and canonical (the plugin resolves them: LES-105) — never `/`, never a `.` / `..` or
//! empty part; a `\` is written `\\` and a newline `\n`. A glob's `*` / `?` never cross a `/` and
//! never sit in its first part. Comments (`#`) and blank lines are skipped.
//!
//! Pure: no system call here, so the parser's tests run on any OS.

use std::collections::BTreeSet;

/// Line 1 of every policy this build reads.
pub const HEADER: &str = "# blackbox-sandbox policy 1";
/// The most of a policy file read (a person with thousands of protected items stays far below).
pub const MAX_BYTES: usize = 1024 * 1024;
/// The most directives one policy may hold.
pub const MAX_ENTRIES: usize = 20_000;
/// The longest path Linux accepts (`PATH_MAX`).
pub const MAX_PATH: usize = 4096;

/// What the sandbox does to one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// A rename or removal of it fails (`EBUSY`): it is a mount point of its own.
    Pin,
    /// Readable, never changed (`EROFS`).
    ReadOnly,
    /// Covered by an empty mode-0000 mask: no read, no write, no link (`EACCES`).
    Hide,
}

/// One place: a path, or a glob expanded when the agent starts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    Path(String),
    Glob(String),
}

/// One directive about a place.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry {
    pub action: Action,
    pub target: Target,
}

/// Whether one ability is refused inside (the abilities the helper or the mounts enforce).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Switch {
    #[default]
    Allow,
    Refuse,
}

/// A whole policy (see the module doc). `Default` is the empty policy: nothing refused.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    /// The digest line 2 names ("" when it names none).
    pub digest: String,
    pub entries: Vec<Entry>,
    pub canary: Option<String>,
    pub display: Switch,
    pub bus: Switch,
    pub docker: Switch,
    pub devices: Switch,
    /// Local ports refused but [`Policy::allow_ports`] and the dashboard's (the helper enforces it).
    pub local_ports: Switch,
    pub allow_ports: BTreeSet<u16>,
    pub dashboard_port: Option<u16>,
}

/// Decodes one escaped path: `\\` → `\`, `\n` → newline; any other escape is refused.
fn unescape(text: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(char) = chars.next() {
        if char != '\\' {
            out.push(char);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            other => return Err(format!("unknown escape \\{}", other.map(String::from).unwrap_or_default())),
        }
    }
    Ok(out)
}

/// The written form of *path* (the inverse of [`unescape`]).
pub fn escape(path: &str) -> String {
    path.replace('\\', "\\\\").replace('\n', "\\n")
}

/// *path* when it is absolute and canonical in form (see the module doc).
fn checked_path(path: &str, glob: bool) -> Result<String, String> {
    if !path.starts_with('/') || path == "/" || path.len() > MAX_PATH || path.contains('\0') {
        return Err(format!("not an absolute path other than /: {path:?}"));
    }
    let parts: Vec<&str> = path[1..].split('/').collect();
    if parts.iter().any(|part| part.is_empty() || *part == "." || *part == "..") {
        return Err(format!("not a canonical path: {path:?}"));
    }
    let wild = |part: &str| part.contains('*') || part.contains('?');
    if glob {
        if wild(parts[0]) || !parts.iter().any(|part| wild(part)) {
            return Err(format!("a glob needs a wildcard after its first part: {path:?}"));
        }
        if parts.iter().any(|part| part.contains('[')) {
            return Err(format!("only * and ? are wildcards: {path:?}"));
        }
    }
    Ok(path.to_string())
}

fn switch(value: &str, refuse: &str) -> Result<Switch, String> {
    match value {
        "allow" => Ok(Switch::Allow),
        other if other == refuse => Ok(Switch::Refuse),
        other => Err(format!("expected allow or {refuse}, not {other:?}")),
    }
}

fn port(value: &str) -> Result<u16, String> {
    match value.parse::<u16>() {
        Ok(number) if number > 0 && value.bytes().all(|b| b.is_ascii_digit()) => Ok(number),
        _ => Err(format!("not a port: {value:?}")),
    }
}

/// Reads one directive line into *policy*.
fn directive(policy: &mut Policy, name: &str, value: &str) -> Result<(), String> {
    let place = |action, glob: bool| -> Result<Entry, String> {
        let path = checked_path(&unescape(value)?, glob)?;
        Ok(Entry { action, target: if glob { Target::Glob(path) } else { Target::Path(path) } })
    };
    let entry = match name {
        "hide-dir" | "hide-file" | "hide-socket" => place(Action::Hide, false)?,
        "hide-glob" | "hide-socket-glob" => place(Action::Hide, true)?,
        "canary" => {
            let entry = place(Action::Hide, false)?;
            if let Target::Path(path) = &entry.target {
                policy.canary = Some(path.clone());
            }
            entry
        }
        "ro" | "ro-file" | "startup-ro" => place(Action::ReadOnly, false)?,
        "ro-glob" | "startup-ro-glob" => place(Action::ReadOnly, true)?,
        "pin" => place(Action::Pin, false)?,
        "display" => return switch(value, "refuse").map(|on| policy.display = on),
        "bus" => return switch(value, "refuse").map(|on| policy.bus = on),
        "docker" => return switch(value, "refuse").map(|on| policy.docker = on),
        "devices" => return switch(value, "refuse").map(|on| policy.devices = on),
        "local-ports" => return switch(value, "block").map(|on| policy.local_ports = on),
        "allow-port" => return port(value).map(|number| { policy.allow_ports.insert(number); }),
        "dashboard-port" => return port(value).map(|number| policy.dashboard_port = Some(number)),
        other => return Err(format!("unknown directive {other:?}")),
    };
    if policy.entries.len() >= MAX_ENTRIES {
        return Err(format!("more than {MAX_ENTRIES} directives"));
    }
    policy.entries.push(entry);
    Ok(())
}

/// The digest line 2 names, if any.
fn digest_of(line: &str) -> String {
    line.rsplit_once("sha256:").map(|(_, hex)| hex.trim()).filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_default().to_string()
}

/// The policy in *text*, or why it is refused as a whole (the line number and the reason).
pub fn parse(text: &[u8]) -> Result<Policy, String> {
    if text.len() > MAX_BYTES {
        return Err(format!("the policy is larger than {MAX_BYTES} bytes"));
    }
    let text = std::str::from_utf8(text).map_err(|_| "the policy is not UTF-8".to_string())?;
    let mut lines = text.split('\n');
    if lines.next().map(str::trim_end) != Some(HEADER) {
        return Err(format!("line 1 is not {HEADER:?}"));
    }
    let mut policy = Policy::default();
    for (index, line) in lines.enumerate() {
        let number = index + 2;
        let line = line.strip_suffix('\r').unwrap_or(line);
        if number == 2 {
            policy.digest = digest_of(line);
        }
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once(' ').ok_or_else(|| format!("line {number}: a directive needs a value"))?;
        directive(&mut policy, name, value).map_err(|why| format!("line {number}: {why}"))?;
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(body: &str) -> Result<Policy, String> {
        parse(format!("{HEADER}\n# Blackbox agent sandbox — generated, do not edit. sha256:00ff\n{body}").as_bytes())
    }

    #[test]
    fn a_full_policy_reads_every_directive() {
        let read = policy("hide-dir /home/me/Taxes\nhide-glob /home/me/.hermes/blackbox/*.pem\ncanary /home/me/c\nro /home/me/.hermes\n\
                           pin /home/me\nstartup-ro /home/me/.config/autostart\nhide-socket /run/user/1000/bus\n\
                           display refuse\nbus refuse\ndocker refuse\ndevices allow\nlocal-ports block\nallow-port 5432\n\
                           allow-port 3000\ndashboard-port 9700\n# a comment\n\n").unwrap();
        assert_eq!(read.digest, "00ff");
        assert_eq!(read.canary.as_deref(), Some("/home/me/c"));
        assert_eq!(read.entries.len(), 7);
        assert_eq!(read.entries[1], Entry { action: Action::Hide, target: Target::Glob("/home/me/.hermes/blackbox/*.pem".into()) });
        assert_eq!(read.entries[3].action, Action::ReadOnly);
        assert_eq!(read.entries[4].action, Action::Pin);
        assert_eq!((read.display, read.bus, read.docker, read.devices), (Switch::Refuse, Switch::Refuse, Switch::Refuse, Switch::Allow));
        assert_eq!(read.local_ports, Switch::Refuse);
        assert_eq!(read.allow_ports.iter().copied().collect::<Vec<_>>(), vec![3000, 5432]);
        assert_eq!(read.dashboard_port, Some(9700));
    }

    #[test]
    fn anything_not_understood_refuses_the_whole_policy() {
        for bad in ["hide-dir relative/path", "hide-dir /", "hide-dir /a/../b", "hide-dir /a//b", "hide-dir /a/./b",
                    "frobnicate /a", "hide-dir", "display maybe", "local-ports refuse", "allow-port 0", "allow-port 70000",
                    "allow-port +5", "hide-glob /a/b", "hide-glob /*/b", "hide-glob /a/[ab]", "hide-dir /a\\tb",
                    "dashboard-port x"] {
            assert!(policy(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(parse(b"hide-dir /a\n").is_err(), "no header");
        assert!(parse(b"# blackbox-sandbox policy 2\n").is_err(), "a newer format is not guessed at");
        assert!(parse(&[0xff, 0xfe]).is_err(), "not UTF-8");
        assert!(parse(&vec![b'#'; MAX_BYTES + 1]).is_err(), "too large");
    }

    #[test]
    fn escaped_paths_round_trip() {
        let odd = "/home/me/odd\\name\nwith newline";
        let read = policy(&format!("hide-file {}\n", escape(odd))).unwrap();
        assert_eq!(read.entries[0].target, Target::Path(odd.into()));
        assert_eq!(policy("hide-dir /home/me/a b c").unwrap().entries[0].target, Target::Path("/home/me/a b c".into()));
    }

    #[test]
    fn a_policy_without_a_digest_reads_with_an_empty_one() {
        let read = parse(format!("{HEADER}\n# no digest\nbus refuse\n").as_bytes()).unwrap();
        assert_eq!(read.digest, "");
        assert_eq!(read.bus, Switch::Refuse);
    }

    #[test]
    fn too_many_directives_are_refused() {
        let body = "pin /home/me\n".repeat(MAX_ENTRIES + 1);
        assert!(policy(&body).unwrap_err().contains("more than"));
    }
}
