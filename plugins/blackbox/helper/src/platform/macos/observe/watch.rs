//! What the helper watches while Network Shield is on: SSH into this Mac, and the files that
//! decide who may log in or where names go.
//!
//! Every [`WATCH_EVERY`] the helper reads `netstat -an -p tcp` (who is connected to port 22,
//! whether anything listens there — Remote Login) and fingerprints the watched files
//! ([`watched_paths`]: each user's `~/.ssh/authorized_keys`, `known_hosts` and `config`,
//! `/etc/hosts`, `/etc/ssh/sshd_config`). [`Watch::tick`] compares with the last look and queues
//! an event for each change; the helper then reports at once.
//!
//! **Never a file's contents**: a fingerprint is sha256 + size + mtime + line count, and an
//! event carries only the path, what changed, the change in line count and an 8-hex sha prefix.
//! The first look is the baseline (no events), so a restart does not alert on everything.
//! Observing only: it decides nothing (the plugin turns events into alerts).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const WATCH_EVERY: Duration = Duration::from_secs(2);
const NETSTAT: &str = "/usr/sbin/netstat";
const SSH_PORT: &str = "22";
/// The most events kept for one report (the plugin refuses more), and sessions / files reported.
pub const MAX_PENDING: usize = 200;
const MAX_SESSIONS: usize = 200;
const MAX_FILES: usize = 100;
/// A watched file larger than this is fingerprinted by size and mtime only (never read whole).
const MAX_READ: u64 = 8 * 1024 * 1024;
const USER_FILES: [&str; 3] = ["authorized_keys", "known_hosts", "config"];
const SYSTEM_FILES: [&str; 2] = ["/etc/hosts", "/etc/ssh/sshd_config"];

/// One file's fingerprint (no contents).
#[derive(Debug, Clone, PartialEq)]
pub struct Mark {
    pub sha: String,
    pub size: u64,
    pub mtime: u64,
    pub lines: usize,
}

/// What the last look saw, and the events not yet reported.
#[derive(Debug, Default)]
pub struct Watch {
    started: bool,
    remote_login: bool,
    sessions: BTreeMap<(String, u16), u64>,
    files: BTreeMap<String, Option<Mark>>,
    changed_at: BTreeMap<String, u64>,
    pending: Vec<Value>,
}

impl Watch {
    /// Compares one look (*netstat* text, *files* fingerprints) with the last; queues events.
    /// Answers true when it queued any.
    pub fn tick(&mut self, netstat: &str, files: Vec<(String, Option<Mark>)>, now: u64) -> bool {
        let (listening, open) = parse_netstat(netstat);
        let before = self.pending.len();
        let current: BTreeMap<(String, u16), u64> =
            open.into_iter().map(|key| { let since = self.sessions.get(&key).copied().unwrap_or(now); (key, since) }).collect();
        if self.started {
            if listening != self.remote_login {
                self.push(json!({"kind": "remote-login-changed", "ts": now, "on": listening}));
            }
            let opened: Vec<(String, u16)> = current.keys().filter(|key| !self.sessions.contains_key(*key)).cloned().collect();
            for (ip, port) in opened {
                self.push(json!({"kind": "ssh-session-new", "ts": now, "remote_ip": ip, "remote_port": port}));
            }
            for (ip, port) in self.sessions.keys().filter(|key| !current.contains_key(*key)).cloned().collect::<Vec<_>>() {
                self.push(json!({"kind": "ssh-session-ended", "ts": now, "remote_ip": ip, "remote_port": port}));
            }
        }
        for (path, mark) in files {
            let old = self.files.get(&path).cloned();
            if self.started && old.as_ref() != Some(&mark) {
                if let Some(event) = file_event(&path, old.flatten().as_ref(), mark.as_ref(), now) {
                    self.changed_at.insert(path.clone(), now);
                    self.push(event);
                }
            }
            self.files.insert(path, mark);
        }
        self.remote_login = listening;
        self.sessions = current;
        self.started = true;
        self.pending.len() > before
    }

    /// Queues an event (the oldest are dropped past [`MAX_PENDING`]).
    pub fn push(&mut self, event: Value) {
        self.pending.push(event);
        if self.pending.len() > MAX_PENDING {
            let extra = self.pending.len() - MAX_PENDING;
            self.pending.drain(..extra);
        }
    }

    /// The queued events, emptied.
    pub fn drain(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.pending)
    }

    /// Puts back events a failed report did not deliver (ahead of newer ones).
    pub fn requeue(&mut self, events: Vec<Value>) {
        let newer = std::mem::replace(&mut self.pending, events);
        for event in newer {
            self.push(event);
        }
    }

    /// Forgets everything (watching stopped: the next start is a fresh baseline).
    pub fn reset(&mut self) {
        *self = Watch::default();
    }

    /// The report's `watch` object; None before the first look.
    pub fn snapshot(&self) -> Option<Value> {
        if !self.started {
            return None;
        }
        let sessions: Vec<Value> = self.sessions.iter().take(MAX_SESSIONS)
            .map(|((ip, port), since)| json!({"remote_ip": ip, "remote_port": port, "since": since})).collect();
        let files: Vec<Value> = self.files.iter().take(MAX_FILES).map(|(path, mark)| json!({
            "path": path, "exists": mark.is_some(), "changed_at": self.changed_at.get(path),
            "sha_prefix": mark.as_ref().map(|m| m.sha[..8].to_string()).unwrap_or_default(),
        })).collect();
        Some(json!({"remote_login": self.remote_login, "sessions": sessions, "files": files}))
    }
}

fn file_event(path: &str, old: Option<&Mark>, new: Option<&Mark>, now: u64) -> Option<Value> {
    let (change, lines_delta, sha) = match (old, new) {
        (None, None) => return None,
        (None, Some(new)) => ("added", new.lines as i64, new.sha.as_str()),
        (Some(old), None) => ("removed", -(old.lines as i64), ""),
        (Some(old), Some(new)) if old.sha == new.sha => return None,   // touched, not changed
        (Some(old), Some(new)) => ("modified", new.lines as i64 - old.lines as i64, new.sha.as_str()),
    };
    Some(json!({"kind": "file-changed", "ts": now, "path": path, "change": change, "lines_delta": lines_delta,
                "sha_prefix": sha.get(..8).unwrap_or_default()}))
}

/// `(Remote Login listening on 22, established sessions into port 22 as (remote ip, remote port))`
/// from `netstat -an -p tcp` (macOS: `addr.port`, IPv6 scopes like `fe80::1%en0.22`).
pub fn parse_netstat(text: &str) -> (bool, Vec<(String, u16)>) {
    let mut listening = false;
    let mut sessions = vec![];
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || !fields[0].starts_with("tcp") {
            continue;
        }
        let (_local_ip, local_port) = split_endpoint(fields[3]);
        if local_port != SSH_PORT {
            continue;
        }
        match fields[5] {
            "LISTEN" => listening = true,
            "ESTABLISHED" => {
                let (ip, port) = split_endpoint(fields[4]);
                if let (Ok(ip), Ok(port)) = (ip.parse::<std::net::IpAddr>(), port.parse::<u16>()) {
                    sessions.push((ip.to_string(), port));
                }
            }
            _ => {}
        }
    }
    sessions.sort();
    sessions.dedup();
    (listening, sessions)
}

fn split_endpoint(endpoint: &str) -> (&str, &str) {
    let (address, port) = endpoint.rsplit_once('.').unwrap_or((endpoint, ""));
    (address.split('%').next().unwrap_or(address), port)
}

/// The files watched now: each local user's SSH files, then the system ones.
pub fn watched_paths() -> Vec<String> {
    let mut paths = vec![];
    if let Ok(entries) = fs::read_dir("/Users") {
        let mut users: Vec<String> = entries.flatten()
            .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| !name.starts_with('.') && name != "Shared" && name.len() <= 64)
            .collect();
        users.sort();
        for user in users {
            paths.extend(USER_FILES.iter().map(|file| format!("/Users/{user}/.ssh/{file}")));
        }
    }
    paths.extend(SYSTEM_FILES.iter().map(|path| path.to_string()));
    paths.truncate(MAX_FILES);
    paths
}

/// A file's fingerprint; None when it does not exist (or is not a regular file).
pub fn fingerprint(path: &Path) -> Option<Mark> {
    // As root in folders the person can write: the link itself, never what it points to (safe_read).
    let meta = fs::symlink_metadata(path).ok().filter(|meta| meta.file_type().is_file())?;
    let mtime = meta.modified().ok().and_then(|time| time.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
    let mut hasher = Sha256::new();
    let mut lines = 0;
    if meta.len() <= MAX_READ {
        let bytes = crate::safe_read::read_regular(path, MAX_READ)?;
        lines = bytes.iter().filter(|byte| **byte == b'\n').count();
        hasher.update(&bytes);
    } else {
        hasher.update(format!("{}:{mtime}", meta.len()).as_bytes());
    }
    Some(Mark { sha: hex::encode(hasher.finalize()), size: meta.len(), mtime, lines })
}

/// One look: `netstat`'s text and every watched file's fingerprint.
pub fn look() -> (String, Vec<(String, Option<Mark>)>) {
    let netstat = crate::command::output(Command::new(NETSTAT).args(["-an", "-p", "tcp"]), crate::command::TIMEOUT)
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned()).unwrap_or_default();
    let files = watched_paths().into_iter().map(|path| { let mark = fingerprint(Path::new(&path)); (path, mark) }).collect();
    (netstat, files)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETSTAT_TEXT: &str = "Active Internet connections (including servers)\n\
        Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
        tcp4       0      0  192.168.64.27.22       192.168.64.1.50000     ESTABLISHED\n\
        tcp4       0      0  192.168.64.27.54439    172.64.147.103.443     ESTABLISHED\n\
        tcp6       0      0  fe80::1%lo0.22         fe80::1%lo0.61000      ESTABLISHED\n\
        tcp4       0      0  *.22                   *.*                    LISTEN\n";

    fn mark(sha: &str, lines: usize) -> Option<Mark> {
        Some(Mark { sha: sha.repeat(64 / sha.len()), size: 1, mtime: 1, lines })
    }

    #[test]
    fn netstat_gives_remote_login_and_the_ssh_sessions_only() {
        let (listening, sessions) = parse_netstat(NETSTAT_TEXT);
        assert!(listening);
        assert_eq!(sessions, vec![("192.168.64.1".to_string(), 50000), ("fe80::1".to_string(), 61000)]);
        assert_eq!(parse_netstat("tcp4 0 0 10.0.0.2.5000 10.0.0.3.22 ESTABLISHED\n"), (false, vec![]), "an outgoing SSH is not a session into this Mac");
    }

    #[test]
    fn the_first_look_is_the_baseline_then_each_change_is_one_event() {
        let mut watch = Watch::default();
        let keys = "/Users/me/.ssh/authorized_keys".to_string();
        assert!(!watch.tick("", vec![(keys.clone(), mark("a", 2))], 100), "no alerts on the first look");
        assert!(watch.snapshot().is_some());
        assert!(watch.tick(NETSTAT_TEXT, vec![(keys.clone(), mark("b", 3))], 110));
        let events = watch.drain();
        let kinds: Vec<&str> = events.iter().map(|e| e["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["remote-login-changed", "ssh-session-new", "ssh-session-new", "file-changed"]);
        assert_eq!(events[3]["lines_delta"], 1);
        assert_eq!(events[3]["sha_prefix"], "bbbbbbbb");
        assert!(!watch.tick(NETSTAT_TEXT, vec![(keys.clone(), mark("b", 3))], 120), "nothing changed");
        assert!(watch.tick("", vec![(keys, None)], 130));
        let ended: Vec<String> = watch.drain().iter().map(|e| format!("{}:{}", e["kind"], e.get("change").map(|c| c.to_string()).unwrap_or_default())).collect();
        assert!(ended.contains(&"\"ssh-session-ended\":".to_string()) && ended.contains(&"\"file-changed\":\"removed\"".to_string()));
    }

    #[test]
    fn events_never_carry_contents_and_stay_bounded() {
        let mut watch = Watch::default();
        for n in 0..(MAX_PENDING + 50) {
            watch.push(json!({"kind": "connection-cut", "ts": n, "remote_ip": "45.130.148.102"}));
        }
        let events = watch.drain();
        assert_eq!(events.len(), MAX_PENDING);
        assert_eq!(events[0]["ts"], 50, "the oldest are dropped");
        let event = file_event("/etc/hosts", None, mark("c", 4).as_ref(), 1).unwrap();
        let keys: Vec<&String> = event.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["change", "kind", "lines_delta", "path", "sha_prefix", "ts"]);
    }

    #[test]
    fn a_fingerprint_counts_lines_and_hashes_without_keeping_contents() {
        let dir = std::env::temp_dir().join(format!("bb-watch-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("hosts");
        fs::write(&file, "127.0.0.1 localhost\n::1 localhost\n").unwrap();
        let found = fingerprint(&file).unwrap();
        assert_eq!((found.lines, found.size, found.sha.len()), (2, 34, 64));
        assert_eq!(fingerprint(&dir.join("missing")), None);
        fs::remove_dir_all(dir).unwrap();
    }
}
