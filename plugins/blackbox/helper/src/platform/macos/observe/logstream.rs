//! Remote logins as they happen: one `log stream --style ndjson` child (the helper's own), filtered
//! to the processes that let people into this Mac — the SSH server (`sshd`, `sshd-session`,
//! `sshd-auth`), Screen Sharing (`screensharingd`), Remote Management (`ARDAgent`) and Tailscale
//! SSH (`tailscaled` / the Tailscale extension). Event-driven: a login is known the moment macOS
//! logs it, not at the next poll.
//!
//! Each line becomes a [`LogEvent`] — what happened (an accepted or failed login, a disconnect),
//! how (ssh with a key, a password …), the user and the source. **Never a message's text**: only
//! the parsed fields leave this module, and a key is named by its fingerprint only.
//!
//! [`Stream`] owns the child: [`Stream::start`] spawns it with a reader thread, [`Stream::drain`]
//! hands over what was parsed, [`Stream::stop`] ends it (waited for); a child that exits on its
//! own is restarted with a growing back-off. Observing only — nothing here changes the system.

use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use serde_json::Value;

const LOG: &str = "/usr/bin/log";
/// The processes whose messages say who logged in remotely (and nothing else is read).
pub const PREDICATE: &str = "(process == \"sshd\" OR process == \"sshd-session\" OR process == \"sshd-auth\" \
OR process == \"screensharingd\" OR process == \"ARDAgent\" OR process == \"tailscaled\" OR process == \"IPNExtension\") \
AND (eventMessage CONTAINS \"Accepted \" OR eventMessage CONTAINS \"Failed \" OR eventMessage CONTAINS \"Invalid user\" \
OR eventMessage CONTAINS \"authentication error\" OR eventMessage CONTAINS \"Disconnected from\" \
OR eventMessage CONTAINS \"Viewer Address\" OR eventMessage CONTAINS \"new SSH connection\")";
/// The most events buffered between two drains (the oldest are dropped past it).
const MAX_BUFFERED: usize = 500;
const BACKOFF_FIRST: Duration = Duration::from_secs(2);
const BACKOFF_MOST: Duration = Duration::from_secs(60);

/// What a log line said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    /// A login that succeeded (SSH, Screen Sharing, Tailscale SSH).
    Accepted,
    /// A login attempt that failed (wrong password, unknown user, refused key).
    Failed,
    /// A logged-in SSH session ended.
    Disconnected,
}

/// One parsed login event.
#[derive(Debug, Clone, PartialEq)]
pub struct LogEvent {
    pub kind: LogKind,
    /// `ssh`, `screen-sharing`, `remote-desktop` or `tailscale-ssh`.
    pub how: &'static str,
    /// `publickey`, `password`, `keyboard-interactive` or "" (unknown / not applicable).
    pub method: &'static str,
    /// The user named in the message ("" when none).
    pub user: String,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: Option<u16>,
    /// `SHA256:…` of the key that logged in, when the message names one.
    pub fingerprint: String,
    /// The process that logged it (the session's sshd process for SSH).
    pub pid: u32,
}

/// A user or login name as it may be kept: printable, no spaces, bounded.
fn clean_user(text: &str) -> String {
    text.chars().filter(|c| c.is_ascii_graphic() && *c != '"' && *c != '\\').take(64).collect()
}

fn ip(text: &str) -> Option<IpAddr> {
    text.trim_matches(|c| c == '(' || c == ')' || c == ',' || c == '[' || c == ']').split('%').next()?.parse().ok()
}

/// The word after *marker* in *words*.
fn after<'a>(words: &[&'a str], marker: &str) -> Option<&'a str> {
    words.iter().position(|word| *word == marker).and_then(|at| words.get(at + 1).copied())
}

fn method_of(word: &str) -> &'static str {
    match word {
        "publickey" => "publickey",
        "password" => "password",
        w if w.starts_with("keyboard-interactive") => "keyboard-interactive",
        _ => "",
    }
}

/// An SSH server message (OpenSSH's own wording) as an event.
fn parse_sshd(message: &str, pid: u32) -> Option<LogEvent> {
    let words: Vec<&str> = message.split_whitespace().collect();
    let event = |kind, method, user: &str, ip_word: Option<&str>, port_word: Option<&str>, fingerprint: &str| LogEvent {
        kind, how: "ssh", method, user: clean_user(user), remote_ip: ip_word.and_then(ip),
        remote_port: port_word.and_then(|p| p.trim_end_matches(':').parse().ok()), fingerprint: fingerprint.to_string(), pid,
    };
    if words.first() == Some(&"Accepted") {
        // Accepted publickey for amos from 192.168.64.1 port 52344 ssh2: ED25519 SHA256:…
        let fingerprint = words.iter().find(|w| w.starts_with("SHA256:")).map(|w| &w[..w.len().min(80)]).unwrap_or("");
        return Some(event(LogKind::Accepted, method_of(words.get(1)?), after(&words, "for")?, after(&words, "from"), after(&words, "port"), fingerprint));
    }
    if words.first() == Some(&"Failed") {
        // Failed password for [invalid user] bob from 1.2.3.4 port 5555 ssh2
        let user = if after(&words, "for") == Some("invalid") { after(&words, "user")? } else { after(&words, "for")? };
        return Some(event(LogKind::Failed, method_of(words.get(1)?), user, after(&words, "from"), after(&words, "port"), ""));
    }
    if message.starts_with("Invalid user ") {
        return Some(event(LogKind::Failed, "", after(&words, "user")?, after(&words, "from"), after(&words, "port"), ""));
    }
    if message.contains("authentication error for") {
        // error: PAM: authentication error for amos from 192.168.64.1
        let user = after(&words, "for")?;
        return Some(event(LogKind::Failed, "password", user, after(&words, "from"), None, ""));
    }
    if message.starts_with("Disconnected from user ") {
        // Disconnected from user amos 192.168.64.1 port 52344
        return Some(event(LogKind::Disconnected, "", after(&words, "user")?, words.get(4).copied(), after(&words, "port"), ""));
    }
    None
}

/// Screen Sharing's "Authentication: SUCCEEDED :: User Name: amos :: Viewer Address: 1.2.3.4 :: …".
fn parse_screen_sharing(message: &str, pid: u32, how: &'static str) -> Option<LogEvent> {
    let kind = if message.contains("SUCCEEDED") { LogKind::Accepted } else if message.contains("FAILED") { LogKind::Failed } else { return None };
    let field = |name: &str| message.split("::").find_map(|part| part.trim().strip_prefix(name).map(|v| v.trim().to_string()));
    Some(LogEvent {
        kind, how, method: "password", user: clean_user(&field("User Name:").unwrap_or_default()),
        remote_ip: field("Viewer Address:").as_deref().and_then(ip), remote_port: None, fingerprint: String::new(), pid,
    })
}

/// Tailscale SSH's `handling new SSH connection from amos@example.com (100.101.102.103) to ssh-user "admin"`.
fn parse_tailscale(message: &str, pid: u32) -> Option<LogEvent> {
    let rest = message.split("new SSH connection from ").nth(1)?;
    let (_login, rest) = rest.split_once(" (")?;
    let (address, rest) = rest.split_once(')')?;
    let user = rest.split('"').nth(1).unwrap_or("");
    Some(LogEvent {
        kind: LogKind::Accepted, how: "tailscale-ssh", method: "", user: clean_user(user), remote_ip: ip(address),
        remote_port: None, fingerprint: String::new(), pid,
    })
}

/// One ndjson line of `log stream` as an event; None for anything that is not a login event.
pub fn parse_line(line: &str) -> Option<LogEvent> {
    let value: Value = serde_json::from_str(line.trim()).ok()?;
    let message = value.get("eventMessage")?.as_str()?;
    let process = value.get("processImagePath").and_then(Value::as_str).unwrap_or("").rsplit('/').next().unwrap_or("");
    let pid = value.get("processID").and_then(Value::as_u64).unwrap_or(0) as u32;
    match process {
        "sshd" | "sshd-session" | "sshd-auth" => parse_sshd(message.trim_start_matches("error: ").trim_start_matches("PAM: "), pid)
            .or_else(|| parse_sshd(message, pid)),
        "screensharingd" => parse_screen_sharing(message, pid, "screen-sharing"),
        "ARDAgent" => parse_screen_sharing(message, pid, "remote-desktop"),
        "tailscaled" | "IPNExtension" => parse_tailscale(message, pid),
        _ => None,
    }
}

/// The running `log stream` child and what it parsed.
pub struct Stream {
    child: Option<Child>,
    events: Option<Receiver<LogEvent>>,
    backoff: Duration,
    retry_at: Option<Instant>,
}

impl Default for Stream {
    fn default() -> Self {
        Stream { child: None, events: None, backoff: BACKOFF_FIRST, retry_at: None }
    }
}

impl Stream {
    /// Starts the child if it is not running (or restarts it after its back-off).
    pub fn ensure_running(&mut self) {
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(None) => return,
                _ => {
                    self.child = None;
                    self.events = None;
                    self.retry_at = Some(Instant::now() + self.backoff);
                    self.backoff = (self.backoff * 2).min(BACKOFF_MOST);
                }
            }
        }
        if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }
        let spawned = Command::new(LOG)
            .args(["stream", "--style", "ndjson", "--level", "info", "--predicate", PREDICATE])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
        let Ok(mut child) = spawned else {
            self.retry_at = Some(Instant::now() + self.backoff);
            self.backoff = (self.backoff * 2).min(BACKOFF_MOST);
            return;
        };
        let Some(stdout) = child.stdout.take() else { let _ = child.kill(); let _ = child.wait(); return };
        let (send, receive) = channel();
        std::thread::Builder::new().name("blackbox-netd-logstream".into()).spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(event) = parse_line(&line) {
                    if send.send(event).is_err() {
                        break;
                    }
                }
            }
        }).ok();
        self.child = Some(child);
        self.events = Some(receive);
        self.retry_at = None;
    }

    /// The events parsed since the last call (bounded).
    pub fn drain(&mut self) -> Vec<LogEvent> {
        let mut out: Vec<LogEvent> = self.events.as_ref().map(|events| events.try_iter().collect()).unwrap_or_default();
        if out.len() > MAX_BUFFERED {
            out.drain(..out.len() - MAX_BUFFERED);
        }
        out
    }

    /// Ends the child (this helper's own) and forgets the back-off.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // WHY field by field and never `*self = Stream::default()`: assigning to `*self` drops the
        // old value, its Drop calls stop() again, which assigns again … an endless recursion that
        // overflowed the helper's stack at start-up as root (found on bb-e2e-1121, 2026-11-21).
        self.events = None;
        self.backoff = BACKOFF_FIRST;
        self.retry_at = None;
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stopping or dropping a Stream must never re-enter Drop: on a small stack an endless
    /// stop → drop → stop recursion aborts the process (the helper crashed this way as root).
    #[test]
    fn stopping_and_dropping_a_stream_returns_on_a_small_stack() {
        std::thread::Builder::new().stack_size(64 * 1024).spawn(|| {
            let mut stream = Stream::default();
            stream.stop();
            stream.stop();
            drop(stream);
            drop(Stream::default());
        }).unwrap().join().expect("stop and drop return");
    }

    fn line(process: &str, pid: u32, message: &str) -> String {
        serde_json::json!({"eventMessage": message, "processImagePath": format!("/usr/libexec/{process}"), "processID": pid}).to_string()
    }

    #[test]
    fn ssh_logins_parse_with_method_key_user_and_source() {
        let key = parse_line(&line("sshd-session", 812, "Accepted publickey for admin from 192.168.64.1 port 52344 ssh2: ED25519 SHA256:AbC123xyz")).unwrap();
        assert_eq!((key.kind, key.how, key.method, key.user.as_str()), (LogKind::Accepted, "ssh", "publickey", "admin"));
        assert_eq!((key.remote_ip.unwrap().to_string(), key.remote_port, key.fingerprint.as_str(), key.pid), ("192.168.64.1".into(), Some(52344), "SHA256:AbC123xyz", 812));
        let pass = parse_line(&line("sshd", 9, "Accepted keyboard-interactive/pam for admin from 10.0.0.2 port 5 ssh2")).unwrap();
        assert_eq!(pass.method, "keyboard-interactive");
    }

    #[test]
    fn failed_ssh_attempts_parse_including_unknown_users() {
        let wrong = parse_line(&line("sshd-session", 1, "Failed password for admin from 203.0.113.9 port 4000 ssh2")).unwrap();
        assert_eq!((wrong.kind, wrong.user.as_str(), wrong.remote_ip.unwrap().to_string()), (LogKind::Failed, "admin", "203.0.113.9".into()));
        let invalid = parse_line(&line("sshd-session", 1, "Failed password for invalid user bob from 203.0.113.9 port 4001 ssh2")).unwrap();
        assert_eq!(invalid.user, "bob");
        let probe = parse_line(&line("sshd", 1, "Invalid user root from 198.51.100.7 port 22")).unwrap();
        assert_eq!((probe.kind, probe.user.as_str()), (LogKind::Failed, "root"));
        let pam = parse_line(&line("sshd-session", 1, "error: PAM: authentication error for admin from 192.168.64.1")).unwrap();
        assert_eq!((pam.kind, pam.remote_ip.unwrap().to_string()), (LogKind::Failed, "192.168.64.1".into()));
    }

    #[test]
    fn disconnects_screen_sharing_and_tailscale_parse() {
        let gone = parse_line(&line("sshd-session", 812, "Disconnected from user admin 192.168.64.1 port 52344")).unwrap();
        assert_eq!((gone.kind, gone.remote_ip.unwrap().to_string(), gone.remote_port), (LogKind::Disconnected, "192.168.64.1".into(), Some(52344)));
        let screen = parse_line(&line("screensharingd", 77, "Authentication: SUCCEEDED :: User Name: admin :: Viewer Address: 192.168.64.1 :: Type: DH")).unwrap();
        assert_eq!((screen.how, screen.kind, screen.user.as_str()), ("screen-sharing", LogKind::Accepted, "admin"));
        let refused = parse_line(&line("screensharingd", 77, "Authentication: FAILED :: User Name: eve :: Viewer Address: 203.0.113.4 :: Type: DH")).unwrap();
        assert_eq!(refused.kind, LogKind::Failed);
        let tailnet = parse_line(&line("tailscaled", 50, "ssh-session(sess-1): handling new SSH connection from amos@example.com (100.101.102.103) to ssh-user \"admin\"")).unwrap();
        assert_eq!((tailnet.how, tailnet.user.as_str(), tailnet.remote_ip.unwrap().to_string()), ("tailscale-ssh", "admin", "100.101.102.103".into()));
    }

    #[test]
    fn anything_else_is_not_an_event_and_never_carries_text() {
        assert!(parse_line(&line("sshd", 1, "Server listening on :: port 22.")).is_none());
        assert!(parse_line(&line("Safari", 1, "Accepted publickey for x from 1.2.3.4 port 1 ssh2")).is_none());
        assert!(parse_line("not json").is_none());
        let odd = parse_line(&line("sshd", 1, "Accepted password for \"ev il\\x from 1.2.3.4 port 1 ssh2")).unwrap();
        assert!(!odd.user.contains('"') && !odd.user.contains('\\'));
    }
}
