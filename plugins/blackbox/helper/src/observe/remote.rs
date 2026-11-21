//! Who is in this Mac right now, and how: every remote session on the ports people use to get in
//! — SSH (22, and Tailscale SSH), Screen Sharing / VNC (5900), Remote Management (3283), file
//! sharing (445) and Remote Apple Events (3031) — joined with the login events of [`super::logstream`].
//!
//! Each [`Remote::tick`] (every [`REMOTE_EVERY`]) takes the sockets of every process, the process
//! table ([`super::remote_procs`]) and the login events since the last tick, and answers whether
//! it queued news: a session opened or ended, a failed login, a remote-access service switched on
//! or off. A session is one inbound connection, named by its serving process (the per-connection
//! `sshd-session`, `screensharingd` …), with the account it runs as, how it logged in (key — with
//! its fingerprint — or password), when it started and the programs running under it (paths
//! only, never arguments). The first tick is the baseline: a restart does not alert on sessions
//! already open. Observing only — ending a session is a separate, confirmed user action.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Duration;

use serde_json::{json, Value};

use super::logstream::{LogEvent, LogKind};
use super::remote_procs::{descendants, Procs};

pub const REMOTE_EVERY: Duration = Duration::from_secs(1);
/// The ports that let people in, and what each is.
pub const REMOTE_PORTS: [(u16, &str); 5] =
    [(22, "ssh"), (5900, "screen-sharing"), (3283, "remote-desktop"), (445, "smb"), (3031, "remote-apple-events")];
/// The service each port belongs to, in the report's `services`.
const SERVICES: [(u16, &str); 5] =
    [(22, "remote_login"), (5900, "screen_sharing"), (3283, "remote_management"), (445, "file_sharing"), (3031, "remote_apple_events")];
const MAX_PENDING: usize = 200;
const MAX_SESSIONS: usize = 100;
const MAX_PROCESSES: usize = 20;
/// How long a login event waits to be matched with its connection.
const MATCH_SECONDS: u64 = 120;

/// One socket, as the watch needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct Inbound {
    pub pid: u32,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub listening: bool,
    pub established: bool,
}

/// One remote session.
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: String,
    pub how: &'static str,
    pub method: &'static str,
    pub fingerprint: String,
    pub user: String,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub local_port: u16,
    /// The process serving the session, and its start (a later process with the same pid differs).
    pub pid: u32,
    pub proc_start: u64,
    pub started: u64,
    pub processes: Vec<(u32, String, String)>,
}

/// The sessions, services and login events of the last tick; the events not yet reported.
#[derive(Debug, Default)]
pub struct Remote {
    started: bool,
    sessions: BTreeMap<String, Session>,
    services: BTreeMap<&'static str, bool>,
    logins: Vec<(u64, LogEvent)>,
    pending: Vec<Value>,
}

fn is_tailnet(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
}

fn how_of(port: u16, owner: &str, local_ip: &IpAddr) -> &'static str {
    let base = REMOTE_PORTS.iter().find(|(p, _)| *p == port).map(|(_, how)| *how).unwrap_or("ssh");
    if base == "ssh" && (owner.to_ascii_lowercase().contains("tailscale") || owner == "IPNExtension" || is_tailnet(local_ip)) {
        "tailscale-ssh"
    } else {
        base
    }
}

impl Remote {
    /// One look. *sockets*: every process's sockets; *procs*: the process table; *logins*: the
    /// login events since the last tick. Answers true when it queued news.
    pub fn tick(&mut self, sockets: &[Inbound], procs: &Procs, logins: Vec<LogEvent>, now: u64) -> bool {
        let before = self.pending.len();
        for login in &logins {
            if login.kind == LogKind::Failed && self.started {
                self.push(json!({"kind": "remote-auth-failed", "ts": now, "how": login.how, "method": login.method,
                                 "user": login.user, "remote_ip": login.remote_ip.map(|ip| ip.to_string())}));
            }
        }
        self.logins.extend(logins.into_iter().filter(|l| l.kind == LogKind::Accepted).map(|l| (now, l)));
        self.logins.retain(|(at, _)| now.saturating_sub(*at) <= MATCH_SECONDS);

        let services: BTreeMap<&'static str, bool> = SERVICES.iter()
            .map(|(port, name)| (*name, sockets.iter().any(|s| s.listening && s.local_port == *port))).collect();
        if self.started {
            for (name, on) in &services {
                if self.services.get(name) != Some(on) {
                    self.push(json!({"kind": "remote-service-changed", "ts": now, "service": name, "on": on}));
                }
            }
        }

        let current = self.sessions_now(sockets, procs, now);
        if self.started {
            for (id, session) in &current {
                if !self.sessions.contains_key(id) {
                    self.push(session_event("remote-session-new", session, now, ""));
                }
            }
            for (id, session) in &self.sessions.clone() {
                if !current.contains_key(id) {
                    self.push(session_event("remote-session-ended", session, now, "closed"));
                }
            }
        }
        self.sessions = current;
        self.services = services;
        self.started = true;
        self.pending.len() > before
    }

    fn sessions_now(&self, sockets: &[Inbound], procs: &Procs, now: u64) -> BTreeMap<String, Session> {
        // One connection is often held by a parent and a child: keep the lowest pid per connection.
        let mut by_connection: HashMap<(u16, IpAddr, u16), &Inbound> = HashMap::new();
        for socket in sockets.iter().filter(|s| s.established && !s.remote_ip.is_loopback()
            && REMOTE_PORTS.iter().any(|(port, _)| *port == s.local_port)) {
            let key = (socket.local_port, socket.remote_ip, socket.remote_port);
            let keep = by_connection.get(&key).is_none_or(|kept| socket.pid < kept.pid);
            if keep {
                by_connection.insert(key, socket);
            }
        }
        let mut sessions = BTreeMap::new();
        for socket in by_connection.values().take(MAX_SESSIONS) {
            let owner = procs.get(&socket.pid);
            let how = how_of(socket.local_port, owner.map(|p| p.name.as_str()).unwrap_or(""), &socket.local_ip);
            let id = format!("{how}-{}-{}-{}", socket.pid, socket.remote_ip, socket.remote_port);
            let login = self.logins.iter().rev().map(|(_, l)| l).find(|l| l.remote_ip == Some(socket.remote_ip)
                && l.remote_port.is_none_or(|port| port == socket.remote_port)
                && (l.how == how || (l.how == "ssh" && how == "tailscale-ssh")));
            let under = descendants(procs, socket.pid, MAX_PROCESSES);
            let user = login.map(|l| l.user.clone()).filter(|u| !u.is_empty())
                .or_else(|| under.iter().map(|p| p.user.clone()).find(|u| !u.is_empty() && u != "root"))
                .or_else(|| owner.map(|p| p.user.clone()).filter(|u| !u.is_empty() && u != "root"))
                .unwrap_or_default();
            let previous = self.sessions.get(&id);
            sessions.insert(id.clone(), Session {
                id, how, method: login.map(|l| l.method).or(previous.map(|p| p.method)).unwrap_or(""),
                fingerprint: login.map(|l| l.fingerprint.clone()).or(previous.map(|p| p.fingerprint.clone())).unwrap_or_default(),
                user, remote_ip: socket.remote_ip, remote_port: socket.remote_port, local_port: socket.local_port,
                pid: socket.pid, proc_start: owner.map(|p| p.start).unwrap_or(0),
                started: previous.map(|p| p.started).unwrap_or(now),
                processes: under.iter().map(|p| (p.pid, p.name.clone(), p.path.clone())).collect(),
            });
        }
        sessions
    }

    pub fn push(&mut self, event: Value) {
        self.pending.push(event);
        if self.pending.len() > MAX_PENDING {
            let extra = self.pending.len() - MAX_PENDING;
            self.pending.drain(..extra);
        }
    }

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

    pub fn reset(&mut self) {
        *self = Remote::default();
    }

    /// The live session with this id.
    pub fn session(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// The report's `remote` snapshot; None before the first tick.
    pub fn snapshot(&self) -> Option<Value> {
        if !self.started {
            return None;
        }
        let sessions: Vec<Value> = self.sessions.values().map(|s| json!({
            "id": s.id, "how": s.how, "method": s.method, "fingerprint": s.fingerprint, "user": s.user,
            "remote_ip": s.remote_ip.to_string(), "remote_port": s.remote_port, "local_port": s.local_port,
            "pid": s.pid, "started": s.started,
            "processes": s.processes.iter().map(|(pid, name, path)| json!({"pid": pid, "name": name, "path": path})).collect::<Vec<_>>(),
        })).collect();
        Some(json!({"sessions": sessions, "services": self.services}))
    }
}

/// A session event (`reason`: "closed", "ended" when the user ended it, "" for a new one).
pub fn session_event(kind: &str, session: &Session, now: u64, reason: &str) -> Value {
    json!({"kind": kind, "ts": now, "session_id": session.id, "how": session.how, "method": session.method,
           "user": session.user, "remote_ip": session.remote_ip.to_string(), "remote_port": session.remote_port, "reason": reason})
}

#[cfg(test)]
mod tests {
    use super::super::remote_procs::Proc;
    use super::*;

    fn inbound(pid: u32, port: u16, remote: &str, rport: u16) -> Inbound {
        Inbound { pid, local_ip: "192.168.64.5".parse().unwrap(), local_port: port, remote_ip: remote.parse().unwrap(), remote_port: rport, listening: false, established: true }
    }

    fn listening(port: u16) -> Inbound {
        Inbound { pid: 1, local_ip: "0.0.0.0".parse().unwrap(), local_port: port, remote_ip: "0.0.0.0".parse().unwrap(), remote_port: 0, listening: true, established: false }
    }

    fn procs() -> Procs {
        let mut table = Procs::new();
        for (pid, ppid, name, user) in [(800, 1, "sshd-session", "root"), (801, 800, "sshd-session", "admin"), (802, 801, "zsh", "admin"), (900, 1, "screensharingd", "root")] {
            table.insert(pid, Proc { pid, ppid, name: name.into(), path: format!("/usr/bin/{name}"), user: user.into(), start: 1000 + pid as u64 });
        }
        table
    }

    fn login(kind: LogKind, how: &'static str, remote: &str, port: Option<u16>) -> LogEvent {
        LogEvent { kind, how, method: "publickey", user: "admin".into(), remote_ip: remote.parse().ok(), remote_port: port, fingerprint: "SHA256:abc".into(), pid: 800 }
    }

    #[test]
    fn a_session_opens_with_who_how_and_what_then_ends() {
        let mut remote = Remote::default();
        assert!(!remote.tick(&[listening(22)], &procs(), vec![], 100), "the first look is the baseline");
        let socket = inbound(800, 22, "192.168.64.1", 52344);
        let news = remote.tick(&[listening(22), socket.clone(), Inbound { pid: 801, ..socket.clone() }], &procs(),
                               vec![login(LogKind::Accepted, "ssh", "192.168.64.1", Some(52344))], 101);
        assert!(news);
        let snap = remote.snapshot().unwrap();
        let session = &snap["sessions"][0];
        assert_eq!((session["how"].as_str(), session["method"].as_str(), session["user"].as_str()), (Some("ssh"), Some("publickey"), Some("admin")));
        assert_eq!(session["pid"], 800, "the parent holding the connection names the session");
        assert_eq!(session["fingerprint"], "SHA256:abc");
        assert!(session["processes"].as_array().unwrap().iter().any(|p| p["name"] == "zsh"));
        let events = remote.drain();
        assert_eq!(events[0]["kind"], "remote-session-new");
        assert!(remote.tick(&[listening(22)], &procs(), vec![], 105));
        assert_eq!(remote.drain()[0]["kind"], "remote-session-ended");
    }

    #[test]
    fn failed_logins_services_and_kinds_of_access_are_told_apart() {
        let mut remote = Remote::default();
        remote.tick(&[], &procs(), vec![], 1);
        remote.tick(&[listening(5900)], &procs(), vec![login(LogKind::Failed, "ssh", "203.0.113.9", Some(4000))], 2);
        let kinds: Vec<String> = remote.drain().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect();
        assert!(kinds.contains(&"remote-auth-failed".to_string()) && kinds.contains(&"remote-service-changed".to_string()));
        let mut tailnet = inbound(50, 22, "100.101.102.103", 7000);
        tailnet.local_ip = "100.64.0.9".parse().unwrap();
        remote.tick(&[inbound(900, 5900, "192.168.64.1", 6000), tailnet], &procs(), vec![], 3);
        let hows: Vec<String> = remote.snapshot().unwrap()["sessions"].as_array().unwrap().iter().map(|s| s["how"].as_str().unwrap().to_string()).collect();
        assert!(hows.contains(&"screen-sharing".to_string()) && hows.contains(&"tailscale-ssh".to_string()));
    }

    #[test]
    fn loopback_and_outbound_connections_are_not_sessions() {
        let mut remote = Remote::default();
        let mut local = inbound(800, 22, "127.0.0.1", 5000);
        local.remote_ip = "127.0.0.1".parse().unwrap();
        remote.tick(&[local, inbound(800, 443, "1.2.3.4", 5000)], &procs(), vec![], 1);
        assert!(remote.snapshot().unwrap()["sessions"].as_array().unwrap().is_empty());
    }
}

#[cfg(test)]
mod stack_tests {
    use super::super::remote_procs::ProcReader;
    use super::*;

    /// The remote watch's whole tick on a thread with Rust's default 2 MiB stack.
    #[test]
    fn one_look_fits_a_default_thread_stack() {
        std::thread::spawn(|| {
            let mut reader = crate::sockets::Reader::default();
            let sockets: Vec<Inbound> = reader.sockets().into_iter().map(|s| Inbound {
                pid: s.pid, local_ip: s.local_ip, local_port: s.local_port, remote_ip: s.remote_ip, remote_port: s.remote_port,
                listening: s.listening(), established: s.state == "Established" }).collect();
            let procs = ProcReader::default().read();
            let mut remote = Remote::default();
            remote.tick(&sockets, &procs, vec![], 1);
            remote.tick(&sockets, &procs, vec![], 2);
        }).join().expect("no stack overflow");
    }
}
