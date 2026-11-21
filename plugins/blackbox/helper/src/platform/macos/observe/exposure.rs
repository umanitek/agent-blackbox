//! Exposure: every socket this Mac serves that the network can reach — a TCP listener, or a UDP
//! socket bound to a fixed (non-ephemeral) port — on any address but loopback.
//!
//! Read with the same native socket reader the app's live traffic uses
//! (`crate::sockets`); run as root it sees every process, not only the user's. The first
//! look is a baseline; afterwards each new listener queues a `listener-new` event (the helper
//! reports it at once) and each one gone a `listener-closed`. Observing only.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::{json, Value};

use crate::sockets::Socket;

/// UDP ports from here up are the OS's ephemeral client ports, not services.
const EPHEMERAL_FROM: u16 = 49152;
const MAX_LISTENERS: usize = 300;
const MAX_PENDING: usize = 200;

/// One reachable listener: who serves which port on which address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listener {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub program: String,
    pub pid: u32,
}

/// True when *ip* is reachable from another machine (any address but loopback).
pub fn reachable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback(),
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    }
}

/// The reachable listeners among *sockets*; *program_of* names a process's executable.
pub fn listeners(sockets: &[Socket], program_of: &dyn Fn(u32) -> String) -> Vec<Listener> {
    let mut found: Vec<Listener> = sockets.iter()
        .filter(|s| reachable(&s.local_ip))
        .filter(|s| if s.protocol.starts_with("tcp") { s.listening() } else { s.remote_port == 0 && s.local_port != 0 && s.local_port < EPHEMERAL_FROM })
        .map(|s| Listener { protocol: s.protocol.clone(), address: s.local_ip.to_string(), port: s.local_port, program: program_of(s.pid), pid: s.pid })
        .collect();
    found.sort();
    found.dedup_by(|a, b| a.protocol == b.protocol && a.address == b.address && a.port == b.port && a.program == b.program);
    found.truncate(MAX_LISTENERS);
    found
}

type Key = (String, String, u16, String);

fn key(listener: &Listener) -> Key {
    (listener.protocol.clone(), listener.address.clone(), listener.port, listener.program.clone())
}

/// What the last look saw (first-seen times) and the events not yet reported.
#[derive(Debug, Default)]
pub struct Exposure {
    started: bool,
    seen: BTreeMap<Key, (u64, Listener)>,
    pending: Vec<Value>,
}

impl Exposure {
    /// Compares *current* with the last look; queues events. True when it queued any.
    pub fn tick(&mut self, current: Vec<Listener>, now: u64) -> bool {
        let before = self.pending.len();
        let mut next = BTreeMap::new();
        for listener in current {
            let since = self.seen.get(&key(&listener)).map(|(at, _)| *at).unwrap_or(now);
            if self.started && !self.seen.contains_key(&key(&listener)) {
                self.push(json!({"kind": "listener-new", "ts": now, "protocol": listener.protocol, "address": listener.address,
                                 "port": listener.port, "program": listener.program}));
            }
            next.insert(key(&listener), (since, listener));
        }
        if self.started {
            let closed: Vec<Listener> = self.seen.iter().filter(|(k, _)| !next.contains_key(*k)).map(|(_, (_, l))| l.clone()).collect();
            for listener in closed {
                self.push(json!({"kind": "listener-closed", "ts": now, "protocol": listener.protocol, "address": listener.address,
                                 "port": listener.port, "program": listener.program}));
            }
        }
        self.seen = next;
        self.started = true;
        self.pending.len() > before
    }

    fn push(&mut self, event: Value) {
        if self.pending.len() < MAX_PENDING {
            self.pending.push(event);
        }
    }

    /// Every listener now, with when it was first seen.
    pub fn snapshot(&self) -> Vec<Value> {
        self.seen.values().map(|(since, l)| json!({"protocol": l.protocol, "address": l.address, "port": l.port,
                                                    "program": l.program, "pid": l.pid, "since": since})).collect()
    }

    pub fn take_events(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.pending)
    }

    /// Forget everything (the shield went off): the next look is a new baseline.
    pub fn reset(&mut self) {
        *self = Exposure::default();
    }
}

/// The executable of process *pid* ("" when it cannot be read).
pub fn program_of(pid: u32) -> String {
    let mut buffer = vec![0u8; 4096];
    // SAFETY: proc_pidpath writes at most `buffer.len()` bytes into the buffer and answers the length.
    let length = unsafe { libc::proc_pidpath(pid as libc::c_int, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if length <= 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buffer[..length as usize]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(protocol: &str, local: &str, port: u16, remote_port: u16, state: &'static str, pid: u32) -> Socket {
        Socket { pid, protocol: protocol.into(), local_ip: local.parse().unwrap(), local_port: port,
                 remote_ip: "0.0.0.0".parse().unwrap(), remote_port, state }
    }

    #[test]
    fn only_reachable_services_count() {
        let sockets = vec![
            sock("tcp4", "0.0.0.0", 8000, 0, "Listen", 1),          // a web server on every address
            sock("tcp4", "127.0.0.1", 9700, 0, "Listen", 2),        // loopback only: not exposed
            sock("tcp6", "::1", 9701, 0, "Listen", 2),
            sock("tcp4", "192.168.1.5", 50000, 443, "Established", 3), // a client connection
            sock("udp4", "0.0.0.0", 5353, 0, "", 4),                 // mDNS service port
            sock("udp4", "0.0.0.0", 61000, 0, "", 5),                // ephemeral client port
        ];
        let found = listeners(&sockets, &|pid| format!("/bin/p{pid}"));
        let ports: Vec<u16> = found.iter().map(|l| l.port).collect();
        assert_eq!(ports, vec![8000, 5353]);
    }

    #[test]
    fn a_new_listener_is_an_event_after_the_baseline() {
        let mut exposure = Exposure::default();
        let web = Listener { protocol: "tcp4".into(), address: "0.0.0.0".into(), port: 8000, program: "/usr/bin/python3".into(), pid: 9 };
        assert!(!exposure.tick(vec![], 1), "the first look is the baseline");
        assert!(exposure.tick(vec![web.clone()], 2));
        let events = exposure.take_events();
        assert_eq!(events[0]["kind"], "listener-new");
        assert_eq!(events[0]["port"], 8000);
        assert!(!exposure.tick(vec![web.clone()], 3), "still there: nothing new");
        assert!(exposure.tick(vec![], 4));
        assert_eq!(exposure.take_events()[0]["kind"], "listener-closed");
    }

    #[test]
    fn this_process_path_is_readable() {
        assert!(!program_of(std::process::id()).is_empty());
    }
}
