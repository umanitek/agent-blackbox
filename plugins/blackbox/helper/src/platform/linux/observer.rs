//! What the helper watches on Linux: the system watch loop ([`super::system_guard`]: exposure,
//! persistence, the run-later places, tampering, posture and the DNS tamper guard). SSH and remote
//! sessions (journald, utmp) and File Shield's real-time watch (fanotify) are later build steps
//! (11 and 10): until then their looks see nothing and ending a session answers [`NOT_YET`].
//!
//! The events the daemon itself records (`connection-cut`, `firewall-restored`) are queued here
//! and go out with the next report (bounded: [`MAX_QUEUED`]). WHY (KI-688 fix wave): the queue was
//! a no-op, so on Linux the person was never told a connection was cut or the firewall put back.

use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

use crate::platform::{EndRequest, Observer};

use super::NOT_YET;

/// The most events kept for the next report (the oldest go first past it).
pub const MAX_QUEUED: usize = 200;

/// The Linux observer.
#[derive(Debug, Default)]
pub struct LinuxObserver {
    events: Mutex<Vec<Value>>,
}

impl LinuxObserver {
    fn keep(&self, mut more: Vec<Value>, newer: bool) {
        if let Ok(mut events) = self.events.lock() {
            if newer { events.append(&mut more) } else { more.append(&mut events); *events = more; }
            let extra = events.len().saturating_sub(MAX_QUEUED);
            events.drain(..extra);
        }
    }
}

impl Observer for LinuxObserver {
    const WATCH_EVERY: Duration = Duration::from_secs(60);
    const REMOTE_EVERY: Duration = Duration::from_secs(60);
    const SYSTEM_WATCH_STACK: usize = super::system_guard::STACK_BYTES;

    fn look(&self, _watching: bool) -> bool { false }
    fn look_remote(&self, _watching: bool) -> bool { false }
    fn verify_end(&self, _request: &EndRequest) -> Result<(), String> { Err(NOT_YET.into()) }
    fn record_end(&self, _request: &EndRequest, _result: Result<(), String>) {}
    fn record(&self, event: Value) {
        self.keep(vec![event], true);
    }
    fn watch_snapshot(&self) -> Option<Value> { None }
    fn remote_snapshot(&self) -> Option<Value> { None }
    fn drain(&self) -> (Vec<Value>, Vec<Value>) {
        (self.events.lock().map(|mut events| std::mem::take(&mut *events)).unwrap_or_default(), vec![])
    }
    /// Events not delivered go back BEFORE any recorded since (the order they happened in).
    fn requeue(&self, watch: Vec<Value>, _remote: Vec<Value>) {
        self.keep(watch, false);
    }
    fn stop(&self) {}
    fn run_system_watch(&self) {
        super::system_guard::run();
    }
    /// File Shield's real-time watch on Linux (fanotify, build step 10) is not in yet; the watch
    /// plan's other reader, the agent guard (per-agent network rules for sandboxed agents), runs here.
    fn run_file_watch(&self) {
        super::agent_guard::run()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recorded_events_go_out_with_the_next_report_and_come_back_when_not_delivered() {
        let observer = LinuxObserver::default();
        observer.record(json!({"kind": "firewall-restored", "ts": 1}));
        let (events, remote) = observer.drain();
        assert_eq!((events.len(), remote.len()), (1, 0));
        assert!(observer.drain().0.is_empty(), "each event goes out once");
        observer.record(json!({"kind": "connection-cut", "ts": 2}));
        observer.requeue(events, vec![]);
        let kinds: Vec<_> = observer.drain().0.iter().map(|event| event["kind"].clone()).collect();
        assert_eq!(kinds, [json!("firewall-restored"), json!("connection-cut")], "undelivered first, in order");
        for ts in 0..(MAX_QUEUED + 5) {
            observer.record(json!({"kind": "connection-cut", "ts": ts}));
        }
        assert_eq!(observer.drain().0.len(), MAX_QUEUED, "bounded");
    }
}
