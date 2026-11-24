//! What the helper watches on Linux: the system watch loop ([`super::system_guard`]: exposure,
//! persistence, the run-later places, tampering, posture and the DNS tamper guard). SSH and remote
//! sessions (journald, utmp) and File Shield's real-time watch (fanotify) are later build steps
//! (11 and 10): until then their looks see nothing and ending a session answers [`NOT_YET`].

use std::time::Duration;

use serde_json::Value;

use crate::platform::{EndRequest, Observer};

use super::NOT_YET;

/// The Linux observer.
#[derive(Debug, Default)]
pub struct LinuxObserver;

impl Observer for LinuxObserver {
    const WATCH_EVERY: Duration = Duration::from_secs(60);
    const REMOTE_EVERY: Duration = Duration::from_secs(60);
    const SYSTEM_WATCH_STACK: usize = super::system_guard::STACK_BYTES;

    fn look(&self, _watching: bool) -> bool { false }
    fn look_remote(&self, _watching: bool) -> bool { false }
    fn verify_end(&self, _request: &EndRequest) -> Result<(), String> { Err(NOT_YET.into()) }
    fn record_end(&self, _request: &EndRequest, _result: Result<(), String>) {}
    fn record(&self, _event: Value) {}
    fn watch_snapshot(&self) -> Option<Value> { None }
    fn remote_snapshot(&self) -> Option<Value> { None }
    fn drain(&self) -> (Vec<Value>, Vec<Value>) { (vec![], vec![]) }
    fn requeue(&self, _watch: Vec<Value>, _remote: Vec<Value>) {}
    fn stop(&self) {}
    fn run_system_watch(&self) {
        super::system_guard::run();
    }
    fn run_file_watch(&self) {}
}
