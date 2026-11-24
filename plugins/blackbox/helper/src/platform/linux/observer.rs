//! What the helper watches on Linux. Sees nothing until the observe readers land (build step 6);
//! the daemon never runs it while [`super::SUPPORTED`] is false.

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
    const SYSTEM_WATCH_STACK: usize = 64 * 1024;

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
    fn run_system_watch(&self) {}
    fn run_file_watch(&self) {}
}
