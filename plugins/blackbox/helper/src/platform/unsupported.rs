//! The fallback for an operating system with no port yet: the same two types as `macos/`, so the
//! shared helper compiles everywhere, but nothing is changed or watched — every change answers
//! [`NOT_SUPPORTED`] and every look sees nothing. [`SUPPORTED`] is false, so the helper refuses
//! to start (`daemon::run`) and `install` / `uninstall` say why, instead of half-working.
//!
//! A port replaces this file for its OS with a folder (`windows/`, `linux/`) that implements
//! [`Enforcer`] and [`Observer`] for real (see `macos/`).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde_json::Value;

use super::{EndRequest, Enforcer, Filter, Observer, SavedDns};

/// The helper does not run on this operating system yet.
pub const SUPPORTED: bool = false;
/// No folder of its own here (the helper never starts).
pub const HOME: &str = "";
/// What every change answers on this operating system.
pub const NOT_SUPPORTED: &str = "Blackbox's system protection helper does not support this operating system yet";

/// `install` / `uninstall` answer why they cannot run; anything else is not a subcommand.
pub fn subcommand(args: &[String]) -> Option<Result<(), String>> {
    matches!(args.first().map(String::as_str), Some("install" | "uninstall")).then(|| Err(NOT_SUPPORTED.into()))
}

/// Changes nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnforcer;

impl Enforcer for SystemEnforcer {
    fn point_dns_at_shield(&self) -> Result<SavedDns, String> { Err(NOT_SUPPORTED.into()) }
    fn restore_dns(&self, _saved: &SavedDns) -> Vec<String> { vec![] }
    fn current_upstreams(&self) -> Vec<SocketAddr> { vec![] }
    fn dhcp_upstreams(&self) -> Vec<SocketAddr> { vec![] }
    fn upstreams_from_saved(&self, _saved: &SavedDns) -> Vec<SocketAddr> { vec![] }
    fn boot_time(&self) -> u64 { 0 }
    fn apply_filter(&self, filter: &Filter, _token: Option<String>) -> Result<Option<String>, String> {
        // Removing rules that were never set always succeeds; anything else cannot be done here.
        if filter.is_off() { Ok(None) } else { Err(NOT_SUPPORTED.into()) }
    }
    fn kill_states(&self, _ip: &IpAddr) -> Result<u64, String> { Err(NOT_SUPPORTED.into()) }
    fn dropped(&self) -> u64 { 0 }
    fn filter_enabled(&self) -> Option<bool> { None }
    fn end_session(&self, _pid: u32) -> Result<(), String> { Err(NOT_SUPPORTED.into()) }
    fn undo_hardening(&self) {}
}

/// Watches nothing.
#[derive(Debug, Default)]
pub struct SystemObserver;

impl Observer for SystemObserver {
    const WATCH_EVERY: Duration = Duration::from_secs(60);
    const REMOTE_EVERY: Duration = Duration::from_secs(60);
    const SYSTEM_WATCH_STACK: usize = 64 * 1024;

    fn look(&self, _watching: bool) -> bool { false }
    fn look_remote(&self, _watching: bool) -> bool { false }
    fn verify_end(&self, _request: &EndRequest) -> Result<(), String> { Err(NOT_SUPPORTED.into()) }
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
