//! The operating-system seam: every part of the helper that changes or reads the system lives
//! under this folder, one folder per operating system (per-OS structure, Amos 2026-11-21).
//!
//! This file is the contract. The shared helper (the plan, the signed link, the saved state,
//! undo, the DNS resolver and the loop in `daemon`) calls the system ONLY through the two traits
//! below, on the two types this build's OS folder provides:
//!
//! * [`Enforcer`] (type [`SystemEnforcer`]): what the helper changes — the system's DNS settings,
//!   the firewall, ending one remote session, the posture fixes. Every change is reversible.
//! * [`Observer`] (type [`SystemObserver`]): what it watches — inbound remote sessions and the
//!   login files, and the system watch (exposure, startup items, tampering, posture). Observing
//!   never changes the system.
//!
//! `macos/` implements them; `linux/` is being ported (its `SUPPORTED` stays false until its
//! firewall, DNS and install are in, so the helper refuses to start there meanwhile);
//! `unsupported.rs` is the fallback for an OS with no port yet (it refuses to run, so nothing
//! half-works). Each build compiles only its own OS's folder (`#[cfg(target_os)]` below): a macOS
//! build contains no other OS's code. Porting = add `windows/` with the same two types and point
//! `os` at it; nothing outside `platform/` changes. The guard test `tests/platform_guard.rs` fails if a system tool is named
//! outside this folder.
//!
//! Pattern: **Strategy** (the two traits, one implementation per OS) behind a **Facade** (this
//! module's re-exports).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

pub mod sockets;
pub mod system_watch;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use unsupported as os;

/// This OS's implementations of the two traits, the helper's root-owned folder, whether the
/// helper can run here at all, and its `install` / `uninstall` subcommands.
pub use os::{subcommand, SystemEnforcer, SystemObserver, HOME, SUPPORTED};

/// Each network service's DNS servers as they were before DNS Shield pointed the system at its
/// resolver (restored exactly; an empty list means "automatic").
pub type SavedDns = BTreeMap<String, Vec<String>>;

/// What the firewall must enforce; `None` = that protection is off.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    pub threats: Option<Vec<IpAddr>>,
    pub cut: Option<Vec<IpAddr>>,
    /// Allowed SSH sources: addresses or networks, already checked by [`source`].
    pub ssh_allow: Option<Vec<String>>,
    /// Lock remote access: the remote-access ports closed to everyone but this machine.
    pub remote_lock: bool,
    /// Addresses refused inbound entirely (blocked by the user or for repeated failed logins).
    pub remote_block: Option<Vec<IpAddr>>,
}

impl Filter {
    pub fn is_off(&self) -> bool {
        self.threats.is_none() && self.cut.is_none() && self.ssh_allow.is_none() && !self.remote_lock && self.remote_block.is_none()
    }
}

/// An SSH source in canonical form (`192.168.1.0/24`, `10.0.0.5`, `fd00::/8`); None when invalid.
/// Everything that goes into a firewall table passes through this or `IpAddr`.
pub fn source(text: &str) -> Option<String> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let ip: IpAddr = address.trim().parse().ok()?;
    match prefix {
        None => Some(ip.to_string()),
        Some(prefix) => {
            let bits: u8 = prefix.trim().parse().ok()?;
            let most = if ip.is_ipv4() { 32 } else { 128 };
            (bits <= most).then(|| format!("{ip}/{bits}"))
        }
    }
}

/// One end request from the plan: a remote session the user confirmed ending.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct EndRequest {
    pub session_id: String,
    pub pid: u32,
    /// When the watch first saw the session (unix seconds), as it reported it.
    pub started: u64,
}

/// What the helper changes on the system. Every method is reversible by another one here, and
/// none decides policy: the plan says what, this says how on this OS.
pub trait Enforcer: Send + Sync {
    /// Points every network service's DNS at the local resolver; answers what each had before.
    fn point_dns_at_shield(&self) -> Result<SavedDns, String>;
    /// Puts each service's DNS back exactly as saved; answers what failed (nothing → empty).
    fn restore_dns(&self, saved: &SavedDns) -> Vec<String>;
    /// The DNS servers the system resolves with now (the resolver's upstreams).
    fn current_upstreams(&self) -> Vec<SocketAddr>;
    /// The DNS servers this network handed out (DHCP).
    fn dhcp_upstreams(&self) -> Vec<SocketAddr>;
    /// The saved servers as upstreams (after a restart while DNS Shield was on).
    fn upstreams_from_saved(&self, saved: &SavedDns) -> Vec<SocketAddr>;
    /// When this machine booted (unix seconds): a firewall token from another boot is stale.
    fn boot_time(&self) -> u64;
    /// Makes the firewall enforce *filter* (an all-off filter removes Blackbox's rules and
    /// releases the firewall); answers the token to release it with later.
    fn apply_filter(&self, filter: &Filter, token: Option<String>) -> Result<Option<String>, String>;
    /// Ends the firewall's open states to *ip*; answers how many.
    fn kill_states(&self, ip: &IpAddr) -> Result<u64, String>;
    /// Packets Blackbox's rules dropped so far.
    fn dropped(&self) -> u64;
    /// Whether the firewall is really enforcing (None when it cannot be read).
    fn filter_enabled(&self) -> Option<bool>;
    /// Ends the process serving one remote session (already checked by [`Observer::verify_end`]).
    fn end_session(&self, pid: u32) -> Result<(), String>;
    /// Reverses every posture fix the person asked for (only on their explicit choice).
    fn undo_hardening(&self);
}

/// What the helper watches. Holds its own state between looks; never changes the system.
pub trait Observer: Send + Sync {
    /// How often [`Observer::look`] runs.
    const WATCH_EVERY: Duration;
    /// How often [`Observer::look_remote`] runs.
    const REMOTE_EVERY: Duration;
    /// The stack the system watch thread needs.
    const SYSTEM_WATCH_STACK: usize;

    /// One look at SSH and the login files while *watching* (else it forgets what it saw);
    /// true when something new happened.
    fn look(&self, watching: bool) -> bool;
    /// One look at who is in this machine and how, while *watching* (else it stops its log
    /// reader and forgets); true when something new happened.
    fn look_remote(&self, watching: bool) -> bool;
    /// Why *request* must not be carried out, or Ok when its process may be ended: the session is
    /// still live, still served by that very process, and of a kind that has its own process.
    fn verify_end(&self, request: &EndRequest) -> Result<(), String>;
    /// Records what came of an end request (the session ended, or why it was refused).
    fn record_end(&self, request: &EndRequest, result: Result<(), String>);
    /// Records one event for the next report (e.g. a connection the firewall cut).
    fn record(&self, event: Value);
    /// The SSH and login-file snapshot (None while not watching).
    fn watch_snapshot(&self) -> Option<Value>;
    /// The remote-sessions snapshot (None while not watching).
    fn remote_snapshot(&self) -> Option<Value>;
    /// The SSH / login-file events and the remote-session events not yet reported.
    fn drain(&self) -> (Vec<Value>, Vec<Value>);
    /// Puts back events a report could not deliver.
    fn requeue(&self, watch: Vec<Value>, remote: Vec<Value>);
    /// Stops whatever the remote watch keeps running (the helper stops).
    fn stop(&self);
    /// The system watch loop — exposure, startup items, tampering, posture and the posture fixes
    /// — with its own small plan and report. Runs until the process ends.
    fn run_system_watch(&self);
    /// File Shield's real-time watch — changes inside protected items and watched folders, as the
    /// operating system reports them — with its own small plan and report. Runs until the process ends.
    fn run_file_watch(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_sources_are_addresses_or_networks_only() {
        assert_eq!(source("192.168.1.0/24").as_deref(), Some("192.168.1.0/24"));
        assert_eq!(source("10.0.0.5").as_deref(), Some("10.0.0.5"));
        assert_eq!(source("fd00::/8").as_deref(), Some("fd00::/8"));
        for bad in ["10.0.0.0/33", "example.com", "1.2.3.4/x", "1.2.3.4\nblock all", ""] {
            assert_eq!(source(bad), None, "{bad:?}");
        }
    }
}
