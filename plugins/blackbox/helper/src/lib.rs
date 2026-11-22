//! `blackbox-netd`: Network Shield's enforcer — the small root helper that applies the plan.
//!
//! **It decides nothing.** All policy lives in the Blackbox plugin's Network Shield
//! (`plugins/blackbox/shields/network`): what DNS must refuse, which IPs the firewall drops,
//! which connections to cut, who may SSH in, whether to watch. This process only:
//!
//! 1. pulls the plan every [`PLAN_EVERY`] from the plugin
//!    (`GET /api/shields/network-shield/api/enforcement?have=<version>`; an unchanged plan costs
//!    nothing) and applies it — the resolver's sets, the Mac's DNS settings, the pf anchor
//!    ([`pf`]: threats, cut connections, SSH lockdown);
//! 2. while the plan says `watch`, looks every [`watch::WATCH_EVERY`] at SSH into this Mac and
//!    the login files ([`watch`]) — observing only, never a file's contents;
//! 3. reports back every [`REPORT_EVERY`], and **at once** when something happened (a new SSH
//!    session, a changed file, a cut connection): `POST …/api/enforcer-report`.
//!
//! It opens no port of its own besides DNS on 127.0.0.1:53, and takes no commands from the app:
//! there is no control API to attack. Runs as a LaunchDaemon (`ai.umanitek.blackbox.netd`),
//! installed with one admin approval (by Blackbox's installer when the person turns on system
//! protection, or by Blackbox Desktop). When the plugin cannot be reached it
//! keeps enforcing the last plan; when it is stopped it puts the Mac's DNS settings and pf back.
//!
//! Modules: [`dns`] (the resolver), [`plan`] (the plan), [`link`] (the signed link to the
//! plugin), [`platform`] (everything that changes or reads the system: one folder per OS, behind
//! the [`Enforcer`] and [`Observer`] traits).

pub mod platform;
pub mod command;
pub mod dns;
pub mod handover;
pub mod link;
pub mod last_plan;
pub mod plan;
pub mod private_files;
pub mod safe_read;
mod daemon;
mod state;
mod undo;

// The system is reached only through the platform's two traits (platform/mod.rs).
pub use platform::{Enforcer, Observer, SystemEnforcer, SystemObserver, HOME};

/// The socket and interface records, and on macOS the native reader — Blackbox Desktop's live
/// traffic collector reads it as the person (fast tier). Elsewhere only the records exist.
pub mod sockets {
    pub use crate::platform::sockets::{Iface, Socket};
    #[cfg(target_os = "macos")]
    pub use crate::platform::macos::sockets::{layouts_match, tcp_state_name, Reader};
}
/// The helper's LaunchDaemon label (Blackbox Desktop installs and checks the same service).
#[cfg(target_os = "macos")]
pub use platform::macos::LABEL;

use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use plan::Plan;
pub use daemon::run;
pub use state::State;
pub use undo::{put_back, undo_for, Stopping, Undo};

const PLAN_PATH: &str = "/api/shields/network-shield/api/enforcement";
const REPORT_PATH: &str = "/api/shields/network-shield/api/enforcer-report";
pub const PLAN_EVERY: Duration = Duration::from_secs(15);
/// The plan is asked for this often while watching (an unchanged plan costs one tiny answer), so a
/// session the user chose to end, a lock or a block takes effect within seconds.
pub const PLAN_EVERY_WATCHING: Duration = Duration::from_secs(3);
pub const REPORT_EVERY: Duration = Duration::from_secs(30);
const PLAN_TIMEOUT: Duration = Duration::from_secs(120);
const REPORT_TIMEOUT: Duration = Duration::from_secs(15);
