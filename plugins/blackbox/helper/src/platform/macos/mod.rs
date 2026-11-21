//! macOS: the [`super::Enforcer`] and [`super::Observer`] for a Mac, and the parts they use —
//! the enforce side (pf, the Mac's DNS settings, posture fixes, ending a session), the observe
//! side (SSH and login files, remote sessions, exposure, persistence, tampering, posture), the
//! LaunchDaemon install, pf's status, the libproc socket reader and the system watch loop.
//! Compiled only for macOS (`super`'s `#[cfg(target_os)]`).

pub mod enforce;
mod enforcer;
pub mod install;
pub mod observe;
mod observer;
pub mod pf_status;
pub mod sockets;
pub(crate) mod system_guard;

pub use enforcer::MacEnforcer as SystemEnforcer;
pub use install::subcommand;
pub use observer::MacObserver as SystemObserver;

/// The helper runs on macOS.
pub const SUPPORTED: bool = true;
/// The LaunchDaemon label.
pub const LABEL: &str = "ai.umanitek.blackbox.netd";
/// The helper's root-owned folder.
pub const HOME: &str = "/Library/Application Support/Blackbox/netd";
