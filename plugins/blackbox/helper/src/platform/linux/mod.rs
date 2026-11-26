//! Linux: the [`super::Enforcer`] and [`super::Observer`] for a Linux machine (design: Linux deep
//! layers). In: `/proc` ([`procfs`]), the kernel's socket table ([`sock_diag`], [`sockets`]), the
//! firewall (one nftables table) and DNS Shield's settings ([`enforce`]), the observe readers
//! ([`observe`]) and the system watch loop that runs them (`system_guard`), and the systemd
//! install ([`install`]: `blackbox-netd install` / `uninstall`). Later steps: SSH and remote
//! sessions, File Shield's real-time watch, the agent sandbox launcher (`sandbox`).
//! Compiled only for Linux (`super`'s `#[cfg(target_os)]`).

pub mod agent_guard;
pub mod enforce;
mod enforcer;
pub mod install;
pub mod observe;
mod observer;
pub mod procfs;
pub mod sandbox;
pub mod sock_diag;
pub mod sockets;
mod systemd;
pub(crate) mod system_guard;

pub use enforcer::LinuxEnforcer as SystemEnforcer;
pub use observer::LinuxObserver as SystemObserver;

/// The helper runs on Linux: nftables, DNS Shield, the system watch and the systemd install are in,
/// and the plugin and the installer install, find and remove it (`kernel/system_helper/platform/linux.py`).
pub const SUPPORTED: bool = true;
/// The helper's root-owned folder.
pub const HOME: &str = "/var/lib/blackbox/netd";
/// The systemd unit the install writes.
pub const UNIT: &str = "/etc/systemd/system/blackbox-netd.service";
/// Where the install puts the helper's program.
pub const BINARY: &str = "/usr/local/libexec/blackbox/blackbox-netd";
/// What a change the Linux helper cannot make yet answers (ending a remote session: build step 11).
pub const NOT_YET: &str = "Blackbox's system protection helper is not ready on Linux yet";

pub use install::subcommand;
