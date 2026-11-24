//! Linux: the [`super::Enforcer`] and [`super::Observer`] for a Linux machine, being ported in
//! small steps (design: Linux deep layers, build order 1–9). In so far: `/proc` ([`procfs`]),
//! the kernel's socket table ([`sock_diag`], [`sockets`]) and the observe readers ([`observe`]:
//! exposure, persistence, run-later, tamper, posture — the system watch loop wires them later). Until the firewall (nftables), DNS
//! Shield and the systemd install are all in, [`SUPPORTED`] stays false: the helper refuses to
//! start and `install` / `uninstall` say why, so nothing half-works on a person's machine.
//! Compiled only for Linux (`super`'s `#[cfg(target_os)]`).

pub mod enforce;
mod enforcer;
pub mod observe;
mod observer;
pub mod procfs;
pub mod sandbox;
pub mod sock_diag;
pub mod sockets;

pub use enforcer::LinuxEnforcer as SystemEnforcer;
pub use observer::LinuxObserver as SystemObserver;

/// Not yet: true once nftables, DNS Shield and the install are in (build step 9).
pub const SUPPORTED: bool = false;
/// The helper's root-owned folder.
pub const HOME: &str = "/var/lib/blackbox/netd";
/// The systemd unit the install writes (build step 9).
pub const UNIT: &str = "/etc/systemd/system/blackbox-netd.service";
/// Where the install puts the helper's program (build step 9).
pub const BINARY: &str = "/usr/local/libexec/blackbox/blackbox-netd";
/// What a change the port cannot make yet answers.
pub const NOT_YET: &str = "Blackbox's system protection helper is not ready on Linux yet";

/// `install` / `uninstall` answer why they cannot run yet; anything else is not a subcommand.
pub fn subcommand(args: &[String]) -> Option<Result<(), String>> {
    matches!(args.first().map(String::as_str), Some("install" | "uninstall")).then(|| Err(NOT_YET.into()))
}
