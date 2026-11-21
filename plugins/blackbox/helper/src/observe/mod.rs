//! The helper's OBSERVE side — what it watches, never what it changes.
//!
//! [`watch`]: inbound SSH sessions, whether Remote Login is on, and fingerprints of the login
//! files. [`logstream`] + [`remote`] (+ [`remote_procs`]): who is in this Mac right now and how —
//! remote logins as macOS logs them, joined with the inbound sessions on the remote-access ports.
//! [`exposure`] (listeners the network can reach), [`persistence`] (what starts by itself),
//! [`tamper`] (DNS / proxy / VPN / firewall / Blackbox's helper changed) and [`posture`] (the
//! facts behind the posture check) — read by [`super::system_guard`].
//! Rule (tested below): nothing here reaches into `enforce` — observing never changes pf,
//! DNS or a process.

pub mod exposure;
pub mod logstream;
pub mod persistence;
pub mod posture;
pub mod remote;
pub mod remote_procs;
pub mod tamper;
pub mod watch;

#[cfg(test)]
mod tests {
    /// Every observe source, read at build time: none may name the enforce side.
    const SOURCES: &[(&str, &str)] = &[
        ("observe/watch.rs", include_str!("watch.rs")),
        ("observe/logstream.rs", include_str!("logstream.rs")),
        ("observe/remote.rs", include_str!("remote.rs")),
        ("observe/remote_procs.rs", include_str!("remote_procs.rs")),
        ("observe/exposure.rs", include_str!("exposure.rs")),
        ("observe/persistence.rs", include_str!("persistence.rs")),
        ("observe/tamper.rs", include_str!("tamper.rs")),
        ("observe/posture.rs", include_str!("posture.rs")),
    ];
    const ENFORCE_NAMES: &[&str] = &["enforce", "pf::", "dns::", "system::", "pfctl", "networksetup"];

    #[test]
    fn observe_never_reaches_into_enforce() {
        for (file, source) in SOURCES {
            for name in ENFORCE_NAMES {
                assert!(!source.contains(name), "{file} names {name}: observing must never change the system");
            }
        }
    }
}
