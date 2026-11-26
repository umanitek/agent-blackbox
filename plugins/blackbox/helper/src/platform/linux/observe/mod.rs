//! The Linux helper's OBSERVE side — what it watches, never what it changes.
//!
//! [`exposure`] (a listener's program), [`persistence`] (what starts by itself: systemd units,
//! autostart entries, cron, D-Bus services, root configuration), [`run_later`] (what runs at a
//! login, a shell or a typed command), [`tamper`] (DNS, proxies, VPNs, the system firewall,
//! Blackbox's helper) and [`posture`] (the facts behind the posture check). The state each look
//! fills (what was seen, the events a change queues) is every OS's: `platform/system_watch/`.
//! Rule (tested below): nothing here reaches into the enforce side — observing never changes
//! nftables, DNS or a process.

pub mod exposure;
pub mod persistence;
pub mod posture;
pub mod run_later;
pub mod tamper;
pub mod unit_files;

#[cfg(test)]
mod tests {
    /// Every observe source, read at build time: none may name the enforce side.
    const SOURCES: &[(&str, &str)] = &[
        ("observe/exposure.rs", include_str!("exposure.rs")),
        ("observe/persistence.rs", include_str!("persistence.rs")),
        ("observe/posture.rs", include_str!("posture.rs")),
        ("observe/run_later.rs", include_str!("run_later.rs")),
        ("observe/tamper.rs", include_str!("tamper.rs")),
        ("observe/unit_files.rs", include_str!("unit_files.rs")),
    ];
    const ENFORCE_NAMES: &[&str] = &["enforce", "nft::", "dns::", "-f -", "resolvectl", "nmcli", "systemctl"];

    #[test]
    fn observe_never_reaches_into_enforce() {
        for (file, source) in SOURCES {
            for name in ENFORCE_NAMES {
                assert!(!source.contains(name), "{file} names {name}: observing must never change the system");
            }
        }
    }
}
