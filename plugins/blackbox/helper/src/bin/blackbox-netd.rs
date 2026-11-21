//! `blackbox-netd` — Network Shield's enforcer (DNS Shield and the Threat Firewall).
//! Started by launchd (`ai.umanitek.blackbox.netd`) as root; applies the plan the Blackbox
//! plugin's Network Shield publishes. See the `blackbox_helper` crate.

fn main() {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("blackbox-netd must run as root (it is started by launchd)");
        std::process::exit(2);
    }
    if let Err(error) = blackbox_helper::run() {
        eprintln!("blackbox-netd: {error}");
        std::process::exit(1);
    }
}
