//! `blackbox-netd` — Network Shield's enforcer (DNS Shield and the Threat Firewall).
//! Started by launchd (`ai.umanitek.blackbox.netd`) as root; applies the plan the Blackbox
//! plugin's Network Shield publishes. See the `blackbox_helper` crate.
//!
//! `blackbox-netd install …` / `blackbox-netd uninstall [--undo-hardening]` put it on the Mac
//! and take it off (`blackbox_helper::platform::subcommand`).

fn main() {
    // SAFETY: getuid has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("blackbox-netd must run as root (launchd starts it; install / uninstall run with sudo)");
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(result) = blackbox_helper::platform::subcommand(&args) {
        match result {
            Ok(()) => return,
            Err(error) => {
                eprintln!("blackbox-netd: {error}");
                std::process::exit(1);
            }
        }
    }
    if let Err(error) = blackbox_helper::run() {
        eprintln!("blackbox-netd: {error}");
        std::process::exit(1);
    }
}
