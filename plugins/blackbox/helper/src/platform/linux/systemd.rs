//! systemd, as the helper's Linux install needs it: stop the unit, reload the unit files, enable
//! and start it, and wait (bounded) until systemd reports it active — and SELinux's file labels
//! on the installed program and unit (`restorecon`, only where SELinux is on: Fedora, RHEL).
//!
//! [`Systemd`] is a Strategy: [`SystemSystemd`] runs `systemctl`; tests pass a fake that records
//! what was asked and can refuse a start.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::command;

/// How many times (250 ms apart) to ask whether a freshly started unit is active (10 s).
pub const ACTIVE_TRIES: u32 = 40;
const ACTIVE_PAUSE: Duration = Duration::from_millis(250);
/// Where SELinux says it is on; `restorecon` runs only then.
pub const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
pub const SYSTEMCTL: &str = "systemctl";
pub const RESTORECON: &str = "restorecon";

/// What the install asks of systemd. *unit* is the unit's name (`blackbox-netd.service`).
pub trait Systemd {
    /// Stops *unit* (no error when it is not loaded).
    fn stop(&self, unit: &str);
    /// `daemon-reload`, then `enable --now` *unit*.
    fn enable_now(&self, unit: &str) -> Result<(), String>;
    /// `disable` *unit* (no error when it is not enabled).
    fn disable(&self, unit: &str);
    /// `daemon-reload` (after a unit file was removed).
    fn reload(&self);
    /// Whether *unit* is active (`is-active`).
    fn active(&self, unit: &str) -> bool;
    /// Gives *paths* SELinux's default labels when SELinux is on.
    fn relabel(&self, paths: &[&Path]);
    /// Waits *pause* (a fake returns at once).
    fn pause(&self, pause: Duration);
}

/// Enables and starts *unit*, then waits until it is active. Call [`Systemd::stop`] first.
pub fn start(systemd: &dyn Systemd, unit: &str) -> Result<(), String> {
    systemd.enable_now(unit)?;
    for _ in 0..ACTIVE_TRIES {
        if systemd.active(unit) {
            return Ok(());
        }
        systemd.pause(ACTIVE_PAUSE);
    }
    Err("systemd does not show the helper active".into())
}

/// The real systemd (`systemctl`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemSystemd;

impl SystemSystemd {
    fn run(program: &str, args: &[&str]) -> Result<String, String> {
        let out = command::output(Command::new(program).args(args), command::TIMEOUT).map_err(|error| error.to_string())?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if out.status.success() { Ok(text) } else { Err(format!("{program} {}: {}", args.join(" "), text.trim())) }
    }
}

impl Systemd for SystemSystemd {
    fn stop(&self, unit: &str) {
        let _ = Self::run(SYSTEMCTL, &["stop", unit]);   // not loaded on a first install
    }

    fn enable_now(&self, unit: &str) -> Result<(), String> {
        Self::run(SYSTEMCTL, &["daemon-reload"])?;
        Self::run(SYSTEMCTL, &["enable", "--now", unit]).map(|_| ())
    }

    fn disable(&self, unit: &str) {
        let _ = Self::run(SYSTEMCTL, &["disable", unit]);
    }

    fn reload(&self) {
        let _ = Self::run(SYSTEMCTL, &["daemon-reload"]);
    }

    fn active(&self, unit: &str) -> bool {
        Self::run(SYSTEMCTL, &["is-active", "--quiet", unit]).is_ok()
    }

    fn relabel(&self, paths: &[&Path]) {
        if !Path::new(SELINUX_ENFORCE).exists() {
            return;
        }
        let mut args = vec!["-F".to_string()];
        args.extend(paths.iter().map(|path| path.display().to_string()));
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = Self::run(RESTORECON, &words);   // a wrong label shows as the unit not starting, reported there
    }

    fn pause(&self, pause: Duration) {
        std::thread::sleep(pause);
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A systemd that records the install's questions and can refuse to start a given program.
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    #[derive(Default)]
    pub struct FakeSystemd {
        /// A start fails while the file at this path holds these bytes (the new helper of a failed update).
        pub refuse: Option<(PathBuf, Vec<u8>)>,
        pub state: RefCell<FakeState>,
    }

    #[derive(Default, Debug)]
    pub struct FakeState {
        pub active: bool,
        pub enabled: bool,
        pub starts: u32,
        pub stops: u32,
        pub relabelled: Vec<String>,
    }

    impl Systemd for FakeSystemd {
        fn stop(&self, _unit: &str) {
            let mut state = self.state.borrow_mut();
            state.active = false;
            state.stops += 1;
        }
        fn enable_now(&self, _unit: &str) -> Result<(), String> {
            let mut state = self.state.borrow_mut();
            state.starts += 1;
            if let Some((program, bytes)) = &self.refuse {
                if std::fs::read(program).map(|found| &found == bytes).unwrap_or(false) {
                    return Err("Job for blackbox-netd.service failed".into());
                }
            }
            state.active = true;
            state.enabled = true;
            Ok(())
        }
        fn disable(&self, _unit: &str) {
            self.state.borrow_mut().enabled = false;
        }
        fn reload(&self) {}
        fn active(&self, _unit: &str) -> bool {
            self.state.borrow().active
        }
        fn relabel(&self, paths: &[&Path]) {
            self.state.borrow_mut().relabelled.extend(paths.iter().map(|path| path.display().to_string()));
        }
        fn pause(&self, _pause: Duration) {}
    }
}
