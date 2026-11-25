//! launchd, as the helper's install needs it: stop a job, wait until launchd has really let go of
//! it, load it again, and wait until it runs.
//!
//! WHY the wait: `launchctl bootout` returns before the job has gone. A `bootstrap` sent while the
//! old job is still being torn down fails with "Bootstrap failed: 5: Input/output error" and leaves
//! the job UNLOADED (LES-086). The installer's dashboard reload hit this first (KI-513) and waits,
//! bounded, then retries bootstrap once; the helper's own reinstall does exactly the same here
//! (E2E 2026-11-21: an update that skipped the wait ended with no helper at all).
//!
//! [`Launchd`] is a Strategy: [`SystemLaunchd`] runs `/bin/launchctl`; tests pass a fake that
//! behaves like launchd (a job that lingers after bootout, a bootstrap refused while it does).

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::command;

/// How many times (one second apart) to ask whether launchd still knows the old job — the same
/// bound as the installer's `BLACKBOX_LAUNCHD_GONE_TRIES`.
pub const GONE_TRIES: u32 = 10;
/// How many times (250 ms apart) to ask whether a freshly loaded job runs (10 s).
pub const RUNNING_TRIES: u32 = 40;
const GONE_PAUSE: Duration = Duration::from_secs(1);
const RUNNING_PAUSE: Duration = Duration::from_millis(250);
const RETRY_PAUSE: Duration = Duration::from_secs(1);

/// What the install asks of launchd. *target* is `system/<label>`.
pub trait Launchd {
    /// Asks launchd to stop and unload *target* (no error when it is not loaded).
    fn bootout(&self, target: &str);
    /// Loads the job in *plist* into the system domain.
    fn bootstrap(&self, plist: &Path) -> Result<(), String>;
    /// Whether launchd still knows *target* (`launchctl print` succeeds).
    fn known(&self, target: &str) -> bool;
    /// Whether *target* is running.
    fn running(&self, target: &str) -> bool;
    /// Waits *pause* (a fake returns at once).
    fn pause(&self, pause: Duration);
}

/// Stops *target* and waits (at most [`GONE_TRIES`] seconds) until launchd has let go of it.
/// Answers whether it is gone.
pub fn stop(launchd: &dyn Launchd, target: &str) -> bool {
    launchd.bootout(target);
    for _ in 0..GONE_TRIES {
        if !launchd.known(target) {
            return true;
        }
        launchd.pause(GONE_PAUSE);
    }
    !launchd.known(target)
}

/// Loads *plist* (retrying once after a pause, as the installer does) and waits until *target*
/// runs. Call [`stop`] first.
pub fn start(launchd: &dyn Launchd, target: &str, plist: &Path) -> Result<(), String> {
    if let Err(first) = launchd.bootstrap(plist) {
        launchd.pause(RETRY_PAUSE);
        launchd.bootstrap(plist).map_err(|second| format!("{first}; again: {second}"))?;
    }
    for _ in 0..RUNNING_TRIES {
        if launchd.running(target) {
            return Ok(());
        }
        launchd.pause(RUNNING_PAUSE);
    }
    Err("launchd does not show the helper running".into())
}

/// Whether `launchctl print system/<label>` shows the job running.
pub fn parse_running(text: &str) -> bool {
    text.lines().any(|line| line.trim() == "state = running")
}

/// The real launchd (`/bin/launchctl`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLaunchd;

impl SystemLaunchd {
    fn run(args: &[&str]) -> Result<String, String> {
        let out = command::output(Command::new("/bin/launchctl").args(args), command::TIMEOUT).map_err(|error| error.to_string())?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if out.status.success() { Ok(text) } else { Err(format!("launchctl {}: {}", args.join(" "), text.trim())) }
    }
}

impl Launchd for SystemLaunchd {
    fn bootout(&self, target: &str) {
        let _ = Self::run(&["bootout", target]);   // not loaded on a first install
    }

    fn bootstrap(&self, plist: &Path) -> Result<(), String> {
        Self::run(&["bootstrap", "system", &plist.to_string_lossy()]).map(|_| ())
    }

    fn known(&self, target: &str) -> bool {
        Self::run(&["print", target]).is_ok()
    }

    fn running(&self, target: &str) -> bool {
        Self::run(&["print", target]).map(|text| parse_running(&text)).unwrap_or(false)
    }

    fn pause(&self, pause: Duration) {
        std::thread::sleep(pause);
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A launchd that lingers after bootout and refuses a bootstrap while it does — the behaviour
    //! behind "Bootstrap failed: 5: Input/output error".
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    #[derive(Default)]
    pub struct FakeLaunchd {
        /// How many `known` questions the old job survives after a bootout.
        pub linger: u32,
        /// A bootstrap fails while the file at this path holds these bytes (a program launchd
        /// will not start — the new helper of a failed update).
        pub refuse: Option<(PathBuf, Vec<u8>)>,
        pub state: RefCell<FakeState>,
    }

    #[derive(Default, Debug)]
    pub struct FakeState {
        pub loaded: bool,
        pub lingering: u32,
        pub bootstraps: u32,
        pub pauses: u32,
        /// The plist text each successful bootstrap loaded.
        pub loaded_plists: Vec<String>,
    }

    impl Launchd for FakeLaunchd {
        fn bootout(&self, _target: &str) {
            let mut state = self.state.borrow_mut();
            if state.loaded {
                state.loaded = false;
                state.lingering = self.linger;
            }
        }

        fn bootstrap(&self, plist: &Path) -> Result<(), String> {
            let mut state = self.state.borrow_mut();
            state.bootstraps += 1;
            if state.lingering > 0 {
                return Err("Bootstrap failed: 5: Input/output error".into());
            }
            let text = std::fs::read_to_string(plist).map_err(|error| error.to_string())?;
            if let Some((program, bytes)) = &self.refuse {
                if std::fs::read(program).map(|found| &found == bytes).unwrap_or(false) {
                    return Err("Bootstrap failed: 5: Input/output error".into());
                }
            }
            state.loaded = true;
            state.loaded_plists.push(text);
            Ok(())
        }

        fn known(&self, _target: &str) -> bool {
            let mut state = self.state.borrow_mut();
            if state.lingering > 0 {
                state.lingering -= 1;
                return true;
            }
            state.loaded
        }

        fn running(&self, _target: &str) -> bool {
            self.state.borrow().loaded
        }

        fn pause(&self, _pause: Duration) {
            // Time passes: the old job is a little closer to gone.
            let mut state = self.state.borrow_mut();
            state.pauses += 1;
            state.lingering = state.lingering.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeLaunchd;
    use super::*;

    #[test]
    fn a_reload_waits_until_launchd_has_let_go_of_the_old_job_before_loading_again() {
        let dir = std::env::temp_dir().join(format!("bb-launchd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plist = dir.join("job.plist");
        std::fs::write(&plist, "<plist/>").unwrap();
        // The old job lingers for 3 questions after bootout: loading at once would fail (5: I/O error).
        let launchd = FakeLaunchd { linger: 3, ..Default::default() };
        launchd.state.borrow_mut().loaded = true;
        assert!(stop(&launchd, "system/x"), "gone within the bound");
        start(&launchd, "system/x", &plist).expect("loaded once launchd let go");
        let state = launchd.state.borrow();
        assert_eq!(state.bootstraps, 1, "no failed bootstrap: it waited first");
        assert!(state.loaded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_job_that_outlives_the_bound_still_gets_one_retry_and_the_answer_says_so() {
        let dir = std::env::temp_dir().join(format!("bb-launchd-slow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plist = dir.join("job.plist");
        std::fs::write(&plist, "<plist/>").unwrap();
        // Each question and each pause wears it down by one; this outlasts the whole bound.
        let launchd = FakeLaunchd { linger: 2 * GONE_TRIES + 2, ..Default::default() };
        launchd.state.borrow_mut().loaded = true;
        assert!(!stop(&launchd, "system/x"), "still known after the bound");
        // The first bootstrap still meets it (5: I/O error); the retry after a pause loads it.
        start(&launchd, "system/x", &plist).expect("the retry loads it");
        assert_eq!(launchd.state.borrow().bootstraps, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn launchd_answers_read() {
        assert!(parse_running("system/ai.umanitek.blackbox.netd = {\n\tactive count = 1\n\tstate = running\n"));
        assert!(!parse_running("\tstate = spawn scheduled\n"));
    }
}
