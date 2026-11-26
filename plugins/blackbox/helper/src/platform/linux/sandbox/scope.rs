//! The cgroup scope each sandboxed agent runs in: `systemd-run --user --scope` puts it in
//! [`SLICE`] under the person's own systemd, as `blackbox-agent-<digest12>-<id>.scope`.
//! The scope is the handle the root helper's per-agent network rules match
//! (`nft … socket cgroupv2 …`: local ports, ssh back into this machine, Docker's TCP port —
//! `agent_guard.rs`); the digest in its name says which policy's rules apply.
//!
//! This module is the ONE definition of the scope's naming both sides read: the launcher names its
//! scope with [`unit_name`] / [`systemd_run_argv`], the helper finds it with [`digest_of_unit`] and
//! [`slice_cgroup_path`]. WHY the last one exists: systemd nests a slice by the dashes in its name —
//! `blackbox-agents.slice` lives at `blackbox.slice/blackbox-agents.slice` — and Linux round L2
//! found the helper looking one level up, so no agent's rules ever loaded (security Critical
//! 2026-11-24-linux-sandbox-the-helper-never-finds-an-).
//!
//! The launcher waits a short, bounded time for the helper to say a scope's rules are loaded
//! ([`READY_FOLDER`]`/<unit>.ready`, [`wait_ready`]); a machine without the helper waits for nothing.
//! When the helper IS installed and the mark does not come, the start is never silent: the launcher
//! says so on stderr and leaves an [`UNBOUND_FOLDER`] mark the status page reads.
//!
//! Pure apart from [`wait_ready`] (a few `stat`s) and the marks.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The slice every sandboxed agent's scope is placed in.
pub const SLICE: &str = "blackbox-agents.slice";
/// The start of every scope's name.
pub const UNIT_PREFIX: &str = "blackbox-agent-";
/// Where systemd-run usually lives.
pub const SYSTEMD_RUN: &[&str] = &["/usr/bin/systemd-run", "/bin/systemd-run"];
/// The helper's per-scope readiness marks (root-owned; absent without the helper).
pub const READY_FOLDER: &str = "/run/blackbox-netd/agents";
/// The installed helper (root-owned): its presence means a scope's rules SHOULD come.
pub const HELPER: &str = super::super::BINARY;
/// Inside `$XDG_RUNTIME_DIR`: one empty file per agent start whose rules did not come in time
/// (the plugin's status page reads it: `shields/files/sandbox/platform/linux/probe.py`). A start
/// whose rules did come clears it.
pub const UNBOUND_FOLDER: &str = "blackbox/sandbox-unbound";
/// How long an agent's start waits for its scope's network rules, at most. WHY 2 s (Linux round
/// L7, BB-LINUX-PENDING-530001): on the busy VM loading the table overran 500 ms and agents started
/// with their network rules NOT applied; a start waits longer only while the rules are not there,
/// and every millisecond of that wait is one the agent's connections are not left unguarded.
pub const READY_WAIT: Duration = Duration::from_millis(2000);
const READY_POLL: Duration = Duration::from_millis(10);
/// The digest characters a unit name carries.
pub const DIGEST_CHARS: usize = 12;

/// The unit name for a policy *digest* and a launch *id* (hex), e.g. `blackbox-agent-0123456789ab-5f3c.scope`.
/// A digest that is not hex (or none) becomes `nodigest`, so a name never carries what a policy wrote.
pub fn unit_name(digest: &str, id: &str) -> String {
    let short: String = digest.chars().take(DIGEST_CHARS).collect();
    let short = if short.len() == DIGEST_CHARS && short.bytes().all(|b| b.is_ascii_hexdigit()) { short } else { "nodigest".into() };
    format!("{UNIT_PREFIX}{short}-{id}.scope")
}

/// The digest part of a scope's unit name (the helper's side), None for any other name.
pub fn digest_of_unit(unit: &str) -> Option<&str> {
    let rest = unit.strip_prefix(UNIT_PREFIX)?.strip_suffix(".scope")?;
    let (digest, id) = rest.split_once('-')?;
    let hex = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit());
    (digest.len() == DIGEST_CHARS && hex(digest) && hex(id)).then_some(digest)
}

/// Where systemd puts *slice* below its manager's cgroup: one folder per dash-separated prefix
/// (`a-b-c.slice` → `a.slice/a-b.slice/a-b-c.slice`, systemd.slice(5)).
pub fn slice_cgroup_path(slice: &str) -> String {
    let name = slice.strip_suffix(".slice").unwrap_or(slice);
    let parts: Vec<&str> = name.split('-').collect();
    (1..=parts.len()).map(|count| format!("{}.slice", parts[..count].join("-"))).collect::<Vec<_>>().join("/")
}

/// The `systemd-run` argv that starts *inner* (this launcher again, `run --in-scope …`) in scope *unit*.
pub fn systemd_run_argv(systemd_run: &str, unit: &str, inner: &[String]) -> Vec<String> {
    let mut argv = vec![systemd_run.to_string(), "--user".into(), "--scope".into(), "--quiet".into(), "--collect".into(),
                        format!("--slice={SLICE}"), format!("--unit={unit}"), "--".into()];
    argv.extend(inner.iter().cloned());
    argv
}

/// The readiness mark for *unit* in *folder*.
pub fn ready_mark(folder: &Path, unit: &str) -> PathBuf {
    folder.join(format!("{unit}.ready"))
}

/// What one agent start learned about its scope's network rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ready {
    /// The helper loaded them before the agent started.
    Bound,
    /// No helper on this machine: there are no per-agent rules to wait for.
    NoHelper,
    /// The helper is installed but did not load them within the wait: the agent starts WITHOUT them.
    NotBound,
}

/// Waits at most *wait* for the helper's mark for *unit* in *folder*. *helper_installed*: whether
/// the helper is on this machine (its program, or its folder, is there) — then a missing mark is
/// [`Ready::NotBound`], never a silent pass.
pub fn wait_ready(folder: &Path, unit: &str, helper_installed: bool, wait: Duration) -> Ready {
    if !helper_installed && !folder.is_dir() {
        return Ready::NoHelper;
    }
    let mark = ready_mark(folder, unit);
    let started = Instant::now();
    loop {
        if mark.exists() {
            return Ready::Bound;
        }
        if started.elapsed() >= wait {
            return Ready::NotBound;
        }
        std::thread::sleep(READY_POLL);
    }
}

/// What the launcher says on stderr when an agent starts without its rules.
pub const NOT_BOUND_LINE: &str = "blackbox: WARNING — the system protection helper did not apply this agent's network rules \
                                  in time, so ssh back into this computer, its local ports and Docker's TCP port are NOT refused for \
                                  it. Restart the agent; if this stays, run `blackbox status`.";

/// Records *outcome* for *unit* in *runtime*'s [`UNBOUND_FOLDER`]: a mark for a start without its
/// rules; every mark cleared by one with them. Best effort: a mark that can not be written only
/// loses the status page's count (the stderr line still says it).
pub fn record(runtime: &Path, unit: &str, outcome: Ready) {
    let folder = runtime.join(UNBOUND_FOLDER);
    match outcome {
        Ready::NotBound => {
            if std::fs::create_dir_all(&folder).is_ok() {
                let _ = std::fs::write(folder.join(unit), b"");
            }
        }
        Ready::Bound => {
            if let Ok(entries) = std::fs::read_dir(&folder) {
                for entry in entries.filter_map(Result::ok) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        Ready::NoHelper => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_name_carries_only_a_hex_digest_and_reads_back() {
        let unit = unit_name("0123456789abcdef", "5f3c");
        assert_eq!(unit, "blackbox-agent-0123456789ab-5f3c.scope");
        assert_eq!(digest_of_unit(&unit), Some("0123456789ab"));
        assert_eq!(unit_name("../../evil", "1"), "blackbox-agent-nodigest-1.scope");
        assert_eq!(digest_of_unit("blackbox-agent-nodigest-1.scope"), None);
        for other in ["user@1000.service", "blackbox-agent-0123456789ab.scope", "blackbox-agent-0123456789ab-zz.scope"] {
            assert_eq!(digest_of_unit(other), None, "{other}");
        }
    }

    /// The slice's real place, as systemd 255 made it on Ubuntu 24.04 / kernel 7.0 (Linux round L2:
    /// `/proc/self/cgroup` of a scope started with [`systemd_run_argv`], recorded in
    /// `../fixtures/cgroup_tree_ubuntu24.txt`) — never a path typed by hand (LES-153).
    #[test]
    fn the_slice_path_is_where_systemd_really_puts_it() {
        assert_eq!(slice_cgroup_path(SLICE), "blackbox.slice/blackbox-agents.slice");
        assert_eq!(slice_cgroup_path("a.slice"), "a.slice");
        assert_eq!(slice_cgroup_path("a-b-c.slice"), "a.slice/a-b.slice/a-b-c.slice");
        let recorded = include_str!("../fixtures/cgroup_tree_ubuntu24.txt");
        let own = recorded.lines().find_map(|line| line.strip_prefix("0::/")).expect("the scope's own /proc/self/cgroup line");
        assert!(own.contains(&format!("/user@1000.service/{}/blackbox-agent-", slice_cgroup_path(SLICE))), "{own}");
    }

    #[test]
    fn a_start_without_its_rules_is_never_silent_when_the_helper_is_installed() {
        let folder = std::env::temp_dir().join(format!("bb-scope-ready-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        let unit = "blackbox-agent-0123456789ab-1.scope";
        assert_eq!(wait_ready(&folder, unit, false, Duration::ZERO), Ready::NoHelper, "no helper, no folder: nothing to wait for");
        assert_eq!(wait_ready(&folder, unit, true, Duration::ZERO), Ready::NotBound, "the helper is installed: a missing mark is said");
        std::fs::create_dir_all(&folder).unwrap();
        assert_eq!(wait_ready(&folder, unit, false, Duration::ZERO), Ready::NotBound, "the helper's folder is there");
        std::fs::write(ready_mark(&folder, unit), b"1\n").unwrap();
        assert_eq!(wait_ready(&folder, unit, true, Duration::ZERO), Ready::Bound);
        let runtime = folder.join("runtime");
        record(&runtime, unit, Ready::NotBound);
        assert!(runtime.join(UNBOUND_FOLDER).join(unit).exists(), "the status page can count it");
        record(&runtime, "blackbox-agent-0123456789ab-2.scope", Ready::Bound);
        assert_eq!(std::fs::read_dir(runtime.join(UNBOUND_FOLDER)).unwrap().count(), 0, "a start with its rules clears the marks");
        let _ = std::fs::remove_dir_all(folder);
    }

    #[test]
    fn systemd_run_starts_the_inner_launcher_in_the_agents_slice() {
        let argv = systemd_run_argv("/usr/bin/systemd-run", "blackbox-agent-x-1.scope", &["/bin/self".into(), "run".into()]);
        assert_eq!(argv[..7], ["/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--collect",
                               "--slice=blackbox-agents.slice", "--unit=blackbox-agent-x-1.scope"]);
        assert_eq!(argv[7..], ["--", "/bin/self", "run"]);
    }
}
