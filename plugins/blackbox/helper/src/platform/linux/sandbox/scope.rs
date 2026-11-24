//! The cgroup scope each sandboxed agent runs in: `systemd-run --user --scope` puts it in
//! `blackbox-agents.slice` under the person's own systemd, as `blackbox-agent-<digest12>-<id>.scope`.
//! The scope is the handle the root helper's per-agent network rules match
//! (`nft … socket cgroupv2 …`: local ports, ssh back into this machine, Docker's TCP port —
//! `agent_guard.rs`); the digest in its name says which policy's rules apply.
//!
//! The launcher waits a short, bounded time for the helper to say a scope's rules are loaded
//! ([`READY_FOLDER`]`/<unit>.ready`); a machine without the helper waits for nothing.
//!
//! Pure apart from [`wait_ready`] (a few `stat`s).

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
/// How long an agent's start waits for its scope's network rules, at most.
pub const READY_WAIT: Duration = Duration::from_millis(500);
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

/// The `systemd-run` argv that starts *inner* (this launcher again, `run --in-scope …`) in scope *unit*.
pub fn systemd_run_argv(systemd_run: &str, unit: &str, inner: &[String]) -> Vec<String> {
    let mut argv = vec![systemd_run.to_string(), "--user".into(), "--scope".into(), "--quiet".into(), "--collect".into(),
                        format!("--slice={SLICE}"), format!("--unit={unit}"), "--".into()];
    argv.extend(inner.iter().cloned());
    argv
}

/// The readiness mark for *unit*.
pub fn ready_mark(unit: &str) -> PathBuf {
    Path::new(READY_FOLDER).join(format!("{unit}.ready"))
}

/// Waits at most [`READY_WAIT`] for the helper's mark for *unit*: true when it came, false when
/// the helper is not installed (no folder) or did not answer in time.
pub fn wait_ready(unit: &str) -> bool {
    if !Path::new(READY_FOLDER).is_dir() {
        return false;
    }
    let mark = ready_mark(unit);
    let started = Instant::now();
    loop {
        if mark.exists() {
            return true;
        }
        if started.elapsed() >= READY_WAIT {
            return false;
        }
        std::thread::sleep(READY_POLL);
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

    #[test]
    fn systemd_run_starts_the_inner_launcher_in_the_agents_slice() {
        let argv = systemd_run_argv("/usr/bin/systemd-run", "blackbox-agent-x-1.scope", &["/bin/self".into(), "run".into()]);
        assert_eq!(argv[..7], ["/usr/bin/systemd-run", "--user", "--scope", "--quiet", "--collect",
                               "--slice=blackbox-agents.slice", "--unit=blackbox-agent-x-1.scope"]);
        assert_eq!(argv[7..], ["--", "/bin/self", "run"]);
    }
}
