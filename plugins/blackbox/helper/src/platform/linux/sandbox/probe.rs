//! `blackbox-sandbox probe`: what this machine lets the sandbox do, as one JSON object the plugin
//! reads (`shields/files/sandbox/platform/linux` — `unavailable()` and the status page say each
//! layer is enforced or why not):
//!
//! ```json
//! {"format": 1, "kernel": "6.8.0-49-generic", "userns": true, "why": "",
//!  "apparmor_userns_restricted": false, "landlock_abi": 4, "signals": "pid-namespace",
//!  "abstract_sockets": "reachable", "seccomp": true, "scope": true, "helper_rules": false}
//! ```
//!
//! `userns` is proven, not guessed: a child process really enters a user and mount namespace and
//! changes a mount there (Ubuntu 24.04's AppArmor restriction lets `unshare` succeed and refuses
//! the mount — the only reliable test).

use std::path::Path;

use serde::Serialize;
use serde_json::json;

use super::scope;
use super::system::{self, Ids};

/// Ubuntu's switch for AppArmor's restriction of unprivileged user namespaces.
pub const APPARMOR_USERNS: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
/// The first Landlock ABI with scopes (kernel 6.12).
pub const SCOPE_ABI: i64 = 6;

/// What the probe found.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Probe {
    pub format: u32,
    pub kernel: String,
    pub userns: bool,
    /// Why the sandbox can not start here ("" when it can).
    pub why: String,
    pub apparmor_userns_restricted: Option<bool>,
    pub landlock_abi: i64,
    /// What keeps an agent's signals inside: `landlock-scope`, `pid-namespace` or `none`.
    pub signals: String,
    /// `landlock-scope` or `reachable`.
    pub abstract_sockets: String,
    pub seccomp: bool,
    /// Whether agents get their own cgroup scope (`systemd-run --user`).
    pub scope: bool,
    /// Whether the root helper's per-agent network rules are there.
    pub helper_rules: bool,
}

fn apparmor_restricted() -> Option<bool> {
    std::fs::read_to_string(APPARMOR_USERNS).ok().map(|text| text.trim() == "1")
}

/// How the namespace test ended (the child's exit code).
const USERNS_OK: i32 = 0;
const USERNS_REFUSED: i32 = 1;
const USERNS_MOUNT_REFUSED: i32 = 3;

/// Enters a user + mount namespace in a child and changes a mount there; the child's exit code.
fn try_namespaces() -> i32 {
    let ids = Ids::current();
    // SAFETY: the child only makes the calls below and exits; the probe is single-threaded.
    match unsafe { libc::fork() } {
        0 => {
            let code = match system::enter_namespaces(ids, libc::CLONE_NEWNS) {
                Err(_) => USERNS_REFUSED,
                Ok(()) => if system::make_root_slave().is_ok() { USERNS_OK } else { USERNS_MOUNT_REFUSED },
            };
            unsafe { libc::_exit(code) }
        }
        child if child > 0 => {
            let mut status = 0;
            unsafe { libc::waitpid(child, &mut status, 0) };
            if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { USERNS_REFUSED }
        }
        _ => USERNS_REFUSED,
    }
}

/// Why the namespace test failed, for a person.
pub fn reason(code: i32, apparmor: Option<bool>) -> String {
    match (code, apparmor) {
        (USERNS_OK, _) => String::new(),
        (USERNS_MOUNT_REFUSED, Some(true)) | (USERNS_REFUSED, Some(true)) =>
            "Ubuntu's AppArmor restricts user namespaces here and Blackbox's AppArmor rule for its sandbox is not installed \
             (it comes with the system protection helper)".into(),
        (USERNS_MOUNT_REFUSED, _) => "this machine refuses mounts inside an unprivileged user namespace".into(),
        _ => "this machine does not allow unprivileged user namespaces (a hardened kernel or a container)".into(),
    }
}

/// Runs every check (see the module doc).
pub fn probe() -> Probe {
    let apparmor = apparmor_restricted();
    let code = try_namespaces();
    let abi = system::landlock_abi();
    let scoped = abi >= SCOPE_ABI;
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from);
    let user_manager = runtime.is_some_and(|dir| dir.join("systemd/private").exists() || dir.join("bus").exists());
    Probe {
        format: 1,
        kernel: system::kernel_release(),
        userns: code == USERNS_OK,
        why: reason(code, apparmor),
        apparmor_userns_restricted: apparmor,
        landlock_abi: abi,
        signals: if scoped { "landlock-scope" } else { "pid-namespace" }.into(),
        abstract_sockets: if scoped { "landlock-scope" } else { "reachable" }.into(),
        seccomp: system::seccomp_available(),
        scope: user_manager && scope::SYSTEMD_RUN.iter().any(|path| Path::new(path).exists()),
        helper_rules: Path::new(scope::READY_FOLDER).is_dir(),
    }
}

/// Prints the probe as JSON; exit code 0.
pub fn print() -> i32 {
    println!("{}", serde_json::to_string(&probe()).unwrap_or_else(|_| json!({"format": 1, "userns": false}).to_string()));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_has_a_reason_a_person_can_act_on() {
        assert_eq!(reason(USERNS_OK, Some(true)), "");
        assert!(reason(USERNS_MOUNT_REFUSED, Some(true)).contains("AppArmor"));
        assert!(reason(USERNS_REFUSED, Some(false)).contains("does not allow"));
        assert!(reason(USERNS_MOUNT_REFUSED, None).contains("refuses mounts"));
    }
}
