//! The agent sandbox launcher (`blackbox-sandbox`) on a REAL Linux kernel: each test starts a
//! program inside it and checks what the kernel refused. Linux only; on a machine without
//! unprivileged user namespaces each test says so and passes — except where
//! `BLACKBOX_REQUIRE_NETNS=1` (the CI helper lane, which lifts Ubuntu's AppArmor restriction):
//! there they must run.
//!
//! The probes that need a system call no shell tool makes (TIOCSTI, keyctl, umount, a nested
//! namespace, a unix socket) run THIS test binary again inside the sandbox: [`child_probe`] does
//! the one call named in `BB_SANDBOX_CHILD` and prints `RESULT:<errno>` (0 = it worked).
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SANDBOX: &str = env!("CARGO_BIN_EXE_blackbox-sandbox");
const HEADER: &str = "# blackbox-sandbox policy 1\n# Blackbox agent sandbox — generated, do not edit. sha256:0123456789abcdef\n";

fn namespaces_work() -> bool {
    let out = Command::new(SANDBOX).arg("probe").output().expect("probe runs");
    let probe: serde_json::Value = serde_json::from_slice(&out.stdout).expect("probe prints JSON");
    if probe["userns"] == true {
        return true;
    }
    assert!(std::env::var("BLACKBOX_REQUIRE_NETNS").as_deref() != Ok("1"), "namespaces must work here: {probe}");
    eprintln!("skipped: no unprivileged user namespaces here ({})", probe["why"]);
    false
}

/// A fresh folder for one test, with `layout` (paths ending in `/` are folders, others files).
fn scratch(name: &str, layout: &[&str]) -> PathBuf {
    let root = std::env::temp_dir().join(format!("bb-sandbox-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let root = fs::canonicalize(&root).unwrap();
    for entry in layout {
        let path = root.join(entry.trim_end_matches('/'));
        if entry.ends_with('/') {
            fs::create_dir_all(&path).unwrap();
        } else {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, "secret").unwrap();
        }
    }
    root
}

fn policy(root: &Path, body: &str) -> PathBuf {
    let path = root.join("agent.policy");
    fs::write(&path, format!("{HEADER}{}", body.replace("{root}", root.to_str().unwrap()))).unwrap();
    path
}

fn sh(policy: &Path, script: &str) -> Output {
    Command::new(SANDBOX).arg("run").arg("--policy").arg(policy).arg("--").args(["/bin/sh", "-c", script]).output().unwrap()
}

fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// Runs this test binary inside the sandbox doing *action* with *argument*; the errno it got.
fn child(policy: &Path, action: &str, argument: &str) -> i32 {
    let me = std::env::current_exe().unwrap();
    let out = Command::new(SANDBOX).arg("run").arg("--policy").arg(policy).arg("--").arg(me)
        .args(["--exact", "child_probe", "--nocapture", "--test-threads=1"])
        .env("BB_SANDBOX_CHILD", action).env("BB_SANDBOX_ARG", argument).output().unwrap();
    let all = text(&out);
    let found = all.lines().find_map(|line| line.trim().strip_prefix("RESULT:")).unwrap_or_else(|| panic!("no result: {all}"));
    found.trim().parse().unwrap()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn c(text: &str) -> std::ffi::CString {
    std::ffi::CString::new(text).unwrap()
}

/// The inside half of [`child`]: does nothing unless `BB_SANDBOX_CHILD` names an action.
#[test]
fn child_probe() {
    let Ok(action) = std::env::var("BB_SANDBOX_CHILD") else { return };
    let argument = std::env::var("BB_SANDBOX_ARG").unwrap_or_default();
    // SAFETY: each arm makes one system call with valid arguments.
    let result = unsafe {
        let ok = |done: bool| if done { 0 } else { errno() };
        match action.as_str() {
            "tiocsti" => {
                let byte = b'x';
                ok(libc::ioctl(0, libc::TIOCSTI, &byte) == 0)
            }
            "keyctl" => ok(libc::syscall(libc::SYS_keyctl, 0, -3i64, 0) >= 0),
            "umount" => ok(libc::umount2(c(&argument).as_ptr(), libc::MNT_DETACH) == 0),
            "nested-umount" => {
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
                    errno()
                } else {
                    let _ = fs::write("/proc/self/setgroups", "deny");
                    let uid = libc::getuid();
                    let _ = fs::write("/proc/self/uid_map", format!("0 {uid} 1"));
                    let umounted = libc::umount2(c(&argument).as_ptr(), libc::MNT_DETACH) == 0;
                    let readable = fs::read(&argument).is_ok() || fs::read_dir(&argument).is_ok();
                    if umounted && readable { 0 } else { libc::EPERM }
                }
            }
            "nested-userns" => ok(libc::unshare(libc::CLONE_NEWUSER) == 0),
            "kill" => ok(libc::kill(argument.parse().unwrap(), libc::SIGTERM) == 0),
            "unix-socket" => {
                let path = Path::new(&argument).join("rpc.sock");
                let listener = std::os::unix::net::UnixListener::bind(&path);
                let connected = listener.is_ok() && std::os::unix::net::UnixStream::connect(&path).is_ok();
                if connected { 0 } else { libc::EACCES }
            }
            other => panic!("unknown action {other}"),
        }
    };
    println!("RESULT:{result}");
    std::process::exit(0);
}

#[test]
fn a_hidden_folder_and_file_can_not_be_read_linked_or_moved_and_a_neighbour_can() {
    if !namespaces_work() {
        return;
    }
    let root = scratch("hide", &["Docs/Taxes/2025.pdf", "Docs/notes.txt", "keys/id"]);
    let policy = policy(&root, "hide-dir {root}/Docs/Taxes\nhide-file {root}/keys/id\npin {root}/Docs\n");
    let out = sh(&policy, &format!("cd '{0}'; cat Docs/Taxes/2025.pdf; echo A=$?; cat keys/id; echo B=$?; cat Docs/notes.txt; echo C=$?; \
                                    ln -s Docs/Taxes/2025.pdf l; cat l; echo D=$?; ln keys/id h; echo E=$?; mv keys/id moved; echo F=$?; \
                                    mv Docs D2; echo G=$?; ls Docs/Taxes; echo H=$?", root.display()));
    let all = text(&out);
    for refused in ["A=1", "B=1", "D=1", "E=1", "F=1", "G=1", "H=2"] {
        assert!(all.contains(refused) || all.contains(&refused.replace("=1", "=2")), "{refused} in {all}");
    }
    assert!(all.contains("C=0") && all.contains("secret"), "the neighbour stays readable: {all}");
    assert!(root.join("keys/id").exists() && root.join("Docs/Taxes/2025.pdf").exists());
}

#[test]
fn a_read_only_place_is_readable_and_never_changed() {
    if !namespaces_work() {
        return;
    }
    let root = scratch("ro", &["own/settings.yaml", "rc"]);
    let policy = policy(&root, "ro {root}/own\nro-file {root}/rc\n");
    let out = sh(&policy, &format!("cd '{0}'; cat own/settings.yaml >/dev/null; echo A=$?; echo x > own/new; echo B=$?; \
                                    echo x >> rc; echo C=$?; rm own/settings.yaml; echo D=$?; mv rc rc2; echo E=$?", root.display()));
    let all = text(&out);
    assert!(all.contains("A=0"), "{all}");
    for refused in ["B=", "C=", "D=", "E="] {
        assert!(!all.contains(&format!("{refused}0")), "{refused} must fail: {all}");
    }
    assert!(all.contains("Read-only file system"), "the refusal names EROFS: {all}");
    assert_eq!(fs::read_to_string(root.join("rc")).unwrap(), "secret");
}

#[test]
fn the_canary_is_unreadable_and_the_exit_code_passes_through() {
    if !namespaces_work() {
        return;
    }
    let root = scratch("canary", &["canary"]);
    let policy = policy(&root, "canary {root}/canary\n");
    let out = sh(&policy, &format!("cat '{}/canary' >/dev/null 2>&1 || exit 7", root.display()));
    assert_eq!(out.status.code(), Some(7), "{}", text(&out));
}

#[test]
fn no_new_privileges_and_the_seccomp_filter_hold_inside() {
    if !namespaces_work() {
        return;
    }
    let root = scratch("nnp", &[]);
    let policy = policy(&root, "");
    let out = sh(&policy, "grep -E '^(NoNewPrivs|Seccomp):' /proc/self/status");
    let all = text(&out);
    assert!(all.contains("NoNewPrivs:\t1") && all.contains("Seccomp:\t2"), "{all}");
    assert_eq!(child(&policy, "tiocsti", ""), libc::EPERM, "typing into the terminal is refused");
    assert_eq!(child(&policy, "keyctl", ""), libc::EPERM, "the kernel keyrings are refused");
}

#[test]
fn a_mask_can_not_be_unmounted_even_from_a_nested_namespace_and_nested_sandboxes_still_start() {
    if !namespaces_work() {
        return;
    }
    let root = scratch("lock", &["Taxes/x"]);
    let policy = policy(&root, "hide-dir {root}/Taxes\n");
    let hidden = root.join("Taxes");
    assert_ne!(child(&policy, "umount", hidden.to_str().unwrap()), 0, "no capability to unmount");
    assert_ne!(child(&policy, "nested-umount", hidden.to_str().unwrap()), 0, "the mask is locked");
    assert_eq!(child(&policy, "nested-userns", ""), 0, "a nested sandbox (bubblewrap, Electron) can still start");
    assert_eq!(child(&policy, "unix-socket", root.to_str().unwrap()), 0, "path unix sockets (Hermes' RPC) work");
}

#[test]
fn a_signal_to_a_process_outside_is_refused_with_landlock_scopes() {
    if !namespaces_work() {
        return;
    }
    let out = Command::new(SANDBOX).arg("probe").output().unwrap();
    let probe: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    if probe["signals"] == "none" {
        eprintln!("skipped: Landlock ABI {} has no signal scope (kernel below 6.12)", probe["landlock_abi"]);
        return;
    }
    let root = scratch("signal", &[]);
    let policy = policy(&root, "");
    let mut outside = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    assert_eq!(child(&policy, "kill", &outside.id().to_string()), libc::EPERM);
    assert!(outside.try_wait().unwrap().is_none(), "the outside process still runs");
    let _ = outside.kill();
}

#[test]
fn an_unreadable_policy_starts_the_program_with_the_hooks_only_line() {
    let root = scratch("failopen", &[]);
    let path = root.join("broken.policy");
    fs::write(&path, "not a policy\n").unwrap();
    let out = sh(&path, "echo ran");
    let all = text(&out);
    assert!(all.contains("ran"), "{all}");
    assert!(all.contains("blackbox: no sandbox profile — sh runs with Blackbox's hooks only"), "{all}");
}
