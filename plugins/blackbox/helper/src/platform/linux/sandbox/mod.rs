//! `blackbox-sandbox`: the agent sandbox on Linux (design "Linux deep layers" §1). The launchers
//! the plugin puts first on PATH run `blackbox-sandbox run --policy <file> -- <agent> <args>`;
//! the agent then runs for life inside:
//!
//! 1. its own cgroup scope (`systemd-run --user --scope`, [`scope`]) — the handle the root
//!    helper's per-agent network rules match (local ports, ssh back into this machine, Docker's TCP);
//! 2. a private user + mount namespace where the policy is MOUNTS ([`plan`]): each protected item
//!    under an empty mode-0000 mask (`EACCES`), Blackbox's own places and the startup places bound
//!    read-only (`EROFS`), the folders above a protected item pinned (rename / remove: `EBUSY`),
//!    the session bus, Docker's sockets and — when refused — the display and the camera and
//!    microphone hidden. Root's mounts are slaves of the person's: theirs still appear, ours never leak;
//! 3. a second, nested user + mount namespace, which LOCKS every mount above (the kernel refuses to
//!    unmount or remount a mount inherited from a more privileged namespace) — so nested sandboxes
//!    (Claude Code's own bubblewrap, Flatpak, an Electron app) still work and none can lift ours;
//! 4. `PR_SET_NO_NEW_PRIVS` (no setuid: `sudo`, `su`, `pkexec` fail) and a seccomp filter
//!    ([`filter`]: terminal injection, the kernel keyrings, bpf, perf, userfaultfd);
//! 5. on Landlock ABI 6+ (kernel 6.12), Landlock's scopes: no signal to, no ptrace of and no
//!    abstract unix socket of any process outside (Blackbox's dashboard and helper among them);
//!    below 6.12, a PID namespace with a fresh `/proc` instead (no process outside is visible).
//!    The hooks then see namespace pids: the launcher exports [`SANDBOX_ID`] (the scope's name)
//!    and the plugin's Linux observer maps (id, pid) back to the host pid.
//!
//! Why not Landlock for the files: Landlock only ALLOWS paths, and a right on a folder covers
//! everything below it — refusing `~/Documents/Taxes` while `~` stays usable would forbid creating
//! and renaming in `~` (Claude Code's atomic rename of `~/.claude.json`). Mounts express "everything
//! but these", the policy Seatbelt has on macOS.
//!
//! Fail-open: a policy it can not read, or a namespace the machine refuses, starts the agent with
//! Blackbox's hooks only and one line on stderr — an agent always starts. The supervisor
//! ([`supervisor`]) passes the agent's exit code and the signals sent to it.
//!
//! `blackbox-sandbox probe` prints what this machine allows ([`probe`]). On Ubuntu 23.10+ the
//! helper's install adds the AppArmor rule that lets the launcher make its namespaces ([`apparmor`]).
//!
//! Pattern: **Template Method** — [`run`] is the fixed order of steps; each step is a function of
//! [`system`] (the kernel calls) fed by the pure planners.

pub mod apparmor;
pub mod filter;
pub mod plan;
pub mod policy;
pub mod probe;
pub mod scope;
mod supervisor;
mod system;

use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;

use policy::Policy;
use system::{Ids, Masks, SystemDisk};

/// What the launcher exports for the session's records: the scope (or launch) id.
pub const SANDBOX_ID: &str = "BLACKBOX_SANDBOX_ID";
const USAGE: &str = "usage: blackbox-sandbox probe | run [--in-scope --ready-fd N --unit NAME] --policy FILE -- PROGRAM [ARGS…]";

/// One `run` command line.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Run {
    pub policy: String,
    pub in_scope: bool,
    pub ready_fd: Option<i32>,
    pub unit: String,
    pub program: Vec<OsString>,
}

/// Reads `run`'s words (after `run`); None when they are not a valid command line.
pub fn parse_run(words: &[OsString]) -> Option<Run> {
    let mut run = Run::default();
    let mut index = 0;
    while index < words.len() {
        let word = words[index].to_str()?;
        let value = |at: usize| words.get(at).and_then(|w| w.to_str()).map(String::from);
        match word {
            "--" => {
                run.program = words[index + 1..].to_vec();
                break;
            }
            "--in-scope" => run.in_scope = true,
            "--policy" => { run.policy = value(index + 1)?; index += 1; }
            "--unit" => { run.unit = value(index + 1)?; index += 1; }
            "--ready-fd" => { run.ready_fd = Some(value(index + 1)?.parse().ok()?); index += 1; }
            _ => return None,
        }
        index += 1;
    }
    (!run.program.is_empty() && !run.policy.is_empty()).then_some(run)
}

/// The entry of the `blackbox-sandbox` program: its exit code (only reached when nothing was exec'd).
pub fn main(args: Vec<OsString>) -> i32 {
    match args.first().and_then(|word| word.to_str()) {
        Some("probe") => probe::print(),
        Some("run") => match parse_run(&args[1..]) {
            Some(command) => run(command),
            None => {
                eprintln!("{USAGE}");
                2
            }
        },
        _ => {
            eprintln!("{USAGE}");
            2
        }
    }
}

/// The standard fail-open line, then the program itself with Blackbox's hooks only.
fn fail_open(program: &[OsString], why: &str) -> i32 {
    let name = system::program_name(&program[0]);
    if why.is_empty() {
        eprintln!("blackbox: no sandbox profile — {name} runs with Blackbox's hooks only");
    } else {
        eprintln!("blackbox: no sandbox ({why}) — {name} runs with Blackbox's hooks only");
    }
    exec(program)
}

fn exec(program: &[OsString]) -> i32 {
    use std::os::unix::process::CommandExt;
    let error = std::process::Command::new(&program[0]).args(&program[1..]).exec();
    eprintln!("blackbox: could not start {}: {error}", system::program_name(&program[0]));
    127
}

fn read_policy(path: &str) -> Result<Policy, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    policy::parse(&bytes)
}

/// The fixed order of steps (see the module doc).
fn run(command: Run) -> i32 {
    let policy = match read_policy(&command.policy) {
        Ok(policy) => policy,
        Err(_) => return fail_open(&command.program, ""),
    };
    let unit = if command.in_scope {
        if let Some(fd) = command.ready_fd {
            // SAFETY: one byte to the supervisor's pipe, then closed (it reads "the scope took us").
            unsafe {
                libc::write(fd, b"1".as_ptr().cast(), 1);
                libc::close(fd);
            }
        }
        let helper = std::path::Path::new(scope::HELPER).exists();
        let ready = scope::wait_ready(std::path::Path::new(scope::READY_FOLDER), &command.unit, helper, scope::READY_WAIT);
        if ready == scope::Ready::NotBound {
            eprintln!("{}", scope::NOT_BOUND_LINE);
        }
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            scope::record(std::path::Path::new(&runtime), &command.unit, ready);
        }
        command.unit.clone()
    } else {
        let unit = scope::unit_name(&policy.digest, &system::random_id());
        if let Some(code) = start_in_scope(&command, &unit) {
            return code;
        }
        format!("noscope-{}", system::random_id())
    };
    std::env::set_var(SANDBOX_ID, &unit);
    match enter(&policy) {
        Ok(Entered::Exec) => exec(&command.program),
        Ok(Entered::Ended(code)) => code,
        Err(why) => fail_open(&command.program, &why),
    }
}

/// What [`enter`] leaves the caller to do.
enum Entered {
    /// Exec the program in this process (everything is in place).
    Exec,
    /// A supervisor here saw the program end with this code (the PID-namespace path).
    Ended(i32),
}

/// Starts this launcher again inside a new cgroup scope and supervises it; None when no scope
/// could be made (no systemd-run, no user manager): the caller then goes on without one.
fn start_in_scope(command: &Run, unit: &str) -> Option<i32> {
    let systemd_run = scope::SYSTEMD_RUN.iter().find(|path| std::path::Path::new(path).exists())?;
    let me = std::env::current_exe().ok()?;
    let mut fds = [0; 2];
    // SAFETY: pipe2 fills two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return None;
    }
    let (read_end, write_end) = (fds[0], fds[1]);
    let inner: Vec<String> = vec![me.to_string_lossy().into_owned(), "run".into(), "--in-scope".into(), "--ready-fd".into(),
                                  write_end.to_string(), "--unit".into(), unit.into(), "--policy".into(), command.policy.clone(), "--".into()];
    let argv_text = scope::systemd_run_argv(systemd_run, unit, &inner);
    let mut words: Vec<CString> = argv_text.iter().filter_map(|word| CString::new(word.as_bytes()).ok()).collect();
    words.extend(command.program.iter().filter_map(|word| CString::new(word.clone().into_vec()).ok()));
    if words.len() != argv_text.len() + command.program.len() {
        return None;
    }
    let argv = supervisor::Argv::new(&words);
    let blocked = supervisor::block();
    // SAFETY: the child only clears close-on-exec, restores the mask and execs (single-threaded).
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(read_end);
            libc::fcntl(write_end, libc::F_SETFD, 0);
        }
        supervisor::unblock(&blocked);
        argv.exec();
        unsafe { libc::_exit(127) };
    }
    unsafe { libc::close(write_end) };
    if child < 0 {
        unsafe { libc::close(read_end) };
        supervisor::unblock(&blocked);
        return None;
    }
    let mut byte = [0u8; 1];
    // SAFETY: a one-byte read into a local buffer.
    let taken = unsafe { libc::read(read_end, byte.as_mut_ptr().cast(), 1) } == 1;
    unsafe { libc::close(read_end) };
    if taken {
        return Some(supervisor::supervise(child, false));
    }
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    supervisor::unblock(&blocked);
    None
}

/// Steps 2–5 of the module doc. Only a namespace the machine refuses fails it (the agent then
/// starts with the hooks only); a place that could not be closed is said on stderr and the rest
/// still holds — a partial sandbox is always more than none.
///
/// Kernels below 6.12 have no Landlock signal scope, so the agent gets its own PID namespace
/// instead, with a fresh `/proc`: no process outside is visible, so none can be signalled, traced
/// or read through `/proc/<pid>` (Debian's and Fedora's `ptrace_scope=0` would otherwise let an
/// agent attach to the person's shell). Process 1 of that namespace is a small init (this
/// launcher, [`supervisor::supervise`] reaping every orphan) — a program run as process 1 would
/// ignore Ctrl-C.
fn enter(policy: &Policy) -> Result<Entered, String> {
    let ids = Ids::current();
    let mounts = plan::build(policy, &SystemDisk);
    let abi = system::landlock_abi();
    let pid_namespace = abi < probe::SCOPE_ABI;
    system::enter_namespaces(ids, libc::CLONE_NEWNS | if pid_namespace { libc::CLONE_NEWPID } else { 0 })?;
    system::make_root_slave()?;
    close_places(&mounts)?;
    if !pid_namespace {
        lock_and_restrict(ids, abi)?;
        return Ok(Entered::Exec);
    }
    let blocked = supervisor::block();
    // SAFETY: single-threaded; each side only makes the calls below.
    let init = unsafe { libc::fork() };
    if init < 0 {
        supervisor::unblock(&blocked);
        return Err("fork (PID namespace)".into());
    }
    if init > 0 {
        return Ok(Entered::Ended(supervisor::supervise(init, false)));
    }
    // Process 1 of the new PID namespace.
    if let Err(why) = system::mount_fresh_proc() {
        eprintln!("blackbox: a fresh /proc could not be mounted ({why}); other programs stay visible to the agent");
    }
    if let Err(why) = lock_and_restrict(ids, abi) {
        eprintln!("blackbox: the sandbox could not be locked ({why})");
        unsafe { libc::_exit(126) };
    }
    // SAFETY: as above.
    let program = unsafe { libc::fork() };
    if program == 0 {
        supervisor::unblock(&blocked);
        return Ok(Entered::Exec);
    }
    let code = if program > 0 { supervisor::supervise(program, true) } else { 126 };
    unsafe { libc::_exit(code) }
}

/// Step 2's mounts (see [`enter`]).
fn close_places(mounts: &[plan::Mount]) -> Result<(), String> {
    let masks = Masks::create()?;
    let mut failed: Vec<String> = Vec::new();
    for mount in mounts {
        let done = match mount.action {
            policy::Action::Hide => masks.cover(&mount.path, mount.kind),
            policy::Action::ReadOnly => system::bind_self(&mount.path).and_then(|()| system::remount_read_only(&mount.path)),
            policy::Action::Pin => system::bind_self(&mount.path),
        };
        // A place that vanished between the plan and its mount needs nothing.
        if let Err(why) = done {
            if std::path::Path::new(&mount.path).exists() {
                failed.push(why);
            }
        }
    }
    masks.finish();
    if let Some(first) = failed.first() {
        eprintln!("blackbox: {} sandbox place(s) could not be closed ({first}); the rest of the sandbox holds", failed.len());
    }
    Ok(())
}

/// Steps 3–5: the nested namespace that locks the mounts, no new privileges, Landlock's scopes
/// (ABI 6+), the seccomp filter, no capabilities.
fn lock_and_restrict(ids: Ids, abi: i64) -> Result<(), String> {
    system::enter_namespaces(ids, libc::CLONE_NEWNS)?;
    system::no_new_privileges()?;
    if abi >= probe::SCOPE_ABI {
        system::landlock_scope(abi)?;
    }
    if system::seccomp_available() {
        system::install_filter(&filter::program())?;
    }
    system::drop_capabilities()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &[&str]) -> Vec<OsString> {
        text.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_run_command_line_reads_its_options_and_keeps_the_program_as_given() {
        let run = parse_run(&words(&["--in-scope", "--ready-fd", "5", "--unit", "u.scope", "--policy", "/p", "--", "claude", "--", "-x"])).unwrap();
        assert_eq!(run, Run { policy: "/p".into(), in_scope: true, ready_fd: Some(5), unit: "u.scope".into(),
                              program: words(&["claude", "--", "-x"]) });
    }

    #[test]
    fn a_broken_command_line_is_refused() {
        for bad in [&["--policy", "/p"][..], &["--policy"], &["--", "claude"], &["--bogus", "--policy", "/p", "--", "x"],
                    &["--ready-fd", "x", "--policy", "/p", "--", "x"]] {
            assert_eq!(parse_run(&words(bad)), None, "{bad:?}");
        }
    }
}
