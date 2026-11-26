//! The supervisor: a process that starts one child and stays until it ends, so the person's
//! terminal (or the agent host) sees the child's exit code and can stop it.
//!
//! Signals: the ones a terminal sends to its whole foreground process group (Ctrl-C's `SIGINT`,
//! `SIGQUIT`) already reach the child, so the supervisor only waits through them — forwarding them
//! would deliver each twice (two Ctrl-Cs make some agents quit). The ones sent to the supervisor
//! alone (`SIGTERM`, `SIGHUP`, `SIGUSR1`, `SIGUSR2`) are passed on. The child's exit code is the
//! supervisor's; a child killed by a signal answers `128 + signal`, as a shell does.
//!
//! Signals are blocked BEFORE the fork (none is lost between fork and wait) and unblocked in the
//! child before it execs.

use std::ffi::CString;

/// The signals the supervisor waits on.
const HANDLED: [libc::c_int; 7] = [libc::SIGCHLD, libc::SIGTERM, libc::SIGHUP, libc::SIGUSR1, libc::SIGUSR2, libc::SIGINT, libc::SIGQUIT];
/// The ones it passes on to the child.
const FORWARDED: [libc::c_int; 4] = [libc::SIGTERM, libc::SIGHUP, libc::SIGUSR1, libc::SIGUSR2];

/// The signal mask in force before [`block`].
pub struct Blocked(libc::sigset_t);

fn handled_set() -> libc::sigset_t {
    // SAFETY: sigemptyset / sigaddset fill the zeroed set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for signal in HANDLED {
            libc::sigaddset(&mut set, signal);
        }
        set
    }
}

/// Blocks the handled signals; answers the mask to put back.
pub fn block() -> Blocked {
    let set = handled_set();
    // SAFETY: sigprocmask with valid sets.
    unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old);
        Blocked(old)
    }
}

/// Puts the mask back (in a child before exec, or when no child was started).
pub fn unblock(blocked: &Blocked) {
    // SAFETY: restores a mask sigprocmask answered.
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, &blocked.0, std::ptr::null_mut()) };
}

/// A wait status as an exit code (`128 + signal` for a killed child).
pub fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Waits for *child* (signals blocked by [`block`]), passing on the forwarded signals; answers its
/// exit code. With *reap_all* (process 1 of a PID namespace) every other ended process is reaped too.
pub fn supervise(child: libc::pid_t, reap_all: bool) -> i32 {
    let set = handled_set();
    loop {
        // SAFETY: sigwaitinfo fills the zeroed info for a signal in the blocked set.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let signal = unsafe { libc::sigwaitinfo(&set, &mut info) };
        if signal == libc::SIGCHLD || signal < 0 {
            loop {
                let mut status = 0;
                let target = if reap_all { -1 } else { child };
                // SAFETY: waitpid with a valid status pointer.
                let ended = unsafe { libc::waitpid(target, &mut status, libc::WNOHANG) };
                if ended == child {
                    return exit_code(status);
                }
                if ended <= 0 {
                    break;
                }
            }
        } else if FORWARDED.contains(&signal) {
            // SAFETY: kill with a pid this process started.
            unsafe { libc::kill(child, signal) };
        }
    }
}

/// A NUL-terminated argv, made BEFORE a fork (the child then only calls `execv`).
pub struct Argv {
    _owned: Vec<CString>,
    pointers: Vec<*const libc::c_char>,
}

impl Argv {
    pub fn new(words: &[CString]) -> Argv {
        let owned = words.to_vec();
        let mut pointers: Vec<*const libc::c_char> = owned.iter().map(|word| word.as_ptr()).collect();
        pointers.push(std::ptr::null());
        Argv { _owned: owned, pointers }
    }

    /// `execv` of argv[0] with this argv; only returns when it failed.
    pub fn exec(&self) {
        // SAFETY: pointers are NUL-terminated strings owned by self, the list ends with null.
        unsafe { libc::execv(self.pointers[0], self.pointers.as_ptr()) };
    }
}
