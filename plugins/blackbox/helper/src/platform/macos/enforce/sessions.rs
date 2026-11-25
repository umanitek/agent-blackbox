//! Ending a remote session — only the one the user chose, and only after checking it is still
//! that session.
//!
//! The plan carries end requests (`remote.end`: session id, serving pid, its start), each put
//! there by the plugin when the user confirmed "End session" for a session the watch reported.
//! The helper ends a session only when ALL hold ([`verify`]): the watch still sees a live
//! session with that id; it is served by that very pid; that pid's process is the same one (same
//! start time, so a reused pid is never hit); the session is a kind that has its own process
//! (SSH, Screen Sharing, Remote Management — never Tailscale SSH or file sharing, whose server
//! serves everyone); and the process is one of the known serving programs. Then SIGTERM, and
//! SIGKILL if it is still there after [`GRACE`].
//!
//! Undo: none needed — ending a connection changes nothing that persists; the person can log in
//! again (unless "Lock remote access" or a block says otherwise).

use std::time::{Duration, Instant};

use crate::platform::macos::observe::remote::{Session, SERVING_PROGRAMS};
use crate::platform::EndRequest;

/// How long a session's process has to end after SIGTERM.
pub const GRACE: Duration = Duration::from_secs(2);
/// Kinds of session that have a process of their own to end.
const ENDABLE: [&str; 3] = ["ssh", "screen-sharing", "remote-desktop"];

/// Why a request was refused, or Ok when the process may be ended. *live*: the watch's session
/// with that id; *process*: (name, start) of the pid now.
pub fn verify(request: &EndRequest, live: Option<&Session>, process: Option<(&str, u64)>) -> Result<(), String> {
    let session = live.ok_or("that session has already ended")?;
    if session.pid != request.pid || session.started != request.started || request.pid <= 1 {
        return Err("that is not the session the watch reports".into());
    }
    if !ENDABLE.contains(&session.how) {
        return Err(format!("a {} session has no process of its own to end", session.how));
    }
    let (name, start) = process.ok_or("the session's process has already ended")?;
    if start != session.proc_start || !SERVING_PROGRAMS.contains(&name) {
        return Err("the process is no longer the session's".into());
    }
    Ok(())
}

/// Ends the verified process: SIGTERM, then SIGKILL after [`GRACE`] if it is still there.
pub fn end(pid: u32) -> Result<(), String> {
    let pid = pid as libc::pid_t;
    // SAFETY: plain syscalls on a pid the caller verified with `verify`.
    unsafe {
        if libc::kill(pid, libc::SIGTERM) != 0 {
            return Err(format!("could not end process {pid}"));
        }
        let deadline = Instant::now() + GRACE;
        while Instant::now() < deadline {
            if libc::kill(pid, 0) != 0 {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        libc::kill(pid, libc::SIGKILL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(how: &'static str) -> Session {
        Session {
            id: "ssh-800-192.168.64.1-52344".into(), how, method: "publickey", fingerprint: String::new(), user: "admin".into(),
            remote_ip: "192.168.64.1".parse().unwrap(), remote_port: 52344, local_port: 22, pid: 800, proc_start: 1800,
            started: 101, processes: vec![],
        }
    }

    fn request() -> EndRequest {
        EndRequest { session_id: "ssh-800-192.168.64.1-52344".into(), pid: 800, started: 101 }
    }

    #[test]
    fn only_the_very_session_the_watch_reports_may_be_ended() {
        let live = session("ssh");
        assert!(verify(&request(), Some(&live), Some(("sshd-session", 1800))).is_ok());
        assert!(verify(&request(), None, Some(("sshd-session", 1800))).is_err(), "gone");
        assert!(verify(&EndRequest { pid: 801, ..request() }, Some(&live), Some(("sshd-session", 1800))).is_err(), "another pid");
        assert!(verify(&EndRequest { started: 5, ..request() }, Some(&live), Some(("sshd-session", 1800))).is_err(), "another session");
        assert!(verify(&request(), Some(&live), Some(("sshd-session", 9999))).is_err(), "a reused pid");
        assert!(verify(&request(), Some(&live), Some(("Safari", 1800))).is_err(), "not a server");
        assert!(verify(&request(), Some(&session("tailscale-ssh")), Some(("tailscaled", 1800))).is_err(), "shared server");
        assert!(verify(&EndRequest { pid: 1, ..request() }, Some(&Session { pid: 1, ..live.clone() }), Some(("sshd", 1800))).is_err(), "never launchd");
    }
}
