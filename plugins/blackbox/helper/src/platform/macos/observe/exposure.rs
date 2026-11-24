//! Exposure on macOS: the listeners themselves are every OS's ([`crate::platform::system_watch::exposure`]);
//! this names a process's program (`proc_pidpath`).

pub use crate::platform::system_watch::exposure::{listeners, reachable, Exposure, Listener};

/// The executable of process *pid* ("" when it cannot be read).
pub fn program_of(pid: u32) -> String {
    let mut buffer = vec![0u8; 4096];
    // SAFETY: proc_pidpath writes at most `buffer.len()` bytes into the buffer and answers the length.
    let length = unsafe { libc::proc_pidpath(pid as libc::c_int, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if length <= 0 {
        return String::new();
    }
    String::from_utf8_lossy(&buffer[..length as usize]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_path_is_readable() {
        assert!(!program_of(std::process::id()).is_empty());
    }
}
