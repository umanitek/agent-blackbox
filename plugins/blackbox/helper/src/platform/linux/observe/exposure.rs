//! Exposure on Linux: the listeners themselves are every OS's
//! ([`crate::platform::system_watch::exposure`]); this names a process's program
//! (`/proc/<pid>/exe`).

use std::path::Path;

pub use crate::platform::system_watch::exposure::{listeners, reachable, Exposure, Listener};

use crate::platform::linux::procfs;

/// The executable of process *pid* ("" when it cannot be read).
pub fn program_of(pid: u32) -> String {
    procfs::exe(Path::new(procfs::PROC), pid)
}
