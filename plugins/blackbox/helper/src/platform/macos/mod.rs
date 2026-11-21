//! macOS: the enforce side (pf, the Mac's DNS settings, posture fixes, ending a session), the
//! observe side (SSH and login files, remote sessions, exposure, persistence, tampering,
//! posture), the LaunchDaemon install, pf's status, the libproc socket reader and the system
//! watch loop.

pub mod enforce;
pub mod install;
pub mod observe;
pub mod pf_status;
pub mod sockets;
pub(crate) mod system_guard;
