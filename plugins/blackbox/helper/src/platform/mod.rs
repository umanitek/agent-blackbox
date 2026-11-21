//! The operating-system seam: every part of the helper that changes or reads the system lives
//! under this folder, one folder per operating system (per-OS structure, Amos 2026-11-21).
//! `macos/` holds today's implementation; only the build for that OS compiles it.

#[cfg(target_os = "macos")]
pub mod macos;
