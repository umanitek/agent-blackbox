//! The helper's own files, never readable by other accounts (security finding: state.json — which
//! names every saved DNS server and cut address — and the logs were world-readable).
//!
//! * [`ensure_dir`] makes a folder owned by whoever runs the helper (root) with mode 0700, and
//!   tightens an existing one.
//! * [`write`] writes a file atomically (a temporary sibling, then rename) with mode 0600 from the
//!   moment it exists — never written first and narrowed after.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const DIR_MODE: u32 = 0o700;
pub const FILE_MODE: u32 = 0o600;

/// Creates *dir* (and its parents) if needed and makes it 0700.
pub fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
}

/// Writes *bytes* to *path* atomically, 0600 throughout.
pub fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    let _ = fs::remove_file(&temporary);   // a leftover (or a planted link) is never written through
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(FILE_MODE).open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_folder_is_0700_and_files_are_0600_even_over_a_world_readable_one() {
        let dir = std::env::temp_dir().join(format!("bb-private-{}", std::process::id())).join("netd");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_dir(&dir).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, DIR_MODE);
        let state = dir.join("state.json");
        fs::write(&state, "old").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
        write(&state, b"{}").unwrap();
        assert_eq!(fs::metadata(&state).unwrap().permissions().mode() & 0o777, FILE_MODE);
        assert_eq!(fs::read(&state).unwrap(), b"{}");
        let _ = fs::remove_dir_all(dir.parent().unwrap());
    }
}
