//! Reading a file as root without being tricked (security finding: root followed symlinks and
//! opened FIFOs in user-writable folders such as ~/Library/LaunchAgents).
//!
//! [`read_regular`] opens with `O_NOFOLLOW | O_NONBLOCK` (a symlink is refused, a FIFO never
//! blocks), checks the OPEN descriptor is a regular file, and reads at most *cap* bytes.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The bytes of *path* if it is a regular file (not a link, FIFO, device or folder) no larger than
/// *cap*; None otherwise.
pub fn read_regular(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let file: File = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() || meta.len() > cap {
        return None;
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(cap).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// The first *cap* bytes of a kernel attribute file at *path* (sysfs: `/sys/class/net/<name>/flags`),
/// opened as [`read_regular`] opens a file. WHY no size check: sysfs reports every attribute as one
/// page (4 KiB, 64 KiB on some ARM kernels) whatever it holds, so the size says nothing — KI-669: the
/// helper's 64-byte cap refused every interface's flags and no interface was ever up.
pub fn read_attribute(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let file: File = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    if !file.metadata().ok()?.file_type().is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(cap).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// Whether *path* itself (not what it points to) is a regular file.
pub fn is_regular(path: &Path) -> bool {
    std::fs::symlink_metadata(path).map(|m| m.file_type().is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-safe-read-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    #[test]
    fn a_symlink_a_fifo_and_a_big_file_are_refused_a_small_regular_file_is_read() {
        let dir = dir();
        let secret = dir.join("secret.plist");
        std::fs::write(&secret, b"<plist/>").unwrap();
        assert_eq!(read_regular(&secret, 1024).as_deref(), Some(&b"<plist/>"[..]));
        let link = dir.join("link.plist");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(read_regular(&link, 1024).is_none(), "a symlink is never followed");
        assert!(!is_regular(&link));
        let fifo = dir.join("fifo.plist");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid C string path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert!(read_regular(&fifo, 1024).is_none(), "a FIFO is refused");
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "and never blocks");
        std::fs::write(dir.join("big"), vec![0u8; 4096]).unwrap();
        assert!(read_regular(&dir.join("big"), 1024).is_none(), "over the cap");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_kernel_attribute_is_read_whatever_size_it_reports_and_never_past_its_cap() {
        let dir = dir();
        let flags = dir.join("flags");
        let mut page = b"0x9\n".to_vec();
        page.resize(4096, 0);   // what sysfs reports: one page
        std::fs::write(&flags, &page).unwrap();
        assert_eq!(read_attribute(&flags, 64).unwrap().len(), 64);
        assert!(read_attribute(&flags, 64).unwrap().starts_with(b"0x9\n"));
        let link = dir.join("link");
        std::os::unix::fs::symlink(&flags, &link).unwrap();
        assert!(read_attribute(&link, 64).is_none(), "a symlink is never followed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
