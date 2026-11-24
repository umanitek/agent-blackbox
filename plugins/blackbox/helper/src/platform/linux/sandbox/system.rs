//! Every kernel call the sandbox launcher makes, each a thin wrapper answering why it failed.
//! The decisions live in `policy.rs`, `plan.rs`, `filter.rs` and `scope.rs` (pure, tested on any
//! OS); this file only carries them out, and its behaviour is proven by the Linux-only tests in
//! `tests/sandbox_linux.rs` and the VM checklist.
//!
//! Called from a single-threaded process only: `unshare(CLONE_NEWUSER)` refuses a threaded one,
//! and the launcher never starts a thread.

use std::ffi::{CString, OsStr};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::filter::Instruction;
use super::plan::{Disk, Kind};

fn c_path(path: &str) -> Result<CString, String> {
    CString::new(path).map_err(|_| format!("a path holds a NUL byte: {path:?}"))
}

fn last_error(what: &str) -> String {
    format!("{what}: {}", io::Error::last_os_error())
}

/// The disk as it is, links followed (what a mount covers).
pub struct SystemDisk;

impl Disk for SystemDisk {
    fn kind(&self, path: &str) -> Option<Kind> {
        fs::metadata(path).ok().map(|meta| if meta.is_dir() { Kind::Folder } else { Kind::Other })
    }
    fn names(&self, path: &str) -> Vec<String> {
        fs::read_dir(path).map(|entries| {
            entries.filter_map(Result::ok).filter_map(|entry| entry.file_name().to_str().map(String::from)).collect()
        }).unwrap_or_default()
    }
}

/// The person's ids, mapped to themselves inside every namespace the launcher makes (never to
/// root: a process that is not uid 0 in its namespace loses every capability when it execs).
#[derive(Debug, Clone, Copy)]
pub struct Ids {
    pub uid: u32,
    pub gid: u32,
}

impl Ids {
    pub fn current() -> Ids {
        // SAFETY: getuid / getgid have no preconditions.
        unsafe { Ids { uid: libc::getuid(), gid: libc::getgid() } }
    }
}

fn write_proc(file: &str, text: &str) -> Result<(), String> {
    fs::write(Path::new("/proc/self").join(file), text).map_err(|error| format!("writing /proc/self/{file}: {error}"))
}

/// A new user namespace (plus *extra* namespaces, e.g. a mount namespace), the person mapped to themselves.
pub fn enter_namespaces(ids: Ids, extra: libc::c_int) -> Result<(), String> {
    // SAFETY: unshare takes flags only.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | extra) } != 0 {
        return Err(last_error("unshare (user namespace)"));
    }
    write_proc("setgroups", "deny")?;
    write_proc("uid_map", &format!("{0} {0} 1\n", ids.uid))?;
    write_proc("gid_map", &format!("{0} {0} 1\n", ids.gid))
}

fn mount(source: Option<&str>, target: &str, fstype: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> Result<(), String> {
    let source = source.map(c_path).transpose()?;
    let target_c = c_path(target)?;
    let fstype = fstype.map(c_path).transpose()?;
    let data = data.map(c_path).transpose()?;
    let pointer = |value: &Option<CString>| value.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: every pointer is a NUL-terminated string that outlives the call, or null.
    let done = unsafe { libc::mount(pointer(&source), target_c.as_ptr(), pointer(&fstype), flags, pointer(&data).cast()) };
    if done != 0 {
        return Err(last_error(&format!("mount on {target}")));
    }
    Ok(())
}

/// Makes every mount below `/` a slave of the person's: their new mounts (a USB stick) still
/// appear inside, and nothing the sandbox mounts ever leaks out.
pub fn make_root_slave() -> Result<(), String> {
    mount(None, "/", None, libc::MS_SLAVE | libc::MS_REC, None)
}

/// The flags a read-only remount must keep: in a user namespace, a mount's nosuid / nodev /
/// noexec / atime flags are locked, and a remount that drops one is refused.
fn kept_flags(path: &str) -> Result<libc::c_ulong, String> {
    let target = c_path(path)?;
    // SAFETY: statvfs fills the zeroed struct it is handed.
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(target.as_ptr(), &mut stats) } != 0 {
        return Err(last_error(&format!("statvfs {path}")));
    }
    // WHY a literal: `nosymfollow` (Linux 5.10) is locked like the others; libc names only some.
    const NOSYMFOLLOW: libc::c_ulong = 256;
    let pairs = [(NOSYMFOLLOW, NOSYMFOLLOW), (libc::ST_NOSUID, libc::MS_NOSUID), (libc::ST_NODEV, libc::MS_NODEV), (libc::ST_NOEXEC, libc::MS_NOEXEC),
                 (libc::ST_NOATIME, libc::MS_NOATIME), (libc::ST_NODIRATIME, libc::MS_NODIRATIME), (libc::ST_RELATIME, libc::MS_RELATIME)];
    Ok(pairs.iter().filter(|(st, _)| stats.f_flag & st != 0).fold(0, |flags, (_, ms)| flags | ms))
}

/// Binds *path* onto itself, with every mount below it (a pin: renaming or removing it is `EBUSY`).
pub fn bind_self(path: &str) -> Result<(), String> {
    mount(Some(path), path, None, libc::MS_BIND | libc::MS_REC, None)
}

/// Makes the mount at *path* read-only (`EROFS` for every change through it).
pub fn remount_read_only(path: &str) -> Result<(), String> {
    let kept = kept_flags(path)?;
    mount(None, path, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | kept, None)
}

/// The two masks every hidden place is covered with: an empty folder and an empty file, both mode
/// 0000, on a small read-only tmpfs (so even their owner can not `chmod` them: `EROFS`).
pub struct Masks {
    root: String,
    pub folder: String,
    pub file: String,
}

impl Masks {
    /// Makes the masks (inside the new mount namespace: the tmpfs never shows outside).
    pub fn create() -> Result<Masks, String> {
        let mut template = *b"/tmp/blackbox-sandbox-XXXXXX\0";
        // SAFETY: mkdtemp rewrites the NUL-terminated template in place.
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err(last_error("mkdtemp"));
        }
        let root = String::from_utf8_lossy(&template[..template.len() - 1]).into_owned();
        let quiet = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        mount(Some("tmpfs"), &root, Some("tmpfs"), quiet, Some("mode=0755,size=16k,nr_inodes=8"))?;
        let masks = Masks { folder: format!("{root}/folder"), file: format!("{root}/file"), root };
        fs::create_dir(&masks.folder).map_err(|error| format!("mask folder: {error}"))?;
        fs::File::create(&masks.file).map_err(|error| format!("mask file: {error}"))?;
        for mask in [&masks.folder, &masks.file] {
            let path = c_path(mask)?;
            // SAFETY: chmod on a NUL-terminated path.
            if unsafe { libc::chmod(path.as_ptr(), 0) } != 0 {
                return Err(last_error("chmod mask"));
            }
        }
        mount(None, &masks.root, None, libc::MS_REMOUNT | libc::MS_RDONLY | quiet, None)?;
        Ok(masks)
    }

    /// Covers *target* with the mask of its *kind* (read-only, like the tmpfs it comes from).
    pub fn cover(&self, target: &str, kind: Kind) -> Result<(), String> {
        let source = if kind == Kind::Folder { &self.folder } else { &self.file };
        mount(Some(source), target, None, libc::MS_BIND, None)?;
        mount(None, target, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None)
    }

    /// Detaches the tmpfs from its temporary folder and removes the folder: the masks already
    /// bound stay (a bind keeps its file system alive), and nothing is left in `/tmp`.
    pub fn finish(self) {
        if let Ok(root) = c_path(&self.root) {
            // SAFETY: umount2 / rmdir on a NUL-terminated path; failure only leaves an empty folder.
            unsafe {
                libc::umount2(root.as_ptr(), libc::MNT_DETACH);
                libc::rmdir(root.as_ptr());
            }
        }
    }
}

/// A fresh `/proc` for a new PID namespace (process 1 of it calls this): only the namespace's own
/// processes are listed.
pub fn mount_fresh_proc() -> Result<(), String> {
    mount(Some("proc"), "/proc", Some("proc"), libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None)
}

/// `PR_SET_NO_NEW_PRIVS`: no setuid or file capability lifts this process or a child above the
/// person (`sudo`, `su`, `pkexec` fail) — and the precondition of seccomp and Landlock.
pub fn no_new_privileges() -> Result<(), String> {
    // SAFETY: prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(last_error("no_new_privs"));
    }
    Ok(())
}

/// Installs *program* as this process's seccomp filter (inherited by every child, never lifted).
pub fn install_filter(program: &[Instruction]) -> Result<(), String> {
    let mut filters: Vec<libc::sock_filter> = program.iter()
        .map(|op| libc::sock_filter { code: op.code, jt: op.jt, jf: op.jf, k: op.k }).collect();
    let fprog = libc::sock_fprog { len: u16::try_from(filters.len()).map_err(|_| "filter too long".to_string())?, filter: filters.as_mut_ptr() };
    // SAFETY: fprog points at `filters`, alive for the call; the kernel copies it.
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog as *const libc::sock_fprog) } != 0 {
        return Err(last_error("seccomp"));
    }
    Ok(())
}

/// Clears every capability (and the ambient set) before the program starts: belt and braces —
/// an exec as a non-root uid in a user namespace drops them anyway.
pub fn drop_capabilities() -> Result<(), String> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const VERSION_3: u32 = 0x2008_0522;
    let mut header = Header { version: VERSION_3, pid: 0 };
    let data = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    // SAFETY: prctl with integers; capset reads the header and two data records.
    unsafe {
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        if libc::syscall(libc::SYS_capset, &mut header as *mut Header, data.as_ptr()) != 0 {
            return Err(last_error("capset"));
        }
    }
    Ok(())
}

/// The Landlock ABI this kernel speaks (0 when it has none or it is off).
pub fn landlock_abi() -> i64 {
    const CREATE_RULESET: libc::c_long = 444;
    const VERSION: u32 = 1;
    // SAFETY: the version query takes no attribute.
    let abi = unsafe { libc::syscall(CREATE_RULESET, std::ptr::null::<u8>(), 0usize, VERSION) };
    abi.max(0)
}

/// Landlock's scopes (ABI 6, kernel 6.12+): no signal to a process outside this domain, no
/// connection to an abstract unix socket made outside it (X11's `@/tmp/.X11-unix/X0`) — and, as
/// for any Landlock domain, no ptrace or `/proc/<pid>` access to a process outside. No file
/// system rights are handled, so mounts and nested sandboxes keep working. ABI 7 also asks the
/// kernel to log each refusal of the program it starts (the audit log).
pub fn landlock_scope(abi: i64) -> Result<(), String> {
    const CREATE_RULESET: libc::c_long = 444;
    const RESTRICT_SELF: libc::c_long = 446;
    const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    const SCOPE_SIGNAL: u64 = 1 << 1;
    const LOG_NEW_EXEC_ON: u32 = 1 << 1;
    #[repr(C)]
    struct Attr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }
    let attr = Attr { handled_access_fs: 0, handled_access_net: 0, scoped: SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL };
    // SAFETY: attr outlives the call; the size is the struct's.
    let fd = unsafe { libc::syscall(CREATE_RULESET, &attr as *const Attr, std::mem::size_of::<Attr>(), 0u32) };
    if fd < 0 {
        return Err(last_error("landlock ruleset"));
    }
    let flags = if abi >= 7 { LOG_NEW_EXEC_ON } else { 0 };
    // SAFETY: fd is the ruleset just made; closed right after.
    let done = unsafe { libc::syscall(RESTRICT_SELF, fd as libc::c_int, flags) };
    unsafe { libc::close(fd as libc::c_int) };
    if done != 0 {
        return Err(last_error("landlock restrict"));
    }
    Ok(())
}

/// Whether this kernel has seccomp filters at all.
pub fn seccomp_available() -> bool {
    // SAFETY: PR_GET_SECCOMP takes no pointer; EINVAL means the kernel has no seccomp.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
}

/// The kernel's release (`uname -r`).
pub fn kernel_release() -> String {
    // SAFETY: uname fills the zeroed struct.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut name) } != 0 {
        return String::new();
    }
    let bytes: Vec<u8> = name.release.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// A short random id (hex) for a scope's name.
pub fn random_id() -> String {
    let mut bytes = [0u8; 4];
    if getrandom::getrandom(&mut bytes).is_err() {
        // SAFETY: getpid has no preconditions; a pid is unique enough as a fallback.
        return format!("{:x}", unsafe { libc::getpid() });
    }
    hex::encode(bytes)
}

/// The program name for a person-facing line (`claude`, not `/home/me/.local/bin/claude`).
pub fn program_name(program: &OsStr) -> String {
    let bytes = program.as_bytes();
    let base = bytes.rsplit(|b| *b == b'/').next().unwrap_or(bytes);
    String::from_utf8_lossy(base).into_owned()
}
