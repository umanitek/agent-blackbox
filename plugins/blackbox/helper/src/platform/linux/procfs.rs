//! `/proc`, read as root and never trusted: a process's `stat`, `status`, `cmdline`, `exe`,
//! `cgroup` and its socket descriptors; the boot time; each interface's 64-bit counters
//! (`/proc/net/dev`, with its flags from `/sys/class/net/<name>/flags`).
//!
//! Every reader takes the root it reads under (`/proc` in the helper, a fake tree in a test), and
//! reads through [`crate::safe_read::read_regular`] (no link followed, a FIFO never blocks,
//! capped). A process that ended while it was read simply answers nothing.

use std::fs;
use std::path::{Path, PathBuf};

use crate::platform::sockets::Iface;

/// The process file system.
pub const PROC: &str = "/proc";
/// Where each interface's flags are (`IFF_UP` 0x1, `IFF_LOOPBACK` 0x8).
pub const SYS_NET: &str = "/sys/class/net";
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
/// `stat`, `status`, `cgroup`: a few KiB at most.
const SMALL: u64 = 64 * 1024;
/// `cmdline`: arguments are bounded by the kernel's ARG_MAX; more than this is never needed.
const CMDLINE: u64 = 256 * 1024;
/// The most descriptors looked at per process (bounded work for a process with thousands).
pub const MAX_FDS: usize = 4096;
/// `stat`'s fields after `(comm)`: index 0 is field 3 (state), so field N is at N - 3.
const PPID_AT: usize = 4 - 3;
const STARTTIME_AT: usize = 22 - 3;

/// The fields of `/proc/<pid>/stat` the helper uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub pid: u32,
    /// The short program name (at most 15 bytes; may hold spaces and parentheses).
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    /// When it started, in clock ticks after boot.
    pub start_ticks: u64,
}

/// The fields of `/proc/<pid>/status` the helper uses (None / empty: the line was not there).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// (real, effective) user id.
    pub uid: Option<(u32, u32)>,
    pub no_new_privs: Option<bool>,
    /// 0 none, 1 strict, 2 a filter.
    pub seccomp: Option<u8>,
    /// The pid in each PID namespace, outermost first (one entry outside any namespace).
    pub nspid: Vec<u32>,
}

/// `/proc/<pid>/stat`: the name ends at the LAST `)`, since it may hold `)` itself.
pub fn parse_stat(text: &str) -> Option<Stat> {
    let (head, rest) = text.rsplit_once(')')?;
    let (pid, comm) = head.split_once('(')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    Some(Stat {
        pid: pid.trim().parse().ok()?,
        comm: comm.to_string(),
        state: fields.first()?.chars().next()?,
        ppid: fields.get(PPID_AT)?.parse().ok()?,
        start_ticks: fields.get(STARTTIME_AT)?.parse().ok()?,
    })
}

/// `/proc/<pid>/status`.
pub fn parse_status(text: &str) -> Status {
    let mut status = Status::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let numbers: Vec<u32> = value.split_whitespace().filter_map(|word| word.parse().ok()).collect();
        match key {
            "Uid" if numbers.len() >= 2 => status.uid = Some((numbers[0], numbers[1])),
            "NoNewPrivs" => status.no_new_privs = numbers.first().map(|n| *n == 1),
            "Seccomp" => status.seccomp = numbers.first().and_then(|n| u8::try_from(*n).ok()),
            "NSpid" => status.nspid = numbers,
            _ => {}
        }
    }
    status
}

/// The boot time (unix seconds) from `/proc/stat`'s `btime` line.
pub fn parse_btime(text: &str) -> Option<u64> {
    text.lines().find_map(|line| line.strip_prefix("btime ")).and_then(|value| value.trim().parse().ok())
}

/// `/proc/net/dev` (two header lines, then `name: rx_bytes rx_packets … tx_bytes tx_packets …`),
/// each interface's flags from *flags_of* (None: down, not loopback).
pub fn parse_net_dev(text: &str, flags_of: &dyn Fn(&str) -> Option<u32>) -> Vec<Iface> {
    text.lines().skip(2).filter_map(|line| {
        let (name, counters) = line.split_once(':')?;
        let numbers: Vec<u64> = counters.split_whitespace().map(|word| word.parse().ok()).collect::<Option<_>>()?;
        if numbers.len() < 10 {
            return None;
        }
        let name = name.trim().to_string();
        let flags = flags_of(&name).unwrap_or(0);
        Some(Iface { loopback: flags & IFF_LOOPBACK != 0, up: flags & IFF_UP != 0, bytes_in: numbers[0], packets_in: numbers[1],
                     bytes_out: numbers[8], packets_out: numbers[9], name })
    }).collect()
}

fn text(path: &Path, cap: u64) -> Option<String> {
    crate::safe_read::read_regular(path, cap).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn of(root: &Path, pid: u32, name: &str) -> PathBuf {
    root.join(pid.to_string()).join(name)
}

/// Every pid under *root*, ascending.
pub fn pids(root: &Path) -> Vec<u32> {
    let Ok(entries) = fs::read_dir(root) else { return Vec::new() };
    let mut found: Vec<u32> = entries.flatten().filter_map(|entry| entry.file_name().to_str()?.parse().ok()).collect();
    found.sort_unstable();
    found
}

pub fn stat(root: &Path, pid: u32) -> Option<Stat> {
    parse_stat(&text(&of(root, pid, "stat"), SMALL)?)
}

pub fn status(root: &Path, pid: u32) -> Option<Status> {
    text(&of(root, pid, "status"), SMALL).map(|t| parse_status(&t))
}

/// *pid*'s arguments, each whole ([] when gone).
pub fn cmdline(root: &Path, pid: u32) -> Vec<String> {
    let Some(bytes) = crate::safe_read::read_regular(&of(root, pid, "cmdline"), CMDLINE) else { return Vec::new() };
    let trimmed = bytes.strip_suffix(b"\0").unwrap_or(&bytes);
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed.split(|byte| *byte == 0).map(|word| String::from_utf8_lossy(word).into_owned()).collect()
}

/// The executable *pid* runs ("" when gone; a deleted file without its " (deleted)" mark).
pub fn exe(root: &Path, pid: u32) -> String {
    fs::read_link(of(root, pid, "exe")).map(|target| {
        let shown = target.display().to_string();
        shown.strip_suffix(" (deleted)").map(str::to_string).unwrap_or(shown)
    }).unwrap_or_default()
}

/// *pid*'s cgroup lines ("" when gone).
pub fn cgroup(root: &Path, pid: u32) -> String {
    text(&of(root, pid, "cgroup"), SMALL).unwrap_or_default()
}

/// The inodes of *pid*'s sockets (its `fd/*` links that read `socket:[N]`), at most [`MAX_FDS`].
pub fn socket_inodes(root: &Path, pid: u32) -> Vec<u64> {
    let Ok(entries) = fs::read_dir(of(root, pid, "fd")) else { return Vec::new() };
    entries.flatten().take(MAX_FDS).filter_map(|entry| {
        let target = fs::read_link(entry.path()).ok()?;
        target.to_str()?.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
    }).collect()
}

/// When this machine booted (unix seconds; 0 when unreadable).
pub fn boot_time(root: &Path) -> u64 {
    text(&root.join("stat"), SMALL).and_then(|t| parse_btime(&t)).unwrap_or(0)
}

/// Every interface's counters under *proc* (`net/dev`) with its flags under *sys_net*.
pub fn ifaces(proc: &Path, sys_net: &Path) -> Vec<Iface> {
    let Some(table) = text(&proc.join("net").join("dev"), SMALL) else { return Vec::new() };
    let flags_of = |name: &str| -> Option<u32> {
        let raw = crate::safe_read::read_attribute(&sys_net.join(name).join("flags"), 64)?;
        let raw = String::from_utf8_lossy(&raw);
        let word = raw.split(|c: char| c.is_whitespace() || c == '\0').next()?;
        u32::from_str_radix(word.trim_start_matches("0x"), 16).ok()
    };
    parse_net_dev(&table, &flags_of)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_root() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-procfs-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(dir.join("700/fd")).unwrap();
        dir
    }

    #[test]
    fn stat_reads_a_name_with_spaces_and_parentheses() {
        let stat = parse_stat("700 (tmux: server) (x)) S 1 700 700 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 4242 1 2 3").unwrap();
        assert_eq!((stat.pid, stat.comm.as_str(), stat.state, stat.ppid, stat.start_ticks), (700, "tmux: server) (x)", 'S', 1, 4242));
        assert!(parse_stat("garbage").is_none() && parse_stat("1 (x) S").is_none());
    }

    #[test]
    fn status_reads_uids_no_new_privs_seccomp_and_namespace_pids() {
        let status = parse_status("Name:\tbash\nUid:\t1000\t0\t0\t0\nNoNewPrivs:\t1\nSeccomp:\t2\nNSpid:\t4321\t7\n");
        assert_eq!(status, Status { uid: Some((1000, 0)), no_new_privs: Some(true), seccomp: Some(2), nspid: vec![4321, 7] });
        assert_eq!(parse_status(""), Status::default());
    }

    #[test]
    fn the_boot_time_and_interface_counters_parse() {
        assert_eq!(parse_btime("cpu  1 2\nbtime 1700000000\nprocesses 4\n"), Some(1_700_000_000));
        let dev = "Inter-|   Receive                            |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 9876543210 1200 0 0 0 0 0 0 9876543210 1200 0 0 0 0 0 0\nenp0s1: 5000 40 0 0 0 0 0 3 7000 50 0 0 0 0 0 0\n";
        let flags = |name: &str| Some(if name == "lo" { 0x9 } else { 0x1003 });
        let found = parse_net_dev(dev, &flags);
        assert_eq!(found.len(), 2);
        assert!(found[0].loopback && found[0].up && found[0].bytes_in == 9_876_543_210, "64-bit counters (KI-588)");
        assert_eq!((found[1].name.as_str(), found[1].bytes_out, found[1].packets_out, found[1].loopback), ("enp0s1", 7000, 50, false));
    }

    #[test]
    fn a_fake_tree_reads_like_proc() {
        let root = fake_root();
        fs::write(root.join("stat"), "btime 1700000000\n").unwrap();
        fs::write(root.join("700/stat"), "700 (sshd) S 1 700 700 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99 1 1").unwrap();
        fs::write(root.join("700/cmdline"), b"sshd: amos [priv]\0").unwrap();
        std::os::unix::fs::symlink("/usr/sbin/sshd (deleted)", root.join("700/exe")).unwrap();
        std::os::unix::fs::symlink("socket:[123456]", root.join("700/fd/3")).unwrap();
        std::os::unix::fs::symlink("/dev/null", root.join("700/fd/0")).unwrap();
        assert_eq!(pids(&root), vec![700]);
        assert_eq!(boot_time(&root), 1_700_000_000);
        assert_eq!(stat(&root, 700).unwrap().start_ticks, 99);
        assert_eq!(cmdline(&root, 700), vec!["sshd: amos [priv]"]);
        assert_eq!(exe(&root, 700), "/usr/sbin/sshd");
        assert_eq!(socket_inodes(&root, 700), vec![123456]);
        assert!(stat(&root, 701).is_none() && cmdline(&root, 701).is_empty());
        let _ = fs::remove_dir_all(&root);
    }
}
