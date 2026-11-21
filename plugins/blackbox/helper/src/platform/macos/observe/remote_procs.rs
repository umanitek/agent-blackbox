//! The process table as the remote-access watch needs it: each process's parent, name,
//! executable path, owner and start time (sysinfo — libproc on macOS; the helper runs as root, so
//! it sees every process). Never a command line: only the executable's path.

use std::collections::HashMap;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

/// One process.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// The executable's path ("" when the OS does not say).
    pub path: String,
    /// The owner's account name ("" when unknown).
    pub user: String,
    /// Unix seconds; tells a process from a later one that reused its pid.
    pub start: u64,
}

/// pid → process.
pub type Procs = HashMap<u32, Proc>;

/// Reads the table; keeps sysinfo between reads so slow fields are read once per process.
pub struct ProcReader {
    system: Option<System>,
    users: Option<Users>,
}

impl Default for ProcReader {
    fn default() -> Self {
        ProcReader { system: System::new().ok(), users: Users::new_with_refreshed_list().ok() }
    }
}

impl ProcReader {
    /// Every process now (empty when the OS refused).
    pub fn read(&mut self) -> Procs {
        let Some(system) = self.system.as_mut() else { return Procs::new() };
        let kind = ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet).with_user(UpdateKind::OnlyIfNotSet);
        system.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        system.processes().iter().map(|(pid, process)| {
            let user = process.user_id()
                .and_then(|uid| self.users.as_ref().and_then(|users| users.get_user_by_id(uid)))
                .map(|user| user.name().to_string()).unwrap_or_default();
            (pid.as_u32(), Proc {
                pid: pid.as_u32(), ppid: process.parent().map(|p| p.as_u32()).unwrap_or(0),
                name: process.name().to_string_lossy().chars().take(64).collect(),
                path: process.exe().map(|path| path.display().to_string()).unwrap_or_default().chars().take(512).collect(),
                user, start: process.start_time(),
            })
        }).collect()
    }
}

/// The processes below *root* (children, their children …), nearest first, at most *limit*.
pub fn descendants(procs: &Procs, root: u32, limit: usize) -> Vec<&Proc> {
    let mut children: HashMap<u32, Vec<&Proc>> = HashMap::new();
    for process in procs.values() {
        children.entry(process.ppid).or_default().push(process);
    }
    for list in children.values_mut() {
        list.sort_by_key(|process| process.pid);
    }
    let mut out = vec![];
    let mut queue = std::collections::VecDeque::from([root]);
    let mut seen = std::collections::HashSet::from([root]);
    while let Some(pid) = queue.pop_front() {
        for child in children.get(&pid).into_iter().flatten() {
            if out.len() >= limit || !seen.insert(child.pid) {
                continue;
            }
            out.push(*child);
            queue.push_back(child.pid);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, ppid: u32, name: &str) -> (u32, Proc) {
        (pid, Proc { pid, ppid, name: name.into(), ..Default::default() })
    }

    #[test]
    fn descendants_are_nearest_first_bounded_and_cycle_safe() {
        let procs: Procs = [proc(10, 1, "sshd-session"), proc(11, 10, "zsh"), proc(12, 11, "vim"), proc(13, 11, "curl"), proc(20, 1, "other")].into();
        let names: Vec<&str> = descendants(&procs, 10, 10).iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["zsh", "vim", "curl"]);
        assert_eq!(descendants(&procs, 10, 1).len(), 1);
        let looped: Procs = [proc(5, 6, "a"), proc(6, 5, "b")].into();
        assert!(descendants(&looped, 5, 10).len() <= 2);
    }

    #[test]
    fn the_real_table_reads() {
        let procs = ProcReader::default().read();
        assert!(procs.contains_key(&std::process::id()), "this test process is in the table");
    }
}
