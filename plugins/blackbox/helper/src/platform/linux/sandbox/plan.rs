//! The mounts one policy becomes when an agent starts: every glob expanded against the disk as it
//! is now, every place that does not exist dropped (a mount needs something to cover), and the
//! rest ordered so no mount undoes another.
//!
//! Ordering rules (each proven by a test below):
//!
//! * shallow before deep — a folder's own bind (read-only or pinned) is made before a mask inside
//!   it, and self-binds are recursive, so a deeper mount made earlier is never dropped;
//! * one mount per path, the strongest action winning (hide over read-only over pin);
//! * nothing beneath a hidden folder (it can not be reached anyway, and a mount there would need
//!   the folder to be traversable).
//!
//! A pin or a read-only bind made inside a read-only folder stays read-only: a bind mount takes
//! the flags of the mount it is made from.
//!
//! Pure apart from the [`Disk`] it is handed (a fake one in the tests), so it runs on any OS.

use std::collections::BTreeMap;

use super::policy::{Action, Policy, Target};

/// The most paths one glob may expand to (a bounded start for any policy).
pub const MAX_GLOB_MATCHES: usize = 4096;

/// What sits at a path, following links (a mount is made on what a link points at).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Folder,
    /// A file, a socket, a device: anything that is not a folder.
    Other,
}

/// The disk as the plan sees it.
pub trait Disk {
    /// What is at *path* (links followed), None when nothing is.
    fn kind(&self, path: &str) -> Option<Kind>;
    /// The names inside folder *path* (empty when it can not be read).
    fn names(&self, path: &str) -> Vec<String>;
}

/// One mount the sandbox makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub action: Action,
    pub path: String,
    pub kind: Kind,
}

/// Whether *name* matches one glob part (`*` any run of characters, `?` one; dot files too, as on macOS).
pub fn matches(part: &str, name: &str) -> bool {
    let (pattern, name): (Vec<char>, Vec<char>) = (part.chars().collect(), name.chars().collect());
    let (mut p, mut n, mut star, mut mark) = (0, 0, None, 0);
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = n;
            p += 1;
        } else if let Some(at) = star {
            p = at + 1;
            mark += 1;
            n = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

/// Every existing path *glob* names, at most [`MAX_GLOB_MATCHES`].
pub fn expand(glob: &str, disk: &dyn Disk) -> Vec<String> {
    let mut found = vec![String::new()];
    for part in glob[1..].split('/') {
        let wild = part.contains('*') || part.contains('?');
        let mut next = Vec::new();
        for base in &found {
            if wild {
                let folder = if base.is_empty() { "/" } else { base.as_str() };
                let mut names: Vec<String> = disk.names(folder).into_iter().filter(|name| matches(part, name)).collect();
                names.sort();
                next.extend(names.into_iter().map(|name| format!("{base}/{name}")));
            } else {
                next.push(format!("{base}/{part}"));
            }
            if next.len() >= MAX_GLOB_MATCHES {
                next.truncate(MAX_GLOB_MATCHES);
                break;
            }
        }
        found = next;
    }
    found.retain(|path| disk.kind(path).is_some());
    found
}

fn depth(path: &str) -> usize {
    path.matches('/').count()
}

fn beneath(path: &str, folder: &str) -> bool {
    path.len() > folder.len() && path.starts_with(folder) && path.as_bytes()[folder.len()] == b'/'
}

/// The mounts *policy* needs on *disk*, in the order they must be made (see the module doc).
pub fn build(policy: &Policy, disk: &dyn Disk) -> Vec<Mount> {
    let mut strongest: BTreeMap<String, Action> = BTreeMap::new();
    for entry in &policy.entries {
        let paths = match &entry.target {
            Target::Path(path) => vec![path.clone()],
            Target::Glob(glob) => expand(glob, disk),
        };
        for path in paths {
            let action = strongest.entry(path).or_insert(entry.action);
            *action = (*action).max(entry.action);
        }
    }
    let mut mounts: Vec<Mount> = strongest.into_iter()
        .filter_map(|(path, action)| disk.kind(&path).map(|kind| Mount { action, path, kind }))
        .collect();
    let hidden: Vec<String> = mounts.iter().filter(|m| m.action == Action::Hide && m.kind == Kind::Folder).map(|m| m.path.clone()).collect();
    mounts.retain(|mount| !hidden.iter().any(|folder| beneath(&mount.path, folder)));
    mounts.sort_by(|a, b| depth(&a.path).cmp(&depth(&b.path)).then_with(|| a.path.cmp(&b.path)));
    mounts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::sandbox::policy::{parse, HEADER};
    use std::collections::BTreeSet;

    /// A disk of folders (ending in `/`) and files.
    struct Fake(BTreeSet<String>);

    impl Fake {
        fn new(paths: &[&str]) -> Fake {
            Fake(paths.iter().map(|p| p.to_string()).collect())
        }
    }

    impl Disk for Fake {
        fn kind(&self, path: &str) -> Option<Kind> {
            if path == "/" || self.0.contains(&format!("{path}/")) {
                Some(Kind::Folder)
            } else {
                self.0.contains(path).then_some(Kind::Other)
            }
        }
        fn names(&self, path: &str) -> Vec<String> {
            let prefix = if path == "/" { "/".to_string() } else { format!("{path}/") };
            self.0.iter().filter_map(|p| p.strip_prefix(&prefix)).map(|rest| rest.trim_end_matches('/'))
                .filter(|rest| !rest.is_empty() && !rest.contains('/')).map(String::from).collect()
        }
    }

    fn plan(body: &str, disk: &Fake) -> Vec<(Action, String)> {
        let policy = parse(format!("{HEADER}\n#\n{body}").as_bytes()).unwrap();
        build(&policy, disk).into_iter().map(|m| (m.action, m.path)).collect()
    }

    #[test]
    fn globs_match_one_part_each_including_dot_files() {
        assert!(matches("*.pem", "key.pem") && matches("*.pem", ".hidden.pem") && matches("?ey*", "key.pem"));
        assert!(!matches("*.pem", "key.pem.bak") && !matches("k?y", "ky") && matches("*", ""));
        let disk = Fake::new(&["/h/", "/h/b/", "/h/b/a.pem", "/h/b/b.pem", "/h/b/c.txt", "/h/b/sub/", "/h/b/sub/d.pem"]);
        assert_eq!(expand("/h/b/*.pem", &disk), vec!["/h/b/a.pem", "/h/b/b.pem"]);
        assert_eq!(expand("/h/*/sub", &disk), vec!["/h/b/sub"]);
        assert!(expand("/h/nothing/*.pem", &disk).is_empty());
    }

    #[test]
    fn missing_places_are_dropped_and_the_strongest_action_wins() {
        let disk = Fake::new(&["/h/", "/h/a/", "/h/b"]);
        assert_eq!(plan("pin /h/a\nro /h/a\nhide-file /h/b\nro /h/b\nhide-dir /h/missing\n", &disk),
                   vec![(Action::ReadOnly, "/h/a".into()), (Action::Hide, "/h/b".into())]);
    }

    #[test]
    fn shallow_mounts_come_first_and_nothing_is_mounted_inside_a_hidden_folder() {
        let disk = Fake::new(&["/h/", "/h/me/", "/h/me/Docs/", "/h/me/Docs/Taxes/", "/h/me/Docs/Taxes/x", "/h/me/.bb/"]);
        let mounts = plan("hide-dir /h/me/Docs/Taxes\nro-file /h/me/Docs/Taxes/x\npin /h/me/Docs\npin /h/me\nro /h/me/.bb\n", &disk);
        assert_eq!(mounts, vec![(Action::Pin, "/h/me".into()), (Action::ReadOnly, "/h/me/.bb".into()),
                                (Action::Pin, "/h/me/Docs".into()), (Action::Hide, "/h/me/Docs/Taxes".into())]);
    }

    #[test]
    fn a_hidden_file_keeps_its_kind_so_the_right_mask_covers_it() {
        let disk = Fake::new(&["/run/", "/run/bus", "/dev/", "/dev/snd/"]);
        let policy = parse(format!("{HEADER}\n#\nhide-socket /run/bus\nhide-socket /dev/snd\n").as_bytes()).unwrap();
        let kinds: Vec<Kind> = build(&policy, &disk).into_iter().map(|m| m.kind).collect();
        assert_eq!(kinds, vec![Kind::Folder, Kind::Other], "/dev/snd (a folder), then /run/bus (a socket)");
    }
}
