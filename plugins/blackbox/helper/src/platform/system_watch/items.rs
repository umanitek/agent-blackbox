//! The state the persistence watches share on every OS: one item that starts (or runs) by itself,
//! its mark (what changes when it changes), and [`Persistence`] — what the last look saw and the
//! `persistence-new` / `-changed` / `-removed` events a change queues. Each OS's observe side
//! finds the items (`platform/<os>/observe/persistence.rs`, `run_later.rs`) and fills this.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The most items one kind of look keeps.
pub const MAX_ITEMS: usize = 1000;
const MAX_PENDING: usize = 200;
/// The most bytes read of one item (a bigger one is marked by size and time alone).
pub const MAX_READ: u64 = 1024 * 1024;
const FIELD: usize = 512;


/// One thing that starts by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// launch-agent | launch-daemon | user-agent | cron | periodic | login-item | profile |
    /// system-extension | kernel-extension
    pub kind: &'static str,
    /// The plist / job file, or the identifier for command-listed items.
    pub id: String,
    pub label: String,
    pub program: String,
    /// What changes when the item changes (size + mtime + sha prefix, or the listing line).
    pub mark: String,
}

impl Item {
    fn json(&self) -> Value {
        json!({"kind": self.kind, "id": cut(&self.id), "label": cut(&self.label), "program": cut(&self.program)})
    }
}

fn cut(text: &str) -> String {
    text.chars().take(FIELD).collect()
}

/// Every user's home folder under *users* (`/Users/<name>`, not `Shared`): real folders only — a
/// link to another home (`/Users/runner -> /Users/admin` on CI images) would report every entry of
/// that home twice under a second spelling (KI-615).
pub fn user_homes(users: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(users) else { return Vec::new() };
    let mut homes: Vec<String> = entries.flatten()
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))   // a link is not followed
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "Shared" && !name.starts_with('.'))
        .map(|name| users.join(name).display().to_string()).collect();
    homes.sort();
    homes
}

pub fn mark_of(path: &Path) -> Option<String> {
    // As root in folders the person can write: the link itself, never what it points to (safe_read).
    let meta = fs::symlink_metadata(path).ok().filter(|m| m.file_type().is_file())?;
    let mtime = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
    let mut hasher = Sha256::new();
    if meta.len() <= MAX_READ {
        let bytes = crate::safe_read::read_regular(path, MAX_READ)?;
        hasher.update(&bytes);
    }
    let sha: String = hasher.finalize().iter().take(4).map(|b| format!("{b:02x}")).collect();
    Some(format!("{}:{}:{}", meta.len(), mtime, sha))
}

/// True when two marks say the entry holds what it held: a file's `size:mtime:sha` compared by size
/// and sha — a rewrite that leaves its bytes as they were (`sed -i` deleting nothing) is not a
/// change (KI-636: it raised a critical alert); a file too big to hash, and every other mark, whole.
fn same_content(old: &str, new: &str) -> bool {
    let content = |mark: &str| -> Option<(String, String)> {
        let parts: Vec<&str> = mark.split(':').collect();
        match parts.as_slice() {
            [size, mtime, sha] if mtime.parse::<u64>().is_ok() && size.parse::<u64>().is_ok_and(|n| n <= MAX_READ) =>
                Some((size.to_string(), sha.to_string())),
            _ => None,
        }
    };
    match (content(old), content(new)) {
        (Some(before), Some(after)) => before == after,
        _ => old == new,
    }
}

/// What the last look saw and the events not yet reported.
#[derive(Debug, Default)]
pub struct Persistence {
    started: bool,
    items: BTreeMap<String, Item>,
    pending: Vec<Value>,
}

impl Persistence {
    /// The items of the kinds *kinds* were looked at again: compare, queue events. A kind whose
    /// source failed (None) keeps its last items. True when it queued any event.
    pub fn update(&mut self, kinds: &[&str], found: Vec<Item>, now: u64) -> bool {
        self.update_capped(kinds, found, now, MAX_ITEMS)
    }

    /// [`Self::update`] keeping at most *cap* items (the run-later watch's program folders hold thousands).
    pub fn update_capped(&mut self, kinds: &[&str], found: Vec<Item>, now: u64, cap: usize) -> bool {
        let before = self.pending.len();
        let fresh: BTreeMap<String, Item> = found.into_iter().map(|i| (format!("{}|{}", i.kind, i.id), i)).collect();
        for (key, item) in &fresh {
            match self.items.get(key) {
                None if self.started => self.push("persistence-new", item, now),
                Some(old) if self.started && !same_content(&old.mark, &item.mark) => self.push("persistence-changed", item, now),
                _ => {}
            }
        }
        let gone: Vec<String> = self.items.iter().filter(|(k, i)| kinds.contains(&i.kind) && !fresh.contains_key(*k)).map(|(k, _)| k.clone()).collect();
        for key in gone {
            if let Some(item) = self.items.remove(&key) {
                if self.started { self.push("persistence-removed", &item, now); }
            }
        }
        for (key, item) in fresh.into_iter().take(cap) {
            self.items.insert(key, item);
        }
        self.pending.len() > before
    }

    /// The first complete look is done: from now on changes are events.
    pub fn baseline_done(&mut self) {
        self.started = true;
    }

    fn push(&mut self, kind: &str, item: &Item, now: u64) {
        if self.pending.len() < MAX_PENDING {
            let mut event = item.json();
            event["mark"] = json!(cut(&item.mark));   // size:mtime:hash — one report per entry, and the writer's evidence (KI-615)
            event["kind"] = json!(kind);
            event["item_kind"] = json!(item.kind);
            event["ts"] = json!(now);
            self.pending.push(event);
        }
    }

    /// The items known now, keyed by id (for re-reading only changed plists).
    pub fn known(&self) -> BTreeMap<String, Item> {
        self.items.values().map(|i| (i.id.clone(), i.clone())).collect()
    }

    pub fn snapshot(&self) -> Vec<Value> {
        self.items.values().map(Item::json).collect()
    }

    pub fn take_events(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.pending)
    }

    pub fn reset(&mut self) {
        *self = Persistence::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fifo_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-persist-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_fifo_or_a_link_is_never_read_or_followed() {
        let dir = fifo_dir();
        let fifo = dir.join("x.plist");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid C string path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert!(mark_of(&fifo).is_none());
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "a FIFO must never block the system guard");
        let secret = dir.join("root-only");
        std::fs::write(&secret, b"secret").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(mark_of(&link).is_none(), "a link is not followed");
        assert!(mark_of(&secret).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_job_after_the_baseline_is_an_event_and_a_failed_source_keeps_its_items() {
        let job = |id: &str, mark: &str| Item { kind: "user-agent", id: id.into(), label: "x".into(), program: "/tmp/x".into(), mark: mark.into() };
        let mut watch = Persistence::default();
        assert!(!watch.update(&["user-agent"], vec![job("/a.plist", "1")], 1));
        watch.baseline_done();
        assert!(watch.update(&["user-agent"], vec![job("/a.plist", "1"), job("/b.plist", "1")], 2));
        assert_eq!(watch.take_events()[0]["kind"], "persistence-new");
        assert!(watch.update(&["user-agent"], vec![job("/a.plist", "2"), job("/b.plist", "1")], 3));
        assert_eq!(watch.take_events()[0]["kind"], "persistence-changed");
        assert!(!watch.update(&["profile"], vec![], 4), "a profile look never removes jobs");
        assert!(watch.update(&["user-agent"], vec![job("/a.plist", "2")], 5));
        assert_eq!(watch.take_events()[0]["kind"], "persistence-removed");
    }

    #[test]
    fn a_rewrite_that_leaves_the_content_as_it_was_is_not_a_change() {
        // KI-636 (security round 6): the harness's `sed -i` on ~/.ssh/authorized_keys deleted nothing,
        // and the new write time alone raised "Startup item changed".
        let key = |mark: &str| Item { kind: "ssh-login", id: "/u/.ssh/authorized_keys".into(), label: "authorized_keys".into(), program: String::new(), mark: mark.into() };
        let mut watch = Persistence::default();
        watch.update(&["ssh-login"], vec![key("120:1795462800:ab12cd34")], 1);
        watch.baseline_done();
        assert!(!watch.update(&["ssh-login"], vec![key("120:1795462830:ab12cd34")], 2), "same bytes, new write time");
        assert!(watch.update(&["ssh-login"], vec![key("161:1795462841:ffee0011")], 3));
        assert_eq!(watch.take_events()[0]["kind"], "persistence-changed");
        let big = MAX_READ + 1;
        assert!(watch.update(&["ssh-login"], vec![key(&format!("{big}:5:e3b0c442"))], 4));
        watch.take_events();
        assert!(watch.update(&["ssh-login"], vec![key(&format!("{big}:6:e3b0c442"))], 5), "a file too big to hash: its write time is all there is");
    }
}
