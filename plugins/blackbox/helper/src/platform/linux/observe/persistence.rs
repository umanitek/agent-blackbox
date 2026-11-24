//! Persistence on Linux: what starts by itself — the way unwanted software survives a restart or
//! a login. Watched every [`FOLDERS_EVERY`], observing only (a file is marked by size, time and a
//! hash of its bytes, read safely; a unit or desktop entry is read for its name and program only
//! when it is new or changed; a link or folder is marked by `lstat`, never followed):
//!
//! * systemd units — the system's (`/etc/systemd/system`, `/etc/systemd/user`, their `*.wants`
//!   folders are entries: enabling a unit changes them) and every user's (`~/.config/systemd/user`,
//!   `~/.local/share/systemd/user`);
//! * desktop and session autostart (`/etc/xdg/autostart`, `~/.config/autostart`, Plasma's and
//!   GNOME Shell's), D-Bus activation (`~/.local/share/dbus-1/services`), `~/.config/environment.d`;
//! * cron and anacron (`/etc/crontab`, `/etc/cron.d`, `/etc/cron.*`, the spools);
//! * root configuration that runs or trusts something (sudoers, PAM, udev, the dynamic loader,
//!   profile scripts, NetworkManager's dispatcher, apt hooks, modprobe, init.d, rc.local).
//!
//! The places are the plugin's ONE list (`kernel.persistence_places` `LINUX_PERSISTENCE_*` and
//! `SHARED_*`); a parity test there holds every folder and file here to it (LES-137). The first
//! complete look is the baseline; afterwards each item added, changed or removed is a
//! `persistence-*` event ([`crate::platform::system_watch::items::Persistence`]).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use super::unit_files;
use crate::platform::system_watch::items::{entry_mark, mark_of, user_homes, Item, MAX_ITEMS, MAX_READ};

pub const FOLDERS_EVERY: Duration = Duration::from_secs(5);
/// Where the users' homes are (and root's own).
pub const HOMES: &str = "/home";
pub const ROOT_HOME: &str = "/root";

/// System-wide folders, with the kind of item each holds.
pub const SYSTEM_FOLDERS: &[(&str, &str)] = &[
    ("systemd-unit", "/etc/systemd/system"), ("systemd-unit", "/etc/systemd/user"), ("autostart", "/etc/xdg/autostart"),
    ("cron", "/etc/cron.d"), ("cron", "/etc/cron.hourly"), ("cron", "/etc/cron.daily"), ("cron", "/etc/cron.weekly"),
    ("cron", "/etc/cron.monthly"), ("cron", "/var/spool/cron"), ("cron", "/var/spool/cron/crontabs"),
    ("root-config", "/etc/sudoers.d"), ("root-config", "/etc/udev/rules.d"), ("root-config", "/etc/ld.so.conf.d"),
    ("root-config", "/etc/pam.d"), ("root-config", "/etc/profile.d"), ("root-config", "/etc/update-motd.d"),
    ("root-config", "/etc/NetworkManager/dispatcher.d"), ("root-config", "/etc/apt/apt.conf.d"),
    ("root-config", "/etc/modprobe.d"), ("root-config", "/etc/init.d"),
];
/// System-wide files.
pub const SYSTEM_FILES: &[(&str, &str)] = &[
    ("cron", "/etc/crontab"), ("cron", "/etc/anacrontab"), ("root-config", "/etc/sudoers"), ("root-config", "/etc/ld.so.preload"),
    ("root-config", "/etc/environment"), ("root-config", "/etc/rc.local"), ("root-config", "/etc/security/pam_env.conf"),
];
/// Folders under each user's home.
pub const USER_FOLDERS: &[(&str, &str)] = &[
    ("user-unit", ".config/systemd/user"), ("user-unit", ".local/share/systemd/user"), ("autostart", ".config/autostart"),
    ("autostart", ".config/autostart-scripts"), ("autostart", ".config/plasma-workspace/env"),
    ("autostart", ".config/plasma-workspace/shutdown"), ("autostart", ".local/share/gnome-shell/extensions"),
    ("dbus-service", ".local/share/dbus-1/services"), ("session-start", ".config/environment.d"),
];
/// The item kinds this module reports.
pub const KINDS: &[&str] = &["systemd-unit", "user-unit", "autostart", "cron", "dbus-service", "session-start", "root-config"];

/// Every home to look in: each folder under [`HOMES`] (never a link to another) and root's.
pub fn homes() -> Vec<String> {
    let mut found = user_homes(Path::new(HOMES));
    if Path::new(ROOT_HOME).is_dir() {
        found.push(ROOT_HOME.to_string());
    }
    found
}

/// One entry of a watched folder as an item: a regular file by its content (a unit or desktop
/// entry also by its name and program, re-read only when its mark changed), anything else — a
/// `*.wants` folder, an enabling link — by `lstat`, a link naming where it points.
fn entry_item(kind: &'static str, path: &Path, known: &BTreeMap<String, Item>) -> Option<Item> {
    let id = path.display().to_string();
    let name = path.file_name()?.to_string_lossy().into_owned();
    if let Some(mark) = mark_of(path) {
        let (label, program) = match known.get(&id) {
            Some(old) if old.mark == mark => (old.label.clone(), old.program.clone()),
            _ if unit_files::is_described(&name) => crate::safe_read::read_regular(path, MAX_READ)
                .map(|bytes| unit_files::describe(&name, &String::from_utf8_lossy(&bytes))).unwrap_or_default(),
            _ => (String::new(), String::new()),
        };
        return Some(Item { kind, id, label: if label.is_empty() { name } else { label }, program, mark });
    }
    let mark = entry_mark(path)?;
    let program = fs::read_link(path).map(|target| target.display().to_string()).unwrap_or_default();
    Some(Item { kind, id, label: name, program, mark })
}

fn folder_items(kind: &'static str, folder: &str, known: &BTreeMap<String, Item>, items: &mut Vec<Item>) {
    let Ok(entries) = fs::read_dir(folder) else { return };
    // A dot entry is a tool's own bookkeeping (an editor's swap file), never what runs.
    items.extend(entries.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('.')).take(MAX_ITEMS)
        .filter_map(|entry| entry_item(kind, &entry.path(), known)));
}

/// Every item now, for the users at *homes*. *known* holds the last look's items by id (an
/// unchanged unit is not read again).
pub fn file_items(homes: &[String], known: &BTreeMap<String, Item>) -> Vec<Item> {
    let mut items = Vec::new();
    for (kind, folder) in SYSTEM_FOLDERS {
        folder_items(kind, folder, known, &mut items);
    }
    for (kind, path) in SYSTEM_FILES {
        items.extend(entry_item(kind, Path::new(path), known));
    }
    for home in homes {
        for (kind, folder) in USER_FOLDERS {
            folder_items(kind, &format!("{home}/{folder}"), known, &mut items);
        }
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::system_watch::items::Persistence;

    fn temp_home() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-linux-persist-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(dir.join(".config/systemd/user")).unwrap();
        fs::create_dir_all(dir.join(".config/autostart")).unwrap();
        dir
    }

    #[test]
    fn a_user_unit_an_enabling_link_and_an_autostart_entry_are_events_after_the_baseline() {
        let home = temp_home();
        let homes = vec![home.display().to_string()];
        let units = home.join(".config/systemd/user");
        let mut watch = Persistence::default();
        watch.update(KINDS, file_items(&homes, &BTreeMap::new()), 1);
        watch.baseline_done();
        fs::write(units.join("sync.service"), "[Unit]\nDescription=Sync\n[Service]\nExecStart=/home/x/.cache/s --loop\n").unwrap();
        fs::create_dir_all(units.join("default.target.wants")).unwrap();
        std::os::unix::fs::symlink(units.join("sync.service"), units.join("default.target.wants/sync.service")).unwrap();
        fs::write(home.join(".config/autostart/u.desktop"), "Name=Updater\nExec=/tmp/u\n").unwrap();
        fs::write(home.join(".config/autostart/.u.desktop.swp"), "x").unwrap();
        assert!(watch.update(KINDS, file_items(&homes, &watch.known()), 2));
        let events = watch.take_events();
        let seen: Vec<(String, String, String)> = events.iter().map(|e| (e["item_kind"].as_str().unwrap().into(),
            e["label"].as_str().unwrap().into(), e["program"].as_str().unwrap().into())).collect();
        assert!(seen.contains(&("user-unit".into(), "Sync".into(), "/home/x/.cache/s".into())), "{seen:?}");
        assert!(seen.iter().any(|(kind, label, _)| kind == "user-unit" && label == "default.target.wants"), "the wants folder is an entry");
        assert!(seen.contains(&("autostart".into(), "Updater".into(), "/tmp/u".into())), "{seen:?}");
        assert!(!seen.iter().any(|(_, label, _)| label.ends_with(".swp")), "dot entries are not items");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn every_kind_watched_is_a_reported_kind() {
        for (kind, _) in SYSTEM_FOLDERS.iter().chain(SYSTEM_FILES).chain(USER_FOLDERS) {
            assert!(KINDS.contains(kind), "{kind}");
        }
    }
}
