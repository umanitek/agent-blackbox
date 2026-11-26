//! Persistence: what starts by itself on this Mac — the classic way unwanted software survives a
//! restart. Watched (observing only, never a file's contents beyond what names the item):
//!
//! * launchd jobs — `/Library/LaunchAgents`, `/Library/LaunchDaemons`, every user's
//!   `~/Library/LaunchAgents` (folders looked at every [`FOLDERS_EVERY`]; a new or changed plist
//!   is read with `plutil` for its label and program);
//! * cron and periodic jobs — `/usr/lib/cron/tabs/*`, `/etc/crontab`, `/etc/periodic/*/*`;
//! * login items and background items — `sfltool dumpbtm` (root), every [`COMMANDS_EVERY`];
//! * configuration profiles (`profiles list -all`), system extensions (`systemextensionsctl list`)
//!   and third-party kernel extensions (`kmutil showloaded --list-only`, every [`KEXTS_EVERY`]).
//!
//! The first complete look is the baseline; afterwards each item added, changed or removed queues a
//! `persistence-new` / `-changed` / `-removed` event. `/System` is read-only and not watched.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

// The items, their marks and the diff that queues events are every OS's (platform/system_watch).
pub use crate::platform::system_watch::items::{mark_of, user_homes, Item, Persistence, MAX_ITEMS, MAX_READ};

pub const FOLDERS_EVERY: Duration = Duration::from_secs(5);
pub const COMMANDS_EVERY: Duration = Duration::from_secs(60);
pub const KEXTS_EVERY: Duration = Duration::from_secs(300);

/// The folders of plist jobs, with their kind.
pub fn job_folders() -> Vec<(&'static str, String)> {
    let mut folders = vec![("launch-agent", "/Library/LaunchAgents".to_string()), ("launch-daemon", "/Library/LaunchDaemons".to_string())];
    for home in user_homes(Path::new("/Users")) {
        folders.push(("user-agent", format!("{home}/Library/LaunchAgents")));
    }
    folders
}

/// A launchd plist's label and program (`plutil -convert json`), read only when it is new or changed.
pub fn job_of(path: &Path) -> (String, String) {
    // Read safely as root (no links, no FIFOs, capped), then parsed from stdin: plutil never
    // opens a path the person controls.
    let Some(bytes) = crate::safe_read::read_regular(path, MAX_READ) else { return (String::new(), String::new()) };
    let output = crate::command::output_with_input(Command::new("/usr/bin/plutil").args(["-convert", "json", "-o", "-", "--", "-"]), Some(&bytes), crate::command::TIMEOUT);
    let parsed: Value = output.ok().and_then(|out| serde_json::from_slice(&out.stdout).ok()).unwrap_or(Value::Null);
    let label = parsed["Label"].as_str().unwrap_or_default().to_string();
    let program = parsed["Program"].as_str().or_else(|| parsed["ProgramArguments"][0].as_str()).unwrap_or_default().to_string();
    (label, program)
}

/// Every plist job, cron and periodic file now. *known* holds the last look's items by id: an
/// unchanged file is not read again.
pub fn file_items(known: &BTreeMap<String, Item>) -> Vec<Item> {
    let mut items = Vec::new();
    for (kind, folder) in job_folders() {
        let Ok(entries) = fs::read_dir(&folder) else { continue };
        for entry in entries.flatten().take(MAX_ITEMS) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("plist") { continue; }
            let Some(mark) = mark_of(&path) else { continue };
            let id = path.display().to_string();
            let (label, program) = match known.get(&id) {
                Some(old) if old.mark == mark => (old.label.clone(), old.program.clone()),
                _ => job_of(&path),
            };
            items.push(Item { kind, id, label, program, mark });
        }
    }
    let mut jobs: Vec<(&'static str, String)> = vec![("cron", "/etc/crontab".into())];
    for (kind, folder) in [("cron", "/usr/lib/cron/tabs"), ("periodic", "/etc/periodic/daily"), ("periodic", "/etc/periodic/weekly"),
                           ("periodic", "/etc/periodic/monthly"), ("periodic", "/usr/local/etc/periodic/daily")] {
        if let Ok(entries) = fs::read_dir(folder) {
            jobs.extend(entries.flatten().take(MAX_ITEMS).map(|e| (kind, e.path().display().to_string())));
        }
    }
    for (kind, path) in jobs {
        if let Some(mark) = mark_of(Path::new(&path)) {
            let label = Path::new(&path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            items.push(Item { kind, id: path, label, program: String::new(), mark });
        }
    }
    items
}

/// Login and background items from `sfltool dumpbtm` (blocks of `Key: value` lines after `#N:`).
/// Items whose URL is a plist in a watched job folder are left to the folder scan. A `developer`
/// entry is only macOS's grouping of one developer's items (no program; its URL is "(null)") —
/// never a thing that runs, so it is not listed (E2E recheck 2026-11-21: two "(null)" rows).
/// `sfltool` writes a missing value as "(null)"; it is read as empty.
pub fn parse_btm(text: &str) -> Vec<Item> {
    let mut items = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let flush = |fields: &mut BTreeMap<String, String>, items: &mut Vec<Item>| {
        fields.retain(|_, value| value != "(null)");
        let identifier = fields.get("Identifier").cloned().unwrap_or_default();
        let url = fields.get("URL").cloned().unwrap_or_default();
        let in_folder = url.contains("/LaunchAgents/") || url.contains("/LaunchDaemons/");
        let grouping = fields.get("Type").is_some_and(|kind| kind.starts_with("developer"));
        if !identifier.is_empty() && !in_folder && !grouping {
            let program = fields.get("Executable Path").cloned().unwrap_or_else(|| url.trim_start_matches("file://").to_string());
            let label = fields.get("Name").cloned().unwrap_or_else(|| identifier.clone());
            let mark = format!("{}|{}|{}", fields.get("Type").cloned().unwrap_or_default(), fields.get("Disposition").cloned().unwrap_or_default(), program);
            items.push(Item { kind: "login-item", id: identifier, label, program, mark });
        }
        fields.clear();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') && trimmed.ends_with(':') {
            flush(&mut fields, &mut items);
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(": ") {
            fields.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    flush(&mut fields, &mut items);
    items.dedup_by(|a, b| a.id == b.id);
    items
}

/// Configuration profiles from `profiles list -all` (`… attribute: profileIdentifier: X`).
pub fn parse_profiles(text: &str) -> Vec<Item> {
    text.lines().filter_map(|line| line.split("profileIdentifier:").nth(1)).map(str::trim).filter(|id| !id.is_empty())
        .map(|id| Item { kind: "profile", id: id.to_string(), label: id.to_string(), program: String::new(), mark: id.to_string() })
        .collect()
}

/// System extensions from `systemextensionsctl list` (tab-separated rows ending in `[state]`).
pub fn parse_system_extensions(text: &str) -> Vec<Item> {
    // Rows end in "[state]"; the column header ("… bundleID (version) … [state]") does too.
    text.lines().filter(|line| line.trim_end().ends_with(']') && !line.contains("bundleID")).filter_map(|line| {
        let columns: Vec<&str> = line.split('\t').map(str::trim).filter(|c| !c.is_empty() && *c != "*").collect();
        let team = columns.first()?;
        let bundle = columns.get(1)?.split(' ').next()?;
        let name = columns.get(2).copied().unwrap_or(bundle);
        let state = columns.last().copied().unwrap_or_default();
        Some(Item { kind: "system-extension", id: format!("{team}/{bundle}"), label: name.to_string(), program: bundle.to_string(),
                    mark: format!("{}|{state}", columns.get(1).copied().unwrap_or_default()) })
    }).collect()
}

/// Third-party kernel extensions from `kmutil showloaded --list-only` (Apple's are left out).
pub fn parse_kexts(text: &str) -> Vec<Item> {
    text.lines().filter_map(|line| {
        let name = line.split_whitespace().find(|word| word.matches('.').count() >= 2 && !word.starts_with("0x"))?;
        if name.starts_with("com.apple.") { return None; }
        Some(Item { kind: "kernel-extension", id: name.to_string(), label: name.to_string(), program: String::new(), mark: line.trim().to_string() })
    }).collect()
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = crate::command::output(Command::new(program).args(args), crate::command::TIMEOUT).ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The command-listed items (`kexts` too when *with_kexts*); None for a source that failed.
pub fn command_items(with_kexts: bool) -> Vec<(&'static str, Option<Vec<Item>>)> {
    let mut sources = vec![
        ("login-item", run("/usr/bin/sfltool", &["dumpbtm"]).map(|t| parse_btm(&t))),
        ("profile", run("/usr/bin/profiles", &["list", "-all"]).map(|t| parse_profiles(&t))),
        ("system-extension", run("/usr/bin/systemextensionsctl", &["list"]).map(|t| parse_system_extensions(&t))),
    ];
    if with_kexts {
        sources.push(("kernel-extension", run("/usr/bin/kmutil", &["showloaded", "--list-only"]).map(|t| parse_kexts(&t))));
    }
    sources
}

#[cfg(test)]
mod tests {

    fn fifo_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-persist-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_fifo_or_a_link_in_a_launch_agents_folder_is_never_parsed() {
        let dir = fifo_dir();
        let fifo = dir.join("x.plist");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid C string path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert_eq!(job_of(&fifo), (String::new(), String::new()));
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "a FIFO must never block the system guard");
        let secret = dir.join("root-only.plist");
        std::fs::write(&secret, br#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>secret.label</string></dict></plist>"#).unwrap();
        let link = dir.join("link.plist");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert_eq!(job_of(&link).0, "", "a link's target is never read");
        assert_eq!(job_of(&secret).0, "secret.label", "a regular plist is read (from stdin)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    #[test]
    fn btm_login_items_parse_and_folder_jobs_are_left_to_the_scan() {
        let text = " Items:\n\n #1:\n                 Name: Docker\n                 Type: legacy daemon (0x10010)\n           Identifier: com.docker.vmnetd\n                  URL: file:///Library/LaunchDaemons/com.docker.vmnetd.plist\n #2:\n                 Name: Rectangle\n                 Type: app (0x2)\n          Disposition: [enabled, allowed, visible, notified] (0xb)\n           Identifier: com.knollsoft.Rectangle\n                  URL: file:///Applications/Rectangle.app/\n";
        let items = parse_btm(text);
        assert_eq!(items.len(), 1);
        assert_eq!((items[0].id.as_str(), items[0].label.as_str()), ("com.knollsoft.Rectangle", "Rectangle"));
        assert_eq!(items[0].program, "/Applications/Rectangle.app/");
    }

    #[test]
    fn profiles_extensions_and_kexts_parse() {
        assert_eq!(parse_profiles("_computerlevel[1] attribute: profileIdentifier: com.corp.mdm\nThere are 1 configuration profiles installed\n")[0].id, "com.corp.mdm");
        assert!(parse_profiles("There are no configuration profiles installed\n").is_empty());
        let ext = parse_system_extensions("1 extension(s)\n--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tX8Q7\tcom.vendor.filter (1.2/3)\tVendor Filter\t[activated enabled]\n");
        assert_eq!(ext.len(), 1);
        assert_eq!((ext[0].id.as_str(), ext[0].label.as_str()), ("X8Q7/com.vendor.filter", "Vendor Filter"));
        let kexts = parse_kexts("Index Refs Address Size Wired Name (Version)\n  1  0 0xffff 0x1 0x1 com.apple.kpi.bsd (24.0)\n 88  0 0xffff 0x1 0x1 com.vendor.driver (2.0) ABC <1>\n");
        assert_eq!(kexts.len(), 1);
        assert_eq!(kexts[0].id, "com.vendor.driver");
    }

    #[test]
    fn a_plist_job_names_its_label_and_program() {
        let dir = std::env::temp_dir().join(format!("bb-persist-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let plist = dir.join("com.test.job.plist");
        fs::write(&plist, "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>com.test.job</string><key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>").unwrap();
        assert_eq!(job_of(&plist), ("com.test.job".to_string(), "/usr/bin/true".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_developer_grouping_is_not_a_login_item_and_null_is_empty() {
        // Real `sfltool dumpbtm` shape (Tart VM, 2026-11-21): developer groupings carry no program.
        let text = " #1:\n                 Name: (null)\n       Developer Name: (null)\n                 Type: developer (0x20)\n           Identifier: Unknown Developer\n                  URL: (null)\n    #1: 16.limit.maxfiles\n #4:\n                 Name: Cirrus Labs, Inc.\n                 Type: developer (0x20)\n           Identifier: Cirrus Labs, Inc.\n                  URL: (null)\n #6:\n                 Name: Helper\n                 Type: app (0x2)\n           Identifier: com.example.helper\n                  URL: (null)\n      Executable Path: /Applications/Example.app/Contents/MacOS/helper\n";
        let items = parse_btm(text);
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!(items[0].id, "com.example.helper");
        assert_eq!(items[0].program, "/Applications/Example.app/Contents/MacOS/helper");
    }
}
