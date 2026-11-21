//! `blackbox-netd install` and `blackbox-netd uninstall` — the ONE way the root helper is put on
//! a Mac and taken off it, used by the plugin's installer (`scripts/blackbox-install.sh`) and by
//! Blackbox Desktop alike. Run as root (sudo, or Desktop's admin prompt).
//!
//! ```text
//! blackbox-netd install --from <binary> --sha256 <64 hex> [--team-id <ID>]
//!                       [--key-for <folder> --owner <uid>]
//! blackbox-netd uninstall [--undo-hardening]
//! ```
//!
//! Install (security finding: the old script copied whatever sat at the path and bootstrapped it
//! unverified): the binary is copied — without following links, regular file only — into a
//! root-only staging folder; the SHA-256 of THAT copy (and, with `--team-id`, its Developer ID
//! signature) is checked BEFORE anything is installed or started, so the file that runs is
//! exactly the file that was checked. Then the old service stops, the copy moves into place, the
//! LaunchDaemon is written and bootstrapped, and the install waits until launchd reports it
//! running. The per-install plan key is created once ([`crate::link`]); `--key-for` hands a copy
//! to the plugin's state folder, written AS that user (never root writing into a folder the user
//! controls).
//!
//! Uninstall: stops the service (which puts DNS and its pf rules back), then puts them back again
//! from `state.json` alone — so a dead helper cannot leave the Mac pointed at a resolver that is
//! gone — removes the files, and keeps posture hardening unless `--undo-hardening` was given.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::{LABEL, HOME};
use crate::{command, link, private_files};

pub const BINARY: &str = "blackbox-netd";
/// A helper bigger than this is not ours.
const MAX_BINARY: u64 = 64 * 1024 * 1024;
const RUNNING_WAIT: Duration = Duration::from_secs(10);

pub fn plist_path() -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{LABEL}.plist"))
}

/// The parsed command line of `install`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstallArgs {
    pub from: PathBuf,
    pub sha256: String,
    pub team_id: Option<String>,
    pub key_for: Option<PathBuf>,
    pub owner: Option<u32>,
}

impl InstallArgs {
    pub fn parse(args: &[String]) -> Result<InstallArgs, String> {
        let mut parsed = InstallArgs::default();
        let mut words = args.iter();
        while let Some(word) = words.next() {
            let mut value = || words.next().cloned().ok_or(format!("{word} needs a value"));
            match word.as_str() {
                "--from" => parsed.from = PathBuf::from(value()?),
                "--sha256" => parsed.sha256 = value()?.to_ascii_lowercase(),
                "--team-id" => parsed.team_id = Some(value()?),
                "--key-for" => parsed.key_for = Some(PathBuf::from(value()?)),
                "--owner" => parsed.owner = Some(value()?.parse().map_err(|_| "--owner takes a numeric user id".to_string())?),
                other => return Err(format!("unknown option {other}")),
            }
        }
        if parsed.from.as_os_str().is_empty() {
            return Err("--from <binary> is required".into());
        }
        if parsed.sha256.len() != 64 || !parsed.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("--sha256 takes the binary's 64-character SHA-256".into());
        }
        if parsed.key_for.is_some() != parsed.owner.is_some() {
            return Err("--key-for and --owner go together".into());
        }
        if let Some(team) = &parsed.team_id {
            if team.is_empty() || !team.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err("--team-id takes a Developer ID team identifier".into());
            }
        }
        Ok(parsed)
    }
}

/// Copies *from* into *staging* (links not followed, regular file only, capped) and checks the
/// copy's SHA-256 against *expected*. The copy is removed on a mismatch. Answers the copy's path.
pub fn stage(from: &Path, expected: &str, staging: &Path) -> Result<PathBuf, String> {
    let bytes = crate::safe_read::read_regular(from, MAX_BINARY)
        .ok_or_else(|| format!("{}: not a regular file Blackbox can install", from.display()))?;
    let copy = staging.join(BINARY);
    private_files::write(&copy, &bytes).map_err(|error| format!("{}: {error}", copy.display()))?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != expected.to_ascii_lowercase() {
        let _ = fs::remove_file(&copy);
        return Err(format!("the helper's checksum does not match (expected {expected}, got {actual}): nothing was installed"));
    }
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    Ok(copy)
}

/// `TeamIdentifier=ABCDE12345` from `codesign -dv` (it writes to stderr).
pub fn parse_team_id(text: &str) -> Option<String> {
    text.lines().find_map(|line| line.trim().strip_prefix("TeamIdentifier=").map(str::to_string)).filter(|t| t != "not set")
}

fn check_signature(copy: &Path, team: &str) -> Result<(), String> {
    let verify = command::output(Command::new("/usr/bin/codesign").args(["--verify", "--strict"]).arg(copy), command::TIMEOUT)
        .map_err(|error| error.to_string())?;
    if !verify.status.success() {
        return Err(format!("the helper's signature is not valid: {}", String::from_utf8_lossy(&verify.stderr).trim()));
    }
    let details = command::output(Command::new("/usr/bin/codesign").arg("-dv").arg(copy), command::TIMEOUT).map_err(|error| error.to_string())?;
    match parse_team_id(&String::from_utf8_lossy(&details.stderr)) {
        Some(found) if found == team => Ok(()),
        found => Err(format!("the helper is not signed by team {team} (found {})", found.as_deref().unwrap_or("none"))),
    }
}

/// The LaunchDaemon. Logs go inside the helper's own 0700 folder.
pub fn plist() -> String {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{HOME}/{BINARY}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{HOME}/netd.log</string>
  <key>StandardErrorPath</key><string>{HOME}/netd.log</string>
</dict>
</plist>
"#)
}

/// Whether `launchctl print system/<label>` shows the job running.
pub fn parse_running(text: &str) -> bool {
    text.lines().any(|line| line.trim() == "state = running")
}

fn launchctl(args: &[&str]) -> Result<String, String> {
    let out = command::output(Command::new("/bin/launchctl").args(args), command::TIMEOUT).map_err(|error| error.to_string())?;
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() { Ok(text) } else { Err(format!("launchctl {}: {}", args.join(" "), text.trim())) }
}

/// Hands the plugin its copy of the key, written as *owner* (umask 077) in *folder*.
fn hand_key_to(folder: &Path, owner: u32, key: &[u8]) -> Result<(), String> {
    // SAFETY: getpwuid returns a pointer into static storage or null; read at once.
    let gid = unsafe { let entry = libc::getpwuid(owner); if entry.is_null() { None } else { Some((*entry).pw_gid) } }
        .ok_or_else(|| format!("no user with id {owner}"))?;
    let script = r#"umask 077 && mkdir -p "$1" && cat > "$1/plan.key.tmp" && mv -f "$1/plan.key.tmp" "$1/plan.key""#;
    let mut sh = Command::new("/bin/sh");
    sh.args(["-c", script, "sh"]).arg(folder).uid(owner).gid(gid).env_clear();
    let out = command::output_with_input(&mut sh, Some(key), command::TIMEOUT).map_err(|error| error.to_string())?;
    if out.status.success() { Ok(()) } else { Err(format!("the plugin's key copy: {}", String::from_utf8_lossy(&out.stderr).trim())) }
}

/// The plan key, created once (a reinstall keeps it, so the plugin's copy stays valid).
fn ensure_key(home: &Path) -> Result<Vec<u8>, String> {
    if let Some(key) = link::load_key(home).filter(|key| key.len() == link::KEY_BYTES) {
        return Ok(key);
    }
    let key = link::new_key();
    private_files::write(&home.join(link::KEY_FILE), &key).map_err(|error| error.to_string())?;
    Ok(key)
}

pub fn install(args: &InstallArgs) -> Result<(), String> {
    let parent = Path::new(HOME).parent().ok_or("the helper's folder has no parent")?;
    fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    let staging = parent.join(format!(".netd-staging-{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    private_files::ensure_dir(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
    let result = install_from_staging(args, &staging);
    let _ = fs::remove_dir_all(&staging);
    result
}

fn install_from_staging(args: &InstallArgs, staging: &Path) -> Result<(), String> {
    let copy = stage(&args.from, &args.sha256, staging)?;
    if let Some(team) = &args.team_id {
        check_signature(&copy, team)?;
    }
    // Verified. Only now does anything on the Mac change.
    let _ = launchctl(&["bootout", &format!("system/{LABEL}")]);   // not loaded on a first install
    let home = Path::new(HOME);
    private_files::ensure_dir(home).map_err(|error| format!("{HOME}: {error}"))?;
    let target = home.join(BINARY);
    fs::rename(&copy, &target).map_err(|error| format!("{}: {error}", target.display()))?;
    let key = ensure_key(home)?;
    if let (Some(folder), Some(owner)) = (&args.key_for, args.owner) {
        hand_key_to(folder, owner, &key)?;
    }
    let plist_file = plist_path();
    fs::write(&plist_file, plist()).map_err(|error| format!("{}: {error}", plist_file.display()))?;
    fs::set_permissions(&plist_file, fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())?;
    launchctl(&["bootstrap", "system", &plist_file.to_string_lossy()])?;
    let started = Instant::now();
    while started.elapsed() < RUNNING_WAIT {
        if launchctl(&["print", &format!("system/{LABEL}")]).map(|text| parse_running(&text)).unwrap_or(false) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!("the helper was installed but launchd does not show it running (see {HOME}/netd.log)"))
}

pub fn uninstall(undo_hardening: bool) -> Result<(), String> {
    let _ = launchctl(&["bootout", &format!("system/{LABEL}")]);
    let errors = crate::put_back(&super::SystemEnforcer::default(), crate::undo_for(crate::Stopping::Uninstall { undo_hardening }));
    let _ = fs::remove_file(plist_path());
    if errors.is_empty() {
        let _ = fs::remove_dir_all(HOME);
        Ok(())
    } else {
        // The state stays, so a second uninstall can try again.
        Err(format!("the helper was stopped but not everything could be put back: {}", errors.join("; ")))
    }
}

/// The `install` / `uninstall` subcommands. None when *args* names neither (run the service).
pub fn subcommand(args: &[String]) -> Option<Result<(), String>> {
    match args.first().map(String::as_str) {
        Some("install") => Some(InstallArgs::parse(&args[1..]).and_then(|parsed| install(&parsed))),
        Some("uninstall") => Some(match &args[1..] {
            [] => uninstall(false),
            [flag] if flag == "--undo-hardening" => uninstall(true),
            _ => Err("uninstall takes only --undo-hardening".into()),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-install-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_binary_whose_checksum_does_not_match_is_never_installed() {
        let dir = temp("mismatch");
        let source = dir.join("downloaded");
        fs::write(&source, b"not the helper").unwrap();
        let staging = dir.join("staging");
        private_files::ensure_dir(&staging).unwrap();
        let wrong = "0".repeat(64);
        assert!(stage(&source, &wrong, &staging).unwrap_err().contains("does not match"));
        assert!(!staging.join(BINARY).exists(), "the refused copy is gone");
        let right = hex::encode(Sha256::digest(b"not the helper"));
        let copy = stage(&source, &right, &staging).unwrap();
        assert_eq!(fs::read(&copy).unwrap(), b"not the helper");
        assert_eq!(fs::metadata(&copy).unwrap().permissions().mode() & 0o777, 0o755);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_link_is_never_staged() {
        let dir = temp("link");
        fs::write(dir.join("real"), b"x").unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        let right = hex::encode(Sha256::digest(b"x"));
        assert!(stage(&dir.join("link"), &right, &dir).is_err(), "swapping a link in after the check is pointless: links are refused");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_command_line_is_strict() {
        let words = |text: &str| text.split_whitespace().map(String::from).collect::<Vec<_>>();
        let sha = "a".repeat(64);
        let ok = InstallArgs::parse(&words(&format!("--from /tmp/h --sha256 {sha} --key-for /Users/a/.bb/helper --owner 501"))).unwrap();
        assert_eq!((ok.owner, ok.key_for.as_deref()), (Some(501), Some(Path::new("/Users/a/.bb/helper"))));
        assert!(InstallArgs::parse(&words("--from /tmp/h --sha256 abc")).is_err(), "a short checksum");
        assert!(InstallArgs::parse(&words(&format!("--sha256 {sha}"))).is_err(), "no binary");
        assert!(InstallArgs::parse(&words(&format!("--from /tmp/h --sha256 {sha} --owner 501"))).is_err(), "owner without folder");
        assert!(InstallArgs::parse(&words(&format!("--from /tmp/h --sha256 {sha} --team-id A;B"))).is_err());
        assert!(subcommand(&words("uninstall --everything")).unwrap().is_err());
        assert!(subcommand(&[]).is_none(), "no subcommand: run the service");
    }

    #[test]
    fn launchd_and_codesign_answers_read() {
        assert!(parse_running("system/ai.umanitek.blackbox.netd = {\n\tactive count = 1\n\tstate = running\n"));
        assert!(!parse_running("\tstate = spawn scheduled\n"));
        assert_eq!(parse_team_id("Executable=/x\nTeamIdentifier=ABCDE12345\n"), Some("ABCDE12345".into()));
        assert_eq!(parse_team_id("TeamIdentifier=not set\n"), None);
        assert!(plist().contains(&format!("{HOME}/netd.log")), "logs inside the 0700 folder");
    }
}
