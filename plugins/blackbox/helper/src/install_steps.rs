//! The steps of putting the root helper on a machine that every OS's install shares (macOS's
//! `platform/macos/install.rs`, Linux's `platform/linux/install.rs`): the strict command line,
//! staging the downloaded program into a root-only folder and checking ITS SHA-256 (links never
//! followed, regular file only, capped), the per-install plan key created once and handed to the
//! person's key folder AS that person, and the public receipt (`sha256 <hex>`, 0644) the installer
//! reads without root. Each OS's install adds its own service manager and file places.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::{command, link, private_files};

pub const BINARY: &str = "blackbox-netd";
/// A helper bigger than this is not ours.
pub const MAX_BINARY: u64 = 64 * 1024 * 1024;
/// The public receipt's name, beside the helper's (root-only) folder.
pub const RECEIPT: &str = "netd-installed";
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

/// Hands the plugin its copy of the key, written as *owner* (umask 077) in *folder*.
pub fn hand_key_to(folder: &Path, owner: u32, key: &[u8]) -> Result<(), String> {
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
pub fn ensure_key(home: &Path) -> Result<Vec<u8>, String> {
    if let link::KeyFile::Key(key) = link::load_key(home) {
        return Ok(key);
    }
    let key = link::new_key();
    private_files::write(&home.join(link::KEY_FILE), &key).map_err(|error| error.to_string())?;
    Ok(key)
}

/// The public receipt: `sha256 <hex>`, 0644 — the installer compares it with the helper this
/// release carries, without root (the helper's folder is root-only).
pub fn write_receipt(path: &Path, sha256: &str) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, format!("sha256 {}\n", sha256.to_ascii_lowercase())).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| format!("{}: {error}", path.display()))
}
