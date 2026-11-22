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
//! exactly the file that was checked. Then the old service stops — and the install waits until
//! launchd has let go of it ([`super::launchd`], LES-086) — the copy moves into place, the
//! LaunchDaemon is written and bootstrapped, and the install waits until launchd reports it
//! running. The per-install plan key is created once ([`crate::link`]) and kept by every later
//! install; `--key-for` hands a copy to the plugin's state folder, written AS that user (never root
//! writing into a folder the user controls).
//!
//! An install over a working helper (an upgrade) is all-or-nothing: the helper that was there is
//! set aside first, and if anything after that fails, it is put back and started again — an
//! upgrade never ends with less protection than the person had (E2E 2026-11-21). A successful
//! install writes the public [receipt](Layout::receipt) (the installed program's SHA-256), which
//! lets the installer tell an up-to-date helper from one to upgrade without root.
//!
//! Uninstall: stops the service (which puts DNS and its pf rules back), then puts them back again
//! from `state.json` alone — so a dead helper cannot leave the Mac pointed at a resolver that is
//! gone — removes the files, and keeps posture hardening unless `--undo-hardening` was given.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use super::launchd::{self, Launchd, SystemLaunchd};
use super::{LABEL, HOME};
use crate::{command, link, private_files};

pub const BINARY: &str = "blackbox-netd";
/// A helper bigger than this is not ours.
const MAX_BINARY: u64 = 64 * 1024 * 1024;
/// The public receipt's name, beside the helper's (root-only) folder.
pub const RECEIPT: &str = "netd-installed";
/// Where an upgrade sets the helper that was there aside, inside the staging folder.
const PREVIOUS: &str = "previous-blackbox-netd";

pub fn plist_path() -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{LABEL}.plist"))
}

/// Where the helper lives: its root-only folder, its LaunchDaemon, the public receipt and the
/// launchd target. [`Layout::system`] is the Mac's; tests use a temporary one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub home: PathBuf,
    pub plist: PathBuf,
    /// `sha256 <hex>` of the installed program, 0644, beside `home` — readable without root.
    pub receipt: PathBuf,
    pub target: String,
}

impl Layout {
    pub fn system() -> Layout {
        let home = PathBuf::from(HOME);
        let receipt = home.parent().map(|parent| parent.join(RECEIPT)).unwrap_or_else(|| home.join(RECEIPT));
        Layout { home, plist: plist_path(), receipt, target: format!("system/{LABEL}") }
    }
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
    plist_for(Path::new(HOME))
}

/// The LaunchDaemon for a helper in *home*.
pub fn plist_for(home: &Path) -> String {
    let home = home.display();
    format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{home}/{BINARY}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{home}/netd.log</string>
  <key>StandardErrorPath</key><string>{home}/netd.log</string>
</dict>
</plist>
"#)
}

pub use super::launchd::parse_running;

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
    install_into(args, &Layout::system(), &SystemLaunchd,
                 &|| crate::put_back(&super::SystemEnforcer::default(), crate::undo_for(crate::Stopping::Service)))
}

/// [`install`] into *layout* through *launchd* — what the tests drive with a temporary layout and
/// a fake launchd. *put_back* puts DNS and the firewall back when an upgrade ends with no helper
/// running at all (the old one kept them in place for the hand-over, [`crate::handover`]).
pub fn install_into(args: &InstallArgs, layout: &Layout, launchd: &dyn Launchd,
                    put_back: &dyn Fn() -> Vec<String>) -> Result<(), String> {
    let parent = layout.home.parent().ok_or("the helper's folder has no parent")?;
    fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    let staging = parent.join(format!(".netd-staging-{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    private_files::ensure_dir(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
    let result = install_from_staging(args, &staging, layout, launchd, put_back);
    let _ = fs::remove_dir_all(&staging);
    result
}

/// The helper that was installed before this one, set aside so a failed upgrade can put it back.
struct Previous {
    binary: PathBuf,
    plist: Option<String>,
}

impl Previous {
    /// Moves an installed program aside into *staging* (the same volume: a rename) and keeps its
    /// LaunchDaemon's text. None on a first install.
    fn set_aside(layout: &Layout, staging: &Path) -> Result<Option<Previous>, String> {
        let installed = layout.home.join(BINARY);
        if !installed.is_file() {
            return Ok(None);
        }
        let binary = staging.join(PREVIOUS);
        fs::rename(&installed, &binary).map_err(|error| format!("{}: {error}", installed.display()))?;
        Ok(Some(Previous { binary, plist: fs::read_to_string(&layout.plist).ok() }))
    }

    /// Puts this helper back and starts it again. Answers what could not be done, if anything.
    fn restore(self, layout: &Layout, launchd: &dyn Launchd) -> Result<(), String> {
        launchd::stop(launchd, &layout.target);
        let installed = layout.home.join(BINARY);
        fs::rename(&self.binary, &installed).map_err(|error| format!("{}: {error}", installed.display()))?;
        write_plist(&layout.plist, &self.plist.unwrap_or_else(|| plist_for(&layout.home)))?;
        launchd::start(launchd, &layout.target, &layout.plist)
    }
}

fn install_from_staging(args: &InstallArgs, staging: &Path, layout: &Layout, launchd: &dyn Launchd,
                        put_back: &dyn Fn() -> Vec<String>) -> Result<(), String> {
    let copy = stage(&args.from, &args.sha256, staging)?;
    if let Some(team) = &args.team_id {
        check_signature(&copy, team)?;
    }
    // Verified. Only now does anything on the Mac change — and from here, a failure puts back
    // whatever helper was running before.
    if layout.home.join(BINARY).is_file() {
        // An upgrade: the old helper keeps DNS and the firewall in place when it stops (KI-537).
        crate::handover::begin(&layout.home)?;
    }
    launchd::stop(launchd, &layout.target);
    private_files::ensure_dir(&layout.home).map_err(|error| format!("{}: {error}", layout.home.display()))?;
    let previous = Previous::set_aside(layout, staging)?;
    let placed = put_in_place(args, &copy, layout, launchd);
    crate::handover::clear(&layout.home);   // over either way: the next ordinary stop puts the Mac back
    match placed {
        Ok(()) => write_receipt(&layout.receipt, &args.sha256),
        Err(error) => Err(match previous {
            Some(previous) => match previous.restore(layout, launchd) {
                Ok(()) => format!("{error} — the helper you had is back in place and running"),
                Err(restore) => {
                    // No helper runs at all: DNS must not point at a resolver that is gone.
                    let failed = put_back();
                    let back = if failed.is_empty() { "DNS and the firewall are back to how they were".to_string() }
                               else { format!("putting DNS and the firewall back also failed: {}", failed.join("; ")) };
                    format!("{error}; putting the previous helper back also failed: {restore}; {back}")
                }
            },
            None => {
                // A first install that failed leaves nothing half-installed.
                let _ = fs::remove_file(layout.home.join(BINARY));
                let _ = fs::remove_file(&layout.plist);
                error
            }
        }),
    }
}

/// Moves the verified *copy* into place, keeps (or creates) the plan key, hands it over, writes
/// the LaunchDaemon and starts it.
fn put_in_place(args: &InstallArgs, copy: &Path, layout: &Layout, launchd: &dyn Launchd) -> Result<(), String> {
    let target = layout.home.join(BINARY);
    fs::rename(copy, &target).map_err(|error| format!("{}: {error}", target.display()))?;
    let key = ensure_key(&layout.home)?;
    if let (Some(folder), Some(owner)) = (&args.key_for, args.owner) {
        hand_key_to(folder, owner, &key)?;
    }
    write_plist(&layout.plist, &plist_for(&layout.home))?;
    launchd::start(launchd, &layout.target, &layout.plist)
        .map_err(|error| format!("the helper did not start: {error} (see {}/netd.log)", layout.home.display()))
}

fn write_plist(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())
}

/// The public receipt: `sha256 <hex>`, 0644 — the installer compares it with the helper this
/// release carries, without root (the helper's folder is root-only).
fn write_receipt(path: &Path, sha256: &str) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, format!("sha256 {}\n", sha256.to_ascii_lowercase())).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn uninstall(undo_hardening: bool) -> Result<(), String> {
    let layout = Layout::system();
    launchd::stop(&SystemLaunchd, &layout.target);
    let errors = crate::put_back(&super::SystemEnforcer::default(), crate::undo_for(crate::Stopping::Uninstall { undo_hardening }));
    let _ = fs::remove_file(&layout.plist);
    let _ = fs::remove_file(&layout.receipt);
    if errors.is_empty() {
        remove_home(&layout);
        Ok(())
    } else {
        // The state stays, so a second uninstall can try again.
        Err(format!("the helper was stopped but not everything could be put back: {}", errors.join("; ")))
    }
}

/// Removes the helper's folder, then its parent ("…/Application Support/Blackbox") only when that is
/// left EMPTY — `remove_dir` refuses a folder with anything in it, so another Blackbox part's files
/// are never touched (E2E recheck 2026-11-21: an empty root-owned folder stayed after uninstall).
fn remove_home(layout: &Layout) {
    let _ = fs::remove_dir_all(&layout.home);
    if let Some(parent) = layout.home.parent() {
        let _ = fs::remove_dir(parent);
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

    /// A temporary layout holding an installed helper (*old* bytes, its plan key, a receipt).
    fn installed(name: &str, old: &[u8]) -> (PathBuf, Layout) {
        let dir = temp(name);
        let layout = Layout {
            home: dir.join("netd"),
            plist: dir.join("netd.plist"),
            receipt: dir.join(RECEIPT),
            target: "system/test".into(),
        };
        private_files::ensure_dir(&layout.home).unwrap();
        fs::write(layout.home.join(BINARY), old).unwrap();
        fs::write(&layout.plist, plist_for(&layout.home)).unwrap();
        ensure_key(&layout.home).unwrap();
        write_receipt(&layout.receipt, &hex::encode(Sha256::digest(old))).unwrap();
        (dir, layout)
    }

    fn args_for(dir: &Path, new: &[u8]) -> InstallArgs {
        let from = dir.join("downloaded");
        fs::write(&from, new).unwrap();
        InstallArgs { from, sha256: hex::encode(Sha256::digest(new)), ..Default::default() }
    }

    #[test]
    fn an_upgrade_launchd_refuses_puts_the_helper_that_was_there_back_and_running() {
        // E2E 2026-11-21: "Bootstrap failed: 5: Input/output error" during an upgrade ended with
        // no helper at all. Now the previous one is restored and started again.
        let (dir, layout) = installed("refused", b"old helper");
        let key = link::load_key(&layout.home).unwrap();
        let launchd = launchd::fake::FakeLaunchd {
            linger: 2,
            refuse: Some((layout.home.join(BINARY), b"new helper".to_vec())),
            ..Default::default()
        };
        launchd.state.borrow_mut().loaded = true;
        let error = install_into(&args_for(&dir, b"new helper"), &layout, &launchd, &no_put_back).unwrap_err();
        assert!(error.contains("back in place and running"), "{error}");
        assert_eq!(fs::read(layout.home.join(BINARY)).unwrap(), b"old helper");
        assert!(launchd.state.borrow().loaded, "the old helper runs again");
        assert_eq!(fs::read_to_string(&layout.plist).unwrap(), plist_for(&layout.home));
        assert_eq!(link::load_key(&layout.home).unwrap(), key, "pairing kept");
        assert!(fs::read_to_string(&layout.receipt).unwrap().contains(&hex::encode(Sha256::digest(b"old helper"))));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_upgrade_waits_for_launchd_to_let_go_keeps_the_key_and_records_the_new_helper() {
        let (dir, layout) = installed("upgrade", b"old helper");
        let key = link::load_key(&layout.home).unwrap();
        let launchd = launchd::fake::FakeLaunchd { linger: 3, ..Default::default() };
        launchd.state.borrow_mut().loaded = true;
        install_into(&args_for(&dir, b"new helper"), &layout, &launchd, &no_put_back).unwrap();
        assert_eq!(fs::read(layout.home.join(BINARY)).unwrap(), b"new helper");
        assert_eq!(launchd.state.borrow().bootstraps, 1, "it waited for the old job instead of failing a bootstrap");
        assert_eq!(link::load_key(&layout.home).unwrap(), key, "an upgrade never replaces the plan key");
        assert_eq!(fs::read_to_string(&layout.receipt).unwrap(), format!("sha256 {}\n", hex::encode(Sha256::digest(b"new helper"))));
        assert_eq!(fs::metadata(&layout.receipt).unwrap().permissions().mode() & 0o777, 0o644, "readable without root");
        let _ = fs::remove_dir_all(&dir);
    }

    fn no_put_back() -> Vec<String> {
        panic!("put_back runs only when no helper is left running")
    }

    /// A launchd that answers like the fake, records whether a hand-over was marked when it was
    /// asked to stop the old helper, and can refuse every start.
    struct Watching<'a> {
        inner: launchd::fake::FakeLaunchd,
        home: &'a Path,
        marked_at_stop: std::cell::Cell<Option<bool>>,
        refuse_all: bool,
    }

    impl Launchd for Watching<'_> {
        fn bootout(&self, target: &str) {
            if self.marked_at_stop.get().is_none() {
                self.marked_at_stop.set(Some(crate::handover::pending(self.home, std::time::SystemTime::now())));
            }
            self.inner.bootout(target)
        }
        fn bootstrap(&self, plist: &Path) -> Result<(), String> {
            if self.refuse_all { Err("Bootstrap failed: 5: Input/output error".into()) } else { self.inner.bootstrap(plist) }
        }
        fn known(&self, target: &str) -> bool { self.inner.known(target) }
        fn running(&self, target: &str) -> bool { self.inner.running(target) }
        fn pause(&self, pause: std::time::Duration) { self.inner.pause(pause) }
    }

    #[test]
    fn an_upgrade_marks_a_hand_over_so_the_old_helper_keeps_protection_and_clears_it_after() {
        // KI-537 (E2E full4): the old helper put DNS back and emptied the firewall on every upgrade.
        let (dir, layout) = installed("handover", b"old helper");
        let watching = Watching { inner: Default::default(), home: &layout.home, marked_at_stop: Default::default(), refuse_all: false };
        watching.inner.state.borrow_mut().loaded = true;
        install_into(&args_for(&dir, b"new helper"), &layout, &watching, &no_put_back).unwrap();
        assert_eq!(watching.marked_at_stop.get(), Some(true), "the old helper saw the hand-over when it was stopped");
        assert!(!crate::handover::pending(&layout.home, std::time::SystemTime::now()), "cleared once over");
        assert_eq!(crate::undo_for(crate::Stopping::Handover), crate::Undo { dns: false, filter: false, hardening: false });
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_upgrade_that_ends_with_no_helper_puts_dns_and_the_firewall_back() {
        let (dir, layout) = installed("nohelper", b"old helper");
        let watching = Watching { inner: Default::default(), home: &layout.home, marked_at_stop: Default::default(), refuse_all: true };
        watching.inner.state.borrow_mut().loaded = true;
        let called = std::cell::Cell::new(0);
        let error = install_into(&args_for(&dir, b"new helper"), &layout, &watching, &|| { called.set(called.get() + 1); vec![] })
            .unwrap_err();
        assert_eq!(called.get(), 1, "{error}");
        assert!(error.contains("DNS and the firewall are back"), "{error}");
        assert!(!crate::handover::pending(&layout.home, std::time::SystemTime::now()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_first_install_that_fails_leaves_nothing_half_installed() {
        let dir = temp("first");
        let layout = Layout { home: dir.join("netd"), plist: dir.join("netd.plist"), receipt: dir.join(RECEIPT), target: "system/test".into() };
        let launchd = launchd::fake::FakeLaunchd { refuse: Some((layout.home.join(BINARY), b"new helper".to_vec())), ..Default::default() };
        assert!(install_into(&args_for(&dir, b"new helper"), &layout, &launchd, &no_put_back).is_err());
        assert!(!layout.home.join(BINARY).exists() && !layout.plist.exists() && !layout.receipt.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn launchd_and_codesign_answers_read() {
        assert!(parse_running("system/ai.umanitek.blackbox.netd = {\n\tactive count = 1\n\tstate = running\n"));
        assert!(!parse_running("\tstate = spawn scheduled\n"));
        assert_eq!(parse_team_id("Executable=/x\nTeamIdentifier=ABCDE12345\n"), Some("ABCDE12345".into()));
        assert_eq!(parse_team_id("TeamIdentifier=not set\n"), None);
        assert!(plist().contains(&format!("{HOME}/netd.log")), "logs inside the 0700 folder");
    }

    #[test]
    fn uninstall_removes_the_parent_folder_only_when_it_is_left_empty() {
        let dir = std::env::temp_dir().join(format!("bb-netd-parent-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let parent = dir.join("Blackbox");
        let layout = Layout { home: parent.join("netd"), plist: dir.join("netd.plist"), receipt: parent.join(RECEIPT), target: "system/test".into() };
        fs::create_dir_all(&layout.home).unwrap();
        fs::write(layout.home.join("state.json"), "{}").unwrap();
        remove_home(&layout);
        assert!(!parent.exists(), "an empty parent goes");
        fs::create_dir_all(&layout.home).unwrap();
        fs::write(parent.join("someone-elses.txt"), "keep").unwrap();
        remove_home(&layout);
        assert!(!layout.home.exists() && parent.join("someone-elses.txt").exists(), "a non-empty parent stays");
        let _ = fs::remove_dir_all(&dir);
    }
}
