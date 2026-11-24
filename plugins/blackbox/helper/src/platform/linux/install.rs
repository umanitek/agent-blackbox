//! `blackbox-netd install` and `blackbox-netd uninstall` on Linux — the ONE way the root helper is
//! put on a Linux machine and taken off it, used by the plugin's installer
//! (`scripts/blackbox-install.sh`, under `sudo`, then `sudo -k`). Mirrors `platform/macos/install.rs`
//! with systemd for launchd; the steps every OS shares (the strict command line, the checked
//! root-only staging copy, the plan key and its hand-over, the receipt) are `crate::install_steps`.
//!
//! ```text
//! blackbox-netd install --from <binary> --sha256 <64 hex> [--key-for <folder> --owner <uid>]
//! blackbox-netd uninstall [--undo-hardening]
//! ```
//!
//! Install: the downloaded program is copied (links never followed, regular file only) into a
//! root-only staging folder under [`LIB`] and the SHA-256 of THAT copy is checked before anything
//! changes. An upgrade then marks a hand-over (the old helper keeps DNS and the firewall in place,
//! KI-537), stops the unit, sets the old program aside beside the new place, moves the checked copy
//! to [`BINARY`] (written in its own folder, then renamed: `/usr/local` and `/var/lib` may be
//! different file systems), keeps (or creates once) the plan key, hands the person their copy AS
//! them, writes the unit (0644), gives the program and unit SELinux's labels where SELinux is on
//! (`restorecon -F`), and enables and starts the unit, waiting until systemd reports it active.
//! All-or-nothing: an upgrade that fails puts the old program back and starts it; a first install
//! that fails leaves nothing behind. Success writes the public receipt ([`RECEIPT_PATH`]).
//!
//! Uninstall: stops the unit (the helper's own stop puts DNS and nftables back), puts them back
//! again from `state.json` alone, disables and removes the unit, the program and the helper's
//! folders (a parent only when left empty), and keeps posture hardening unless asked.
//!
//! The unit: `Restart=always` — a SIGTERM is a clean exit for systemd, and Linux round L1 showed
//! `on-failure` leaves a stopped Blackbox service down; `NoNewPrivileges`, a private /tmp, the
//! person's homes read-only, and only the capabilities the helper uses.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::systemd::{self, SystemSystemd, Systemd};
use super::{BINARY, HOME, UNIT};
use crate::install_steps::{ensure_key, hand_key_to, stage, write_receipt, InstallArgs, BINARY as PROGRAM};
use crate::private_files;

/// Blackbox's root-owned folder (the helper's home is inside it).
pub const LIB: &str = "/var/lib/blackbox";
/// The public receipt (`sha256 <hex>`, 0644), readable without root.
pub const RECEIPT_PATH: &str = "/var/lib/blackbox/netd-installed";
/// The unit's name.
pub const UNIT_NAME: &str = "blackbox-netd.service";
/// The program set aside during an upgrade, beside the installed one (same file system).
const PREVIOUS: &str = "blackbox-netd.previous";

/// Where the helper lives on this machine; [`Layout::system`] is the real one, tests use a temporary one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub lib: PathBuf,
    pub home: PathBuf,
    pub binary: PathBuf,
    pub unit: PathBuf,
    pub receipt: PathBuf,
}

impl Layout {
    pub fn system() -> Layout {
        Layout { lib: LIB.into(), home: HOME.into(), binary: BINARY.into(), unit: UNIT.into(), receipt: RECEIPT_PATH.into() }
    }
}

/// The unit for a helper at *binary* keeping its state in *home*.
pub fn unit_text(binary: &Path, home: &Path) -> String {
    let (binary, home) = (binary.display(), home.display());
    format!("# Blackbox system protection helper — written by `blackbox-netd install`, removed by its uninstall.
[Unit]
Description=Blackbox system protection helper (DNS Shield, Threat Firewall, system watch)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary}
Restart=always
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
RuntimeDirectory=blackbox-netd
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_KILL CAP_AUDIT_READ CAP_SYS_PTRACE CAP_CHOWN CAP_FOWNER
StandardOutput=append:{home}/netd.log
StandardError=append:{home}/netd.log

[Install]
WantedBy=multi-user.target
")
}

pub fn install(args: &InstallArgs) -> Result<(), String> {
    install_into(args, &Layout::system(), &SystemSystemd,
                 &|| crate::put_back(&super::SystemEnforcer::default(), crate::undo_for(crate::Stopping::Service)))
}

/// [`install`] into *layout* through *systemd* (tests pass a temporary layout and a fake).
/// *put_back* puts DNS and the firewall back when an upgrade ends with no helper running at all.
pub fn install_into(args: &InstallArgs, layout: &Layout, systemd: &dyn Systemd, put_back: &dyn Fn() -> Vec<String>) -> Result<(), String> {
    if args.team_id.is_some() {
        return Err("--team-id is a macOS signature check; Linux checks the SHA-256 only".into());
    }
    private_files::ensure_dir(&layout.lib).map_err(|error| format!("{}: {error}", layout.lib.display()))?;
    let staging = layout.lib.join(format!(".netd-staging-{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    private_files::ensure_dir(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
    let result = stage(&args.from, &args.sha256, &staging).and_then(|copy| install_checked(args, &copy, layout, systemd, put_back));
    let _ = fs::remove_dir_all(&staging);
    result
}

fn install_checked(args: &InstallArgs, copy: &Path, layout: &Layout, systemd: &dyn Systemd,
                   put_back: &dyn Fn() -> Vec<String>) -> Result<(), String> {
    // Checked. Only now does anything on the machine change — and from here, a failure puts back
    // whatever helper was running before.
    private_files::ensure_dir(&layout.home).map_err(|error| format!("{}: {error}", layout.home.display()))?;
    let upgrade = layout.binary.is_file();
    if upgrade {
        crate::handover::begin(&layout.home)?;
    }
    systemd.stop(UNIT_NAME);
    let previous = layout.binary.with_file_name(PREVIOUS);
    if upgrade {
        fs::rename(&layout.binary, &previous).map_err(|error| format!("{}: {error}", layout.binary.display()))?;
    }
    let placed = put_in_place(args, copy, layout, systemd);
    crate::handover::clear(&layout.home);
    match placed {
        Ok(()) => {
            let _ = fs::remove_file(&previous);
            write_receipt(&layout.receipt, &args.sha256)
        }
        Err(error) if upgrade => Err(restore_previous(error, &previous, layout, systemd, put_back)),
        Err(error) => {
            let _ = fs::remove_file(&layout.binary);
            systemd.disable(UNIT_NAME);
            let _ = fs::remove_file(&layout.unit);
            systemd.reload();
            Err(error)
        }
    }
}

/// A failed upgrade: the program that was there goes back and runs again (or, when even that
/// fails, DNS and the firewall are put back so the machine is never left offline).
fn restore_previous(error: String, previous: &Path, layout: &Layout, systemd: &dyn Systemd, put_back: &dyn Fn() -> Vec<String>) -> String {
    systemd.stop(UNIT_NAME);
    let back = fs::rename(previous, &layout.binary).map_err(|e| e.to_string())
        .and_then(|()| write_unit(&layout.unit, &unit_text(&layout.binary, &layout.home)))
        .and_then(|()| systemd::start(systemd, UNIT_NAME));
    match back {
        Ok(()) => format!("{error} — the helper you had is back in place and running"),
        Err(restore) => {
            let failed = put_back();
            let net = if failed.is_empty() { "DNS and the firewall are back to how they were".to_string() }
                      else { format!("putting DNS and the firewall back also failed: {}", failed.join("; ")) };
            format!("{error}; putting the previous helper back also failed: {restore}; {net}")
        }
    }
}

/// Moves the checked *copy* to the program's place, keeps (or makes) the plan key, hands it over,
/// writes and labels the unit, and starts it.
fn put_in_place(args: &InstallArgs, copy: &Path, layout: &Layout, systemd: &dyn Systemd) -> Result<(), String> {
    let folder = layout.binary.parent().ok_or("the helper's program place has no folder")?;
    fs::create_dir_all(folder).map_err(|error| format!("{}: {error}", folder.display()))?;
    fs::set_permissions(folder, fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    let incoming = folder.join(format!(".{PROGRAM}.incoming"));
    fs::copy(copy, &incoming).map_err(|error| format!("{}: {error}", incoming.display()))?;
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o755)).map_err(|error| error.to_string())?;
    fs::rename(&incoming, &layout.binary).map_err(|error| format!("{}: {error}", layout.binary.display()))?;
    let key = ensure_key(&layout.home)?;
    if let (Some(folder), Some(owner)) = (&args.key_for, args.owner) {
        hand_key_to(folder, owner, &key)?;
    }
    write_unit(&layout.unit, &unit_text(&layout.binary, &layout.home))?;
    systemd.relabel(&[layout.binary.as_path(), layout.unit.as_path()]);
    systemd::start(systemd, UNIT_NAME)
        .map_err(|error| format!("the helper did not start: {error} (see {}/netd.log, journalctl -u {UNIT_NAME})", layout.home.display()))
}

fn write_unit(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(|error| error.to_string())
}

pub fn uninstall(undo_hardening: bool) -> Result<(), String> {
    uninstall_from(&Layout::system(), &SystemSystemd,
                   &|| crate::put_back(&super::SystemEnforcer::default(), crate::undo_for(crate::Stopping::Uninstall { undo_hardening })))
}

/// [`uninstall`] for *layout* through *systemd*; *put_back* restores DNS and the firewall from state.
pub fn uninstall_from(layout: &Layout, systemd: &dyn Systemd, put_back: &dyn Fn() -> Vec<String>) -> Result<(), String> {
    systemd.stop(UNIT_NAME);
    let errors = put_back();
    systemd.disable(UNIT_NAME);
    let _ = fs::remove_file(&layout.unit);
    systemd.reload();
    let _ = fs::remove_file(&layout.receipt);
    let _ = fs::remove_file(&layout.binary);
    if let Some(folder) = layout.binary.parent() {
        let _ = fs::remove_dir(folder);   // only when empty: another Blackbox program may live there
    }
    if !errors.is_empty() {
        // The state stays, so a second uninstall can try again.
        return Err(format!("the helper was stopped but not everything could be put back: {}", errors.join("; ")));
    }
    let _ = fs::remove_dir_all(&layout.home);
    let _ = fs::remove_dir(&layout.lib);   // only when empty
    Ok(())
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
    use crate::link;
    use sha2::{Digest, Sha256};
    use systemd::fake::FakeSystemd;

    fn layout(name: &str) -> (PathBuf, Layout) {
        let dir = std::env::temp_dir().join(format!("bb-linux-install-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let lib = dir.join("var-lib-blackbox");
        let layout = Layout { home: lib.join("netd"), receipt: lib.join(crate::install_steps::RECEIPT), lib, binary: dir.join("libexec/blackbox/blackbox-netd"),
                              unit: dir.join("blackbox-netd.service") };
        (dir, layout)
    }

    fn args_for(dir: &Path, bytes: &[u8]) -> InstallArgs {
        let from = dir.join("downloaded");
        fs::write(&from, bytes).unwrap();
        InstallArgs { from, sha256: hex::encode(Sha256::digest(bytes)), ..Default::default() }
    }

    fn no_put_back() -> Vec<String> {
        panic!("put_back runs only when no helper is left running")
    }

    #[test]
    fn a_first_install_places_the_program_the_unit_the_key_and_the_receipt() {
        let (dir, layout) = layout("first");
        let systemd = FakeSystemd::default();
        install_into(&args_for(&dir, b"new helper"), &layout, &systemd, &no_put_back).unwrap();
        assert_eq!(fs::read(&layout.binary).unwrap(), b"new helper");
        assert_eq!(fs::metadata(&layout.binary).unwrap().permissions().mode() & 0o777, 0o755);
        let unit = fs::read_to_string(&layout.unit).unwrap();
        assert!(unit.contains("Restart=always") && unit.contains("NoNewPrivileges=yes"), "{unit}");
        assert!(unit.contains(&format!("ExecStart={}", layout.binary.display())));
        assert!(link::load_key(&layout.home).is_some_and(|key| key.len() == link::KEY_BYTES));
        assert_eq!(fs::read_to_string(&layout.receipt).unwrap(), format!("sha256 {}\n", hex::encode(Sha256::digest(b"new helper"))));
        assert!(systemd.state.borrow().active && systemd.state.borrow().relabelled.len() == 2, "labelled for SELinux, started");
        assert!(fs::read_dir(&layout.lib).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with(".netd-staging")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrong_checksum_changes_nothing() {
        let (dir, layout) = layout("mismatch");
        let mut args = args_for(&dir, b"tampered");
        args.sha256 = "0".repeat(64);
        assert!(install_into(&args, &layout, &FakeSystemd::default(), &no_put_back).unwrap_err().contains("does not match"));
        assert!(!layout.binary.exists() && !layout.unit.exists() && !layout.receipt.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_upgrade_systemd_refuses_puts_the_old_helper_back_and_running() {
        let (dir, layout) = layout("refused");
        let systemd = FakeSystemd::default();
        install_into(&args_for(&dir, b"old helper"), &layout, &systemd, &no_put_back).unwrap();
        let key = link::load_key(&layout.home).unwrap();
        let refusing = FakeSystemd { refuse: Some((layout.binary.clone(), b"new helper".to_vec())), ..Default::default() };
        refusing.state.borrow_mut().active = true;
        let error = install_into(&args_for(&dir, b"new helper"), &layout, &refusing, &no_put_back).unwrap_err();
        assert!(error.contains("back in place and running"), "{error}");
        assert_eq!(fs::read(&layout.binary).unwrap(), b"old helper");
        assert!(refusing.state.borrow().active);
        assert_eq!(link::load_key(&layout.home).unwrap(), key, "pairing kept");
        assert!(fs::read_to_string(&layout.receipt).unwrap().contains(&hex::encode(Sha256::digest(b"old helper"))));
        assert!(!crate::handover::pending(&layout.home, std::time::SystemTime::now()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_first_install_that_fails_leaves_nothing_half_installed() {
        let (dir, layout) = layout("first-fails");
        let refusing = FakeSystemd { refuse: Some((layout.binary.clone(), b"new helper".to_vec())), ..Default::default() };
        assert!(install_into(&args_for(&dir, b"new helper"), &layout, &refusing, &no_put_back).is_err());
        assert!(!layout.binary.exists() && !layout.unit.exists() && !layout.receipt.exists() && !refusing.state.borrow().enabled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn uninstall_takes_everything_away_and_keeps_state_when_putting_back_failed() {
        let (dir, layout) = layout("uninstall");
        let systemd = FakeSystemd::default();
        install_into(&args_for(&dir, b"helper"), &layout, &systemd, &no_put_back).unwrap();
        assert!(uninstall_from(&layout, &systemd, &|| vec!["resolvectl failed".into()]).is_err());
        assert!(layout.home.exists(), "the saved state stays for a second try");
        uninstall_from(&layout, &systemd, &Vec::new).unwrap();
        assert!(!layout.binary.exists() && !layout.unit.exists() && !layout.receipt.exists() && !layout.lib.exists());
        assert!(!layout.binary.parent().unwrap().exists(), "an empty program folder goes");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_command_line_refuses_a_macos_signature_check() {
        let (dir, layout) = layout("team");
        let mut args = args_for(&dir, b"x");
        args.team_id = Some("ABCDE12345".into());
        assert!(install_into(&args, &layout, &FakeSystemd::default(), &no_put_back).unwrap_err().contains("macOS"));
        assert!(subcommand(&["uninstall".into(), "--all".into()]).unwrap().is_err() && subcommand(&[]).is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
