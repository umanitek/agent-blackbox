//! The AppArmor rule that lets the sandbox launcher make its user namespaces on Ubuntu 23.10+
//! (founder decision F2). Ubuntu restricts unprivileged user namespaces
//! (`kernel.apparmor_restrict_unprivileged_userns=1`): `unshare` still succeeds, but the new
//! namespace has no capabilities, so no mount can be made and the sandbox would fall back to hooks
//! only. One profile names the launcher's installed path and allows it `userns`; it is
//! `unconfined` otherwise (it adds a right, takes none), and what the launcher starts inherits it —
//! so nested sandboxes (Claude Code's bubblewrap, an Electron app) keep working inside.
//!
//! Called by the helper's install (as root, after the launcher is in place) and its uninstall:
//! [`install`] writes `/etc/apparmor.d/blackbox-sandbox` and loads it; [`remove`] unloads and
//! deletes it. A machine without the restriction (Debian, Fedora) or without AppArmor gets nothing.
//!
//! **The AppArmor version** (KI-684, Linux round L3, Ubuntu 22.04.5: AppArmor 3.0.4 has only
//! `abi/3.0`, refused the file with "Could not open 'abi/4.0'", and `apparmor.service` then FAILED at
//! every boot because the file stayed in `/etc/apparmor.d`). The rule's one permission, `userns`, is
//! AppArmor 4's (`abi/4.0`, Ubuntu 23.10+), and so is the restriction it lifts: an AppArmor without
//! `<apparmor.d>/abi/4.0` has nothing to lift and no syntax to lift it with, so it gets no rule (and a
//! file an older install left there is removed). Where the ABI is present the text is still checked
//! first — staged as a dot file (the parser and `apparmor.service` skip dot files), parsed with
//! `apparmor_parser -QK` (no kernel load, no cache), and only a text the parser accepts is renamed
//! into place and loaded; a file the parser or the kernel refuses is never left behind.

use std::path::Path;
use std::process::Command;

/// The profile's file.
pub const PROFILE_FILE: &str = "/etc/apparmor.d/blackbox-sandbox";
/// The profile's name.
pub const PROFILE_NAME: &str = "blackbox-sandbox";
/// Ubuntu's switch (present only where the kernel can restrict user namespaces).
pub const RESTRICT_SYSCTL: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
/// Where `apparmor_parser` lives.
pub const PARSERS: &[&str] = &["/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"];

/// The profile text for the launcher at *binary* (an absolute path without spaces or quotes —
/// the install's own constant).
pub fn profile_text(binary: &str) -> String {
    format!("# Blackbox's agent sandbox launcher may create user namespaces (Ubuntu restricts them).\n\
             # Written by Blackbox's system protection helper; removed by its uninstall.\n\
             abi <abi/4.0>,\n\
             include <tunables/global>\n\n\
             profile {PROFILE_NAME} {binary} flags=(unconfined) {{\n  userns,\n\n  include if exists <local/{PROFILE_NAME}>\n}}\n")
}

/// AppArmor's folder, and the ABI file the rule is written for (present on AppArmor 4 only).
pub const APPARMOR_DIR: &str = "/etc/apparmor.d";
pub const ABI: &str = "abi/4.0";
/// The staged copy's name: a dot file, which neither the parser nor `apparmor.service` loads.
const STAGED: &str = ".blackbox-sandbox.new";

/// Runs `apparmor_parser <flag> <file>`: Err with the parser's own words.
pub type Parser<'a> = &'a dyn Fn(&str, &Path) -> Result<(), String>;

fn parser() -> Option<&'static str> {
    PARSERS.iter().copied().find(|path| Path::new(path).exists())
}

fn run_parser(flag: &str, file: &Path) -> Result<(), String> {
    let parser = parser().ok_or("AppArmor's apparmor_parser is not installed")?;
    let out = crate::command::output(Command::new(parser).arg(flag).arg(file), crate::command::TIMEOUT)
        .map_err(|error| format!("apparmor_parser {flag}: {error}"))?;
    if !out.status.success() {
        return Err(format!("apparmor_parser {flag}: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(())
}

/// Writes and loads the rule for the launcher at *binary*; Ok(false) when this machine does not
/// need it. Root only (the install).
pub fn install(binary: &str) -> Result<bool, String> {
    let restricts = Path::new(RESTRICT_SYSCTL).exists() && parser().is_some();
    install_in(Path::new(APPARMOR_DIR), binary, restricts, &run_parser)
}

/// [`install`] into AppArmor's folder *dir*, where *restricts* says the kernel can restrict user
/// namespaces, through *parser* (tests hand in a fake that answers as a real parser did).
pub fn install_in(dir: &Path, binary: &str, restricts: bool, parser: Parser) -> Result<bool, String> {
    if !binary.starts_with('/') || binary.contains(|c: char| c.is_whitespace() || c == '"' || c == '\0') {
        return Err(format!("not a launcher path the rule can name: {binary:?}"));
    }
    let staged = dir.join(STAGED);
    let _ = std::fs::remove_file(&staged);   // a crash's leftover is never loaded, and never kept
    if !restricts || !dir.join(ABI).exists() {
        // Nothing to lift here (or no syntax to lift it with): an older install's file goes.
        for why in remove_in(dir, parser) {
            eprintln!("blackbox-netd: an earlier AppArmor rule for the agent sandbox: {why}");
        }
        return Ok(false);
    }
    std::fs::write(&staged, profile_text(binary)).map_err(|error| format!("{}: {error}", staged.display()))?;
    if let Err(refused) = parser("-QK", &staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(refused);
    }
    let file = dir.join(PROFILE_NAME);
    std::fs::rename(&staged, &file).map_err(|error| format!("{}: {error}", file.display()))?;
    if let Err(refused) = parser("-r", &file) {
        let _ = std::fs::remove_file(&file);   // the boot would refuse it too: never left behind
        return Err(refused);
    }
    Ok(true)
}

/// Unloads and deletes the rule; answers what failed (nothing → empty). Root only (the uninstall).
pub fn remove() -> Vec<String> {
    remove_in(Path::new(APPARMOR_DIR), &run_parser)
}

/// [`remove`] from *dir* through *parser*. A file the parser refuses was never loaded, so it is
/// only deleted (no `-R`, which would fail on it: the L3 uninstall's noise).
pub fn remove_in(dir: &Path, parser: Parser) -> Vec<String> {
    let file = dir.join(PROFILE_NAME);
    if !file.exists() {
        return vec![];
    }
    let mut failed = vec![];
    if parser("-QK", &file).is_ok() {
        if let Err(why) = parser("-R", &file) {
            failed.push(why);
        }
    }
    if let Err(error) = std::fs::remove_file(&file) {
        failed.push(format!("{}: {error}", file.display()));
    }
    failed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn the_rule_names_the_launcher_and_only_adds_user_namespaces() {
        let text = profile_text("/usr/local/libexec/blackbox/blackbox-sandbox");
        assert!(text.contains("profile blackbox-sandbox /usr/local/libexec/blackbox/blackbox-sandbox flags=(unconfined) {"));
        assert!(text.contains("  userns,\n"));
        assert!(text.starts_with('#') && text.contains("abi <abi/4.0>,"));
        let rules: Vec<&str> = text.lines().map(str::trim).filter(|l| l.ends_with(',') && !l.starts_with("abi")).collect();
        assert_eq!(rules, vec!["userns,"], "no other right is granted");
    }

    #[test]
    fn a_path_the_rule_can_not_name_safely_is_refused_before_anything_is_written() {
        for bad in ["relative/x", "/a b", "/a\"b"] {
            assert!(install(bad).is_err(), "{bad:?}");
        }
    }

    const LAUNCHER: &str = "/usr/local/libexec/blackbox/blackbox-sandbox";

    /// The parser of Ubuntu 22.04.5 (AppArmor 3.0.4), as Linux round L3 captured it (KI-684).
    fn apparmor_3_error(file: &Path) -> String {
        format!("apparmor_parser -r: AppArmor parser error for {0} in profile {0} at line 3: Could not open 'abi/4.0': No such file or directory",
                file.display())
    }

    /// A parser that refuses what AppArmor 3 refuses (a text naming abi/4.0 when the folder has no
    /// such ABI) and records every call.
    struct FakeParser {
        dir: PathBuf,
        calls: RefCell<Vec<(String, String)>>,
        refuse_load: bool,
    }

    impl FakeParser {
        fn new(dir: &Path) -> FakeParser {
            FakeParser { dir: dir.to_path_buf(), calls: RefCell::new(vec![]), refuse_load: false }
        }
        fn run(&self, flag: &str, file: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push((flag.into(), file.file_name().unwrap().to_string_lossy().into()));
            let text = fs::read_to_string(file).unwrap_or_default();
            if text.contains("abi <abi/4.0>") && !self.dir.join(ABI).exists() {
                return Err(apparmor_3_error(file));
            }
            if flag == "-r" && self.refuse_load {
                return Err("apparmor_parser -r: Access denied. You need policy admin privileges".into());
            }
            Ok(())
        }
    }

    fn apparmor_dir(name: &str, abi4: bool) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-apparmor-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("abi")).unwrap();
        fs::write(dir.join("abi/3.0"), "").unwrap();
        if abi4 {
            fs::write(dir.join(ABI), "").unwrap();
        }
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        found.sort();
        found
    }

    /// KI-684: on AppArmor 3 (Ubuntu 22.04) nothing is written, and the unparsable file an older
    /// install left is removed without asking the kernel to unload what it never loaded.
    #[test]
    fn apparmor_3_gets_no_rule_and_an_older_installs_unparsable_file_is_removed() {
        let dir = apparmor_dir("v3", false);
        fs::write(dir.join(PROFILE_NAME), profile_text(LAUNCHER)).unwrap();   // what 6463038577 left
        let parser = FakeParser::new(&dir);
        assert!(parser.run("-QK", &dir.join(PROFILE_NAME)).unwrap_err().contains("Could not open 'abi/4.0'"), "the fixture is L3's refusal");
        parser.calls.borrow_mut().clear();
        assert_eq!(install_in(&dir, LAUNCHER, true, &|flag, file| parser.run(flag, file)), Ok(false));
        assert_eq!(names(&dir), vec!["abi".to_string()], "nothing apparmor.service could fail on");
        assert!(!parser.calls.borrow().iter().any(|(flag, _)| flag == "-R" || flag == "-r"), "{:?}", parser.calls.borrow());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apparmor_4_gets_the_rule_checked_before_it_is_placed_and_loaded() {
        let dir = apparmor_dir("v4", true);
        let parser = FakeParser::new(&dir);
        assert_eq!(install_in(&dir, LAUNCHER, true, &|flag, file| parser.run(flag, file)), Ok(true));
        assert_eq!(names(&dir), vec!["abi".to_string(), PROFILE_NAME.to_string()]);
        assert_eq!(*parser.calls.borrow(), vec![("-QK".to_string(), STAGED.to_string()), ("-r".to_string(), PROFILE_NAME.to_string())]);
        assert!(remove_in(&dir, &|flag, file| parser.run(flag, file)).is_empty());
        assert_eq!(names(&dir), vec!["abi".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_text_the_parser_or_the_kernel_refuses_is_never_left_in_apparmors_folder() {
        let dir = apparmor_dir("refused", true);
        fs::remove_file(dir.join(ABI)).unwrap();
        let parser = FakeParser::new(&dir);
        // The ABI looked present a moment ago (a race, a broken package): the check refuses the text.
        fs::write(dir.join(ABI), "").unwrap();
        let racing = |flag: &str, file: &Path| { let _ = fs::remove_file(dir.join(ABI)); parser.run(flag, file) };
        assert!(install_in(&dir, LAUNCHER, true, &racing).unwrap_err().contains("abi/4.0"));
        assert_eq!(names(&dir), vec!["abi".to_string()]);
        fs::write(dir.join(ABI), "").unwrap();
        let mut refusing = FakeParser::new(&dir);
        refusing.refuse_load = true;
        assert!(install_in(&dir, LAUNCHER, true, &|flag, file| refusing.run(flag, file)).is_err());
        assert_eq!(names(&dir), vec!["abi".to_string()], "a rule the kernel would not load stays out of the boot's way");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_machine_that_does_not_restrict_user_namespaces_gets_no_rule() {
        let dir = apparmor_dir("free", true);
        let parser = FakeParser::new(&dir);
        assert_eq!(install_in(&dir, LAUNCHER, false, &|flag, file| parser.run(flag, file)), Ok(false));
        assert_eq!(names(&dir), vec!["abi".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }
}
