//! What a systemd unit or a desktop entry runs, read from its text (no system call): its name and
//! its program, for a persistence event a person can read ("Backup (/usr/bin/restic)").

/// (label, program) of a systemd unit: `Description=` and the first word of `ExecStart=` (its
/// `-@:+!` prefixes dropped). The first value of each wins.
pub fn parse_unit(text: &str) -> (String, String) {
    let label = value(text, "Description");
    let program = value(text, "ExecStart");
    (label, first_word(program.trim_start_matches(['-', '@', ':', '+', '!'])))
}

/// (label, program) of a desktop entry (`.desktop`): `Name=` and the first word of `Exec=`.
pub fn parse_desktop(text: &str) -> (String, String) {
    (value(text, "Name"), first_word(&value(text, "Exec")))
}

/// Whether *name* is a file whose label and program are read (a unit or a desktop entry).
pub fn is_described(name: &str) -> bool {
    [".service", ".timer", ".socket", ".path", ".desktop"].iter().any(|suffix| name.ends_with(suffix))
}

/// The label and program of a file named *name* holding *text*.
pub fn describe(name: &str, text: &str) -> (String, String) {
    if name.ends_with(".desktop") { parse_desktop(text) } else { parse_unit(text) }
}

fn value(text: &str, key: &str) -> String {
    text.lines().map(str::trim).find_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then(|| value.trim().to_string())
    }).unwrap_or_default()
}

fn first_word(text: &str) -> String {
    text.split_whitespace().next().unwrap_or_default().trim_matches('"').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_unit_names_its_description_and_program() {
        let unit = "[Unit]\nDescription=Nightly backup\n\n[Service]\nType=oneshot\nExecStart=-/usr/bin/restic backup /home\nExecStart=/bin/false\n";
        assert_eq!(parse_unit(unit), ("Nightly backup".to_string(), "/usr/bin/restic".to_string()));
        assert_eq!(parse_unit("[Timer]\nOnCalendar=hourly\n"), (String::new(), String::new()));
    }

    #[test]
    fn a_desktop_entry_names_its_name_and_program() {
        let entry = "[Desktop Entry]\nType=Application\nName=Updater\nExec=\"/home/amos/.cache/u\" --quiet\nX-GNOME-Autostart-enabled=true\n";
        assert_eq!(describe("u.desktop", entry), ("Updater".to_string(), "/home/amos/.cache/u".to_string()));
        assert!(is_described("x.timer") && is_described("x.desktop") && !is_described("x.wants"));
    }
}
