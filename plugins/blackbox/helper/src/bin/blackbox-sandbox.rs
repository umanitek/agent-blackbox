//! `blackbox-sandbox` — the agent sandbox launcher on Linux (unprivileged; installed beside the
//! helper, root-owned, so no agent can replace it). The plugin's agent launchers run
//! `blackbox-sandbox run --policy <file> -- <agent> <args>`; `blackbox-sandbox probe` prints
//! what this machine allows as JSON. See `blackbox_helper::platform::sandbox_main`.

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    std::process::exit(blackbox_helper::platform::sandbox_main(args));
}
