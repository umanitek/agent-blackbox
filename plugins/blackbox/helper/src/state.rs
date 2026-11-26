//! What survives a restart: the helper's saved state.

#[allow(unused_imports)]
use crate::*;

fn state_path() -> PathBuf {
    Path::new(HOME).join("state.json")
}

pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// What survives a restart: what the helper changed on the Mac, so it can always put it back.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// What each network service's DNS was before DNS Shield took over (restored exactly).
    pub saved_dns: platform::SavedDns,
    pub dns_active: bool,
    pub firewall_active: bool,
    pub cut_active: bool,
    pub ssh_lockdown_active: bool,
    pub remote_lock_active: bool,
    pub pf_token: Option<String>,
    /// The addresses cut so far (kept blocked while cutting is on).
    pub cut_ips: Vec<String>,
    /// The plan version last applied (for the record; the next start re-applies the plan in full).
    pub version: String,
    /// The boot the pf token belongs to (kern.boottime): a token from another boot is stale.
    pub boot: u64,
}

impl State {
    pub(crate) fn load() -> State {
        fs::read_to_string(state_path()).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    pub(crate) fn save(&self) {
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = private_files::write(&state_path(), text.as_bytes());
        }
    }
}
