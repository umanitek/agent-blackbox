//! The helper's ONE link to the Blackbox plugin — authenticated (security finding: the helper must
//! not obey whatever program answers on 127.0.0.1:9700).
//!
//! A per-install key ([`KEY_FILE`], 32 random bytes, root-owned 0600) is created by `blackbox-netd
//! install` and a copy handed to the plugin's own state folder (owner: the person, 0600). Then:
//!
//! * **plans**: every request carries a fresh random `nonce`; the plugin answers with
//!   `X-Blackbox-Signature: hex(HMAC-SHA256(key, nonce + "\n" + body))`. A plan that is unsigned,
//!   signed with another key or for another nonce is REFUSED (and reported as an error) — another
//!   local account that grabbed the port first cannot steer the helper or replay an old plan;
//! * **reports** go out only to a server that proved the key within [`VERIFIED_FOR`], each signed
//!   over its time and a fresh nonce with the body ([`sign_report`], headers
//!   [`HELPER_TIMESTAMP_HEADER`] and [`HELPER_NONCE_HEADER`]) — so a squatter never receives what
//!   the helper sees (sessions, startup items, posture), and a report it did catch can not be
//!   replayed to the plugin later (the plugin refuses an old time or a nonce it saw);
//! * losing the plugin NEVER undoes anything: the caller keeps the last verified plan.
//!
//! No usable key — the file missing ("unkeyed") or there but wrong in any way ("broken",
//! [`load_key`]) — refuses every plan and sends no report: the helper keeps the last plan it
//! verified and the plugin's card asks the person to reinstall it. WHY (external review,
//! 2026-11-28): a missing key used to mean "legacy", accepting unsigned plans from whatever answered
//! on the plugin's port; every published helper writes its key at install (since 2026-11-21).
//! Contract: helper/PLAN.md.

use std::path::Path;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::Sha256;

/// The key file in the helper's root-owned folder.
pub const KEY_FILE: &str = "plan.key";
/// The plugin (loopback only).
pub const PLUGIN: &str = "http://127.0.0.1:9700";
/// How long a verified plan exchange lets reports go to that server.
pub const VERIFIED_FOR: Duration = Duration::from_secs(120);
pub const SIGNATURE_HEADER: &str = "X-Blackbox-Signature";
pub const HELPER_SIGNATURE_HEADER: &str = "X-Blackbox-Helper-Signature";
/// The report's time (unix seconds, decimal ASCII) and nonce (32 lower-case hex), both signed.
pub const HELPER_TIMESTAMP_HEADER: &str = "X-Blackbox-Helper-Timestamp";
pub const HELPER_NONCE_HEADER: &str = "X-Blackbox-Helper-Nonce";
/// The first line of a report's signed material: names the form, so a plan signature
/// (`nonce + "\n" + body`) can never pass for a report's.
pub const REPORT_SIGNING_CONTEXT: &[u8] = b"blackbox-helper-report-v2\n";
pub const KEY_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 of *parts* (concatenated) under *key*, as lower-case hex.
pub fn sign(key: &[u8], parts: &[&[u8]]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    hex::encode(mac.finalize().into_bytes())
}

/// A report's signature: hex(HMAC-SHA256(key, "blackbox-helper-report-v2\n" + ts + "\n" + nonce +
/// "\n" + body)), *ts* in decimal ASCII and *nonce* as sent in [`HELPER_NONCE_HEADER`].
pub fn sign_report(key: &[u8], ts: u64, nonce: &str, body: &[u8]) -> String {
    sign(key, &[REPORT_SIGNING_CONTEXT, ts.to_string().as_bytes(), b"\n", nonce.as_bytes(), b"\n", body])
}

/// Whether *signature* is the HMAC of nonce + "\n" + body under *key* (constant time).
pub fn verify_plan(key: &[u8], nonce: &str, body: &[u8], signature: &str) -> bool {
    let Ok(given) = hex::decode(signature.trim()) else { return false };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    mac.verify_slice(&given).is_ok()
}

/// A fresh random nonce (hex).
pub fn nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("the OS random source");
    hex::encode(bytes)
}

/// A new random key (for `install`).
pub fn new_key() -> Vec<u8> {
    let mut bytes = vec![0u8; KEY_BYTES];
    getrandom::getrandom(&mut bytes).expect("the OS random source");
    bytes
}

/// What the key file in the helper's folder is.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyFile {
    /// No file: an install from before keys (2026-11-21), or a key removed — fail closed.
    Missing,
    Key(Vec<u8>),
    /// A file is there but can not be trusted or used (the text says why): fail closed.
    Broken(String),
}

impl KeyFile {
    /// The key, when there is a usable one.
    pub fn usable(self) -> Option<Vec<u8>> {
        match self { KeyFile::Key(key) => Some(key), _ => None }
    }
}

/// Reads the key from *home*. WHY anything but "not found" is [`KeyFile::Broken`] (review finding
/// 2026-11-26): a link, the wrong size, a file other accounts can read or write, or one this
/// account does not own used to read as "no key" — legacy, accepting unsigned plans from whoever
/// answers on the plugin's port.
pub fn load_key(home: &Path) -> KeyFile {
    use std::os::unix::fs::MetadataExt;
    let path = home.join(KEY_FILE);
    let meta = match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return KeyFile::Missing,
        Err(error) => return KeyFile::Broken(format!("the key file can not be read: {error}")),
        Ok(meta) => meta,
    };
    // SAFETY: geteuid has no preconditions and can not fail.
    let me = unsafe { libc::geteuid() };
    let why = if !meta.file_type().is_file() {
        "it is not a plain file"
    } else if meta.len() != KEY_BYTES as u64 {
        "it is not 32 bytes"
    } else if meta.mode() & 0o077 != 0 {
        "other accounts can read or change it"
    } else if meta.uid() != me {
        "it is not owned by the helper's account"
    } else {
        return match crate::safe_read::read_regular(&path, KEY_BYTES as u64) {
            Some(key) if key.len() == KEY_BYTES => KeyFile::Key(key),
            _ => KeyFile::Broken("the key file can not be read".into()),
        };
    };
    KeyFile::Broken(format!("the key file is damaged: {why}"))
}

/// What a plan request came back as.
#[derive(Debug)]
pub enum Fetched<T> {
    /// A plan from the verified plugin (or, legacy, from whoever answered).
    Plan(T),
    /// Nothing usable: keep the last plan. The text says why (shown in reports).
    Refused(String),
}

/// The link: the HTTP client, the key, the plugin's session token and when it last proved the key.
pub struct Link {
    http: reqwest::blocking::Client,
    key: Option<Vec<u8>>,
    broken_key: bool,
    /// No key file at all (refused like a broken one; told apart in [`Link::mode`] and the refusal).
    missing_key: bool,
    token: Option<String>,
    verified_at: Option<Instant>,
    /// The exact bytes of the last plan this link accepted (verified when a key is installed):
    /// what the helper saves to re-apply at its next start ([`Link::take_body`]).
    last_body: Option<Vec<u8>>,
}

impl Link {
    /// The link for the helper in *home*. Without a usable key — none ([`KeyFile::Missing`]) or one
    /// that is not usable ([`KeyFile::Broken`]) — every plan is refused (fail closed).
    pub fn new(home: &Path) -> Result<Link, String> {
        let (key, broken_key, missing_key) = match load_key(home) {
            KeyFile::Key(key) => (Some(key), false, false),
            KeyFile::Missing => (None, false, true),
            KeyFile::Broken(_) => (None, true, false),
        };
        let http = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())   // a loopback plugin never redirects
            .build().map_err(|error| error.to_string())?;
        Ok(Link { http, key, broken_key, missing_key, token: None, verified_at: None, last_body: None })
    }

    /// "signed" (a key is installed), "unkeyed" (no key file) or "broken" — for reports and logs.
    pub fn mode(&self) -> &'static str {
        if self.broken_key { "broken" } else if self.missing_key { "unkeyed" } else { "signed" }
    }

    /// GET *path* with *query* (already encoded) plus a fresh nonce; the answer counts only when
    /// its signature verifies. *timeout* bounds the request.
    pub fn plan<T: DeserializeOwned>(&mut self, path: &str, query: &str, timeout: Duration) -> Fetched<T> {
        self.plan_from(PLUGIN, path, query, timeout)
    }

    /// [`Link::plan`] against *base* (tests point it at a local stand-in server).
    pub fn plan_from<T: DeserializeOwned>(&mut self, base: &str, path: &str, query: &str, timeout: Duration) -> Fetched<T> {
        if self.broken_key {
            return Fetched::Refused("the helper's key file is damaged: reinstall the helper".into());
        }
        if self.missing_key {
            return Fetched::Refused("the helper has no key file: reinstall the helper".into());
        }
        let nonce = nonce();
        let separator = if query.is_empty() { "" } else { "&" };
        let url = format!("{base}{path}?{query}{separator}nonce={nonce}");
        let response = match self.http.get(url).timeout(timeout).send() {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => return Fetched::Refused(format!("the plan was refused: HTTP {}", response.status().as_u16())),
            Err(error) => return Fetched::Refused(format!("the plan could not be read: {error}")),
        };
        let signature = response.headers().get(SIGNATURE_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string);
        let Ok(body) = response.bytes() else { return Fetched::Refused("the plan could not be read".into()) };
        if let Some(key) = &self.key {
            match signature {
                Some(signature) if verify_plan(key, &nonce, &body, &signature) => self.verified_at = Some(Instant::now()),
                Some(_) => return Fetched::Refused("a plan with a wrong signature was refused (not Blackbox's plugin)".into()),
                None => return Fetched::Refused("an unsigned plan was refused (not Blackbox's plugin, or a plugin too old for this helper)".into()),
            }
        }
        match serde_json::from_slice(&body) {
            Ok(plan) => {
                self.last_body = Some(body.to_vec());
                Fetched::Plan(plan)
            }
            Err(error) => Fetched::Refused(format!("the plan could not be read: {error}")),
        }
    }

    /// The bytes of the last plan accepted, once (None after it was taken).
    pub fn take_body(&mut self) -> Option<Vec<u8>> {
        self.last_body.take()
    }

    /// Whether reports may go out now: only to a server that proved the key recently.
    pub fn may_report(&self) -> bool {
        match (&self.key, self.verified_at) {
            (Some(_), Some(at)) => at.elapsed() <= VERIFIED_FOR,
            _ => false,
        }
    }

    /// POSTs *body* to *path*, signed, with the plugin's session token. True when delivered (or
    /// refused on purpose with a 4xx other than 401/403 — resending would block later reports).
    pub fn post(&mut self, path: &str, body: &Value, timeout: Duration) -> bool {
        if !self.may_report() {
            return false;
        }
        let Ok(raw) = serde_json::to_vec(body) else { return true };
        for attempt in 0..2 {
            if self.token.is_none() || attempt > 0 {
                self.token = self.http.get(format!("{PLUGIN}/api/session")).timeout(timeout).send().ok()
                    .and_then(|r| r.json::<Value>().ok()).and_then(|v| v["token"].as_str().map(str::to_string));
            }
            let Some(token) = self.token.clone() else { return false };
            let mut request = self.http.post(format!("{PLUGIN}{path}")).timeout(timeout)
                .header("X-Blackbox-Token", token).header("content-type", "application/json");
            if let Some(key) = &self.key {
                let (ts, nonce) = (crate::state::now(), nonce());
                request = request.header(HELPER_SIGNATURE_HEADER, sign_report(key, ts, &nonce, &raw))
                    .header(HELPER_TIMESTAMP_HEADER, ts.to_string()).header(HELPER_NONCE_HEADER, nonce);
            }
            match request.body(raw.clone()).send() {
                Ok(response) if matches!(response.status().as_u16(), 401 | 403) => continue,
                Ok(_) => return true,
                Err(_) => return false,
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    /// The vector the plugin checks too (tests/plugins/test_blackbox_shields_network_helper_link.py):
    /// one key, nonce and body → the same hex on both sides of the contract.
    #[test]
    fn a_shared_vector_matches_the_plugin() {
        assert_eq!(sign(&KEY, &[b"abc", b"\n", br#"{"version":"v1"}"#]),
                   "556ad530e22f4180c7080a144eb88187e9e5c5668311aa23dc2fd484f285eafa");
        assert!(verify_plan(&KEY, "abc", br#"{"version":"v1"}"#, "556ad530e22f4180c7080a144eb88187e9e5c5668311aa23dc2fd484f285eafa"));
        assert_eq!(sign(&KEY, &[br#"{"running":true}"#]), "ed7cae0659cb0798e3f55b0bb6586ee82d23ca413253a304832605c7bf4dd449");
    }

    /// The report vector the plugin checks too (helper_link.py): v2 signs the time and a nonce with
    /// the body, so a captured report can not be replayed later (review finding 2026-11-26).
    #[test]
    fn a_report_signature_covers_its_time_and_nonce() {
        let body = br#"{"running":true}"#;
        let nonce = "000102030405060708090a0b0c0d0e0f";
        assert_eq!(sign_report(&KEY, 1_700_000_000, nonce, body), "6e4673cb0bd283133f4f0e4cb64a08a542446a2ac5bba7b9aefa4fad7dded6e2");
        assert_ne!(sign_report(&KEY, 1_700_000_001, nonce, body), sign_report(&KEY, 1_700_000_000, nonce, body));
        assert_ne!(sign_report(&KEY, 1_700_000_000, "ff0102030405060708090a0b0c0d0e0f", body), sign_report(&KEY, 1_700_000_000, nonce, body));
    }

    /// Review finding 2026-11-26: a key file that is there but a link, the wrong size or open to
    /// other accounts is BROKEN (every plan refused), never "no key".
    #[test]
    fn a_key_file_that_is_there_but_wrong_is_broken() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bb-link-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(KEY_FILE);
        assert_eq!(load_key(&dir), KeyFile::Missing);
        crate::private_files::write(&path, &KEY).unwrap();
        assert_eq!(load_key(&dir), KeyFile::Key(KEY.to_vec()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load_key(&dir), KeyFile::Broken(_)), "readable by other accounts");
        crate::private_files::write(&path, b"short").unwrap();
        assert!(matches!(load_key(&dir), KeyFile::Broken(_)), "the wrong size");
        std::fs::remove_file(&path).unwrap();
        crate::private_files::write(&dir.join("elsewhere"), &KEY).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), &path).unwrap();
        assert!(matches!(load_key(&dir), KeyFile::Broken(_)), "a link");
        assert_eq!(Link::new(&dir).unwrap().mode(), "broken");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plan_signed_for_this_nonce_with_this_key_verifies() {
        let body = br#"{"version":"v1"}"#;
        let signature = sign(&KEY, &[b"abc", b"\n", body]);
        assert!(verify_plan(&KEY, "abc", body, &signature));
    }

    #[test]
    fn another_key_another_nonce_a_changed_body_or_garbage_is_refused() {
        let body = br#"{"version":"v1"}"#;
        let signature = sign(&KEY, &[b"abc", b"\n", body]);
        assert!(!verify_plan(&[8u8; 32], "abc", body, &signature), "another key");
        assert!(!verify_plan(&KEY, "abd", body, &signature), "a replayed plan for another nonce");
        assert!(!verify_plan(&KEY, "abc", br#"{"version":"v2"}"#, &signature), "a changed plan");
        assert!(!verify_plan(&KEY, "abc", body, "not hex"), "garbage");
        assert!(!verify_plan(&KEY, "abc", body, ""), "empty");
    }

    #[test]
    fn with_a_key_nothing_is_reported_until_the_server_proved_it() {
        let dir = std::env::temp_dir().join(format!("bb-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::private_files::write(&dir.join(KEY_FILE), &KEY).unwrap();
        let link = Link::new(&dir).unwrap();
        assert_eq!(link.mode(), "signed");
        assert!(!link.may_report(), "no report to a server that never proved the key");
        crate::private_files::write(&dir.join(KEY_FILE), b"short").unwrap();
        let mut broken = Link::new(&dir).unwrap();
        assert_eq!(broken.mode(), "broken");
        assert!(!broken.may_report());
        assert!(matches!(broken.plan::<Value>("/x", "", Duration::from_secs(1)), Fetched::Refused(_)), "a damaged key fails closed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// External review 2026-11-28: with no key file the helper used to accept an unsigned plan from
    /// whatever answered on the plugin's port ("legacy"). Now it refuses every plan and reports nothing.
    #[test]
    fn without_a_key_file_every_plan_is_refused_and_nothing_is_reported() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buffer = [0u8; 2048];
                let _ = stream.read(&mut buffer);
                let body = r#"{"version":"unsigned"}"#;
                let _ = write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}", body.len(), body);
            }
        });
        let dir = std::env::temp_dir().join(format!("bb-link-unkeyed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut link = Link::new(&dir).unwrap();
        assert_eq!(link.mode(), "unkeyed");
        assert!(!link.may_report(), "no report without a key");
        let fetched: Fetched<Value> = link.plan_from(&format!("http://127.0.0.1:{port}"), "/plan", "", Duration::from_secs(5));
        assert!(matches!(fetched, Fetched::Refused(ref why) if why.contains("no key file")), "{fetched:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_squatter_answering_without_a_signature_is_refused() {
        // A local server that answers like the plugin but cannot sign.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buffer = [0u8; 2048];
                let _ = stream.read(&mut buffer);
                let body = r#"{"version":"evil","dns":{"enabled":false}}"#;
                let _ = write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}", body.len(), body);
            }
        });
        let dir = std::env::temp_dir().join(format!("bb-link-squat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        crate::private_files::write(&dir.join(KEY_FILE), &KEY).unwrap();
        let mut link = Link::new(&dir).unwrap();
        let fetched: Fetched<Value> = link.plan_from(&format!("http://127.0.0.1:{port}"), "/plan", "", Duration::from_secs(5));
        assert!(matches!(fetched, Fetched::Refused(ref why) if why.contains("unsigned")), "{fetched:?}");
        assert!(!link.may_report());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
