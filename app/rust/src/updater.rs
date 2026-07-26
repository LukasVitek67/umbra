// SPDX-License-Identifier: AGPL-3.0-or-later
//! Self-update from GitHub releases.
//!
//! Three rules shape this module, in this order:
//!
//! 1. **The check goes through Tor.** Asking GitHub "is there a newer build?"
//!    over the clearnet would tell GitHub (and every observer on the way) your
//!    IP address and that you run Umbra — exactly what the app exists to avoid.
//!    Every request here is dialled through the running tor daemon's SOCKS
//!    port, so the update check is as anonymous as the messaging.
//! 2. **Only the author's builds are installed.** The zip must carry a valid
//!    Ed25519 signature from [`UPDATE_PUBKEY_HEX`], which is compiled into the
//!    binary. Whoever takes over the GitHub account still cannot push code to
//!    users without the private key, which never leaves the author's machine.
//! 3. **Nothing is swapped under a running conversation.** A verified update is
//!    unpacked and moved into place next to the app; the running process keeps
//!    going and the UI offers a restart. The next start is the new version.
//!
//! TLS is rustls with the bundled webpki roots (not the Windows store), so a
//! machine-local root injected by a "security" product does not silently gain
//! the power to feed us an update.

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use umbra_core::identity::verify as ed25519_verify;
use umbra_transport::ctor::socks5_connect_isolated;

/// Where releases live. Public on purpose: the updater needs no token, so the
/// binary carries no secret an attacker could pull out of it.
pub const REPO: &str = "LukasVitek67/umbra";

/// Ed25519 public key (hex) that release archives must be signed with.
/// The matching private key is generated with `umbra-sign keygen` and stays
/// with the author — it is never in this repository.
pub const UPDATE_PUBKEY_HEX: &str =
    "89fec22189550db91adda520386ee2810725d95d8e21e71e31d9f5f7ff512e00";

/// This build's version, from `Cargo.toml`.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// How often we ask GitHub. Short, because a security fix is worth having the
/// same day it ships — one small request per interval over an existing circuit.
const CHECK_EVERY: Duration = Duration::from_secs(5 * 60);

/// Refuse absurd downloads outright (a release zip is ~60 MB).
const MAX_DOWNLOAD: usize = 200 * 1024 * 1024;

/// What the updater is doing, for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateState {
    /// Nothing to do; we are on the newest version.
    UpToDate,
    /// A newer version exists and is being fetched.
    Downloading(String),
    /// Installed next to the app; takes effect on the next start.
    Installed(String),
    /// Something went wrong (network, signature, disk).
    Failed(String),
}

/// The newest release we have seen and not installed yet.
static OFFERED: Mutex<Option<Release>> = Mutex::new(None);

/// Watch for new versions. `emit` reports to the UI; nothing is downloaded
/// until the user says yes (see [`install_offered`]) — an update replaces the
/// program they are running, so it is their call, not ours.
pub async fn run_loop<F>(socks_port: u16, install_dir: PathBuf, emit: F)
where
    F: Fn(&str, &str) + Send + Sync + 'static,
{
    // Ask early: a fresh start is the moment the user is most willing to
    // restart, and the check is one request.
    tokio::time::sleep(Duration::from_secs(20)).await;
    let mut announced = String::new();
    loop {
        match check_once(socks_port).await {
            Ok(Some(release)) => {
                let version = release.version.clone();
                *OFFERED.lock().unwrap() = Some(release);
                // Announce a given version once, so the dialog does not
                // reappear every five minutes if they said "later".
                if announced != version {
                    announced = version.clone();
                    emit("update_available", &version);
                }
            }
            Ok(None) => emit("update_uptodate", current_version()),
            Err(e) => emit("update_error", &e),
        }
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

/// Ask GitHub what the newest release is. `Ok(None)` means we are current.
pub async fn check_once(socks_port: u16) -> Result<Option<Release>, String> {
    let latest = latest_release(socks_port).await?;
    if !is_newer(&latest.version, current_version()) {
        return Ok(None);
    }
    if latest.zip_url.is_none() {
        return Err(format!("vydání {} nemá .zip", latest.version));
    }
    if latest.sig_url.is_none() {
        // An unsigned release is not installed. Silence here would be the
        // dangerous option, so it is reported as an error.
        return Err(format!("vydání {} není podepsané", latest.version));
    }
    Ok(Some(latest))
}

/// The version currently on offer, if any.
pub fn offered_version() -> Option<String> {
    OFFERED.lock().unwrap().as_ref().map(|r| r.version.clone())
}

/// Download, verify and install the offered release. Called after the user
/// agrees.
pub async fn install_offered<F>(socks_port: u16, install_dir: PathBuf, emit: F) -> UpdateState
where
    F: Fn(&str, &str),
{
    let Some(release) = OFFERED.lock().unwrap().clone() else {
        return UpdateState::Failed("není co instalovat".to_string());
    };
    let (Some(zip_url), Some(sig_url)) = (release.zip_url.clone(), release.sig_url.clone()) else {
        return UpdateState::Failed("vydání nemá potřebné soubory".to_string());
    };
    emit("update_downloading", &release.version);

    let result = async {
        let zip = http_get(socks_port, &zip_url).await?;
        let sig_raw = http_get(socks_port, &sig_url).await?;
        verify_signature(&zip, &sig_raw)?;
        install(&zip, &install_dir, &release.version)?;
        Ok::<(), String>(())
    }
    .await;

    match result {
        Ok(()) => {
            *OFFERED.lock().unwrap() = None;
            emit("update_installed", &release.version);
            UpdateState::Installed(release.version)
        }
        Err(e) => {
            emit("update_error", &e);
            UpdateState::Failed(e)
        }
    }
}

/// The interesting bits of a GitHub release.
#[derive(Debug, Clone)]
pub struct Release {
    /// Version from the tag, without the leading `v`.
    pub version: String,
    zip_url: Option<String>,
    sig_url: Option<String>,
}

/// What the newest release is.
///
/// The plain `/releases/latest` page is asked first: it answers with a redirect
/// to the tagged version and is *not* rate-limited. The JSON API is only a
/// fallback, because unauthenticated API calls are limited per client IP — and
/// over Tor that IP is an exit shared with the whole world, so it is usually
/// already exhausted (GitHub answers 403).
async fn latest_release(socks_port: u16) -> Result<Release, String> {
    match latest_via_redirect(socks_port).await {
        Ok(release) => Ok(release),
        Err(first) => latest_via_api(socks_port)
            .await
            .map_err(|second| format!("{first}; API: {second}")),
    }
}

/// Read the version from where `/releases/latest` points.
async fn latest_via_redirect(socks_port: u16) -> Result<Release, String> {
    let (status, _, location) = request(socks_port, "github.com", &format!("/{REPO}/releases/latest")).await?;
    let Some(location) = location else {
        return Err(format!("/releases/latest neodpovědělo přesměrováním ({status})"));
    };
    let (tag, version) = tag_from_location(&location)
        .ok_or_else(|| format!("z odkazu {location} nejde vyčíst verze"))?;
    // Release archives are named by tools/release.ps1, so the download URLs
    // follow from the version alone.
    Ok(Release {
        zip_url: Some(format!(
            "https://github.com/{REPO}/releases/download/{tag}/Umbra-{version}.zip"
        )),
        sig_url: Some(format!(
            "https://github.com/{REPO}/releases/download/{tag}/Umbra-{version}.zip.sig"
        )),
        version,
    })
}

/// Pull `("v1.2.3", "1.2.3")` out of a `…/releases/tag/v1.2.3` redirect.
fn tag_from_location(location: &str) -> Option<(String, String)> {
    let tag = location.rsplit("/tag/").next()?.trim();
    if tag.is_empty() || tag == location.trim() {
        return None; // not a tag link at all
    }
    let version = tag.trim_start_matches('v').to_string();
    if version.is_empty() || !version.chars().next()?.is_ascii_digit() {
        return None;
    }
    Some((tag.to_string(), version))
}

async fn latest_via_api(socks_port: u16) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = http_get(socks_port, &url).await?;
    let json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("odpověď GitHubu nedává smysl: {e}"))?;

    let tag = json
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "vydání bez tagu".to_string())?;
    let version = tag.trim_start_matches('v').to_string();

    let mut zip_url = None;
    let mut sig_url = None;
    if let Some(assets) = json.get("assets").and_then(|v| v.as_array()) {
        for a in assets {
            let (Some(name), Some(url)) = (
                a.get("name").and_then(|v| v.as_str()),
                a.get("browser_download_url").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            if name.ends_with(".zip.sig") {
                sig_url = Some(url.to_string());
            } else if name.ends_with(".zip") {
                zip_url = Some(url.to_string());
            }
        }
    }
    Ok(Release { version, zip_url, sig_url })
}

/// Compare dotted numeric versions ("1.10.0" > "1.9.9"), ignoring anything
/// after a dash. Unparseable parts count as 0 rather than crashing the loop.
fn is_newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.split('-')
            .next()
            .unwrap_or("")
            .split('.')
            .map(|p| p.trim().parse::<u64>().unwrap_or(0))
            .collect()
    }
    let (a, b) = (parts(candidate), parts(current));
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

/// The signature file is 64 raw bytes or the same in hex.
fn verify_signature(zip: &[u8], sig_raw: &[u8]) -> Result<(), String> {
    let sig: [u8; 64] = if sig_raw.len() == 64 {
        sig_raw.try_into().unwrap()
    } else {
        let text = String::from_utf8_lossy(sig_raw);
        let bytes = unhex(text.trim()).ok_or_else(|| "podpis není platný".to_string())?;
        bytes
            .try_into()
            .map_err(|_| "podpis má špatnou délku".to_string())?
    };
    let public: [u8; 32] = unhex(UPDATE_PUBKEY_HEX)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "zabudovaný klíč pro aktualizace je poškozený".to_string())?;
    if !ed25519_verify(&public, zip, &sig) {
        return Err("podpis aktualizace nesedí — NEinstaluji".to_string());
    }
    Ok(())
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Unpack a verified zip next to the running app.
///
/// Windows will not let us overwrite the running `umbra.exe`, but it does let
/// us *rename* it — so the old binary is moved aside and the new one takes its
/// place. The process keeps running on the old code until it is restarted.
fn install(zip: &[u8], install_dir: &Path, version: &str) -> Result<(), String> {
    let staging = install_dir.join(format!("update-{version}"));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("nelze vytvořit {staging:?}: {e}"))?;

    let mut archive = zip::ZipArchive::new(Cursor::new(zip))
        .map_err(|e| format!("archiv aktualizace je poškozený: {e}"))?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        // Never trust paths from an archive, even a signed one.
        let Some(rel) = entry.enclosed_name() else {
            return Err("archiv obsahuje podezřelou cestu".to_string());
        };
        // Release zips have everything under a single top folder; drop it so
        // the files land next to the current build.
        let rel: PathBuf = rel.components().skip(1).collect();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out = staging.join(&rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        let mut f = std::fs::File::create(&out).map_err(|e| format!("{out:?}: {e}"))?;
        f.write_all(&buf).map_err(|e| e.to_string())?;
    }

    swap_in(&staging, install_dir)?;
    let _ = std::fs::remove_dir_all(&staging);
    Ok(())
}

/// Move the unpacked files over the installed ones.
fn swap_in(staging: &Path, install_dir: &Path) -> Result<(), String> {
    for entry in walk(staging)? {
        let rel = entry
            .strip_prefix(staging)
            .map_err(|_| "chyba při rozbalování".to_string())?
            .to_path_buf();
        let target = install_dir.join(&rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if target.exists() {
            // A file that is currently in use (our own .exe/.dll) cannot be
            // overwritten, but it can be moved out of the way — unless *another*
            // copy of Umbra is running and holding it, which is worth saying
            // plainly instead of failing with a bare OS error.
            let old = target.with_extension(format!(
                "{}.old",
                target.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default()
            ));
            let _ = std::fs::remove_file(&old);
            std::fs::rename(&target, &old).map_err(|e| {
                format!(
                    "nelze nahradit {}: {e} — běží ještě jiná Umbra? Zavři ji a zkus to znovu.",
                    target.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
                )
            })?;
        }
        std::fs::copy(&entry, &target).map_err(|e| format!("nelze zapsat {target:?}: {e}"))?;
    }
    Ok(())
}

/// Every file under `dir`, recursively.
fn walk(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// Delete the `.old` files a previous update left behind. Called at startup,
/// when nothing holds them open any more.
pub fn clean_leftovers(install_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(install_dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "old").unwrap_or(false) {
            let _ = std::fs::remove_file(path);
        }
    }
}

// --- HTTPS through Tor -----------------------------------------------------

/// GET a URL through Tor, following redirects (GitHub sends assets to a CDN).
async fn http_get(socks_port: u16, url: &str) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    for _ in 0..5 {
        let (host, path) = split_url(&url)?;
        let (status, body, location) = request(socks_port, &host, &path).await?;
        match status {
            200 => return Ok(body),
            301 | 302 | 303 | 307 | 308 => {
                url = location.ok_or_else(|| "přesměrování bez cíle".to_string())?;
            }
            403 | 429 => {
                return Err(format!(
                    "GitHub odmítl dotaz z tohoto Tor uzlu ({status}) — zkusím to znovu později"
                ))
            }
            other => return Err(format!("GitHub odpověděl {other}")),
        }
    }
    Err("příliš mnoho přesměrování".to_string())
}

fn split_url(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "aktualizace se stahují jen přes https".to_string())?;
    match rest.split_once('/') {
        Some((host, path)) => Ok((host.to_string(), format!("/{path}"))),
        None => Ok((rest.to_string(), "/".to_string())),
    }
}

/// One HTTPS request over a Tor circuit. Returns status, body and `Location`.
///
/// A rate-limited or blocked exit is retried once on a **different** circuit —
/// over Tor that is the difference between "GitHub says no" and "this one exit
/// says no".
async fn request(
    socks_port: u16,
    host: &str,
    path: &str,
) -> Result<(u16, Vec<u8>, Option<String>), String> {
    let first = request_on_circuit(socks_port, host, path, "").await;
    match &first {
        Ok((403, _, _)) | Ok((429, _, _)) | Err(_) => {
            // A label Tor has not seen before means a fresh exit.
            let tag = format!("umbra-{}", now_tag());
            match request_on_circuit(socks_port, host, path, &tag).await {
                Ok(second) => Ok(second),
                Err(_) => first,
            }
        }
        _ => first,
    }
}

/// A label that changes between attempts, so Tor builds a new circuit.
fn now_tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn request_on_circuit(
    socks_port: u16,
    host: &str,
    path: &str,
    isolation: &str,
) -> Result<(u16, Vec<u8>, Option<String>), String> {
    // rustls needs a crypto provider chosen once per process.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tcp = socks5_connect_isolated(socks_port, host, 443, isolation)
        .await
        .map_err(|e| format!("Tor nedokázal otevřít spojení na {host}: {e}"))?;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| format!("neplatné jméno serveru {host}"))?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(server, tcp)
        .await
        .map_err(|e| format!("TLS selhalo: {e}"))?;

    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: umbra-updater\r\n\
         Accept: application/octet-stream, application/vnd.github+json\r\n\
         Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("odeslání dotazu selhalo: {e}"))?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = tls.read(&mut buf).await.map_err(|e| format!("čtení selhalo: {e}"))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_DOWNLOAD {
            return Err("odpověď je nesmyslně velká".to_string());
        }
    }
    parse_response(&raw)
}

/// Split an HTTP/1.1 response into status, body and `Location`, decoding
/// chunked transfer if the server used it.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>, Option<String>), String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "odpověď bez hlaviček".to_string())?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let body = &raw[split + 4..];

    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| "odpověď bez stavového kódu".to_string())?;

    let mut location = None;
    let mut chunked = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k.trim().to_ascii_lowercase().as_str() {
            "location" => location = Some(v.trim().to_string()),
            "transfer-encoding" if v.trim().eq_ignore_ascii_case("chunked") => chunked = true,
            _ => {}
        }
    }

    let body = if chunked { dechunk(body)? } else { body.to_vec() };
    Ok((status, body, location))
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let nl = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "poškozený chunked přenos".to_string())?;
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&body[..nl]).split(';').next().unwrap_or("").trim(),
            16,
        )
        .map_err(|_| "poškozená délka chunku".to_string())?;
        body = &body[nl + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err("chunked přenos skončil dřív".to_string());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison_is_numeric_not_lexicographic() {
        assert!(is_newer("1.10.0", "1.9.9"));
        assert!(is_newer("2.0.0", "1.99.99"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("0.9.0", "1.0.0"));
        assert!(is_newer("1.0.1", "1.0"));
        // Pre-release suffixes are ignored, junk counts as zero.
        assert!(!is_newer("1.0.0-rc1", "1.0.0"));
        assert!(!is_newer("x.y.z", "0.0.1"));
    }

    #[test]
    fn a_tampered_archive_fails_verification() {
        let kp = umbra_core::identity::Keypair::generate().unwrap();
        let zip = b"pretend this is a release";
        let sig = kp.sign(zip);
        // Signed by a key that is not the one baked in: must be refused.
        assert!(verify_signature(zip, &sig).is_err());
    }

    #[test]
    fn chunked_bodies_are_reassembled() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n";
        let (status, body, _) = parse_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello!");
    }

    #[test]
    fn the_release_version_comes_from_the_tag_link() {
        let (tag, version) =
            tag_from_location("https://github.com/LukasVitek67/umbra/releases/tag/v1.1.1").unwrap();
        assert_eq!(tag, "v1.1.1");
        assert_eq!(version, "1.1.1");

        // Anything that is not a tag link must not be mistaken for a version.
        assert!(tag_from_location("https://github.com/LukasVitek67/umbra/releases").is_none());
        assert!(tag_from_location("https://github.com/x/y/releases/tag/").is_none());
        assert!(tag_from_location("https://github.com/x/y/releases/tag/nightly").is_none());
    }

    #[test]
    fn redirects_carry_their_target() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: https://objects.example/asset.zip\r\n\r\n";
        let (status, _, location) = parse_response(raw).unwrap();
        assert_eq!(status, 302);
        assert_eq!(location.unwrap(), "https://objects.example/asset.zip");
    }
}
