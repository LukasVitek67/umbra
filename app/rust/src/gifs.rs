// SPDX-License-Identifier: AGPL-3.0-or-later
//! GIF search, over Tor, without exposing the recipient.
//!
//! The rule this module exists to enforce: **the person receiving a GIF never
//! contacts the GIF service.** The sender fetches the bytes and they travel
//! over the same end-to-end encrypted file channel as anything else. Sending a
//! link instead — which is what most messengers do — would hand every
//! recipient's IP address, and the time, to Google.
//!
//! Everything here runs through the running tor daemon's SOCKS port, on a
//! circuit label of its own so the exit that sees a search term is not the exit
//! carrying anything else.
//!
//! See `docs/GIFS.md` for what this still leaks, which is not nothing.

use crate::updater::http_get_via_tor;

/// Tenor's public demo key. It identifies the *application*, not the user, and
/// is not a secret: it ships in every client that uses it, ours included.
/// Treating it as a credential would be theatre.
const TENOR_KEY: &str = "AIzaSyC1FE9wGYYDDs1DKcNMSs_j0hoV6JlvGyE";

/// Refuse anything larger before decoding a single byte. Image decoders are a
/// long-standing source of memory-corruption bugs (CVE-2023-4863 needed no
/// interaction at all), so the cheapest defence is not to hand them the file.
pub const MAX_GIF_BYTES: usize = 8 * 1024 * 1024;

/// One result, as the picker shows it.
pub struct GifResult {
    /// Tenor's id — only ever used to fetch, never sent to a peer.
    pub id: String,
    /// Small still or animated preview.
    pub preview_url: String,
    /// The full-size GIF this would send.
    pub gif_url: String,
    /// For the picker's layout, so results do not jump around while loading.
    pub width: u32,
    pub height: u32,
    /// Alt text, when Tenor has one.
    pub description: String,
}

/// Search Tenor over Tor.
///
/// `isolation` is the SOCKS credential that pins this to its own circuit; the
/// caller passes something stable per session but distinct from messaging.
pub async fn search(
    socks_port: u16,
    query: &str,
    limit: u32,
    isolation: &str,
) -> Result<Vec<GifResult>, String> {
    let q = urlencode(query.trim());
    if q.is_empty() {
        return Ok(Vec::new());
    }
    // `contentfilter=off` is the "uncensored" part of the request. What comes
    // back is whatever Tenor has; nothing here filters it further.
    let url = format!(
        "https://tenor.googleapis.com/v2/search?q={q}&key={TENOR_KEY}\
         &limit={limit}&contentfilter=off&media_filter=gif,tinygif&client_key=nullchat"
    );
    let body = http_get_via_tor(socks_port, &url, isolation).await?;
    parse_results(&body)
}

/// Tenor's "what is popular right now", for an empty search box.
pub async fn featured(
    socks_port: u16,
    limit: u32,
    isolation: &str,
) -> Result<Vec<GifResult>, String> {
    let url = format!(
        "https://tenor.googleapis.com/v2/featured?key={TENOR_KEY}\
         &limit={limit}&contentfilter=off&media_filter=gif,tinygif&client_key=nullchat"
    );
    let body = http_get_via_tor(socks_port, &url, isolation).await?;
    parse_results(&body)
}

/// Fetch the actual GIF, so it can be sent as a file.
///
/// This is the step that keeps the recipient out of it: these bytes go into the
/// encrypted file channel, and their device never learns Tenor exists.
pub async fn fetch(socks_port: u16, url: &str, isolation: &str) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://media.tenor.com/")
        && !url.starts_with("https://media1.tenor.com/")
    {
        // Only ever fetch from where Tenor serves media. Without this, a
        // manipulated search response could point the fetch anywhere it liked.
        return Err("neočekávaná adresa GIFu".to_string());
    }
    let bytes = http_get_via_tor(socks_port, url, isolation).await?;
    check_gif(&bytes)?;
    Ok(bytes)
}

/// Is this really a GIF, and a sane one?
pub fn check_gif(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_GIF_BYTES {
        return Err(format!(
            "GIF je příliš velký ({} MB, limit je {} MB)",
            bytes.len() / (1024 * 1024),
            MAX_GIF_BYTES / (1024 * 1024)
        ));
    }
    if bytes.len() < 10 {
        return Err("prázdná odpověď".to_string());
    }
    // A file that claims to be a GIF and is not never reaches a decoder.
    if !bytes.starts_with(b"GIF87a") && !bytes.starts_with(b"GIF89a") {
        return Err("stažená data nejsou GIF".to_string());
    }
    // Logical screen size sits at bytes 6..10, little-endian.
    let w = u16::from_le_bytes([bytes[6], bytes[7]]) as u32;
    let h = u16::from_le_bytes([bytes[8], bytes[9]]) as u32;
    if w == 0 || h == 0 || w > 2000 || h > 2000 {
        return Err(format!("GIF má nesmyslné rozměry ({w}x{h})"));
    }
    Ok(())
}

/// Pull the fields we need out of Tenor's JSON.
fn parse_results(body: &[u8]) -> Result<Vec<GifResult>, String> {
    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| format!("odpověď služby nedává smysl: {e}"))?;
    let Some(items) = json.get("results").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let formats = item.get("media_formats");
        let gif = formats.and_then(|m| m.get("gif"));
        let tiny = formats.and_then(|m| m.get("tinygif")).or(gif);
        let (Some(gif), Some(tiny)) = (gif, tiny) else { continue };
        let (Some(gif_url), Some(preview_url)) = (
            gif.get("url").and_then(|v| v.as_str()),
            tiny.get("url").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let dims = gif.get("dims").and_then(|v| v.as_array());
        let (w, h) = match dims {
            Some(d) if d.len() == 2 => (
                d[0].as_u64().unwrap_or(0) as u32,
                d[1].as_u64().unwrap_or(0) as u32,
            ),
            _ => (0, 0),
        };
        out.push(GifResult {
            id: item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            preview_url: preview_url.to_string(),
            gif_url: gif_url.to_string(),
            width: w,
            height: h,
            description: item
                .get("content_description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }
    Ok(out)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_real_gifs_reach_a_decoder() {
        // The header is checked, so a file that lies about what it is stops here.
        let mut fake = b"\x89PNG\r\n\x1a\n".to_vec();
        fake.resize(64, 0);
        assert!(check_gif(&fake).is_err());
        assert!(check_gif(b"").is_err());
        assert!(check_gif(b"GIF89a").is_err(), "too short to have dimensions");

        let mut good = b"GIF89a".to_vec();
        good.extend_from_slice(&100u16.to_le_bytes());
        good.extend_from_slice(&80u16.to_le_bytes());
        assert!(check_gif(&good).is_ok());
    }

    #[test]
    fn absurd_sizes_are_refused_before_decoding() {
        let mut huge = b"GIF89a".to_vec();
        huge.extend_from_slice(&9000u16.to_le_bytes());
        huge.extend_from_slice(&9000u16.to_le_bytes());
        assert!(check_gif(&huge).is_err());

        let mut zero = b"GIF89a".to_vec();
        zero.extend_from_slice(&0u16.to_le_bytes());
        zero.extend_from_slice(&0u16.to_le_bytes());
        assert!(check_gif(&zero).is_err());

        let mut over = b"GIF89a".to_vec();
        over.extend_from_slice(&10u16.to_le_bytes());
        over.extend_from_slice(&10u16.to_le_bytes());
        over.resize(MAX_GIF_BYTES + 1, 0);
        assert!(check_gif(&over).is_err());
    }

    /// The fetch must refuse anywhere that is not Tenor's media host, so a
    /// tampered search response cannot turn it into a general-purpose fetcher
    /// pointed at an attacker's server.
    #[tokio::test]
    async fn fetching_from_anywhere_else_is_refused() {
        for url in [
            "https://evil.example/x.gif",
            "http://media.tenor.com/x.gif",
            "https://media.tenor.com.evil.example/x.gif",
        ] {
            let err = fetch(9050, url, "test").await.unwrap_err();
            assert!(err.contains("neočekávaná adresa"), "{url} was not refused: {err}");
        }
    }

    #[test]
    fn results_survive_missing_fields() {
        // Tenor sometimes omits formats; those entries are skipped rather than
        // crashing the picker.
        let body = br#"{"results":[
            {"id":"1","media_formats":{"gif":{"url":"https://media.tenor.com/a.gif","dims":[200,100]},
                                       "tinygif":{"url":"https://media.tenor.com/a-s.gif"}},
             "content_description":"cat"},
            {"id":"2"},
            {"id":"3","media_formats":{}}
        ]}"#;
        let out = parse_results(body).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].gif_url, "https://media.tenor.com/a.gif");
        assert_eq!(out[0].width, 200);
        assert_eq!(out[0].description, "cat");
    }

    #[test]
    fn queries_are_encoded() {
        assert_eq!(urlencode("happy cat"), "happy+cat");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencode("ěš"), "%C4%9B%C5%A1");
    }
}
