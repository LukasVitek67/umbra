// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local accounts — several identities on one computer, like browser profiles.
//!
//! Each account owns a directory (`accounts/<id>/`) holding its encrypted
//! database, its Tor state and its onion-service key, so accounts share nothing
//! and cannot see each other's messages.
//!
//! An account may opt into **auto sign-in**. The passphrase is then stored with
//! Windows DPAPI, which encrypts it against the current *Windows* user account:
//! copying the file to another machine or another user profile makes it
//! undecryptable. That is weaker than typing the passphrase every time — the
//! passphrase then protects data only while the Windows account is locked — so
//! it is per-account and off by default.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One entry in the on-disk account list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntry {
    pub id: String,
    pub name: String,
    /// Sign in without asking for the passphrase.
    #[serde(default)]
    pub autologin: bool,
    /// DPAPI-protected passphrase, base64. Present only when `autologin`.
    #[serde(default)]
    pub secret: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AccountFile {
    #[serde(default)]
    accounts: Vec<AccountEntry>,
}

fn list_path(root: &Path) -> PathBuf {
    root.join("accounts.json")
}

/// The directory that holds one account's data.
pub fn account_dir(root: &Path, id: &str) -> PathBuf {
    root.join("accounts").join(id)
}

/// Read the account list (empty when the file does not exist yet).
pub fn load(root: &Path) -> Vec<AccountEntry> {
    std::fs::read_to_string(list_path(root))
        .ok()
        .and_then(|s| serde_json::from_str::<AccountFile>(&s).ok())
        .map(|f| f.accounts)
        .unwrap_or_default()
}

fn save(root: &Path, accounts: &[AccountEntry]) -> Result<(), String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&AccountFile { accounts: accounts.to_vec() })
        .map_err(|e| e.to_string())?;
    std::fs::write(list_path(root), json).map_err(|e| e.to_string())
}

/// Add or replace an entry.
pub fn upsert(root: &Path, entry: AccountEntry) -> Result<(), String> {
    let mut all = load(root);
    match all.iter_mut().find(|a| a.id == entry.id) {
        Some(existing) => *existing = entry,
        None => all.push(entry),
    }
    save(root, &all)
}

/// Remove an account from the list **and delete its data directory**.
pub fn remove(root: &Path, id: &str) -> Result<(), String> {
    let mut all = load(root);
    all.retain(|a| a.id != id);
    save(root, &all)?;
    let dir = account_dir(root, id);
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// A fresh random account id.
pub fn new_id() -> Result<String, String> {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).map_err(|_| "RNG failed".to_string())?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Move a pre-accounts installation (data straight in `root`) into an account.
///
/// Older builds kept one identity in the root directory. Rather than orphaning
/// it, adopt it as the first account so nobody loses their identity or history.
pub fn migrate_legacy(root: &Path) -> Result<(), String> {
    if !(root.join("nullchat.db").exists() || root.join("umbra.db").exists()) || !load(root).is_empty() {
        return Ok(());
    }
    let id = new_id()?;
    let dir = account_dir(root, &id);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Both spellings: a pre-rename install has the old ones.
    for name in ["nullchat.db", "nullchat.salt", "nullchat.kdf", "umbra.db", "umbra.salt", "umbra.kdf", "torrc", "tor.log", "nullchat-app.log", "umbra-app.log"] {
        let from = root.join(name);
        if from.exists() {
            let _ = std::fs::rename(&from, dir.join(name));
        }
    }
    for name in ["hs", "tor-data", "files"] {
        let from = root.join(name);
        if from.exists() {
            let _ = std::fs::rename(&from, dir.join(name));
        }
    }
    upsert(
        root,
        AccountEntry { id, name: "Account".to_string(), autologin: false, secret: String::new() },
    )
}

// --- passphrase storage (Windows DPAPI) ------------------------------------

#[cfg(windows)]
mod dpapi {
    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(
            data_in: *const DataBlob,
            description: *const u16,
            optional_entropy: *const DataBlob,
            reserved: *mut core::ffi::c_void,
            prompt_struct: *mut core::ffi::c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            data_in: *const DataBlob,
            description: *mut *mut u16,
            optional_entropy: *const DataBlob,
            reserved: *mut core::ffi::c_void,
            prompt_struct: *mut core::ffi::c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    /// Encrypt bytes so only this Windows user on this machine can read them,
    /// and only together with `entropy`.
    pub fn protect(plain: &[u8], entropy: &[u8]) -> Option<Vec<u8>> {
        let input = DataBlob { cb_data: plain.len() as u32, pb_data: plain.as_ptr() as *mut u8 };
        let extra = DataBlob { cb_data: entropy.len() as u32, pb_data: entropy.as_ptr() as *mut u8 };
        let extra_ptr = if entropy.is_empty() { std::ptr::null() } else { &extra };
        let mut out = DataBlob { cb_data: 0, pb_data: std::ptr::null_mut() };
        unsafe {
            let ok = CryptProtectData(
                &input,
                std::ptr::null(),
                extra_ptr,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut out,
            );
            if ok == 0 {
                return None;
            }
            let slice = std::slice::from_raw_parts(out.pb_data, out.cb_data as usize).to_vec();
            LocalFree(out.pb_data as *mut _);
            Some(slice)
        }
    }

    /// Reverse of [`protect`]; returns `None` on another user, another machine,
    /// or the wrong `entropy`.
    pub fn unprotect(blob: &[u8], entropy: &[u8]) -> Option<Vec<u8>> {
        let input = DataBlob { cb_data: blob.len() as u32, pb_data: blob.as_ptr() as *mut u8 };
        let extra = DataBlob { cb_data: entropy.len() as u32, pb_data: entropy.as_ptr() as *mut u8 };
        let extra_ptr = if entropy.is_empty() { std::ptr::null() } else { &extra };
        let mut out = DataBlob { cb_data: 0, pb_data: std::ptr::null_mut() };
        unsafe {
            let ok = CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                extra_ptr,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut out,
            );
            if ok == 0 {
                return None;
            }
            let slice = std::slice::from_raw_parts(out.pb_data, out.cb_data as usize).to_vec();
            LocalFree(out.pb_data as *mut _);
            Some(slice)
        }
    }
}

#[cfg(not(windows))]
mod dpapi {
    // No OS-bound secret store here: refuse rather than write a passphrase in
    // the clear, so "remember me" simply stays unavailable.
    pub fn protect(_plain: &[u8], _entropy: &[u8]) -> Option<Vec<u8>> {
        None
    }
    pub fn unprotect(_blob: &[u8], _entropy: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Extra input the stored passphrase is bound to, on top of DPAPI's own
/// binding to the Windows user.
///
/// Plain DPAPI decrypts for *anything* running as this user, and the tools that
/// go looking for saved credentials work exactly that way: walk the disk, find
/// protected blobs, hand each one back to `CryptUnprotectData`. Mixing in the
/// account's own salt means `accounts.json` by itself yields nothing — the
/// attacker also needs that account's directory, and needs to know this program
/// well enough to pair them.
///
/// It is a higher fence, not a different kind of fence. The source is public and
/// both files sit on the same disk, so anyone who targets NullChat specifically
/// still gets through. That is what the warning next to the checkbox says, and
/// it stays true: auto sign-in trades the passphrase's protection for not
/// typing it.
fn entropy_for(account_dir: &Path) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"nullchat-autologin-v2");
    // Written when the account is created and never touched again. If it cannot
    // be read the blob simply will not open, and an unopenable blob means the
    // app asks for the passphrase — the safe direction to fail in.
    for name in ["nullchat.salt", "umbra.salt"] {
        if let Ok(salt) = std::fs::read(account_dir.join(name)) {
            h.update(&salt);
            break;
        }
    }
    h.finalize().to_vec()
}

/// Protect a passphrase for auto sign-in. Returns base64, or `None` when the
/// platform offers no OS-bound protection.
pub fn protect_passphrase(account_dir: &Path, passphrase: &str) -> Option<String> {
    dpapi::protect(passphrase.as_bytes(), &entropy_for(account_dir)).map(|b| B64.encode(b))
}

/// Recover a passphrase stored by [`protect_passphrase`].
///
/// Builds before 2.3.11 wrote the blob with no entropy at all, so try that too
/// rather than locking those accounts out of their own auto sign-in. Signing in
/// rewrites the entry, which is how they migrate.
pub fn recover_passphrase(account_dir: &Path, secret_b64: &str) -> Option<String> {
    let blob = B64.decode(secret_b64).ok()?;
    let plain = dpapi::unprotect(&blob, &entropy_for(account_dir))
        .or_else(|| dpapi::unprotect(&blob, &[]))?;
    String::from_utf8(plain).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_list_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nullchat-acct-{}", new_id().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load(&dir).is_empty());

        let id = new_id().unwrap();
        upsert(
            &dir,
            AccountEntry { id: id.clone(), name: "Alice".into(), autologin: false, secret: String::new() },
        )
        .unwrap();
        let all = load(&dir);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "Alice");

        remove(&dir, &id).unwrap();
        assert!(load(&dir).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nullchat-dpapi-{}", new_id().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nullchat.salt"), b"sixteen byte salt").unwrap();

        let secret = protect_passphrase(&dir, "tajna fraze 123").expect("DPAPI available");
        assert_ne!(secret, "tajna fraze 123");
        assert_eq!(recover_passphrase(&dir, &secret).unwrap(), "tajna fraze 123");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The point of the entropy: `accounts.json` on its own is not enough.
    #[cfg(windows)]
    #[test]
    fn the_blob_alone_does_not_open() {
        let mine = std::env::temp_dir().join(format!("nullchat-ent-a-{}", new_id().unwrap()));
        let theirs = std::env::temp_dir().join(format!("nullchat-ent-b-{}", new_id().unwrap()));
        std::fs::create_dir_all(&mine).unwrap();
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::write(mine.join("nullchat.salt"), b"the real salt").unwrap();
        std::fs::write(theirs.join("nullchat.salt"), b"a different salt").unwrap();

        let secret = protect_passphrase(&mine, "tajna fraze 123").expect("DPAPI available");
        // Same Windows user, same machine, copied blob — and still nothing,
        // because the account directory did not come with it.
        assert!(recover_passphrase(&theirs, &secret).is_none());

        let _ = std::fs::remove_dir_all(mine);
        let _ = std::fs::remove_dir_all(theirs);
    }
}
