// SPDX-License-Identifier: AGPL-3.0-or-later
//! Release signing for the in-app updater.
//!
//! The app installs an update only if the archive carries a valid Ed25519
//! signature from the key baked into `app/rust/src/updater.rs`. This tool makes
//! that key, signs an archive with it, and can check a signature by hand.
//!
//! ```text
//! nullchat-sign keygen <key-file>          make a new signing key (KEEP IT SECRET)
//! nullchat-sign pubkey <key-file>          print the public key to paste into updater.rs
//! nullchat-sign sign   <key-file> <file>   write <file>.sig
//! nullchat-sign verify <pubkey-hex> <file> check <file> against <file>.sig
//! ```
//!
//! The key file holds the 32-byte secret seed as hex. Anyone who copies it can
//! push code to every NullChat user, so it belongs outside the repository — on the
//! author's machine (and a backup they control), nowhere else.

use std::path::Path;
use std::process::ExitCode;

use nullchat_core::identity::{verify, Keypair};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    let result = match (cmd, args.len()) {
        ("keygen", 2) => keygen(&args[1]),
        ("pubkey", 2) => pubkey(&args[1]),
        ("sign", 3) => sign(&args[1], &args[2]),
        ("verify", 3) => verify_file(&args[1], &args[2]),
        _ => {
            eprintln!(
                "nullchat-sign keygen <key-file>\n\
                 nullchat-sign pubkey <key-file>\n\
                 nullchat-sign sign   <key-file> <file>\n\
                 nullchat-sign verify <pubkey-hex> <file>"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chyba: {e}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(key_file: &str) -> Result<(), String> {
    if Path::new(key_file).exists() {
        // Overwriting a signing key would orphan every already-published
        // release, so it never happens by accident.
        return Err(format!("{key_file} už existuje — nepřepisuji podepisovací klíč"));
    }
    let kp = Keypair::generate().map_err(|e| e.to_string())?;
    std::fs::write(key_file, hex(&*kp.secret_seed())).map_err(|e| e.to_string())?;
    println!("soukromý klíč: {key_file}  (NIKDY nedávej do repozitáře ani nikam nahrávej)");
    println!("veřejný klíč do app/rust/src/updater.rs:");
    println!("{}", hex(&kp.public()));
    Ok(())
}

fn load(key_file: &str) -> Result<Keypair, String> {
    let text = std::fs::read_to_string(key_file).map_err(|e| format!("{key_file}: {e}"))?;
    let seed: [u8; 32] = unhex(text.trim())
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "klíč není 32 bajtů v hexu".to_string())?;
    Ok(Keypair::from_seed(&seed))
}

fn pubkey(key_file: &str) -> Result<(), String> {
    println!("{}", hex(&load(key_file)?.public()));
    Ok(())
}

fn sign(key_file: &str, file: &str) -> Result<(), String> {
    let kp = load(key_file)?;
    let data = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let sig = kp.sign(&data);
    let out = format!("{file}.sig");
    std::fs::write(&out, hex(&sig)).map_err(|e| e.to_string())?;
    println!("{out}");
    Ok(())
}

fn verify_file(pubkey_hex: &str, file: &str) -> Result<(), String> {
    let public: [u8; 32] = unhex(pubkey_hex)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "veřejný klíč není 32 bajtů v hexu".to_string())?;
    let data = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let sig_text = std::fs::read_to_string(format!("{file}.sig"))
        .map_err(|e| format!("{file}.sig: {e}"))?;
    let sig: [u8; 64] = unhex(sig_text.trim())
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "podpis není 64 bajtů v hexu".to_string())?;
    if verify(&public, &data, &sig) {
        println!("podpis sedí");
        Ok(())
    } else {
        Err("podpis NESEDÍ".to_string())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
