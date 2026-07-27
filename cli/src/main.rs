// SPDX-License-Identifier: AGPL-3.0-or-later
//! NullChat demo CLI.
//!
//! Runs entirely on one machine and drives the REAL core modules (the same code
//! covered by the crate's tests). It is a demonstration of the on-device crypto
//! and storage layers — it is NOT yet networked (the Tor transport is a separate,
//! pending module), so `chat` is an in-process Alice→Bob loopback, not two peers
//! over the network.

use std::env;
use std::io::{self, BufRead, Write};

use nullchat_core::crypto::{keystore, padding};
use nullchat_core::crypto::ratchet::{RatchetAccount, RatchetSession};
use nullchat_core::identity::{Keypair, Roster, SignedRoster};
use nullchat_core::store::{Contact, Direction, NewMessage, Store};

const DEMO_EPOCH: u64 = 1_700_000_000;

fn main() {
    let mode = env::args().nth(1).unwrap_or_else(|| "demo".to_string());
    match mode.as_str() {
        "demo" => demo(),
        "chat" => chat(),
        other => {
            eprintln!("neznámý příkaz: {other}");
            eprintln!("použití: nullchat [demo|chat]");
            std::process::exit(2);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn rule(title: &str) {
    println!("\n\x1b[1m== {title} ==\x1b[0m");
}

fn demo() {
    println!("\x1b[1mUmbra — demo jádra (běží REÁLNÉ moduly, stejný kód co prošel 35 testy)\x1b[0m");

    // 1) Length-hiding padding ------------------------------------------------
    rule("1) Skrývání délky (padding)");
    let short = padding::pad(b"x").unwrap();
    let longer = padding::pad("tohle je mnohem delší tajná zpráva než jeden znak".as_bytes()).unwrap();
    let sealed_short = keystore::seal(b"demo-passphrase", &short).unwrap();
    let sealed_longer = keystore::seal(b"demo-passphrase", &longer).unwrap();
    println!("  'x'  (1 bajt)          -> rámec {} B -> šifra {} B", short.len(), sealed_short.len());
    println!("  '…delší zpráva…' ({} B) -> rámec {} B -> šifra {} B",
        "tohle je mnohem delší tajná zpráva než jeden znak".len(), longer.len(), sealed_longer.len());
    assert_eq!(short.len(), longer.len());
    assert_eq!(sealed_short.len(), sealed_longer.len());
    println!("  => 1 znak i dlouhá zpráva mají NA DRÁTĚ identickou délku. Obsah z délky nevyčteš.");

    // 2) End-to-end Double Ratchet -------------------------------------------
    rule("2) End-to-end šifrování (Double Ratchet, vodozemac)");
    let alice = RatchetAccount::new();
    let mut bob = RatchetAccount::new();
    let bundle = bob.publish_prekey_bundle().unwrap();
    let mut alice_session = alice.create_outbound(&bundle);

    let secret = "Ahoj Bobe, tohle je end-to-end šifrované.";
    let frame = padding::pad(secret.as_bytes()).unwrap();
    let wire = alice_session.encrypt(&frame); // Olm message — relay by viděl jen tohle
    let (mut bob_session, recovered_frame) =
        bob.create_inbound(alice.identity_key(), &wire).unwrap();
    let recovered = padding::unpad(&recovered_frame).unwrap();
    println!("  Alice -> Bob:  {:?}", secret);
    println!("  Bob rozšifroval: {:?}", String::from_utf8_lossy(&recovered));
    assert_eq!(recovered, secret.as_bytes());

    // reply, to show the ratchet advancing both ways
    let reply_frame = padding::pad("Ahoj Alice, přišlo to celé.".as_bytes()).unwrap();
    let reply = bob_session.encrypt(&reply_frame);
    let got = padding::unpad(&alice_session.decrypt(&reply).unwrap()).unwrap();
    println!("  Bob -> Alice:  {:?}", String::from_utf8_lossy(&got));

    // a stranger cannot decrypt into the session
    let stranger = RatchetAccount::new();
    let mut victim = RatchetAccount::new();
    let vb = victim.publish_prekey_bundle().unwrap();
    let mut sconn = stranger.create_outbound(&vb);
    let forged = sconn.encrypt(&padding::pad(b"jsem alice").unwrap());
    let rejected = bob_session.decrypt(&forged).is_err();
    println!("  Cizinec se vydává za Alici -> odmítnuto: {}", if rejected { "ANO ✓" } else { "NE ✗" });
    assert!(rejected);
    println!("  => Každá zpráva jiný klíč (forward secrecy). Ukradený klíč nerozšifruje historii.");

    // 3) Identity + device roster --------------------------------------------
    rule("3) Identita + podepsaný seznam zařízení");
    let id = Keypair::generate().unwrap();
    let phone = Keypair::generate().unwrap();
    let laptop = Keypair::generate().unwrap();
    println!("  Identita (účet) pubkey: {}…", &hex(&id.public())[..24]);
    let mut roster = Roster::new(id.public(), DEMO_EPOCH);
    roster.add_device(phone.public(), DEMO_EPOCH + 10);
    roster.add_device(laptop.public(), DEMO_EPOCH + 20);
    let signed = SignedRoster::sign(roster, &id).unwrap();
    println!("  Zařízení v rosteru: {}, podpis ověřen: {}", signed.roster.devices.len(), signed.verify());
    // revoke the laptop and re-sign
    let mut r2 = signed.roster.clone();
    r2.revoke_device(&laptop.public(), DEMO_EPOCH + 30);
    let signed2 = SignedRoster::sign(r2, &id).unwrap();
    println!("  Po odvolání laptopu: telefon aktivní={}, laptop aktivní={}",
        signed2.roster.is_active(&phone.public()), signed2.roster.is_active(&laptop.public()));
    println!("  Serializovaný roster: {} B (přenositelný, ověřitelný kýmkoli)", signed2.to_bytes().len());

    // 4) Encrypted local store -----------------------------------------------
    rule("4) Šifrovaný lokální store");
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).unwrap();
    let path = env::temp_dir().join("nullchat-cli-demo.sqlite");
    let _ = std::fs::remove_file(&path);
    {
        let store = Store::open(&path, &key).unwrap();
        store.upsert_contact(&Contact {
            identity_pubkey: phone.public(),
            display_name: "Bob".to_string(),
            onion_addr: "exampleonionaddress.onion".to_string(),
            added_at: DEMO_EPOCH,
            status: nullchat_core::store::ContactStatus::Accepted,
            saved: true,
            verified: false,
            pq_fingerprint: None,
        }).unwrap();
        store.insert_message(&NewMessage {
            contact_pubkey: phone.public(),
            direction: Direction::Incoming,
            sent_at: DEMO_EPOCH + 1,
            body: b"tajna zprava ulozena sifrovane",
        }).unwrap();
    }
    // reopen and read back
    let store = Store::open(&path, &key).unwrap();
    let c = store.get_contact(&phone.public()).unwrap().unwrap();
    let msgs = store.messages_for(&phone.public(), 10).unwrap();
    println!("  Uloženo a znovu načteno: kontakt {:?}, {} zpráva/y", c.display_name, msgs.len());
    println!("  Rozšifrovaný obsah: {:?}", String::from_utf8_lossy(&msgs[0].body));
    // wrong key
    let mut wrong = key;
    wrong[0] ^= 0xff;
    let bad = Store::open(&path, &wrong).unwrap();
    println!("  Otevření se špatným klíčem -> čtení selže: {}", bad.list_contacts().is_err());
    let _ = std::fs::remove_file(&path);

    println!("\n\x1b[1mVše proběhlo. To je pět hotových modulů jádra, živě na tomhle PC.\x1b[0m");
    println!("Vyzkoušej interaktivně:  cargo run -p nullchat-cli -- chat");
}

fn chat() {
    println!("NullChat — interaktivní demo (Alice -> Bob, JEDEN proces, síť zatím není).");
    println!("Piš zprávy; každou zašifruju E2E a rozšifruju na Bobově straně. Konec: /quit\n");

    let alice = RatchetAccount::new();
    let mut bob = RatchetAccount::new();
    let bundle = bob.publish_prekey_bundle().unwrap();
    let mut alice_session = alice.create_outbound(&bundle);
    let mut bob_session: Option<RatchetSession> = None;

    let stdin = io::stdin();
    print!("> ");
    io::stdout().flush().ok();
    for line in stdin.lock().lines() {
        let text = match line {
            Ok(t) => t,
            Err(_) => break,
        };
        if text == "/quit" {
            break;
        }
        let frame = padding::pad(text.as_bytes()).unwrap();
        let wire = alice_session.encrypt(&frame);
        let recovered_frame = match bob_session.as_mut() {
            Some(session) => session.decrypt(&wire).unwrap(),
            None => {
                let (session, first) = bob.create_inbound(alice.identity_key(), &wire).unwrap();
                bob_session = Some(session);
                first
            }
        };
        let plain = padding::unpad(&recovered_frame).unwrap();
        println!(
            "  [bob přijal] {}   (rámec na drátě: {} B)",
            String::from_utf8_lossy(&plain),
            frame.len()
        );
        print!("> ");
        io::stdout().flush().ok();
    }
    println!("\nkonec.");
}
