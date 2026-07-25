fn main() {
    let s = std::env::args().nth(1).unwrap_or_default();
    match umbra_core::invite::Invite::decode(s.trim()) {
        Ok(i) => {
            let hex: String = i.identity.iter().map(|b| format!("{b:02x}")).collect();
            println!("ONION={}", i.onion);
            println!("IDHEX={hex}");
            println!("NAME={}", i.username);
        }
        Err(e) => println!("CHYBA: {e}"),
    }
}
