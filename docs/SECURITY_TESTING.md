<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Security testing Umbra

What is automated, what has to be done by hand, and — because it saves time —
which commonly recommended tools do **not** apply to this architecture and why.

## Automated, runs on every `cargo test`

| Test | What it defends |
|---|---|
| `core/tests/hostile_input.rs` | ~140 000 malformed inputs through every parser a hostile peer can reach. A panic in Rust aborts the process, so a crash here is a denial of service anyone can trigger from across the world, repeatedly. |
| `transport` handshake tests | A PREKEY not signed by the expected identity is refused; a post-quantum key that does not match the invite is refused; the classical fallback works and is reported. |
| `crypto::pq` tests | A hybrid signature with either half damaged is refused, and so is one truncated to the classical half — the downgrade a quantum attacker would attempt. |
| `store` tests | The database file is scanned byte by byte for identity keys and group ids; two passphrases cannot see each other's rows; a duress wipe leaves size and row counts unchanged. |

Run everything: `cargo test --workspace`

## Automated, run before each release

```bash
cargo audit
```

Checks all dependencies against the RustSec advisory database. Last run: no
vulnerabilities across 318 crates; one unmaintained build-time crate
(`proc-macro-error2`, pulled in by flutter_rust_bridge) with no runtime effect.

```bash
cargo clippy --workspace
```

Last run: no correctness or security findings.

## By hand — and the most important one first

### 1. Clearnet leak test (highest value)

The single most damaging failure this app could have is sending *anything*
outside Tor. It would not break encryption; it would deanonymise the user, which
is worse, because the encryption is not what they came for.

1. Start Wireshark on the real network adapter (not loopback).
2. Filter out Tor's own traffic: `not tcp.port == 9001 and not tcp.port == 443`.
3. Start Umbra, sign in, connect to a contact, send a message and a file.
4. **Expected: nothing.** Every byte Umbra sends should reach the network only
   as Tor cells from `tor.exe`.

Then the harder variant, which catches what passive watching does not:

5. Block `tor.exe` in the firewall while Umbra runs.
6. **Expected: Umbra fails to connect and says so.** If any feature keeps
   working, that feature is not going through Tor.

The updater deserves its own pass — it is the one component that talks to a
clearnet host (GitHub), and it must do so only through the SOCKS port.

### 2. What is in memory

`Frida` or a debugger attached to the running process, searching memory for
known plaintext. Umbra wipes key material on drop (`Zeroizing`), but decrypted
*messages* live in the UI as long as the conversation is open — that is
unavoidable in a messenger and is stated in the threat model. What must **not**
be findable after sign-out is the identity seed or the database key.

### 3. What is on disk

Sign in, write messages, sign out, then search the account directory for
plaintext:

```bash
grep -r "some message you sent" %APPDATA%\org.umbra
```

Expected: nothing. This is exactly how the plaintext log file was found in
1.7.1 — the database was encrypted while `umbra-app.log` sat next to it with
every message in the clear.

## Tools that do not apply, and why

Written down so nobody spends a day discovering it:

- **OWASP ZAP** — an HTTP proxy. Umbra speaks a custom binary protocol between
  peers, not HTTP, so ZAP has nothing to parse. The one exception is the
  updater, which does speak HTTPS to GitHub and can be inspected this way.
- **MobSF** — analyses the Android wrapper. Umbra's logic, crypto and storage
  are in the Rust library inside the APK, which MobSF does not decompile. It
  also flags "unencrypted SQLite" for our database, which is a false positive:
  the file is plain SQLite by design, with every value sealed individually and
  every lookup key blind-indexed (see `core/src/store.rs`).
- **Boofuzz** — network-level fuzzing. Against a Tor onion service this is
  slower by orders of magnitude than fuzzing the parsers directly, and it tests
  the same code. `core/tests/hostile_input.rs` does thousands of cases per
  second on the same functions.
- **Generic web/cloud scanners** — there is no server and no web surface.

## What is still missing

Honestly, rather than implied by omission:

- **An independent audit.** Briar has had two (Cure53 2017, Radically Open
  Security 2024). Umbra has had none. No amount of self-testing substitutes for
  this, and it is the largest single gap between us and the alternatives.
- **Coverage-guided fuzzing** (`cargo-fuzz`) — needs a nightly toolchain and
  libFuzzer; the deterministic suite above is what runs everywhere in the
  meantime.
- **Reproducible builds** — without them, a signature proves "the author built
  this", not "this matches the published source".
