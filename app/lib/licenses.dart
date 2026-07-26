// SPDX-License-Identifier: AGPL-3.0-or-later
//
// What Umbra is made of, and under what terms.
//
// Two reasons this screen exists. The legal one: several of these licences ask
// that their notice travels with the program, so shipping the app without them
// would be a breach. The honest one: a privacy tool asks people to trust code
// they will never read, and the least it can do is say plainly whose code it is
// running — the cryptography, the Tor daemon, all of it.
//
// The list below covers what Umbra ships and depends on directly. The complete
// transitive list (every crate and package, with its licence) lives in
// THIRD-PARTY.md next to the source, and the exact texts of the Dart/Flutter
// licences are one tap away in "Package licences" (Flutter's own registry).

class LicenseEntry {
  const LicenseEntry(this.name, this.license, this.what, {this.url});
  final String name;
  final String license;
  final String what;
  final String? url;
}

class LicenseSection {
  const LicenseSection(this.title, this.entries);
  final String title;
  final List<LicenseEntry> entries;
}

/// Everything Umbra ships or links against, grouped the way a reader thinks
/// about it rather than the way a build system does.
const List<LicenseSection> kLicenses = [
  LicenseSection('Umbra', [
    LicenseEntry(
      'Umbra',
      'AGPL-3.0-or-later',
      'This app. Copyleft: anyone who runs a modified version must be able to get its source.',
      url: 'https://github.com/LukasVitek67/umbra',
    ),
  ]),
  LicenseSection('Cryptography', [
    LicenseEntry(
      'libsignal-protocol (Signal)',
      'AGPL-3.0',
      'The Signal protocol: X3DH/PQXDH session setup and the Double Ratchet that gives every message its own key.',
      url: 'https://github.com/signalapp/libsignal',
    ),
    LicenseEntry('vodozemac (Matrix.org)', 'Apache-2.0',
        'The Olm ratchet used by sessions created before the move to libsignal.'),
    LicenseEntry('ed25519-dalek, curve25519-dalek, x25519-dalek', 'BSD-3-Clause',
        'Identity signatures and key agreement.'),
    LicenseEntry('argon2', 'Apache-2.0 OR MIT',
        'Turns your passphrase into the key that unlocks the local database.'),
    LicenseEntry('chacha20poly1305', 'Apache-2.0 OR MIT',
        'Encrypts everything stored on this computer.'),
    LicenseEntry('sha2, hmac, hkdf, blake2', 'Apache-2.0 OR MIT', 'Hashing and key derivation.'),
    LicenseEntry('zeroize', 'Apache-2.0 OR MIT', 'Wipes key material from memory after use.'),
    LicenseEntry('getrandom', 'Apache-2.0 OR MIT', 'Randomness from the operating system.'),
    LicenseEntry('rustls, ring, webpki-roots', 'Apache-2.0 / ISC / MIT / CDLA-Permissive-2.0',
        'TLS for the update check (which itself runs through Tor).'),
  ]),
  LicenseSection('Network', [
    LicenseEntry(
      'Tor (tor.exe / libtor.so)',
      'BSD-3-Clause',
      'The onion router. Umbra ships the official daemon and drives it; it does not reimplement Tor.',
      url: 'https://www.torproject.org/',
    ),
    LicenseEntry('lyrebird (obfs4, snowflake)', 'BSD-3-Clause',
        'Pluggable transports that get Tor through censorship (desktop only for now).'),
    LicenseEntry('tor-android (Guardian Project)', 'BSD-3-Clause',
        'The same Tor daemon, built for Android.'),
    LicenseEntry('tokio', 'MIT', 'The async runtime the transport runs on.'),
  ]),
  LicenseSection('Storage', [
    LicenseEntry('rusqlite / SQLite', 'MIT / public domain',
        'The local database. SQLite itself is in the public domain.'),
    LicenseEntry('serde, serde_json', 'Apache-2.0 OR MIT', 'Reading and writing structured data.'),
    LicenseEntry('zip', 'MIT', 'Unpacking a downloaded update.'),
  ]),
  LicenseSection('App', [
    LicenseEntry('Flutter, Dart SDK', 'BSD-3-Clause', 'The interface framework.', url: 'https://flutter.dev'),
    LicenseEntry('flutter_rust_bridge, cargokit', 'MIT', 'Connects the Dart interface to the Rust core.'),
    LicenseEntry('path_provider, file_picker', 'BSD-3-Clause / MIT', 'Data folders and picking files to send.'),
    LicenseEntry('window_manager, tray_manager, screen_retriever', 'MIT',
        'Running in the tray and the window behaviour that goes with it.'),
    LicenseEntry('local_notifier', 'MIT', 'Desktop notifications for incoming messages.'),
    LicenseEntry('Material Icons', 'Apache-2.0', 'The icon set.'),
  ]),
];
