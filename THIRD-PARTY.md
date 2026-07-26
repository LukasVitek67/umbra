<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Third-party components

Umbra itself is AGPL-3.0-or-later. Everything it builds on is listed here,
generated from the build (`cargo license`, `flutter pub deps`) plus the
programs shipped next to the app. The same list in plain language is in the
app under Settings -> Licences.

## Shipped programs

| Component | Licence | Source |
|---|---|---|
| Tor daemon (`tor.exe`, `libtor.so`) | BSD-3-Clause | https://www.torproject.org/ |
| lyrebird (obfs4/snowflake) | BSD-3-Clause | https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird |
| tor-android (Android build) | BSD-3-Clause | https://github.com/guardianproject/tor-android |
| libsignal (Signal protocol) | AGPL-3.0 | https://github.com/signalapp/libsignal |

## Rust crates

```
(Apache-2.0 OR MIT) AND Unicode-3.0 (1): unicode-ident
0BSD OR Apache-2.0 OR MIT (1): adler2
AGPL-3.0 (5): libsignal-core, libsignal-debug, libsignal-protocol, signal-crypto, spqr
AGPL-3.0-or-later (3): umbra-cli, umbra-core, umbra-transport
Apache-2.0 (23): core-models, hax-lib, hax-lib-macros, hax-lib-macros-types, libcrux-hacl-rs, libcrux-hmac, libcrux-intrinsics, libcrux-macros, libcrux-ml-kem, libcrux-platform, libcrux-secrets, libcrux-sha2, libcrux-sha3, libcrux-traits, matrix-pickle, matrix-pickle-derive, prost, prost, prost-derive, prost-derive, sorted-vec, vodozemac, zopfli
Apache-2.0 AND ISC (1): ring
Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT (3): wasi, wasip2, wit-bindgen
Apache-2.0 OR BSD-1-Clause OR MIT (2): fiat-crypto, fiat-crypto
Apache-2.0 OR BSD-2-Clause OR MIT (2): zerocopy, zerocopy-derive
Apache-2.0 OR BSD-3-Clause OR MIT (2): num_enum, num_enum_derive
Apache-2.0 OR ISC OR MIT (1): rustls
Apache-2.0 OR LGPL-2.1-or-later OR MIT (2): r-efi, r-efi
Apache-2.0 OR MIT (186): addr2line, aead, aes, aes, aes-gcm-siv, android_log-sys, android_logger, anyhow, arbitrary, argon2, arrayvec, assert_matches, async-trait, atomic, backtrace, base64, base64ct, bitflags, blake2, block-buffer, block-buffer, block-padding, block-padding, bumpalo, cbc, cbc, cfg-if, chacha20, chacha20, chacha20poly1305, cipher, cipher, cmov, console_error_panic_hook, const-oid, const-oid, cpubits, cpufeatures, cpufeatures, crc32fast, crossbeam-deque, crossbeam-epoch, crossbeam-utils, crypto-common, crypto-common, ctr, ctr, ctutils, curve25519-dalek-derive, dart-sys, der, derive-where, derive_arbitrary, digest, digest, displaydoc, ed25519, either, env_filter, equivalent, fallible-iterator, fallible-streaming-iterator, flate2, futures, futures-channel, futures-core, futures-executor, futures-io, futures-macro, futures-sink, futures-task, futures-util, getrandom, getrandom, getrandom, ghash, gimli, hashbrown, hashbrown, hashbrown, hashlink, hermit-abi, hex, hkdf, hkdf, hmac, hmac, hybrid-array, indexmap, inout, inout, itertools, itertools, itoa, js-sys, lazy_static, libc, lock_api, log, md-5, num-bigint, num-integer, num-traits, num_cpus, object, once_cell, opaque-debug, parking_lot_core, password-hash, pastey, pin-project-lite, pkcs8, poly1305, polyval, polyval, portable-atomic, ppv-lite86, proc-macro-crate, proc-macro-error-attr2, proc-macro-error2, proc-macro2, quote, rand, rand, rand, rand_chacha, rand_chacha, rand_core, rand_core, rand_core, rayon, rayon-core, regex, regex-automata, regex-syntax, rustc-demangle, rustls-pki-types, rustversion, scopeguard, serde, serde_bytes, serde_core, serde_derive, serde_json, sha1, sha2, sha2, signature, smallvec, socket2, spki, syn, syn, thiserror, thiserror, thiserror-impl, thiserror-impl, threadpool, tokio-rustls, toml_datetime, toml_edit, toml_parser, typenum, universal-hash, universal-hash, uuid, wasm-bindgen, wasm-bindgen-futures, wasm-bindgen-macro, wasm-bindgen-macro-support, wasm-bindgen-shared, web-sys, windows-link, windows-sys, windows-sys, windows-targets, windows_aarch64_gnullvm, windows_aarch64_msvc, windows_i686_gnu, windows_i686_gnullvm, windows_i686_msvc, windows_x86_64_gnu, windows_x86_64_gnullvm, windows_x86_64_msvc, zeroize, zeroize_derive
Apache-2.0 OR MIT OR Zlib (2): bytemuck, miniz_oxide
BSD-3-Clause (6): curve25519-dalek, curve25519-dalek, ed25519-dalek, subtle, x25519-dalek, x25519-dalek
CDLA-Permissive-2.0 (2): webpki-roots, webpki-roots
Custom License File (1): allo-isolate
ISC (2): rustls-webpki, untrusted
MIT (25): bytes, const-str, crabgrind, dashmap, data-encoding, data-encoding-macro, data-encoding-macro-internal, delegate-attr, derive_more, derive_more-impl, flutter_rust_bridge, flutter_rust_bridge_macros, generic-array, libsqlite3-sys, mio, oslog, redox_syscall, rusqlite, simd-adler32, slab, tokio, tokio-macros, winnow, zip, zmij
MIT OR Unlicense (3): aho-corasick, byteorder, memchr
MPL-2.0 (2): hpke-rs, hpke-rs-crypto
N/A (1): rust_lib_umbra
Zlib (1): foldhash
```

## Dart / Flutter packages

Full licence texts are shown in the app (Settings -> Licences -> Package licence texts).

```
Dart SDK 3.12.2
Flutter SDK 3.44.8
umbra 1.3.0+1

dependencies:
- cupertino_icons 1.0.9
- file_picker 11.0.2 [flutter flutter_web_plugins flutter_plugin_android_lifecycle plugin_platform_interface ffi path win32 cross_file web dbus]
- flutter 0.0.0 [characters collection material_color_utilities meta vector_math sky_engine]
- flutter_rust_bridge 2.12.0 [args async build_cli_annotations meta path web]
- local_notifier 0.1.6 [flutter uuid]
- path_provider 2.1.6 [flutter path_provider_android path_provider_foundation path_provider_linux path_provider_platform_interface path_provider_windows]
- rust_lib_umbra 0.0.1 [flutter plugin_platform_interface]
- tray_manager 0.5.3 [flutter menu_base path shortid]
- window_manager 0.5.2 [flutter path screen_retriever]

transitive dependencies:
- args 2.7.0
- async 2.13.1 [collection meta]
- build_cli_annotations 2.1.1 [args meta]
- characters 1.4.1
- code_assets 1.2.1 [collection hooks]
- collection 1.19.1
- cross_file 0.3.5+4 [meta web]
- crypto 3.0.7 [typed_data]
- dbus 0.7.14 [args ffi meta xml]
- ffi 2.2.0
- fixnum 1.1.1
- flutter_plugin_android_lifecycle 2.0.35 [flutter]
- flutter_web_plugins 0.0.0 [flutter]
- hooks 2.0.2 [collection crypto logging meta pub_semver record_use yaml]
- jni 1.0.0 [args collection ffi meta package_config path plugin_platform_interface]
- jni_flutter 1.0.1 [flutter jni]
- json_annotation 4.12.0 [meta]
- logging 1.3.0
- material_color_utilities 0.13.0 [collection]
- menu_base 0.1.1 [flutter]
- meta 1.18.0
- objective_c 9.4.1 [code_assets collection ffi hooks logging meta pub_semver]
- package_config 2.2.0 [path]
- path 1.9.1
- path_provider_android 2.3.1 [flutter jni jni_flutter path_provider_platform_interface]
- path_provider_foundation 2.6.0 [ffi flutter objective_c path_provider_platform_interface]
- path_provider_linux 2.2.2 [ffi flutter path path_provider_platform_interface xdg_directories]
- path_provider_platform_interface 2.1.3 [flutter platform plugin_platform_interface]
- path_provider_windows 2.3.0 [ffi flutter path path_provider_platform_interface]
- petitparser 7.0.2 [meta collection]
- platform 3.1.6
- plugin_platform_interface 2.1.8 [meta]
- pub_semver 2.2.0 [collection]
- record_use 0.6.0 [collection meta pub_semver]
- screen_retriever 0.2.2 [flutter screen_retriever_linux screen_retriever_macos screen_retriever_platform_interface screen_retriever_windows]
- screen_retriever_linux 0.2.2 [flutter screen_retriever_platform_interface]
- screen_retriever_macos 0.2.2 [flutter screen_retriever_platform_interface]
- screen_retriever_platform_interface 0.2.2 [flutter json_annotation plugin_platform_interface]
- screen_retriever_windows 0.2.2 [flutter screen_retriever_platform_interface]
- shortid 0.1.2
- sky_engine 0.0.0
- source_span 1.10.2 [collection path term_glyph]
- string_scanner 1.4.1 [source_span]
- term_glyph 1.2.2
- typed_data 1.4.0 [collection]
- uuid 4.6.0 [crypto fixnum]
- vector_math 2.2.0
- web 1.1.1
- win32 5.15.0 [ffi]
- xdg_directories 1.1.0 [meta path]
- xml 6.6.1 [collection meta petitparser]
- yaml 3.1.3 [collection source_span string_scanner]
```
