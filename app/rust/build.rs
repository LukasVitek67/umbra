// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The GIF key is read at compile time by `option_env!("NULLCHAT_GIPHY_KEY")`.
// Cargo does not know that, so without the line below a rebuild after setting
// (or changing) the variable would quietly reuse the old object files and ship
// a binary with the wrong key — or with none.

fn main() {
    println!("cargo:rerun-if-env-changed=NULLCHAT_GIPHY_KEY");
}
