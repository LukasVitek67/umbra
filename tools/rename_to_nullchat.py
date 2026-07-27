# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rename Umbra to NullChat across the tree.

Four things must NOT be renamed, and each of them would cost a user something
real:

1. `umbra1:` — the invite prefix. It is a wire format. Changing it means every
   invite anyone has ever shared stops parsing, including the ones already
   pasted into other people's chats.

2. `org.umbra.umbra` — the Android applicationId. Android treats a new
   applicationId as a different app: no update path, no access to the old app's
   data. The user would lose their identity and have to start over. The visible
   name (`android:label`) changes instead, which is what people actually see.

3. `LukasVitek67/umbra` — the GitHub URLs. The repository is still called that.
   Renaming it is the owner's decision, and until it happens these URLs must
   keep working or the updater breaks.

4. `%APPDATA%\\org.umbra\\umbra` — the existing data directory. Handled in Dart
   by preferring the old path when it exists (see `app_dir.dart`), so nobody
   has to migrate anything.

Run:  python tools/rename_to_nullchat.py [--dry-run]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Applied in order. Each is (pattern, replacement); patterns are regexes.
RULES: list[tuple[str, str]] = [
    # Crate and package identifiers.
    (r"\bumbra-core\b", "nullchat-core"),
    (r"\bumbra-transport\b", "nullchat-transport"),
    (r"\bumbra-cli\b", "nullchat-cli"),
    (r"\bumbra_core\b", "nullchat_core"),
    (r"\bumbra_transport\b", "nullchat_transport"),
    (r"\brust_lib_umbra\b", "rust_lib_nullchat"),
    (r"\bumbra-sign\b", "nullchat-sign"),
    (r"\bumbra-chat\b", "nullchat-peer"),
    (r"\bumbra-diagnostika\b", "nullchat-diagnostika"),
    (r"\bumbra-app\.log\b", "nullchat-app.log"),
    (r"\bumbra-tor\.pid\b", "nullchat-tor.pid"),
    (r"\bumbra\.db\b", "nullchat.db"),
    (r"\bumbra\.salt\b", "nullchat.salt"),
    (r"\bumbra\.kdf\b", "nullchat.kdf"),
    # Prose and display names.
    (r"\bUmbra\b", "NullChat"),
    (r"\bUMBRA\b", "NULLCHAT"),
    # Bare lowercase `umbra` last, so the specific rules above win.
    (r"\bumbra\b", "nullchat"),
]

# Substrings that must survive verbatim. A line containing any of these is
# protected: the tokens are restored after the rules run.
PROTECTED = [
    "umbra1:",              # invite prefix — a wire format
    "org.umbra.umbra",      # Android applicationId — renaming loses user data
    "org.umbra/native",     # the platform channel that goes with it
    "LukasVitek67/umbra",   # repository URLs, until the repo itself is renamed
    "org.umbra",            # existing data directory
]

SKIP_DIRS = {".git", "target", "build", ".dart_tool", "dist", ".gradle"}
SKIP_SUFFIXES = {".png", ".ico", ".gif", ".jpg", ".jpeg", ".zip", ".sig", ".otf", ".ttf"}


def protect(text: str) -> tuple[str, dict[str, str]]:
    """Swap protected substrings for placeholders the rules cannot match."""
    saved: dict[str, str] = {}
    for i, token in enumerate(PROTECTED):
        placeholder = f"\x00PROTECTED{i}\x00"
        if token in text:
            saved[placeholder] = token
            text = text.replace(token, placeholder)
    return text, saved


def restore(text: str, saved: dict[str, str]) -> str:
    for placeholder, token in saved.items():
        text = text.replace(placeholder, token)
    return text


def rewrite(path: Path, dry_run: bool) -> int:
    try:
        original = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return 0

    text, saved = protect(original)
    for pattern, replacement in RULES:
        text = re.sub(pattern, replacement, text)
    text = restore(text, saved)

    if text == original:
        return 0
    if not dry_run:
        # Explicit UTF-8, no BOM. Writing these files through PowerShell is what
        # double-encoded the Czech strings once already.
        path.write_text(text, encoding="utf-8", newline="")
    return sum(1 for _ in re.finditer(r"NullChat|nullchat|NULLCHAT", text))


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    files = []
    for line in out.stdout.splitlines():
        p = ROOT / line
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in SKIP_SUFFIXES:
            continue
        files.append(p)
    return files


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    changed = 0
    for path in tracked_files():
        n = rewrite(path, dry_run)
        if n:
            changed += 1
            print(f"  {path.relative_to(ROOT)}")
    print(f"\n{'would change' if dry_run else 'changed'}: {changed} files")
    print("protected and left alone:", ", ".join(PROTECTED))


if __name__ == "__main__":
    main()
