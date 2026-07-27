# SPDX-License-Identifier: AGPL-3.0-or-later
"""Point every call site at AppDir instead of getApplicationSupportDirectory.

Done as a script rather than by hand because missing one of them would leave
part of the app reading the new (empty) location while the rest reads the old
one — settings in one place, accounts in another, with no error to notice.
"""

from __future__ import annotations

import re
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app" / "lib"

# (file, old expression, new expression)
EDITS = [
    ("autostart.dart", "final dir = await getApplicationSupportDirectory();",
     "final dir = Directory(await AppDir.path());"),
    ("l10n.dart", "final dir = await getApplicationSupportDirectory();",
     "final dir = Directory(await AppDir.path());"),
    ("notifications.dart", "final dir = await getApplicationSupportDirectory();",
     "final dir = Directory(await AppDir.path());"),
    ("palette.dart", "final dir = await getApplicationSupportDirectory();",
     "final dir = Directory(await AppDir.path());"),
    ("single_instance.dart", "final dir = await getApplicationSupportDirectory();",
     "final dir = Directory(await AppDir.path());"),
    ("mock.dart", "Future<String> _dir() async => (await getApplicationSupportDirectory()).path;",
     "Future<String> _dir() async => AppDir.path();"),
]


def ensure_import(text: str) -> str:
    if "import 'app_dir.dart';" in text:
        return text
    # Put it with the other local imports, keeping them sorted-ish.
    m = re.search(r"^import '(?!package:|dart:)", text, re.MULTILINE)
    if m:
        return text[: m.start()] + "import 'app_dir.dart';\n" + text[m.start() :]
    m = re.search(r"^(import [^\n]+\n)(?!import)", text, re.MULTILINE)
    if m:
        return text[: m.end()] + "\nimport 'app_dir.dart';\n" + text[m.end() :]
    return "import 'app_dir.dart';\n" + text


def ensure_dart_io(text: str) -> str:
    if "import 'dart:io'" in text:
        return text
    return "import 'dart:io';\n" + text


def main() -> None:
    for name, old, new in EDITS:
        path = APP / name
        text = path.read_text(encoding="utf-8")
        if old not in text:
            print(f"  SKIP {name}: pattern not found")
            continue
        text = text.replace(old, new)
        text = ensure_import(text)
        if "Directory(" in new:
            text = ensure_dart_io(text)
        path.write_text(text, encoding="utf-8", newline="")
        print(f"  {name}")


if __name__ == "__main__":
    main()
