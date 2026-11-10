#!/usr/bin/env python3
"""Copy the playground's stdlib tools into docs/playground/vendor/.

The GitHub Pages playground runs these files in-browser with Pyodide.
They must stay byte-identical to tools/<name>/<name>.py so a Pages visitor
gets the same scanner as the repo.

Usage:
  python3 scripts/sync_playground.py
  python3 scripts/sync_playground.py --check   # exit 1 if vendor copies drift
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
VENDOR_DIR = ROOT / "docs" / "playground" / "vendor"
PLAYGROUND_TOOLS = (
    "resultguard",
    "secretflow",
    "piiguard",
    "mcpposture",
    "shellfence",
)


def vendor_bytes() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for name in PLAYGROUND_TOOLS:
        src = TOOLS_DIR / name / f"{name}.py"
        if not src.is_file():
            raise FileNotFoundError("missing tool script: %s" % src)
        out[f"{name}.py"] = src.read_bytes()
    return out


def write_vendor(dest: Path, files: dict[str, bytes]) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (dest / name).write_bytes(data)
    readme = dest / "README.md"
    readme.write_text(
        "Vendored copies of the five playground scanners, kept identical to "
        "`tools/<name>/<name>.py` by `scripts/sync_playground.py`. Do not edit "
        "these files by hand.\n",
        encoding="utf-8",
    )


def check_vendor(dest: Path, files: dict[str, bytes]) -> list[str]:
    stale = []
    for name, data in files.items():
        path = dest / name
        if not path.is_file():
            stale.append("missing: %s" % name)
            continue
        if path.read_bytes() != data:
            stale.append("stale: %s" % name)
    return stale


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--out", type=Path, default=None, help="vendor directory")
    args = parser.parse_args(argv)
    files = vendor_bytes()
    dest = args.out or VENDOR_DIR
    if args.check:
        stale = check_vendor(dest, files)
        if stale:
            sys.stderr.write(
                "sync_playground: docs/playground/vendor is out of date:\n  "
                + "\n  ".join(stale)
                + "\nRe-run: python3 scripts/sync_playground.py\n"
            )
            return 1
        sys.stdout.write("sync_playground: up to date (%d tools)\n" % len(files))
        return 0
    write_vendor(dest, files)
    sys.stdout.write("sync_playground: wrote %d tools under %s\n" % (len(files), dest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
