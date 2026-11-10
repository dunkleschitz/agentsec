#!/usr/bin/env python3
"""Headless-browser check that the Pages playground renders findings.

This is deliberately *not* part of the stdlib CI matrix. It needs Playwright,
Chromium, and a network fetch of the Pyodide CDN. Run it from a clone:

    python3 -m pip install playwright
    python3 -m playwright install chromium
    python3 scripts/test_playground_browser.py

The script serves docs/ locally, opens /playground/, loads the poisoned
resultguard fixture, waits for findings (e.g. TR01) to appear, and also
checks that piiguard --redact shows a redacted copy. It never posts input
anywhere.
"""
from __future__ import annotations

import argparse
import http.server
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def start_server(directory: Path, port: int) -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    directory_s = str(directory)

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory_s, **kwargs)

        def log_message(self, format, *args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--timeout", type=int, default=120_000, help="ms to wait for Pyodide + scan")
    args = parser.parse_args(argv)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.stderr.write(
            "Playwright is not installed. This check is optional and is not part of CI.\n"
            "Install with: python3 -m pip install playwright && python3 -m playwright install chromium\n"
        )
        return 2

    if not (DOCS / "playground" / "index.html").is_file():
        sys.stderr.write("docs/playground/index.html is missing\n")
        return 2

    server, _thread = start_server(DOCS, args.port)
    url = f"http://127.0.0.1:{args.port}/playground/"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded")
            # Privacy claim is visible without waiting for Pyodide.
            body = page.inner_text("body")
            if "No data leaves the browser" not in body:
                sys.stderr.write("privacy statement missing from rendered page\n")
                return 1
            # Wait until the runtime is ready (status.ready).
            page.wait_for_function(
                "() => document.getElementById('status') && /ready/i.test(document.getElementById('status').textContent)",
                timeout=args.timeout,
            )
            # Default tool is resultguard; load the poisoned sample and scan.
            page.select_option("#sample", "resultguard-poisoned.json")
            # The change handler is async (fetch); wait for textarea to fill.
            page.wait_for_function(
                "() => document.getElementById('input').value.includes('ignore previous instructions')",
                timeout=15_000,
            )
            page.click("#run")
            page.wait_for_selector("#scan-summary", timeout=args.timeout)
            results = page.inner_text("#results")
            if "TR01" not in results:
                sys.stderr.write("resultguard results did not include TR01:\n%s\n" % results[:2000])
                return 1
            if "finding" not in results.lower():
                sys.stderr.write("results did not render a findings summary\n")
                return 1
            print("ok: resultguard rendered TR01 and a findings summary")

            # piiguard --redact path
            page.select_option("#tool", "piiguard")
            page.select_option("#sample", "piiguard-risky.txt")
            page.wait_for_function(
                "() => document.getElementById('input').value.includes('jordan.hale@example.com')",
                timeout=15_000,
            )
            page.click("#run")
            page.wait_for_function(
                "() => document.getElementById('results') && document.getElementById('results').innerText.includes('Redacted copy')",
                timeout=args.timeout,
            )
            results = page.inner_text("#results")
            if not any(tag in results for tag in ("PG02", "PG03", "PG04", "PG01")):
                sys.stderr.write("piiguard results missing a PII finding:\n%s\n" % results[:2000])
                return 1
            if "Redacted copy" not in results:
                sys.stderr.write("piiguard did not render a redacted copy\n")
                return 1
            print("ok: piiguard rendered findings and a redacted copy")
            browser.close()
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
