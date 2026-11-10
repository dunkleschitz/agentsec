"""Checks for the in-browser Pages playground (no Pyodide required)."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in __import__("sys").path:
    __import__("sys").path.insert(0, str(ROOT / "scripts"))

import sync_playground as sync  # noqa: E402

PLAY = ROOT / "docs" / "playground"


class VendorSyncTests(unittest.TestCase):
    def test_vendor_copies_match_tools(self):
        stale = sync.check_vendor(PLAY / "vendor", sync.vendor_bytes())
        self.assertEqual(stale, [], "run: python3 scripts/sync_playground.py")

    def test_sync_check_cli_is_clean(self):
        self.assertEqual(sync.main(["--check"]), 0)


class PlaygroundPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (PLAY / "index.html").read_text(encoding="utf-8")
        cls.js = (PLAY / "playground.js").read_text(encoding="utf-8")

    def test_privacy_claim_is_visible(self):
        lower = self.html.lower()
        self.assertIn("no data leaves the browser", lower)
        self.assertIn("never posts your input", lower)
        self.assertIn("pyodide", lower)

    def test_page_loads_pinned_pyodide_cdn(self):
        self.assertIn("cdn.jsdelivr.net/pyodide/v0.27.7/full/pyodide.js", self.html)
        self.assertIn("https://cdn.jsdelivr.net/pyodide/v0.27.7/full/", self.js)

    def test_all_five_tools_are_wired(self):
        for name in sync.PLAYGROUND_TOOLS:
            with self.subTest(name=name):
                self.assertIn('value="%s"' % name, self.html)
                self.assertIn(name, self.js)
                self.assertTrue((PLAY / "vendor" / f"{name}.py").is_file())

    def test_piiguard_uses_redact(self):
        self.assertIn("--redact", self.js)
        self.assertIn("Redacted copy", self.js)

    def test_sample_fixtures_exist(self):
        samples = list((PLAY / "samples").glob("*"))
        self.assertGreaterEqual(len(samples), 10)
        for path in samples:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.strip(), path)

    def test_canonical_and_nav(self):
        self.assertIn('canonical" href="https://dunkleschitz.github.io/agentsec/playground/"', self.html)
        self.assertIn("playground/", self.html)
        self.assertIn("benchmarks/", self.html)


if __name__ == "__main__":
    unittest.main()
