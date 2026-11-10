"""Tests for scripts/generate_tool_pages.py."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import generate_tool_pages as gen  # noqa: E402


class DiscoverAndParseTests(unittest.TestCase):
    def test_discovers_all_tool_readmes(self):
        names = gen.discover_tools()
        self.assertGreaterEqual(len(names), 35)
        self.assertIn("secretflow", names)
        self.assertIn("toolpin", names)
        self.assertIn("resultguard", names)

    def test_page_title_shape(self):
        for name in gen.discover_tools():
            title = gen.page_title(name)
            self.assertTrue(title.startswith(name + ": detect "), title)
            self.assertTrue(title.endswith(" in AI agents"), title)

    def test_owasp_maps_every_current_tool(self):
        names = gen.discover_tools()
        mapping = gen.parse_owasp((ROOT / "README.md").read_text(encoding="utf-8"))
        missing = [n for n in names if n not in mapping]
        self.assertEqual(missing, [], "README OWASP tables should mention every tool or be parsed")

    def test_meta_description_length(self):
        long = "x" * 400
        desc = gen.meta_description([long], "secretflow", "secrets")
        self.assertLessEqual(len(desc), 160)
        self.assertTrue(desc.endswith("…") or len(desc) < 160)


class GenerateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        cls.names = gen.discover_tools()
        cls.owasp = gen.parse_owasp((ROOT / "README.md").read_text(encoding="utf-8"))
        cls.files = gen.write_tree(cls.out, cls.names, cls.owasp)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_index_and_sitemap_exist(self):
        self.assertIn("tools/index.html", self.files)
        self.assertIn("sitemap.xml", self.files)
        self.assertTrue((self.out / "tools/index.html").is_file())
        sitemap = (self.out / "sitemap.xml").read_text(encoding="utf-8")
        self.assertIn("https://dunkleschitz.github.io/agentsec/tools/", sitemap)
        self.assertIn("https://dunkleschitz.github.io/agentsec/why/", sitemap)
        for name in self.names:
            self.assertIn(f"/tools/{name}/", sitemap)

    def test_each_tool_page_has_required_sections(self):
        required = (
            "what-it-detects",
            "rules",
            "usage",
            "example",
            "sarif-ci",
            "owasp",
        )
        for name in self.names:
            path = self.out / "tools" / name / "index.html"
            text = path.read_text(encoding="utf-8")
            title = gen.page_title(name)
            # Apostrophes are HTML-escaped in titles.
            self.assertIn("<title>", text)
            self.assertIn(name + ": detect ", text)
            self.assertIn(" in AI agents", text)
            self.assertIn('name="description" content="', text)
            desc_attr = text.split('name="description" content="', 1)[1].split('"', 1)[0]
            self.assertTrue(desc_attr.strip(), name)
            self.assertIn(f'canonical" href="https://dunkleschitz.github.io/agentsec/tools/{name}/"', text)
            for sec in required:
                self.assertIn(f'id="{sec}"', text, f"{name} missing {sec}")
            self.assertIn("agentsec " + name, text)
            if name in gen.SARIF_TOOLS:
                self.assertIn("--sarif", text)
            else:
                self.assertIn("does not yet emit SARIF", text)
            self.assertIn("dunkleschitz/agentsec@v0", text)

    def test_secretflow_mentions_owasp_and_captured_output(self):
        text = (self.out / "tools/secretflow/index.html").read_text(encoding="utf-8")
        self.assertIn("LLM02", text)
        self.assertIn("FL01", text)
        self.assertTrue(
            "risky_openai.json" in text or "risky_anthropic.json" in text or "Captured against" in text,
            "secretflow page should include captured fixture output",
        )

    def test_committed_docs_match_generator(self):
        # The Pages site should be regenerated whenever READMEs change.
        stale = gen.check_tree(ROOT / "docs", self.files)
        self.assertEqual(stale, [], "run: python3 scripts/generate_tool_pages.py")


if __name__ == "__main__":
    unittest.main()
