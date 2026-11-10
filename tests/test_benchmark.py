"""Checks for the labeled detection benchmark."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks"
MANIFEST = BENCH / "manifest.json"
RESULTS = BENCH / "results.json"


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.samples = cls.manifest["samples"]

    def test_enough_labeled_samples(self):
        self.assertGreaterEqual(len(self.samples), 40)
        tools = {s["tool"] for s in self.samples}
        for name in ("resultguard", "toolpoison", "tracesweep", "secretflow", "shellfence"):
            self.assertIn(name, tools)
        labels = {s["label"] for s in self.samples}
        self.assertEqual(labels, {"malicious", "benign"})

    def test_every_sample_file_exists_and_is_nonempty(self):
        for sample in self.samples:
            path = BENCH / sample["path"]
            self.assertTrue(path.is_file(), sample["path"])
            self.assertTrue(path.read_text(encoding="utf-8").strip(), sample["path"])
            self.assertEqual(sample["id"], "/".join(Path(sample["path"]).with_suffix("").parts[1:]))

    def test_ids_are_unique(self):
        ids = [s["id"] for s in self.samples]
        self.assertEqual(len(ids), len(set(ids)))

    def test_categories_match_the_brief(self):
        expected = {
            "prompt-injection-tool-result",
            "poisoned-mcp-tool-description",
            "secret-leak",
            "dangerous-shell",
        }
        self.assertEqual({s["category"] for s in self.samples}, expected)

    def test_no_live_looking_placeholder_leaks_in_docs_sense(self):
        # The corpus may contain synthetic provider-shaped keys; it must not
        # claim they are real, and README must say they are fake.
        readme = (BENCH / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("fake", readme)
        self.assertIn("synthetic", readme)


class ResultsTests(unittest.TestCase):
    def test_committed_results_match_a_fresh_run(self):
        import sys

        sys.path.insert(0, str(BENCH))
        import run_benchmark

        self.assertEqual(run_benchmark.main(["--check"]), 0)

    def test_pages_report_exists_and_is_honest(self):
        page = (ROOT / "docs" / "benchmarks" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Detection benchmark", page)
        self.assertIn("False negatives", page)
        self.assertIn("not a red-team dataset", page.lower())
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        self.assertGreaterEqual(results["overall"]["fn"], 1)
        # Info-level inventory must not create a clean-shell false positive.
        by_id = {s["id"]: s for s in results["samples"]}
        clean = by_id["shellfence/benign/01-unit-tests"]
        self.assertEqual(clean["outcome"], "tn")


if __name__ == "__main__":
    unittest.main()
