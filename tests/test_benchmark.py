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
        for name in (
            "resultguard", "toolpoison", "tracesweep", "secretflow", "shellfence",
            "piiguard", "fetchfence", "pathfence", "mcpposture", "memfence",
        ):
            self.assertIn(name, tools)
        self.assertGreaterEqual(len(tools), 10)
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
            "pii-in-transcript",
            "ssrf-fetch-url",
            "sensitive-path",
            "mcp-client-posture",
            "memory-poisoning",
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
        self.assertIn("false negatives", page.lower())
        self.assertIn("not a red-team dataset", page.lower())
        self.assertIn("Before (v0.38.0)", page)
        self.assertIn("Held-out set", page)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        # After the #7-#11 fixes the original 85-sample slice is clean.
        comparable = results["original_comparable"]
        self.assertEqual(comparable["sample_count"], 85)
        self.assertEqual(comparable["overall"]["fn"], 0)
        self.assertEqual(comparable["overall"]["fp"], 0)
        self.assertEqual(comparable["overall"]["tp"], 51)
        # Held-out was written after those fixes and is reported separately.
        heldout = results["heldout"]
        self.assertEqual(heldout["sample_count"], 40)
        self.assertIn("false_negatives", heldout)
        self.assertIn("false_positives", heldout)
        # Info-level inventory must not create a clean-shell false positive.
        by_id = {s["id"]: s for s in results["samples"]}
        clean = by_id["shellfence/benign/01-unit-tests"]
        self.assertEqual(clean["outcome"], "tn")

    def test_heldout_is_separate_and_complete(self):
        held_manifest = json.loads((BENCH / "heldout" / "manifest.json").read_text(encoding="utf-8"))
        samples = held_manifest["samples"]
        self.assertEqual(len(samples), 40)
        blob = " ".join([
            str(held_manifest.get("written_after") or ""),
            str(held_manifest.get("description") or ""),
            str(held_manifest.get("name") or ""),
        ]).lower()
        self.assertTrue("after" in blob and ("fix" in blob or "rule" in blob or "lock" in blob), blob)
        ids = [s["id"] for s in samples]
        self.assertEqual(len(ids), len(set(ids)))
        main_ids = {s["id"] for s in json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]}
        self.assertTrue(set(ids).isdisjoint(main_ids))
        for sample in samples:
            path = BENCH / "heldout" / sample["path"]
            self.assertTrue(path.is_file(), sample["path"])
            self.assertTrue(path.read_text(encoding="utf-8").strip(), sample["path"])

    def test_baseline_is_the_v038_snapshot(self):
        baseline = json.loads((BENCH / "baseline_v0.38.0.json").read_text(encoding="utf-8"))
        self.assertEqual(baseline["version"], "v0.38.0")
        self.assertEqual(baseline["sample_count"], 85)
        self.assertEqual(baseline["overall"]["fn"], 8)
        self.assertEqual(baseline["overall"]["fp"], 4)
        self.assertEqual(baseline["overall"]["tp"], 43)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        self.assertEqual(results["baseline"]["overall"], baseline["overall"])


if __name__ == "__main__":
    unittest.main()
