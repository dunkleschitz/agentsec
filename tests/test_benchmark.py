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
        self.assertIn("Independent red-team results", page)
        self.assertIn("v0.40.0, unseen", page)
        self.assertIn("v0.41.0, unseen", page)
        self.assertIn("Independent red-team round 3", page)
        self.assertIn("v0.43.0, unseen", page)
        self.assertIn("Independent red-team round 4", page)
        self.assertIn("v0.44.0, unseen", page)
        self.assertIn("Independent red-team round 5", page)
        self.assertIn("v0.45.0, unseen", page)
        self.assertIn("now seen", page)
        self.assertIn("no longer an independent score", page.lower())
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


    def test_redteam_is_separate_and_complete(self):
        rt_manifest = json.loads((BENCH / "redteam" / "manifest.json").read_text(encoding="utf-8"))
        samples = rt_manifest["samples"]
        self.assertGreaterEqual(len(samples), 90)
        self.assertLessEqual(len(samples), 120)
        ids = [s["id"] for s in samples]
        self.assertEqual(len(ids), len(set(ids)))
        tools = {s["tool"] for s in samples}
        for name in (
            "resultguard", "toolpoison", "tracesweep", "secretflow", "shellfence",
            "piiguard", "fetchfence", "pathfence", "mcpposture", "memfence",
        ):
            self.assertIn(name, tools)
        main_ids = {s["id"] for s in json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]}
        self.assertTrue(set(ids).isdisjoint(main_ids))
        sources = (BENCH / "redteam" / "SOURCES.md").read_text(encoding="utf-8")
        self.assertIn("Invariant Labs", sources)
        self.assertIn("Trail of Bits", sources)
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        redteam = results["redteam"]
        self.assertEqual(redteam["sample_count"], len(samples))
        self.assertIn("false_negatives", redteam)
        self.assertIn("false_positives", redteam)
        self.assertIn("overall", redteam)
        self.assertTrue(redteam.get("seen"))
        self.assertFalse(redteam.get("independent"))
        # Frozen independent numbers from v0.40.0 stay visible and unchanged.
        independent = results["redteam_independent"]
        self.assertEqual(independent["version"], "v0.40.0")
        self.assertEqual(independent["sample_count"], 100)
        self.assertEqual(independent["overall"]["tp"], 60)
        self.assertEqual(independent["overall"]["fp"], 4)
        self.assertEqual(independent["overall"]["fn"], 10)
        self.assertEqual(independent["overall"]["tn"], 26)
        self.assertEqual(results["redteam_independent"]["overall"],
                         json.loads((BENCH / "baseline_redteam_v0.40.0.json").read_text(encoding="utf-8"))["overall"])
        for sample in samples:
            path = BENCH / "redteam" / sample["path"]
            self.assertTrue(path.is_file(), sample["path"])
            self.assertTrue(path.read_text(encoding="utf-8").strip(), sample["path"])

    def test_redteam2_is_now_seen_and_frozen_unseen_stays(self):
        import sys

        sys.path.insert(0, str(BENCH))
        import run_benchmark

        run_benchmark.ensure_redteam2_fixtures()
        r2_dir = BENCH / "redteam2"
        r2_manifest = json.loads((r2_dir / "manifest.json").read_text(encoding="utf-8"))
        samples = r2_manifest["samples"]
        self.assertGreaterEqual(len(samples), 110)
        ids = [s["id"] for s in samples]
        self.assertEqual(len(ids), len(set(ids)))
        tools = {s["tool"] for s in samples}
        for name in (
            "resultguard", "toolpoison", "tracesweep", "secretflow", "shellfence",
            "piiguard", "fetchfence", "pathfence", "mcpposture", "memfence", "mcpoauth",
        ):
            self.assertIn(name, tools)
        self.assertEqual({s["label"] for s in samples}, {"malicious", "benign"})
        r1_ids = {s["id"] for s in json.loads((BENCH / "redteam" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        main_ids = {s["id"] for s in json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]}
        self.assertTrue(set(ids).isdisjoint(r1_ids | main_ids))
        for sample in samples:
            path = r2_dir / sample["path"]
            self.assertTrue(path.is_file(), sample["path"])
            self.assertTrue(path.read_text(encoding="utf-8").strip(), sample["path"])
            self.assertTrue(sample.get("source"), sample["id"])
        sources = (r2_dir / "SOURCES.md").read_text(encoding="utf-8")
        self.assertIn("ShadowLeak", sources)
        self.assertIn("without reading", sources.lower())
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        r2 = results["redteam2"]
        self.assertEqual(r2["sample_count"], len(samples))
        self.assertTrue(r2["seen"])
        self.assertFalse(r2["independent"])
        frozen = json.loads((BENCH / "baseline_redteam2_v0.41.0.json").read_text(encoding="utf-8"))
        self.assertEqual(frozen["version"], "v0.41.0")
        self.assertEqual(frozen["sample_count"], len(samples))
        self.assertEqual(frozen["overall"]["tp"], 37)
        self.assertEqual(frozen["overall"]["fp"], 9)
        self.assertEqual(frozen["overall"]["fn"], 58)
        self.assertEqual(frozen["overall"]["tn"], 30)
        self.assertEqual(results["redteam2_independent"]["overall"], frozen["overall"])
        page = (ROOT / "docs" / "benchmarks" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Independent red-team round 2", page)
        self.assertIn("v0.41.0, unseen", page)
        self.assertIn("v0.43.0 generalization", page)
        # Round 1 stays visible next to round 2.
        self.assertIn("v0.40.0, unseen", page)

    def test_redteam3_is_now_seen_and_frozen_unseen_stays(self):
        import sys

        sys.path.insert(0, str(BENCH))
        import run_benchmark

        run_benchmark.ensure_redteam3_fixtures()
        r3_dir = BENCH / "redteam3"
        r3_manifest = json.loads((r3_dir / "manifest.json").read_text(encoding="utf-8"))
        samples = r3_manifest["samples"]
        self.assertGreaterEqual(len(samples), 70)
        ids = [s["id"] for s in samples]
        self.assertEqual(len(ids), len(set(ids)))
        tools = {s["tool"] for s in samples}
        for name in (
            "resultguard", "toolpoison", "tracesweep", "secretflow", "shellfence",
            "piiguard", "fetchfence", "pathfence", "mcpposture", "memfence", "mcpoauth",
        ):
            self.assertIn(name, tools)
        self.assertEqual({s["label"] for s in samples}, {"malicious", "benign"})
        r1_ids = {s["id"] for s in json.loads((BENCH / "redteam" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r2_ids = {s["id"] for s in json.loads((BENCH / "redteam2" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        main_ids = {s["id"] for s in json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]}
        self.assertTrue(set(ids).isdisjoint(r1_ids | r2_ids | main_ids))
        for sample in samples:
            path = r3_dir / sample["path"]
            self.assertTrue(path.is_file(), sample["path"])
            self.assertTrue(path.read_text(encoding="utf-8").strip(), sample["path"])
            self.assertTrue(sample.get("source"), sample["id"])
        sources = (r3_dir / "SOURCES.md").read_text(encoding="utf-8")
        self.assertIn("ArtPrompt", sources)
        self.assertIn("Greshake", sources)
        self.assertIn("after the v0.43.0", sources.lower())
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        r3 = results["redteam3"]
        self.assertEqual(r3["sample_count"], len(samples))
        self.assertTrue(r3["seen"])
        self.assertFalse(r3["independent"])
        frozen = json.loads((BENCH / "baseline_redteam3_v0.43.0.json").read_text(encoding="utf-8"))
        self.assertEqual(frozen["version"], "v0.43.0")
        self.assertEqual(frozen["sample_count"], len(samples))
        self.assertEqual(frozen["overall"]["tp"], 36)
        self.assertEqual(frozen["overall"]["fp"], 1)
        self.assertEqual(frozen["overall"]["fn"], 19)
        self.assertEqual(frozen["overall"]["tn"], 28)
        self.assertEqual(results["redteam3_independent"]["overall"], frozen["overall"])
        page = (ROOT / "docs" / "benchmarks" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Independent red-team round 3", page)
        self.assertIn("v0.43.0, unseen", page)
        self.assertIn("v0.44.0 generalization", page)

    def test_redteam4_is_seen_and_frozen_baseline_kept(self):
        import sys

        sys.path.insert(0, str(BENCH))
        import run_benchmark

        run_benchmark.ensure_redteam4_fixtures()
        r4_dir = BENCH / "redteam4"
        r4_manifest = json.loads((r4_dir / "manifest.json").read_text(encoding="utf-8"))
        samples = r4_manifest["samples"]
        self.assertGreaterEqual(len(samples), 70)
        ids = [s["id"] for s in samples]
        self.assertEqual(len(ids), len(set(ids)))
        tools = {s["tool"] for s in samples}
        for name in (
            "resultguard", "toolpoison", "tracesweep", "secretflow", "shellfence",
            "piiguard", "fetchfence", "pathfence", "mcpposture", "memfence", "mcpoauth",
        ):
            self.assertIn(name, tools)
        self.assertEqual({s["label"] for s in samples}, {"malicious", "benign"})
        r1_ids = {s["id"] for s in json.loads((BENCH / "redteam" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r2_ids = {s["id"] for s in json.loads((BENCH / "redteam2" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r3_ids = {s["id"] for s in json.loads((BENCH / "redteam3" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        main_ids = {s["id"] for s in json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]}
        self.assertTrue(set(ids).isdisjoint(r1_ids | r2_ids | r3_ids | main_ids))
        for sample in samples:
            path = r4_dir / sample["path"]
            self.assertTrue(path.is_file(), sample["path"])
            self.assertTrue(path.read_text(encoding="utf-8").strip(), sample["path"])
            self.assertTrue(sample.get("source"), sample["id"])
        sources = (r4_dir / "SOURCES.md").read_text(encoding="utf-8")
        self.assertIn("Policy Puppetry", sources)
        self.assertIn("FigStep", sources)
        self.assertIn("after v0.44.0", sources.lower())
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        r4 = results["redteam4"]
        self.assertEqual(r4["sample_count"], len(samples))
        self.assertTrue(r4["seen"])
        self.assertFalse(r4["independent"])
        frozen = json.loads((BENCH / "baseline_redteam4_v0.44.0.json").read_text(encoding="utf-8"))
        self.assertEqual(frozen["version"], "v0.44.0")
        self.assertEqual(frozen["sample_count"], len(samples))
        self.assertEqual(frozen["overall"]["tp"], 32)
        self.assertEqual(frozen["overall"]["fp"], 1)
        self.assertEqual(frozen["overall"]["fn"], 21)
        self.assertEqual(frozen["overall"]["tn"], 26)
        self.assertEqual(results["redteam4_independent"]["overall"], frozen["overall"])
        page = (ROOT / "docs" / "benchmarks" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Independent red-team round 4", page)
        self.assertIn("v0.44.0, unseen", page)
        self.assertIn("v0.45.0 generalization", page)


    def test_redteam5_is_unseen_and_separate(self):
        import sys

        sys.path.insert(0, str(BENCH))
        import run_benchmark

        run_benchmark.ensure_redteam5_fixtures()
        r5_dir = BENCH / "redteam5"
        r5_manifest = json.loads((r5_dir / "manifest.json").read_text(encoding="utf-8"))
        samples = r5_manifest["samples"]
        self.assertGreaterEqual(len(samples), 70)
        ids = [s["id"] for s in samples]
        self.assertEqual(len(ids), len(set(ids)))
        tools = {s["tool"] for s in samples}
        for name in (
            "resultguard", "toolpoison", "tracesweep", "secretflow", "shellfence",
            "piiguard", "fetchfence", "pathfence", "mcpposture", "memfence", "mcpoauth",
        ):
            self.assertIn(name, tools)
        self.assertEqual({s["label"] for s in samples}, {"malicious", "benign"})
        r1_ids = {s["id"] for s in json.loads((BENCH / "redteam" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r2_ids = {s["id"] for s in json.loads((BENCH / "redteam2" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r3_ids = {s["id"] for s in json.loads((BENCH / "redteam3" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r4_ids = {s["id"] for s in json.loads((BENCH / "redteam4" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        main_ids = {s["id"] for s in json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]}
        self.assertTrue(set(ids).isdisjoint(r1_ids | r2_ids | r3_ids | r4_ids | main_ids))
        for sample in samples:
            path = r5_dir / sample["path"]
            self.assertTrue(path.is_file(), sample["path"])
            self.assertTrue(path.read_text(encoding="utf-8").strip(), sample["path"])
            self.assertTrue(sample.get("source"), sample["id"])
        sources = (r5_dir / "SOURCES.md").read_text(encoding="utf-8")
        self.assertIn("Base32", sources)
        self.assertIn("TCKN", sources)
        self.assertIn("after v0.45.0", sources.lower())
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        r5 = results["redteam5"]
        self.assertEqual(r5["sample_count"], len(samples))
        self.assertTrue(r5["seen"])
        self.assertFalse(r5["independent"])
        frozen = json.loads((BENCH / "baseline_redteam5_v0.45.0.json").read_text(encoding="utf-8"))
        self.assertEqual(frozen["version"], "v0.45.0")
        self.assertEqual(frozen["sample_count"], len(samples))
        self.assertEqual(frozen["overall"]["tp"], 24)
        self.assertEqual(frozen["overall"]["fp"], 1)
        self.assertEqual(frozen["overall"]["fn"], 29)
        self.assertEqual(frozen["overall"]["tn"], 26)
        self.assertEqual(results["redteam5_independent"]["overall"], frozen["overall"])
        page = (ROOT / "docs" / "benchmarks" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Independent red-team round 5", page)
        self.assertIn("v0.45.0, unseen", page)
        self.assertIn("v0.46.0 generalization", page)

    def test_redteam6_is_unseen_and_separate(self):
        import sys

        sys.path.insert(0, str(BENCH))
        import run_benchmark

        run_benchmark.ensure_redteam6_fixtures()
        r6_dir = BENCH / "redteam6"
        r6_manifest = json.loads((r6_dir / "manifest.json").read_text(encoding="utf-8"))
        samples = r6_manifest["samples"]
        self.assertGreaterEqual(len(samples), 70)
        ids = [s["id"] for s in samples]
        self.assertEqual(len(ids), len(set(ids)))
        tools = {s["tool"] for s in samples}
        for name in (
            "resultguard", "toolpoison", "tracesweep", "secretflow", "shellfence",
            "piiguard", "fetchfence", "pathfence", "mcpposture", "memfence", "mcpoauth",
        ):
            self.assertIn(name, tools)
        self.assertEqual({s["label"] for s in samples}, {"malicious", "benign"})
        r1_ids = {s["id"] for s in json.loads((BENCH / "redteam" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r2_ids = {s["id"] for s in json.loads((BENCH / "redteam2" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r3_ids = {s["id"] for s in json.loads((BENCH / "redteam3" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r4_ids = {s["id"] for s in json.loads((BENCH / "redteam4" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        r5_ids = {s["id"] for s in json.loads((BENCH / "redteam5" / "manifest.json").read_text(encoding="utf-8"))["samples"]}
        main_ids = {s["id"] for s in json.loads(MANIFEST.read_text(encoding="utf-8"))["samples"]}
        self.assertTrue(set(ids).isdisjoint(r1_ids | r2_ids | r3_ids | r4_ids | r5_ids | main_ids))
        for sample in samples:
            path = r6_dir / sample["path"]
            self.assertTrue(path.is_file(), sample["path"])
            self.assertTrue(path.read_text(encoding="utf-8").strip(), sample["path"])
            self.assertTrue(sample.get("source"), sample["id"])
        sources = (r6_dir / "SOURCES.md").read_text(encoding="utf-8")
        self.assertIn("Base45", sources)
        self.assertIn("hetu", sources)
        self.assertIn("after v0.46.0", sources.lower())
        results = json.loads(RESULTS.read_text(encoding="utf-8"))
        r6 = results["redteam6"]
        self.assertEqual(r6["sample_count"], len(samples))
        self.assertFalse(r6["seen"])
        self.assertTrue(r6["independent"])
        self.assertIn("overall", r6)
        self.assertIn("false_negatives", r6)
        self.assertIn("false_positives", r6)
        page = (ROOT / "docs" / "benchmarks" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Independent red-team round 6", page)
        self.assertIn("v0.46.0, unseen", page)

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
