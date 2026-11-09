"""Local tests for scripts/action-run.sh, the GitHub Action runner."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "scripts", "action-run.sh")
TOOLS = os.path.join(ROOT, "tools")


def run_action(env_extra, cwd=None):
    """Run the action script with `agentsec` provided by this checkout."""
    bindir = tempfile.mkdtemp(prefix="agentsec-bin-")
    shim = os.path.join(bindir, "agentsec")
    with open(shim, "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/env bash\n")
        fh.write("export PYTHONPATH=%s${PYTHONPATH:+:$PYTHONPATH}\n" % ROOT)
        fh.write("exec %s -m agentsec \"$@\"\n" % sys.executable)
    os.chmod(shim, stat.S_IRWXU)
    env = os.environ.copy()
    env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(env_extra)
    out_file = env.get("GITHUB_OUTPUT")
    proc = subprocess.run(
        ["bash", SCRIPT],
        cwd=cwd or ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    outputs = {}
    if out_file and os.path.isfile(out_file):
        with open(out_file, encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, _, v = line.strip().partition("=")
                    outputs[k] = v
    return proc.returncode, proc.stdout, proc.stderr, outputs


class ActionRunTests(unittest.TestCase):
    def test_clean_resultguard_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            sarif = os.path.join(tmp, "out")
            gh_out = os.path.join(tmp, "gh.out")
            code, out, err, outputs = run_action({
                "INPUT_TOOLS": "resultguard",
                "INPUT_PATHS": os.path.join(TOOLS, "resultguard", "examples", "clean_openai.json"),
                "INPUT_FAIL_ON": "high",
                "INPUT_SARIF": "true",
                "INPUT_SARIF_DIR": sarif,
                "GITHUB_OUTPUT": gh_out,
            })
            self.assertEqual(code, 0, msg=out + err)
            self.assertEqual(outputs.get("ran-tools"), "resultguard")
            self.assertEqual(outputs.get("failed-tools"), "")
            # resultguard has no --sarif yet; the runner should fall back to JSON.
            self.assertTrue(
                os.path.isfile(os.path.join(sarif, "resultguard.json"))
                or os.path.isfile(os.path.join(sarif, "resultguard.sarif"))
            )

    def test_poisoned_resultguard_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sarif = os.path.join(tmp, "out")
            gh_out = os.path.join(tmp, "gh.out")
            code, out, err, outputs = run_action({
                "INPUT_TOOLS": "resultguard",
                "INPUT_PATHS": os.path.join(TOOLS, "resultguard", "examples", "poisoned_openai.json"),
                "INPUT_FAIL_ON": "high",
                "INPUT_SARIF": "true",
                "INPUT_SARIF_DIR": sarif,
                "GITHUB_OUTPUT": gh_out,
            })
            self.assertEqual(code, 1, msg=out + err)
            self.assertEqual(outputs.get("failed-tools"), "resultguard")
            report = os.path.join(sarif, "resultguard.json")
            if not os.path.isfile(report):
                report = os.path.join(sarif, "resultguard.sarif")
            self.assertTrue(os.path.isfile(report), report)
            with open(report, encoding="utf-8") as fh:
                body = fh.read()
            self.assertTrue("TR01" in body or "ruleId" in body)

    def test_toolpin_drift_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            sarif = os.path.join(tmp, "out")
            gh_out = os.path.join(tmp, "gh.out")
            code, out, err, outputs = run_action({
                "INPUT_TOOLS": "toolpin",
                "INPUT_FAIL_ON": "high",
                "INPUT_SARIF": "true",
                "INPUT_SARIF_DIR": sarif,
                "INPUT_MCP_SNAPSHOT": os.path.join(TOOLS, "toolpin", "examples", "drifted.json"),
                "INPUT_MCP_LOCK": os.path.join(TOOLS, "toolpin", "examples", "toolpin.lock.json"),
                "GITHUB_OUTPUT": gh_out,
            })
            self.assertEqual(code, 1, msg=out + err)
            self.assertEqual(outputs.get("failed-tools"), "toolpin")

    def test_toolpin_requires_lock_inputs(self):
        code, out, err, _ = run_action({
            "INPUT_TOOLS": "toolpin",
            "INPUT_PATHS": ".",
            "INPUT_FAIL_ON": "high",
            "INPUT_SARIF": "false",
        })
        self.assertEqual(code, 2, msg=out + err)
        self.assertIn("mcp-snapshot", err)

    def test_tracesweep_writes_sarif(self):
        """A tool that already supports --sarif should emit a SARIF file."""
        with tempfile.TemporaryDirectory() as tmp:
            # tracesweep examples for sessions are generated; use a tiny stdin-like file.
            sample = os.path.join(tmp, "session.txt")
            with open(sample, "w", encoding="utf-8") as fh:
                fh.write("no secrets here\n")
            sarif = os.path.join(tmp, "out")
            code, out, err, _ = run_action({
                "INPUT_TOOLS": "tracesweep",
                "INPUT_PATHS": sample,
                "INPUT_FAIL_ON": "high",
                "INPUT_SARIF": "true",
                "INPUT_SARIF_DIR": sarif,
            })
            self.assertEqual(code, 0, msg=out + err)
            path = os.path.join(sarif, "tracesweep.sarif")
            self.assertTrue(os.path.isfile(path), err + out)
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("https://json.schemastore.org/sarif-2.1.0.json", body)
            self.assertIn('"version": "2.1.0"', body)


if __name__ == "__main__":
    unittest.main()
