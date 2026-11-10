"""Tests for the unified agentsec CLI dispatcher."""
from __future__ import annotations

import os
import sys
import unittest
from io import StringIO
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agentsec import __version__  # noqa: E402
from agentsec.cli import TOOL_NAMES, main, tools_dir  # noqa: E402


def run_cli(*argv):
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class VersionHelpTests(unittest.TestCase):
    def test_version(self):
        code, out, err = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)
        self.assertTrue(out.startswith("agentsec "))
        self.assertEqual(err, "")

    def test_help_lists_every_tool(self):
        code, out, err = run_cli("--help")
        self.assertEqual(code, 0)
        self.assertIn("usage: agentsec <tool>", out)
        for name in TOOL_NAMES:
            self.assertIn(name, out)
        self.assertEqual(len(TOOL_NAMES), 38)

    def test_list(self):
        code, out, err = run_cli("--list")
        self.assertEqual(code, 0)
        names = [line for line in out.splitlines() if line.strip()]
        self.assertEqual(names, list(TOOL_NAMES))

    def test_empty_argv_is_help(self):
        code, out, _ = run_cli()
        self.assertEqual(code, 0)
        self.assertIn("usage:", out)

    def test_unknown_option(self):
        code, _, err = run_cli("--not-a-real-flag")
        self.assertEqual(code, 2)
        self.assertIn("unknown option", err)

    def test_unknown_tool(self):
        code, _, err = run_cli("notatool")
        self.assertEqual(code, 2)
        self.assertIn("unknown tool", err)
        self.assertIn("--list", err)


class DispatchTests(unittest.TestCase):
    def test_tools_dir_points_at_repo_tools(self):
        path = tools_dir()
        self.assertTrue(os.path.isdir(path))
        self.assertTrue(os.path.isfile(os.path.join(path, "resultguard", "resultguard.py")))

    def test_resultguard_help(self):
        code, out, err = run_cli("resultguard", "--help")
        self.assertEqual(code, 0)
        self.assertIn("resultguard", out.lower() + err.lower())
        self.assertIn("--json", out)

    def test_help_tool_alias(self):
        code, out, _ = run_cli("help", "fetchfence")
        self.assertEqual(code, 0)
        self.assertIn("fetchfence", out.lower())

    def test_resultguard_clean_fixture(self):
        fixture = os.path.join(
            tools_dir(), "resultguard", "examples", "clean_openai.json"
        )
        self.assertTrue(os.path.isfile(fixture), fixture)
        code, out, err = run_cli("resultguard", fixture, "--fail-on", "high")
        self.assertEqual(code, 0, msg=out + err)

    def test_resultguard_poisoned_fixture(self):
        fixture = os.path.join(
            tools_dir(), "resultguard", "examples", "poisoned_openai.json"
        )
        self.assertTrue(os.path.isfile(fixture), fixture)
        code, out, err = run_cli("resultguard", fixture, "--fail-on", "high", "--json")
        self.assertEqual(code, 1, msg=out + err)
        self.assertIn("findings", out)

    def test_every_tool_help_exits_clean(self):
        """`--help` must work for all 38 tools through the dispatcher."""
        failed = []
        for name in TOOL_NAMES:
            code, out, err = run_cli(name, "--help")
            text = (out + err).lower()
            if code != 0 or "usage:" not in text:
                failed.append((name, code, text[:400]))
        self.assertEqual(failed, [], msg="help failed for: %s" % failed)


if __name__ == "__main__":
    unittest.main()
