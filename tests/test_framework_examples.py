"""Tests for examples/frameworks (stdlib-only fixtures and normalizer)."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, ROOT)

from agentsec.cli import main as agentsec_main  # noqa: E402

FRAMEWORKS = ROOT / "examples" / "frameworks"
SPEC = importlib.util.spec_from_file_location(
    "frameworks_normalize", FRAMEWORKS / "normalize.py"
)
normalize_mod = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(normalize_mod)


def run_tool(name, path, *args):
    from io import StringIO
    from contextlib import redirect_stderr, redirect_stdout

    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = agentsec_main([name, str(path), *args])
    return code, out.getvalue(), err.getvalue()


def normalize_file(src: Path) -> Path:
    data = normalize_mod._load(str(src))
    kind, transcript = normalize_mod.normalize(data)
    dest = Path(tempfile.mkdtemp()) / "transcript.json"
    import json

    dest.write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")
    return dest


class NormalizeTests(unittest.TestCase):
    def test_langchain_shape(self):
        data = normalize_mod._load(str(FRAMEWORKS / "langchain" / "export.json"))
        kind, tr = normalize_mod.normalize(data)
        self.assertEqual(kind, "langchain")
        roles = [m["role"] for m in tr["messages"]]
        self.assertIn("user", roles)
        self.assertIn("assistant", roles)
        self.assertIn("tool", roles)
        # tool results preserved
        tools = [m for m in tr["messages"] if m["role"] == "tool"]
        self.assertTrue(any("ignore previous instructions" in (m.get("content") or "") for m in tools))
        self.assertTrue(any("FAKE-EXAMPLE-API-KEY" in (m.get("content") or "") for m in tools))

    def test_openai_agents_shape(self):
        data = normalize_mod._load(str(FRAMEWORKS / "openai_agents" / "trace.json"))
        kind, tr = normalize_mod.normalize(data)
        self.assertEqual(kind, "openai_agents")
        calls = []
        for m in tr["messages"]:
            for tc in m.get("tool_calls") or []:
                calls.append(tc["function"]["name"])
        self.assertIn("read_file", calls)
        self.assertIn("http_post", calls)
        self.assertIn("bash", calls)

    def test_crewai_shape(self):
        data = normalize_mod._load(str(FRAMEWORKS / "crewai" / "kickoff.json"))
        kind, tr = normalize_mod.normalize(data)
        self.assertEqual(kind, "crewai")
        tools = [m["name"] for m in tr["messages"] if m.get("role") == "tool"]
        self.assertIn("browse_page", tools)
        self.assertIn("read_file", tools)
        self.assertIn("http_post", tools)

    def test_mcp_config_is_rejected(self):
        data = normalize_mod._load(str(FRAMEWORKS / "mcp_clients" / "cursor.mcp.json"))
        with self.assertRaises(ValueError) as ctx:
            normalize_mod.normalize(data)
        self.assertIn("mcpposture", str(ctx.exception))

    def test_cli_writes_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.json"
            rc = normalize_mod.main(
                [str(FRAMEWORKS / "langchain" / "export.json"), "-o", str(dest)]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(dest.is_file())
            self.assertIn("messages", dest.read_text(encoding="utf-8"))


class ScanFixtureTests(unittest.TestCase):
    def test_langchain_resultguard_and_secretflow_flag_high(self):
        dest = normalize_file(FRAMEWORKS / "langchain" / "export.json")
        code, out, err = run_tool("resultguard", dest, "--fail-on", "high")
        self.assertEqual(code, 1, out + err)
        self.assertTrue("TR01" in out or "TR01" in err)
        code, out, err = run_tool("secretflow", dest, "--fail-on", "high")
        self.assertEqual(code, 1, out + err)
        self.assertIn("FL01", out + err)

    def test_openai_agents_secret_and_pii(self):
        dest = normalize_file(FRAMEWORKS / "openai_agents" / "trace.json")
        code, out, err = run_tool("secretflow", dest, "--fail-on", "high")
        self.assertEqual(code, 1, out + err)
        code, out, err = run_tool("piiguard", dest, "--fail-on", "high")
        self.assertEqual(code, 1, out + err)
        blob = out + err
        self.assertTrue("PG01" in blob or "jane.doe@example.com" in blob or "Email" in blob)

    def test_crewai_resultguard(self):
        dest = normalize_file(FRAMEWORKS / "crewai" / "kickoff.json")
        code, out, err = run_tool("resultguard", dest, "--fail-on", "high")
        self.assertEqual(code, 1, out + err)

    def test_mcp_posture_flags_high(self):
        cursor = FRAMEWORKS / "mcp_clients" / "cursor.mcp.json"
        claude = FRAMEWORKS / "mcp_clients" / "claude_desktop_config.json"
        code, out, err = run_tool("mcpposture", cursor, str(claude), "--min-severity", "high")
        self.assertEqual(code, 1, out + err)
        blob = out + err
        self.assertIn("MP01", blob)
        self.assertTrue("ghp_" in blob or "masked" in blob.lower() or "****" in blob)

    def test_fixtures_use_fake_secrets_only(self):
        banned = ("sk-live-", "sk-proj-", "ghp_real")
        for path in FRAMEWORKS.rglob("*"):
            if not path.is_file() or path.suffix not in {".json", ".md", ".py"}:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("078-05-1120", text)
            for token in banned:
                self.assertNotIn(token, text)


if __name__ == "__main__":
    unittest.main()
