"""Sanity checks for .pre-commit-hooks.yaml (stdlib only; no PyYAML)."""
from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS_PATH = ROOT / ".pre-commit-hooks.yaml"

EXPECTED_IDS = (
    "agentsec-secretflow",
    "agentsec-piiguard",
    "agentsec-toolpin",
    "agentsec-pathfence",
    "agentsec-shellfence",
    "agentsec-resultguard",
    "agentsec-fetchfence",
    "agentsec-tracesweep",
    "agentsec-mcpposture",
    "agentsec-rulesguard",
    "agentsec-promptleak",
    "agentsec-hitlguard",
    "agentsec-memfence",
    "agentsec-tmplfence",
    "agentsec-schemafence",
)


def parse_hooks(text: str) -> list[dict]:
    """Parse the simple hook list this repo ships (scalars + inline args lists)."""
    hooks: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        if raw.lstrip().startswith("#") or not raw.strip():
            continue
        if raw.startswith("- "):
            if current:
                hooks.append(current)
            current = {}
            raw = raw[2:]
        if current is None:
            continue
        line = raw.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            items = []
            if inner:
                for part in inner.split(","):
                    items.append(part.strip().strip('"').strip("'"))
            current[key] = items
        else:
            current[key] = val.strip('"').strip("'")
    if current:
        hooks.append(current)
    return hooks


class HookFileTests(unittest.TestCase):
    def setUp(self):
        self.text = HOOKS_PATH.read_text(encoding="utf-8")
        self.hooks = parse_hooks(self.text)

    def test_file_exists(self):
        self.assertTrue(HOOKS_PATH.is_file())

    def test_expected_hooks_present_once(self):
        ids = [h.get("id") for h in self.hooks]
        self.assertEqual(ids, list(EXPECTED_IDS))

    def test_each_hook_is_python_and_calls_agentsec(self):
        for hook in self.hooks:
            with self.subTest(hook=hook.get("id")):
                self.assertEqual(hook.get("language"), "python")
                entry = hook.get("entry") or ""
                self.assertTrue(entry.startswith("agentsec "), entry)
                self.assertTrue(hook.get("name"))
                self.assertTrue(hook.get("description"))
                self.assertTrue(hook.get("files"), "hook should declare a files filter")

    def test_fail_on_high_where_declared(self):
        for hook in self.hooks:
            args = hook.get("args") or []
            if hook["id"] in {"agentsec-tracesweep", "agentsec-mcpposture"}:
                continue
            self.assertIn("--fail-on", args, hook["id"])
            self.assertIn("high", args, hook["id"])

    def test_toolpin_uses_check_subcommand(self):
        hook = next(h for h in self.hooks if h["id"] == "agentsec-toolpin")
        self.assertEqual(hook["entry"], "agentsec toolpin check")


if __name__ == "__main__":
    unittest.main()
