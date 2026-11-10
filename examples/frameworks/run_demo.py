#!/usr/bin/env python3
"""Run agentsec tools against the bundled framework fixtures (fake data only).

Stdlib only. From the repository root:

    python3 examples/frameworks/run_demo.py
    python3 examples/frameworks/run_demo.py langchain
    python3 examples/frameworks/run_demo.py mcp

Transcript-style fixtures are normalized first, then scanned with
resultguard, secretflow, pathfence, and (where relevant) fetchfence / piiguard /
shellfence. MCP client configs are handed to mcpposture directly.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NORMALIZE = HERE / "normalize.py"

DEMOS = {
    "langchain": {
        "kind": "transcript",
        "input": HERE / "langchain" / "export.json",
        "tools": ("resultguard", "secretflow", "pathfence", "fetchfence"),
    },
    "openai_agents": {
        "kind": "transcript",
        "input": HERE / "openai_agents" / "trace.json",
        "tools": ("resultguard", "secretflow", "pathfence", "shellfence", "fetchfence", "piiguard"),
    },
    "crewai": {
        "kind": "transcript",
        "input": HERE / "crewai" / "kickoff.json",
        "tools": ("resultguard", "secretflow", "pathfence", "fetchfence"),
    },
    "mcp": {
        "kind": "mcp",
        "inputs": (
            HERE / "mcp_clients" / "cursor.mcp.json",
            HERE / "mcp_clients" / "claude_desktop_config.json",
        ),
        "tools": ("mcpposture",),
    },
}

ALIASES = {
    "openai": "openai_agents",
    "openai-agents": "openai_agents",
    "agents": "openai_agents",
    "mcp_clients": "mcp",
    "cursor": "mcp",
    "claude": "mcp",
}


def run_tool(name: str, *paths: Path, extra=None) -> int:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
    cmd = [sys.executable, "-m", "agentsec", name, *[str(p) for p in paths]]
    if extra:
        cmd.extend(extra)
    print("$ " + " ".join(cmd[2:] if cmd[1] == "-m" else cmd))
    print("  ->", "agentsec", name, *[str(p) for p in paths], *(extra or []))
    proc = subprocess.run(cmd, cwd=str(ROOT), env=env)
    return proc.returncode


def normalize_to(src: Path, dest: Path) -> None:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [sys.executable, str(NORMALIZE), str(src), "-o", str(dest)],
        cwd=str(ROOT),
        env=env,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def run_demo(key: str) -> int:
    demo = DEMOS[key]
    print("=" * 70)
    print("demo:", key)
    if demo["kind"] == "mcp":
        rc_all = 0
        for tool in demo["tools"]:
            rc = run_tool(tool, *demo["inputs"], extra=["--min-severity", "high"])
            # findings (1) are expected on the risky fixtures
            if rc not in (0, 1):
                return rc
            rc_all = max(rc_all, rc)
        return rc_all
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "transcript.json"
        normalize_to(demo["input"], dest)
        rc_all = 0
        for tool in demo["tools"]:
            extra = ["--fail-on", "high"]
            rc = run_tool(tool, dest, extra=extra)
            if rc not in (0, 1):
                return rc
            rc_all = max(rc_all, rc)
        return rc_all


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"-h", "--help"}:
        sys.stdout.write(__doc__.strip() + "\navailable: " + ", ".join(DEMOS) + "\n")
        return 0
    keys = []
    for a in argv or list(DEMOS):
        keys.append(ALIASES.get(a, a))
    unknown = [k for k in keys if k not in DEMOS]
    if unknown:
        sys.stderr.write("unknown demo %s (choose: %s)\n" % (unknown, ", ".join(DEMOS)))
        return 2
    worst = 0
    for key in keys:
        rc = run_demo(key)
        if rc not in (0, 1):
            return rc
        worst = max(worst, rc)
    return worst


if __name__ == "__main__":
    sys.exit(main())
