"""Unified CLI: `agentsec <tool> [args...]` dispatches to one of the 37 stdlib tools.

Runtime depends only on the Python standard library. The tools themselves stay
single-file scripts under tools/ (or tools_data/ when installed from a wheel).
"""
from __future__ import annotations

import importlib.util
import os
import sys

from agentsec import __version__

# Display order matches the README tool table.
TOOLS = (
    ("toolpoison", "Scan MCP tool manifests for hidden instructions and rug-pulls"),
    ("tracesweep", "Find secrets leaked into agent transcripts and logs"),
    ("runledger", "Offline token and cost accounting for agent runs"),
    ("vibeaudit", "Heuristic security-smell scanner for AI-written Python and JS/TS"),
    ("canarytrap", "Prompt-injection test harness with canary-tagged payloads"),
    ("mcpposture", "Least-privilege and supply-chain auditor for MCP client configs"),
    ("rundiff", "Behavioral diff of two agent runs"),
    ("scopefit", "Least-privilege checker for GitHub tokens used by agents"),
    ("toolgate", "Policy-as-code for agent tool calls (audit or pre-tool hook)"),
    ("slopcheck", "Flag hallucinated and slopsquatting-prone package names"),
    ("ragsieve", "Scan documents for indirect prompt injection before RAG ingest"),
    ("yolocheck", "Grade coding-agent permission and autonomy settings"),
    ("rulesguard", "Find rules-file backdoors in agent instruction files"),
    ("outfence", "Scan and sanitize LLM output before it is rendered"),
    ("aibom", "AI bill of materials for a repo, with optional baseline diff"),
    ("trifecta", "Find the lethal trifecta across an agent's toolset"),
    ("pickleprobe", "Check pickle-based model files for code-execution risk without loading them"),
    ("promptleak", "Detect system-prompt leakage in transcripts and outputs"),
    ("agentci", "Audit GitHub Actions workflows that run AI agents"),
    ("mcpsink", "Taint-scan Python MCP server tool handlers"),
    ("agentcard", "Audit A2A Agent Cards (auth, endpoints, injection in skill text)"),
    ("loopguard", "Find runaway loops, retry storms, and mid-call crashes"),
    ("toolpin", "Pin MCP tool definitions and catch later rug-pulls"),
    ("resultguard", "Scan tool results for indirect prompt injection"),
    ("fetchfence", "Audit URLs an agent fetched for SSRF and destination risk"),
    ("ctxbudget", "Check tool-result size against context-window budgets"),
    ("modelpin", "Pin expected model IDs and detect alias or mid-run switches"),
    ("hitlguard", "Find consequential tool calls that fired without confirmation"),
    ("pathfence", "Audit file paths an agent touched for sensitive targets"),
    ("shellfence", "Audit shell commands an agent ran for dangerous patterns"),
    ("schemafence", "Audit tool/MCP input schemas for unconstrained privileged parameters"),
    ("memfence", "Scan persistent agent memory for cross-session poisoning"),
    ("tmplfence", "Scan LLM prompt templates for user-controlled system-prompt variables"),
    ("piiguard", "Scan transcripts and logs for PII, with optional redaction"),
    ("secretflow", "Track secret-shaped values flowing from tool results into later args"),
    ("mcpoauth", "Audit MCP server OAuth metadata (PKCE, grants, resource, tokens in URLs)"),
    ("mcpbundle", "Audit MCP Bundle manifest.json and MCP Registry server.json before install"),
)

TOOL_NAMES = tuple(name for name, _ in TOOLS)
TOOL_SET = frozenset(TOOL_NAMES)


def tools_dir() -> str:
    """Return the directory that contains one folder per tool.

    Installed wheels copy tools into agentsec/tools_data. An editable install
    or a repo checkout uses the top-level tools/ directory instead.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(here, "tools_data")
    if os.path.isdir(os.path.join(bundled, "resultguard")):
        return bundled
    repo = os.path.join(os.path.dirname(here), "tools")
    if os.path.isdir(os.path.join(repo, "resultguard")):
        return repo
    raise RuntimeError(
        "agentsec: cannot locate the tools directory (looked for %s and %s)"
        % (bundled, repo)
    )


def load_tool(name: str):
    path = os.path.join(tools_dir(), name, "%s.py" % name)
    if not os.path.isfile(path):
        raise RuntimeError("agentsec: tool file missing: %s" % path)
    mod_name = "agentsec._tool_%s" % name
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("agentsec: cannot load %s from %s" % (name, path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def dispatch(name: str, argv) -> int:
    mod = load_tool(name)
    main = getattr(mod, "main", None)
    if main is None:
        raise RuntimeError("agentsec: %s has no main()" % name)
    try:
        rc = main(argv)
    except SystemExit as exc:
        # argparse --help / --version call sys.exit(); turn that into a return code
        # so the unified CLI and its tests stay consistent.
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        sys.stderr.write("%s\n" % code)
        return 1
    return 0 if rc is None else int(rc)


def _help_text() -> str:
    lines = [
        "agentsec %s — 37 offline, stdlib-only AI-agent security tools" % __version__,
        "",
        "usage: agentsec <tool> [args...]",
        "       agentsec --list",
        "       agentsec --version",
        "       python -m agentsec <tool> [args...]",
        "",
        "Run a tool by name; arguments after the name are passed through.",
        "Example:  agentsec resultguard path/to/transcript.json --json",
        "",
        "Tools:",
    ]
    width = max(len(n) for n, _ in TOOLS)
    for name, summary in TOOLS:
        lines.append("  %-*s  %s" % (width, name, summary))
    lines.append("")
    lines.append("Each tool also accepts --help. Exit codes: 0 clean, 1 findings, 2 usage error.")
    lines.append("Docs: https://dunkleschitz.github.io/agentsec/")
    lines.append("")
    return "\n".join(lines)


def _list_text() -> str:
    return "\n".join(name for name, _ in TOOLS) + "\n"


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        if len(argv) > 1 and argv[-1] in TOOL_SET:
            return dispatch(argv[-1], ["--help"])
        sys.stdout.write(_help_text())
        return 0
    if argv[0] in ("-V", "--version", "version"):
        sys.stdout.write("agentsec %s\n" % __version__)
        return 0
    if argv[0] in ("--list", "list"):
        sys.stdout.write(_list_text())
        return 0
    tool = argv[0]
    if tool.startswith("-"):
        sys.stderr.write("agentsec: unknown option %s\nTry 'agentsec --help'.\n" % tool)
        return 2
    if tool not in TOOL_SET:
        sys.stderr.write(
            "agentsec: unknown tool %r\nTry 'agentsec --list' or 'agentsec --help'.\n" % tool
        )
        return 2
    try:
        return dispatch(tool, argv[1:])
    except RuntimeError as exc:
        sys.stderr.write("%s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
