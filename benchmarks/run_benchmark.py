#!/usr/bin/env python3
"""Run the labeled detection corpus and report per-tool precision / recall.

A sample is counted as flagged when the assigned tool reports at least one
finding with severity low, medium, high, or critical. Info-level inventory
rules (SF12, FL10, and any other severity=info finding) are ignored so a
"commands observed" line cannot turn a benign shell transcript into a
false positive.

Usage:
  python3 benchmarks/run_benchmark.py
  python3 benchmarks/run_benchmark.py --json            # machine-readable only
  python3 benchmarks/run_benchmark.py --write-pages     # also write docs/benchmarks/
  python3 benchmarks/run_benchmark.py --check           # exit 1 if committed results drift

All corpus credentials are synthetic. This is not a real-world attack set.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
DOCS = ROOT / "docs" / "benchmarks"
MANIFEST_PATH = BENCH / "manifest.json"
RESULTS_PATH = BENCH / "results.json"
HELDOUT_DIR = BENCH / "heldout"
HELDOUT_MANIFEST_PATH = HELDOUT_DIR / "manifest.json"
REDTEAM_DIR = BENCH / "redteam"
REDTEAM_MANIFEST_PATH = REDTEAM_DIR / "manifest.json"
BASELINE_PATH = BENCH / "baseline_v0.38.0.json"
REDTEAM_BASELINE_PATH = BENCH / "baseline_redteam_v0.40.0.json"
SITE = "https://dunkleschitz.github.io/agentsec"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Inventory / summary rules that must never count as a detection.
IGNORE_RULES = frozenset(
    {
        "SF12",  # shellfence command inventory
        "FL10",  # secretflow taint inventory
        "PG10",  # piiguard segment inventory
        "PF12",  # pathfence path inventory
        "MF10",  # memfence entry inventory
        "MP17",  # mcpposture duplicate-server-name (info)
        "MP18",  # mcpposture duplicate-package (info)
    }
)


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def extract_findings(payload) -> list[dict]:
    if payload is None:
        return []
    if isinstance(payload, dict):
        findings = payload.get("findings")
        if isinstance(findings, list):
            return [f for f in findings if isinstance(f, dict)]
        return []
    if isinstance(payload, list):
        return [f for f in payload if isinstance(f, dict)]
    return []


def is_signal(finding: dict) -> bool:
    rule = str(finding.get("rule") or finding.get("rule_id") or finding.get("id") or "")
    if rule in IGNORE_RULES:
        return False
    sev = str(finding.get("severity") or "info").lower()
    return SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK["low"]


def tool_argv(tool: str, path: Path) -> list[str]:
    script = TOOLS / tool / f"{tool}.py"
    argv = [sys.executable, str(script), "--json"]
    if tool == "toolpoison":
        argv += ["--min-severity", "low"]
    elif tool == "tracesweep":
        argv += ["--min-severity", "low"]
    elif tool in {
        "resultguard",
        "secretflow",
        "shellfence",
        "piiguard",
        "fetchfence",
        "pathfence",
        "memfence",
    }:
        argv += ["--fail-on", "none"]
    elif tool == "mcpposture":
        argv += ["--exit-zero", "--no-color"]
    argv.append(str(path))
    return argv


def run_tool(tool: str, path: Path) -> dict:
    argv = tool_argv(tool, path)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        argv,
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    payload = None
    parse_error = None
    stdout = proc.stdout or ""
    try:
        payload = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError as exc:
        parse_error = str(exc)
    findings = [f for f in extract_findings(payload) if is_signal(f)]
    rules = sorted({str(f.get("rule") or f.get("rule_id") or f.get("id") or "") for f in findings if (f.get("rule") or f.get("rule_id") or f.get("id"))})
    return {
        "exit_code": proc.returncode,
        "flagged": bool(findings),
        "rules": rules,
        "finding_count": len(findings),
        "parse_error": parse_error,
        "stderr": (proc.stderr or "").strip() or None,
    }


def safe_div(n: float, d: float) -> float | None:
    if d == 0:
        return None
    return n / d


def metrics_from_counts(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    accuracy = safe_div(tp + tn, tp + tn + fp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "support": tp + fp + fn + tn,
    }


def classify(samples_runs: list[dict]) -> tuple[dict, list[dict], list[dict]]:
    by_tool: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    fps: list[dict] = []
    fns: list[dict] = []
    for row in samples_runs:
        tool = row["tool"]
        flagged = row["flagged"]
        label = row["label"]
        if label == "malicious" and flagged:
            by_tool[tool]["tp"] += 1
            row["outcome"] = "tp"
        elif label == "malicious" and not flagged:
            by_tool[tool]["fn"] += 1
            row["outcome"] = "fn"
            fns.append(row)
        elif label == "benign" and flagged:
            by_tool[tool]["fp"] += 1
            row["outcome"] = "fp"
            fps.append(row)
        else:
            by_tool[tool]["tn"] += 1
            row["outcome"] = "tn"
    per_tool = {tool: metrics_from_counts(**counts) for tool, counts in sorted(by_tool.items())}
    return per_tool, fps, fns


def overall(per_tool: dict) -> dict:
    tp = sum(m["tp"] for m in per_tool.values())
    fp = sum(m["fp"] for m in per_tool.values())
    fn = sum(m["fn"] for m in per_tool.values())
    tn = sum(m["tn"] for m in per_tool.values())
    return metrics_from_counts(tp, fp, fn, tn)


def fmt_pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    return "%.1f%%" % (value * 100)


def run_corpus(manifest: dict, root: Path = BENCH) -> dict:
    runs = []
    for sample in manifest["samples"]:
        path = root / sample["path"]
        if not path.is_file():
            raise FileNotFoundError("missing corpus file: %s" % path)
        result = run_tool(sample["tool"], path)
        runs.append(
            {
                "id": sample["id"],
                "tool": sample["tool"],
                "label": sample["label"],
                "category": sample["category"],
                "title": sample["title"],
                "notes": sample["notes"],
                "difficulty": sample.get("difficulty", "easy"),
                "path": sample["path"],
                **result,
            }
        )
    per_tool, fps, fns = classify(runs)
    evading_fns = [r for r in fns if r.get("difficulty") == "evasion"]
    unexpected_fns = [r for r in fns if r.get("difficulty") != "evasion"]
    return {
        "manifest": str(MANIFEST_PATH.relative_to(ROOT)),
        "sample_count": len(runs),
        "positive_definition": manifest.get("positive_definition"),
        "per_tool": per_tool,
        "overall": overall(per_tool),
        "false_positives": [
            {k: r[k] for k in ("id", "tool", "title", "notes", "rules", "difficulty")}
            for r in fps
        ],
        "false_negatives": [
            {k: r[k] for k in ("id", "tool", "title", "notes", "difficulty")}
            for r in fns
        ],
        "evasion_false_negatives": [r["id"] for r in evading_fns],
        "unexpected_false_negatives": [r["id"] for r in unexpected_fns],
        "samples": runs,
    }


def text_report(results: dict) -> str:
    lines = []
    lines.append("agentsec detection benchmark")
    lines.append("samples: %d" % results["sample_count"])
    ov = results["overall"]
    lines.append(
        "overall  P=%s  R=%s  F1=%s  (tp=%d fp=%d fn=%d tn=%d)"
        % (fmt_pct(ov["precision"]), fmt_pct(ov["recall"]), fmt_pct(ov["f1"]), ov["tp"], ov["fp"], ov["fn"], ov["tn"])
    )
    lines.append("")
    lines.append("%-12s %6s %6s %6s %6s %8s %8s %8s" % ("tool", "tp", "fp", "fn", "tn", "P", "R", "F1"))
    for tool, m in results["per_tool"].items():
        lines.append(
            "%-12s %6d %6d %6d %6d %8s %8s %8s"
            % (tool, m["tp"], m["fp"], m["fn"], m["tn"], fmt_pct(m["precision"]), fmt_pct(m["recall"]), fmt_pct(m["f1"]))
        )
    if results["false_negatives"]:
        lines.append("")
        lines.append("False negatives:")
        for r in results["false_negatives"]:
            lines.append("  [%s] %s — %s" % (r["difficulty"], r["id"], r["title"]))
    if results["false_positives"]:
        lines.append("")
        lines.append("False positives:")
        for r in results["false_positives"]:
            lines.append("  [%s] %s — %s  rules=%s" % (r["difficulty"], r["id"], r["title"], ",".join(r["rules"])))
    return "\n".join(lines) + "\n"


def esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def metrics_row(name: str, m: dict) -> str:
    return (
        "<tr>"
        f"<td><code>{esc(name)}</code></td>"
        f"<td>{m['tp']}</td><td>{m['fp']}</td><td>{m['fn']}</td><td>{m['tn']}</td>"
        f"<td>{esc(fmt_pct(m['precision']))}</td>"
        f"<td>{esc(fmt_pct(m['recall']))}</td>"
        f"<td>{esc(fmt_pct(m['f1']))}</td>"
        f"<td>{m['support']}</td>"
        "</tr>"
    )


def list_items(rows: list[dict], kind: str) -> str:
    if not rows:
        return f"<p>None on this corpus ({kind}).</p>"
    items = []
    for r in rows:
        extra = ""
        if kind == "false positive" and r.get("rules"):
            extra = f" (rules: {esc(', '.join(r['rules']))})"
        items.append(
            "<li><code>{}</code> — {}{}<br><span class=\"meta\">{} · {}</span></li>".format(
                esc(r["id"]),
                esc(r["title"]),
                extra,
                esc(r.get("difficulty") or ""),
                esc(r.get("notes") or ""),
            )
        )
    return "<ul>\n" + "\n".join(items) + "\n</ul>"


def section_table(title, anchor, results, intro=""):
    ov = results["overall"]
    tool_rows = "\n".join(metrics_row(name, m) for name, m in results["per_tool"].items())
    intro_html = f"<p>{esc(intro)}</p>\n" if intro else ""
    return f"""
      <h2 id="{anchor}">{esc(title)}</h2>
      {intro_html}
      <table>
        <thead>
          <tr>
            <th>Tool</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th>
            <th>Precision</th><th>Recall</th><th>F1</th><th>n</th>
          </tr>
        </thead>
        <tbody>
          {tool_rows}
          {metrics_row("overall", ov)}
        </tbody>
      </table>
"""


def render_html(results: dict, issues: list[dict] | None = None) -> str:
    ov = results["overall"]
    baseline = results.get("baseline") or {}
    comparable = results.get("original_comparable") or {}
    heldout = results.get("heldout") or {}
    redteam = results.get("redteam") or {}
    redteam_independent = results.get("redteam_independent") or {}

    before_after = ""
    if baseline and comparable:
        before_after = (
            section_table(
                "Before (v0.38.0) — original 85-sample, 5-tool corpus",
                "before",
                {"overall": baseline["overall"], "per_tool": baseline["per_tool"]},
                "Frozen numbers from the v0.38.0 release, before the issue #7–#11 rule changes. "
                "Eight evasions were missed and four benign samples were flagged.",
            )
            + section_table(
                "After — same 85 samples, same five tools",
                "after",
                comparable,
                "Re-run on the identical 85 fixtures after the general rule changes. "
                "The four false positives were removed without dropping any of the original true positives.",
            )
        )

    heldout_html = ""
    if heldout:
        ho_intro = (
            "A fresh set of %d samples was written after the rule changes were locked, "
            "and was not used to tune them. Wording and obfuscation differ from the original "
            "fixtures. Misses on this set, if any, are listed below without being patched away."
            % heldout["sample_count"]
        )
        heldout_html = section_table(
            "Held-out set (written after the fixes)",
            "heldout",
            heldout,
            ho_intro,
        )
        heldout_html += "<h3>Held-out false negatives</h3>\n"
        heldout_html += list_items(heldout.get("false_negatives") or [], "false negative")
        heldout_html += "<h3>Held-out false positives</h3>\n"
        heldout_html += list_items(heldout.get("false_positives") or [], "false positive")

    redteam_html = ""
    if redteam_independent or redteam:
        n = (redteam_independent or redteam).get("sample_count") or (redteam or {}).get("sample_count")
        shared = (
            "An independent red-team wrote %d fresh samples across all ten tools without reading "
            "detector source or rule files (READMEs/usage only). Attacks are drawn from published "
            "research (Invariant Labs, Trail of Bits, CyberArk, Embrace The Red, Aim Security EchoLeak, "
            "PortSwigger SSRF bypasses, Pillar Security, General Analysis / Supabase MCP, Amazon Q wipe "
            "prompt, MINJA, Nx s1ngularity). Benign look-alikes are included. Fixtures live in "
            "<code>benchmarks/redteam/</code> with citations in <code>SOURCES.md</code>."
            % n
        )
        if redteam_independent:
            frozen = dict(redteam_independent)
            # section_table expects overall/per_tool like a results block
            redteam_html += section_table(
                "Independent red-team results (v0.40.0, unseen)",
                "redteam-independent",
                frozen,
                shared + " These are the original independent numbers, frozen from the v0.40.0 release, "
                "before any rule was changed against this set. They remain the honest unseen score.",
            )
            redteam_html += "<h3>Independent-set false negatives (v0.40.0)</h3>\n"
            redteam_html += list_items(redteam_independent.get("false_negatives") or [], "false negative")
            redteam_html += "<h3>Independent-set false positives (v0.40.0)</h3>\n"
            redteam_html += list_items(redteam_independent.get("false_positives") or [], "false positive")
        if redteam:
            if redteam.get("seen"):
                seen_intro = (
                    "The same 100 samples after the general rule changes that closed issues "
                    "#12–#16. This set is now seen: post-fix precision and recall are no longer "
                    "an independent score. The original unseen numbers are kept in the table above."
                )
                title = "Same red-team set after #12–#16 fixes (now seen)"
                anchor = "redteam-seen"
            else:
                seen_intro = shared + " These numbers are the honest independent score; they were not used to retune rules."
                title = "Independent red-team results"
                anchor = "redteam"
            redteam_html += section_table(title, anchor, redteam, seen_intro)
            redteam_html += "<h3>Post-fix red-team false negatives</h3>\n" if redteam.get("seen") else "<h3>Red-team false negatives</h3>\n"
            redteam_html += list_items(redteam.get("false_negatives") or [], "false negative")
            redteam_html += "<h3>Post-fix red-team false positives</h3>\n" if redteam.get("seen") else "<h3>Red-team false positives</h3>\n"
            redteam_html += list_items(redteam.get("false_positives") or [], "false positive")
            if redteam.get("seen"):
                redteam_html += (
                    "<h3>Detection-gap issues #12–#16</h3>\n"
                    "<p>The independent misses and false positives were filed as "
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/12">#12</a> (resultguard), '
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/13">#13</a> (toolpoison), '
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/14">#14</a> (tracesweep), '
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/15">#15</a> (shellfence), and '
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/16">#16</a> (memfence), '
                    "plus two mcpposture false positives on pinned <code>npx -y</code> configs. "
                    "The rule changes in this release are general (quoted-discussion TR01, "
                    "concealment phrasing, private-to-public copy bait, line-jumping command prefixes, "
                    "instructional parameter names, documentary TP03, base64 and cross-turn secret "
                    "reconstruction, home-directory <code>find</code>/<code>rm</code>, DNS exfil, "
                    "ANSI-C/hex command deobfuscation, paste-into-chat harvest wording, MINJA-style "
                    "query remapping, and MP04 suppressed when a package is already pinned), not "
                    "string matches against these fixtures. Those issues are closed against this "
                    "release. Because the rules were then re-run on the same set, the post-fix table "
                    "is a <strong>seen</strong> score.</p>\n"
                )
            else:
                redteam_html += (
                    "<h3>Detection-gap issues for this set</h3>\n"
                    "<p>False negatives above are filed as "
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/12">#12</a> (resultguard), '
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/13">#13</a> (toolpoison), '
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/14">#14</a> (tracesweep), '
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/15">#15</a> (shellfence), and '
                    '<a href="https://github.com/dunkleschitz/agentsec/issues/16">#16</a> (memfence). '
                    "They are labeled <code>detection-gap</code>. This release does <strong>not</strong> "
                    "retune rules against the red-team fixtures.</p>\n"
                )

    closed = """
      <h2 id="gaps">Detection-gap issues #7–#11</h2>
      <p>The eight original evasions and four false positives were filed as
      <a href="https://github.com/dunkleschitz/agentsec/issues/7">#7</a>
      (resultguard),
      <a href="https://github.com/dunkleschitz/agentsec/issues/8">#8</a>
      (toolpoison),
      <a href="https://github.com/dunkleschitz/agentsec/issues/9">#9</a>
      (tracesweep),
      <a href="https://github.com/dunkleschitz/agentsec/issues/10">#10</a>
      (secretflow), and
      <a href="https://github.com/dunkleschitz/agentsec/issues/11">#11</a>
      (shellfence). The rule changes in this release are general (typo-tolerant
      and split-word override matching, ROT13 decode, multilingual override/exfil
      phrasing, soft workspace-dump-into-parameter, secret-prefix concatenation,
      encoded secret reuse, and pipe-to-shell deobfuscation), not string matches
      against the original fixtures. Those issues are closed against this release.</p>
"""

    headline = (
        f"On the expanded {results['sample_count']}-sample synthetic corpus (ten tools), "
        f"overall precision is {fmt_pct(ov['precision'])} and recall is {fmt_pct(ov['recall'])} "
        f"({ov['tp']} true positives, {ov['fp']} false positives, {ov['fn']} false negatives)."
    )
    if comparable:
        cov = comparable["overall"]
        headline += (
            f" On the original 85-sample, 5-tool slice the same run scores "
            f"precision {fmt_pct(cov['precision'])} and recall {fmt_pct(cov['recall'])} "
            f"(was {fmt_pct(baseline['overall']['precision'])} / {fmt_pct(baseline['overall']['recall'])} in v0.38.0)."
        )

    tool_list = """
      <ul>
        <li><strong>Prompt injection in tool results</strong> — <a href="{site}/tools/resultguard/">resultguard</a></li>
        <li><strong>Poisoned MCP tool descriptions</strong> — <a href="{site}/tools/toolpoison/">toolpoison</a></li>
        <li><strong>Secret leaks</strong> — <a href="{site}/tools/tracesweep/">tracesweep</a> (presence) and <a href="{site}/tools/secretflow/">secretflow</a> (propagation into later tool arguments)</li>
        <li><strong>Dangerous shell commands</strong> — <a href="{site}/tools/shellfence/">shellfence</a></li>
        <li><strong>PII in transcripts</strong> — <a href="{site}/tools/piiguard/">piiguard</a></li>
        <li><strong>SSRF / fetch destinations</strong> — <a href="{site}/tools/fetchfence/">fetchfence</a></li>
        <li><strong>Sensitive paths</strong> — <a href="{site}/tools/pathfence/">pathfence</a></li>
        <li><strong>MCP client posture</strong> — <a href="{site}/tools/mcpposture/">mcpposture</a></li>
        <li><strong>Persistent memory poisoning</strong> — <a href="{site}/tools/memfence/">memfence</a></li>
      </ul>
""".format(site=SITE)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Detection benchmark — agentsec</title>
  <meta name="description" content="Synthetic, labeled precision and recall for ten agentsec scanners, with a before/after table on the original 85-sample corpus and a held-out set written after the fixes. All secrets are fake.">
  <link rel="canonical" href="{SITE}/benchmarks/">
  <meta name="robots" content="index,follow">
  <meta name="theme-color" content="#0d0f12">
  <link rel="stylesheet" href="{SITE}/styles.css">
  <meta property="og:type" content="article">
  <meta property="og:site_name" content="agentsec">
  <meta property="og:title" content="Detection benchmark — agentsec">
  <meta property="og:description" content="Synthetic precision and recall for ten agentsec scanners, with before/after and held-out numbers.">
  <meta property="og:url" content="{SITE}/benchmarks/">
  <meta property="og:image" content="{SITE}/og.png">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="Detection benchmark — agentsec">
  <meta name="twitter:description" content="Synthetic precision and recall for ten agentsec scanners, with before/after and held-out numbers.">
  <meta name="twitter:image" content="{SITE}/og.png">
</head>
<body>
  <main class="wrap">
    <nav class="top" aria-label="Site">
      <a href="{SITE}/">Home</a>
      <a href="{SITE}/tools/">Tools</a>
      <a href="{SITE}/playground/">Playground</a>
      <a href="{SITE}/benchmarks/" aria-current="page">Benchmark</a>
      <a href="{SITE}/guides/">Guides</a>
      <a href="{SITE}/why/">Why agentsec</a>
      <a href="https://github.com/dunkleschitz/agentsec">GitHub</a>
    </nav>
    <p class="crumbs"><a href="{SITE}/">agentsec</a> · Benchmark</p>
    <p class="kicker">Offline · stdlib-only · MIT</p>
    <h1>Detection benchmark</h1>
    <hr class="rule">
    <p class="lede">{esc(headline)}</p>
    <p class="note">This is a small, author-written, synthetic corpus. It is not a red-team dataset, not drawn from production traffic, and not a claim about performance on real attacks. Heuristic scanners miss things; misses are listed on purpose.</p>

    <article>
      {before_after}
      {heldout_html}
      {redteam_html}
      {section_table("Expanded corpus (ten tools)", "expanded", results, "The original five tools plus piiguard, fetchfence, pathfence, mcpposture, and memfence, on newly written original fixtures.")}
      <h3>Expanded-corpus false negatives</h3>
      {list_items(results["false_negatives"], "false negative")}
      <h3>Expanded-corpus false positives</h3>
      {list_items(results["false_positives"], "false positive")}
      {closed}

      <h2 id="how">How a detection is counted</h2>
      <p>{esc(results.get("positive_definition") or "")} The script is <code>benchmarks/run_benchmark.py</code>; the labels live in <code>benchmarks/manifest.json</code>, <code>benchmarks/heldout/manifest.json</code>, and <code>benchmarks/redteam/manifest.json</code>. Fixtures are original and use only fake credentials and reserved documentation values.</p>
      <p>Ten jobs are covered:</p>
      {tool_list}

      <h2 id="limits">Limits of this benchmark</h2>
      <ul>
        <li>Every fixture was written for this repository. A detector can look strong here and still fail on a real transcript format or a novel payload.</li>
        <li>The corpus is still small (n={results["sample_count"]} on the expanded set; n={comparable.get("sample_count", "85")} on the original slice; n={(heldout or {}).get("sample_count", "?")} held-out; n={(redteam or {}).get("sample_count", "?")} independent red-team). Percentages will move when a single sample is added or re-labeled.</li>
        <li>The held-out set was written after the #7–#11 fixes and was not used to retune those rules. A strong held-out score is still not evidence of real-world robustness.</li>
        <li>The independent red-team set was written without reading detector source or rule files. The v0.40.0 numbers on that set are the unseen score and stay visible. After issues #12–#16 were closed against general rule changes, the same set was re-run; those post-fix numbers are clearly labeled <strong>seen</strong> and are no longer independent.</li>
        <li>Info-level inventory findings are excluded. If we counted them, several tools would “detect” almost every transcript they parse.</li>
        <li>All secrets and personal-data values are fake. tracesweep also suppresses documentation placeholders (the word <code>example</code>, <code>your_api_key</code>, and similar), which is why those values are not used as the malicious keys in this set.</li>
      </ul>
      <p>Reproduce the table locally:</p>
      <pre><code>python3 benchmarks/run_benchmark.py --write-pages</code></pre>
    </article>
    <footer>
      <p>MIT License · synthetic fixtures only · <a href="https://github.com/dunkleschitz/agentsec/tree/main/benchmarks">benchmarks/ in the repo</a></p>
    </footer>
  </main>
</body>
</html>
"""


def slim_sample(row: dict) -> dict:
    return {
        "id": row["id"],
        "tool": row["tool"],
        "label": row["label"],
        "category": row.get("category"),
        "difficulty": row["difficulty"],
        "flagged": row["flagged"],
        "rules": row["rules"],
        "finding_count": row["finding_count"],
        "outcome": row["outcome"],
        "parse_error": row["parse_error"],
    }


def public_error_row(row: dict, kind: str) -> dict:
    keys = ("id", "tool", "title", "notes", "difficulty")
    out = {k: row[k] for k in keys}
    if kind == "fp":
        out["rules"] = row.get("rules") or []
    return out


def summarize(runs: list[dict], positive_definition: str | None = None) -> dict:
    per_tool, fps, fns = classify(runs)
    evading_fns = [r for r in fns if r.get("difficulty") == "evasion"]
    unexpected_fns = [r for r in fns if r.get("difficulty") != "evasion"]
    return {
        "sample_count": len(runs),
        "positive_definition": positive_definition,
        "per_tool": per_tool,
        "overall": overall(per_tool),
        "false_positives": [public_error_row(r, "fp") for r in fps],
        "false_negatives": [public_error_row(r, "fn") for r in fns],
        "evasion_false_negatives": [r["id"] for r in evading_fns],
        "unexpected_false_negatives": [r["id"] for r in unexpected_fns],
        "samples": [slim_sample(r) for r in runs],
    }


def canonical_results(results: dict) -> dict:
    """Drop per-run stderr noise; keep stable fields for --check."""
    out = {
        "sample_count": results["sample_count"],
        "positive_definition": results["positive_definition"],
        "per_tool": results["per_tool"],
        "overall": results["overall"],
        "false_positives": results["false_positives"],
        "false_negatives": results["false_negatives"],
        "evasion_false_negatives": results["evasion_false_negatives"],
        "unexpected_false_negatives": results["unexpected_false_negatives"],
        "samples": results["samples"] if results["samples"] and "flagged" in results["samples"][0] and "title" not in results["samples"][0]
        else [slim_sample(r) if "outcome" in r and "title" in r else r for r in results["samples"]],
    }
    for key in ("baseline", "original_comparable", "heldout", "redteam", "redteam_independent", "issues"):
        if results.get(key) is not None:
            out[key] = results[key]
    return out


def load_baseline() -> dict | None:
    if not BASELINE_PATH.is_file():
        return None
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def load_redteam_baseline() -> dict | None:
    if not REDTEAM_BASELINE_PATH.is_file():
        return None
    return json.loads(REDTEAM_BASELINE_PATH.read_text(encoding="utf-8"))


def write_outputs(results: dict, issues: list[dict] | None = None) -> None:
    slim = canonical_results(results)
    if issues:
        slim["issues"] = issues
    RESULTS_PATH.write_text(json.dumps(slim, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    DOCS.mkdir(parents=True, exist_ok=True)
    (DOCS / "index.html").write_text(render_html(slim, issues=issues or slim.get("issues")), encoding="utf-8")
    (DOCS / "results.json").write_text(json.dumps(slim, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _without_issues(obj: dict) -> dict:
    out = dict(obj)
    out.pop("issues", None)
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print results JSON to stdout")
    parser.add_argument("--write-pages", action="store_true", help="write benchmarks/results.json and docs/benchmarks/")
    parser.add_argument("--check", action="store_true", help="exit 1 if committed results would change")
    args = parser.parse_args(argv)

    manifest = load_manifest()
    raw = run_corpus(manifest, root=BENCH)
    results = summarize(raw["samples"], manifest.get("positive_definition"))
    # run_corpus already returns a packaged dict with titled samples; prefer that packing
    # but re-summarize so the samples list is the raw runs (with titles) for the HTML lists.
    results = {**raw, **{"samples": raw["samples"]}}
    # Keep titled FP/FN lists from run_corpus (they include titles).

    baseline = load_baseline()
    if baseline and baseline.get("sample_ids"):
        id_set = set(baseline["sample_ids"])
        comparable_runs = [r for r in raw["samples"] if r["id"] in id_set]
        if len(comparable_runs) != len(id_set):
            missing = sorted(id_set - {r["id"] for r in comparable_runs})
            raise SystemExit("baseline sample ids missing from the main corpus: %s" % missing[:5])
        comparable = summarize(comparable_runs, manifest.get("positive_definition"))
        # Restore titles on FP/FN from the raw comparable runs
        comparable["false_positives"] = [
            public_error_row(r, "fp") for r in comparable_runs if r["outcome"] == "fp"
        ]
        comparable["false_negatives"] = [
            public_error_row(r, "fn") for r in comparable_runs if r["outcome"] == "fn"
        ]
        results["baseline"] = {
            "version": baseline.get("version"),
            "sample_count": baseline["sample_count"],
            "overall": baseline["overall"],
            "per_tool": baseline["per_tool"],
            "false_positives": baseline.get("false_positives") or [],
            "false_negatives": baseline.get("false_negatives") or [],
            "evasion_false_negatives": baseline.get("evasion_false_negatives") or [],
        }
        results["original_comparable"] = {
            "sample_count": comparable["sample_count"],
            "overall": comparable["overall"],
            "per_tool": comparable["per_tool"],
            "false_positives": comparable["false_positives"],
            "false_negatives": comparable["false_negatives"],
            "evasion_false_negatives": comparable["evasion_false_negatives"],
            "unexpected_false_negatives": comparable["unexpected_false_negatives"],
        }

    if HELDOUT_MANIFEST_PATH.is_file():
        held_manifest = json.loads(HELDOUT_MANIFEST_PATH.read_text(encoding="utf-8"))
        held_raw = run_corpus(held_manifest, root=HELDOUT_DIR)
        results["heldout"] = {
            "sample_count": held_raw["sample_count"],
            "positive_definition": held_manifest.get("positive_definition"),
            "overall": held_raw["overall"],
            "per_tool": held_raw["per_tool"],
            "false_positives": held_raw["false_positives"],
            "false_negatives": held_raw["false_negatives"],
            "evasion_false_negatives": held_raw["evasion_false_negatives"],
            "unexpected_false_negatives": held_raw["unexpected_false_negatives"],
            "samples": [slim_sample(r) for r in held_raw["samples"]],
            "written_after": held_manifest.get("written_after"),
        }

    if REDTEAM_MANIFEST_PATH.is_file():
        rt_manifest = json.loads(REDTEAM_MANIFEST_PATH.read_text(encoding="utf-8"))
        rt_raw = run_corpus(rt_manifest, root=REDTEAM_DIR)
        rt_block = {
            "sample_count": rt_raw["sample_count"],
            "positive_definition": rt_manifest.get("positive_definition"),
            "overall": rt_raw["overall"],
            "per_tool": rt_raw["per_tool"],
            "false_positives": rt_raw["false_positives"],
            "false_negatives": rt_raw["false_negatives"],
            "evasion_false_negatives": rt_raw["evasion_false_negatives"],
            "unexpected_false_negatives": rt_raw["unexpected_false_negatives"],
            "samples": [slim_sample(r) for r in rt_raw["samples"]],
            "written_by": rt_manifest.get("written_by"),
            "method": rt_manifest.get("method"),
        }
        rt_independent = load_redteam_baseline()
        if rt_independent:
            results["redteam_independent"] = rt_independent
            rt_block["seen"] = True
            rt_block["independent"] = False
            rt_block["tuned_in"] = "v0.41.0"
            rt_block["note"] = (
                "Post-fix numbers on the same 100 samples after the issue #12–#16 "
                "rule changes. This set is now 'seen' and is no longer an independent score."
            )
        else:
            rt_block["seen"] = False
            rt_block["independent"] = True
        results["redteam"] = rt_block

    slim = canonical_results(results)

    if args.check:
        if not RESULTS_PATH.is_file():
            sys.stderr.write("run_benchmark: missing %s (run with --write-pages)\n" % RESULTS_PATH)
            return 1
        committed = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        fresh = _without_issues(slim)
        stored = _without_issues(committed)
        if fresh != stored:
            sys.stderr.write(
                "run_benchmark: benchmarks/results.json is out of date.\n"
                "Re-run: python3 benchmarks/run_benchmark.py --write-pages\n"
            )
            return 1
        page = DOCS / "index.html"
        body = page.read_text(encoding="utf-8") if page.is_file() else ""
        if (
            not page.is_file()
            or "Detection benchmark" not in body
            or "Held-out set" not in body
            or "Before (v0.38.0)" not in body
            or "Independent red-team results" not in body
            or "now seen" not in body
            or "v0.40.0, unseen" not in body
        ):
            sys.stderr.write("run_benchmark: docs/benchmarks/index.html is missing or stale.\n")
            return 1
        sys.stdout.write("run_benchmark: up to date (%d samples)\n" % slim["sample_count"])
        return 0

    if args.write_pages:
        write_outputs(results, issues=slim.get("issues"))
        sys.stdout.write("wrote %s and %s\n" % (RESULTS_PATH, DOCS / "index.html"))

    if args.json:
        sys.stdout.write(json.dumps(slim, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(text_report(results))
        if results.get("original_comparable"):
            sys.stdout.write("\noriginal 85-sample slice (after fixes):\n")
            sys.stdout.write(text_report({**results["original_comparable"], "false_positives": results["original_comparable"]["false_positives"], "false_negatives": results["original_comparable"]["false_negatives"]}))
        if results.get("heldout"):
            sys.stdout.write("\nheld-out set:\n")
            sys.stdout.write(text_report(results["heldout"]))
        if results.get("redteam_independent"):
            sys.stdout.write("\nindependent red-team set (v0.40.0, unseen):\n")
            sys.stdout.write(text_report(results["redteam_independent"]))
        if results.get("redteam"):
            label = "same red-team set after #12–#16 fixes (now seen)" if results["redteam"].get("seen") else "independent red-team set"
            sys.stdout.write("\n%s:\n" % label)
            sys.stdout.write(text_report(results["redteam"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
