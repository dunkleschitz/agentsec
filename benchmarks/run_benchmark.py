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
SITE = "https://dunkleschitz.github.io/agentsec"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Inventory / summary rules that must never count as a detection.
IGNORE_RULES = frozenset(
    {
        "SF12",  # shellfence command inventory
        "FL10",  # secretflow taint inventory
        "PG10",  # piiguard segment inventory (not used here, listed for consistency)
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
    elif tool in {"resultguard", "secretflow", "shellfence", "piiguard"}:
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


def run_corpus(manifest: dict) -> dict:
    runs = []
    for sample in manifest["samples"]:
        path = BENCH / sample["path"]
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


def render_html(results: dict, issues: list[dict] | None = None) -> str:
    ov = results["overall"]
    issue_html = ""
    if issues:
        lis = []
        for iss in issues:
            lis.append(
                "<li><a href=\"{url}\">#{num}: {title}</a> ({tool})</li>".format(
                    url=esc(iss["url"]),
                    num=esc(str(iss["number"])),
                    title=esc(iss["title"]),
                    tool=esc(iss.get("tool") or ""),
                )
            )
        issue_html = "<h2 id=\"gaps\">Open detection-gap issues</h2>\n<ul>\n" + "\n".join(lis) + "\n</ul>\n"
    tool_rows = "\n".join(metrics_row(name, m) for name, m in results["per_tool"].items())
    headline = (
        f"On this {results['sample_count']}-sample synthetic corpus, overall precision is "
        f"{fmt_pct(ov['precision'])} and recall is {fmt_pct(ov['recall'])} "
        f"({ov['tp']} true positives, {ov['fp']} false positives, {ov['fn']} false negatives)."
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Detection benchmark — agentsec</title>
  <meta name="description" content="Synthetic, labeled precision and recall for resultguard, toolpoison, tracesweep, secretflow, and shellfence. Honest about misses. All secrets are fake.">
  <link rel="canonical" href="{SITE}/benchmarks/">
  <meta name="robots" content="index,follow">
  <meta name="theme-color" content="#0d0f12">
  <link rel="stylesheet" href="{SITE}/styles.css">
  <meta property="og:type" content="article">
  <meta property="og:site_name" content="agentsec">
  <meta property="og:title" content="Detection benchmark — agentsec">
  <meta property="og:description" content="Synthetic precision and recall for five agentsec scanners, with documented false negatives.">
  <meta property="og:url" content="{SITE}/benchmarks/">
  <meta property="og:image" content="{SITE}/og.png">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="Detection benchmark — agentsec">
  <meta name="twitter:description" content="Synthetic precision and recall for five agentsec scanners, with documented false negatives.">
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
    <p class="note">This is a small, author-written, synthetic corpus. It is not a red-team dataset, not drawn from production traffic, and not a claim about performance on real attacks. Heuristic scanners miss things; the misses below are listed on purpose.</p>

    <article>
      <h2 id="numbers">Headline numbers</h2>
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

      <h2 id="how">How a detection is counted</h2>
      <p>{esc(results.get("positive_definition") or "")} The script is <code>benchmarks/run_benchmark.py</code>; the labels live in <code>benchmarks/manifest.json</code>. Fixtures are original and use only fake credentials and reserved documentation values (for example the SSA’s well-known fictitious SSN is not used here; tracesweep samples use obviously synthetic key material documented in the corpus README).</p>
      <p>Four jobs are covered:</p>
      <ul>
        <li><strong>Prompt injection in tool results</strong> — <a href="{SITE}/tools/resultguard/">resultguard</a></li>
        <li><strong>Poisoned MCP tool descriptions</strong> — <a href="{SITE}/tools/toolpoison/">toolpoison</a></li>
        <li><strong>Secret leaks</strong> — <a href="{SITE}/tools/tracesweep/">tracesweep</a> (presence) and <a href="{SITE}/tools/secretflow/">secretflow</a> (propagation into later tool arguments)</li>
        <li><strong>Dangerous shell commands</strong> — <a href="{SITE}/tools/shellfence/">shellfence</a></li>
      </ul>

      <h2 id="weaknesses">Weaknesses (be skeptical of a clean result)</h2>
      <p>Several malicious samples were written as <em>evasions</em>: typo-obfuscation, split words, non-English instructions, encodings the tool does not decode, transformed secrets, and unusual tool or shell spellings. A miss on those is expected with a regex/heuristic scanner. Unexpected misses (easy samples the tool should have caught) are treated as bugs and filed with the <code>detection-gap</code> label.</p>
      <h3>False negatives</h3>
      {list_items(results["false_negatives"], "false negative")}
      <h3>False positives</h3>
      {list_items(results["false_positives"], "false positive")}
      {issue_html}
      <h2 id="limits">Limits of this benchmark</h2>
      <ul>
        <li>Every fixture was written for this repository. A detector can look strong here and still fail on a real transcript format or a novel payload.</li>
        <li>The corpus is small (n={results["sample_count"]}). Percentages will move when a single sample is added or re-labeled.</li>
        <li>Labels are a judgment call. A “benign” page that includes a tracking <code>&lt;img&gt;</code> is clean from an operator’s point of view and still a legitimate TR09 hit.</li>
        <li>Info-level inventory findings are excluded. If we counted them, shellfence and secretflow would “detect” almost every transcript they parse.</li>
        <li>All secrets are fake. tracesweep also suppresses documentation placeholders (the word <code>example</code>, <code>your_api_key</code>, and similar), which is why those values are not used as the malicious keys in this set.</li>
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


def canonical_results(results: dict) -> dict:
    """Drop per-run stderr noise; keep stable fields for --check."""
    slim_samples = []
    for row in results["samples"]:
        slim_samples.append(
            {
                "id": row["id"],
                "tool": row["tool"],
                "label": row["label"],
                "category": row["category"],
                "difficulty": row["difficulty"],
                "flagged": row["flagged"],
                "rules": row["rules"],
                "finding_count": row["finding_count"],
                "outcome": row["outcome"],
                "parse_error": row["parse_error"],
            }
        )
    return {
        "sample_count": results["sample_count"],
        "positive_definition": results["positive_definition"],
        "per_tool": results["per_tool"],
        "overall": results["overall"],
        "false_positives": results["false_positives"],
        "false_negatives": results["false_negatives"],
        "evasion_false_negatives": results["evasion_false_negatives"],
        "unexpected_false_negatives": results["unexpected_false_negatives"],
        "samples": slim_samples,
    }


def write_outputs(results: dict, issues: list[dict] | None = None) -> None:
    slim = canonical_results(results)
    if issues:
        slim["issues"] = issues
    RESULTS_PATH.write_text(json.dumps(slim, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    DOCS.mkdir(parents=True, exist_ok=True)
    (DOCS / "index.html").write_text(render_html(slim, issues=issues or slim.get("issues")), encoding="utf-8")
    (DOCS / "results.json").write_text(json.dumps(slim, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print results JSON to stdout")
    parser.add_argument("--write-pages", action="store_true", help="write benchmarks/results.json and docs/benchmarks/")
    parser.add_argument("--check", action="store_true", help="exit 1 if committed results would change")
    args = parser.parse_args(argv)

    manifest = load_manifest()
    results = run_corpus(manifest)
    slim = canonical_results(results)
    # Preserve any already-recorded issue links when rewriting or checking.
    if RESULTS_PATH.is_file():
        try:
            existing = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and existing.get("issues"):
                slim["issues"] = existing["issues"]
                results["issues"] = existing["issues"]
        except json.JSONDecodeError:
            pass

    if args.check:
        if not RESULTS_PATH.is_file():
            sys.stderr.write("run_benchmark: missing %s (run with --write-pages)\n" % RESULTS_PATH)
            return 1
        committed = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
        left = json.dumps(canonical_results({**results, **{"issues": committed.get("issues")}} ) if False else _without_issues(slim), indent=2, sort_keys=True)
        # Compare metrics without requiring issue links to be present in a fresh run.
        fresh = _without_issues(slim)
        stored = _without_issues(committed)
        if fresh != stored:
            sys.stderr.write(
                "run_benchmark: benchmarks/results.json is out of date.\n"
                "Re-run: python3 benchmarks/run_benchmark.py --write-pages\n"
            )
            return 1
        page = DOCS / "index.html"
        if not page.is_file() or "Detection benchmark" not in page.read_text(encoding="utf-8"):
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
    return 0


def _without_issues(obj: dict) -> dict:
    out = dict(obj)
    out.pop("issues", None)
    return out


if __name__ == "__main__":
    sys.exit(main())
