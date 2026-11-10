#!/usr/bin/env python3
"""Generate per-tool GitHub Pages from tools/*/README.md and the OWASP tables.

Writes docs/tools/<name>/index.html, docs/tools/index.html, and refreshes
docs/sitemap.xml (keeping the homepage, guides, and /why/ entries).

Usage:
  python3 scripts/generate_tool_pages.py
  python3 scripts/generate_tool_pages.py --check   # exit 1 if docs would change
  python3 scripts/generate_tool_pages.py --out DIR # write under DIR instead of docs/
"""
from __future__ import annotations

import argparse
import datetime
import html
import io
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
DOCS_DIR = ROOT / "docs"
SITE = "https://dunkleschitz.github.io/agentsec"
STYLES = SITE + "/styles.css"
OG = SITE + "/og.png"
TODAY = datetime.date.today().isoformat()

# "<name>: detect <risk> in AI agents"
RISK_PHRASE = {
    "toolpoison": "hidden instructions and rug-pulls in MCP manifests",
    "tracesweep": "secrets leaked into agent transcripts",
    "runledger": "token and cost overruns in agent runs",
    "vibeaudit": "security smells in AI-written code",
    "canarytrap": "prompt-injection resistance with canary payloads",
    "mcpposture": "least-privilege issues in MCP client configs",
    "rundiff": "behavioral drift between agent runs",
    "scopefit": "over-privileged GitHub tokens used by agents",
    "toolgate": "policy violations in agent tool calls",
    "slopcheck": "hallucinated and typo-squatted package names",
    "ragsieve": "indirect prompt injection in RAG documents",
    "yolocheck": "over-permissive coding-agent settings",
    "rulesguard": "backdoors in AGENTS.md and rule files",
    "outfence": "dangerous LLM output before it is rendered",
    "aibom": "shadow-AI inventory drift in a repository",
    "trifecta": "the lethal trifecta across an agent's tools",
    "pickleprobe": "code-execution risk in pickle model files",
    "promptleak": "system-prompt leakage in transcripts",
    "agentci": "prompt injection in AI-agent GitHub Actions",
    "mcpsink": "taint from MCP arguments into dangerous sinks",
    "agentcard": "auth and injection issues in A2A Agent Cards",
    "loopguard": "runaway loops and retry storms",
    "toolpin": "MCP tool drift and rug-pulls",
    "resultguard": "indirect prompt injection in tool results",
    "fetchfence": "SSRF and destination risk in fetched URLs",
    "ctxbudget": "oversized tool results and context blowups",
    "modelpin": "floating model aliases and mid-run switches",
    "hitlguard": "missing human approval on consequential tool calls",
    "pathfence": "sensitive file paths an agent touched",
    "shellfence": "dangerous shell commands an agent ran",
    "schemafence": "unconstrained high-privilege tool parameters",
    "memfence": "poisoning in persistent agent memory",
    "tmplfence": "prompt-template injection in system prompts",
    "piiguard": "PII in agent transcripts",
    "secretflow": "secrets flowing into later tool arguments",
}

# Tools that currently emit SARIF 2.1.0 (--sarif). Keep in sync with the README.
SARIF_TOOLS = frozenset(
    {
        "agentcard",
        "agentci",
        "ctxbudget",
        "fetchfence",
        "hitlguard",
        "loopguard",
        "mcpposture",
        "mcpsink",
        "memfence",
        "modelpin",
        "outfence",
        "pathfence",
        "pickleprobe",
        "piiguard",
        "promptleak",
        "ragsieve",
        "rulesguard",
        "schemafence",
        "secretflow",
        "shellfence",
        "slopcheck",
        "tmplfence",
        "toolpin",
        "tracesweep",
        "trifecta",
        "vibeaudit",
        "yolocheck",
    }
)

# Prefer these example inputs (relative to the tool folder) when capturing output.
EXAMPLE_COMMANDS = {
    "toolpin": [
        "toolpin.py",
        "check",
        "examples/drifted.json",
        "-l",
        "examples/toolpin.lock.json",
        "--fail-on",
        "none",
    ],
    "trifecta": ["trifecta.py", "examples/agent", "--fail-on", "none"],
    "rundiff": None,  # filled in if two examples exist
}


def discover_tools() -> list[str]:
    names = []
    for path in sorted(TOOLS_DIR.iterdir()):
        if path.is_dir() and (path / "README.md").is_file() and (path / f"{path.name}.py").is_file():
            names.append(path.name)
    return names


# ---------------------------------------------------------------------------
# README parsing
# ---------------------------------------------------------------------------

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
FENCE_RE = re.compile(r"^```(\w*)\s*$")


def split_sections(text: str) -> list[tuple[int, str, str]]:
    """Return [(level, title, body), ...] including a level-0 prelude before the first H2+."""
    lines = text.replace("\r\n", "\n").split("\n")
    sections: list[tuple[int, str, list[str]]] = [(0, "", [])]
    in_fence = False
    for line in lines:
        if FENCE_RE.match(line):
            in_fence = not in_fence
            sections[-1][2].append(line)
            continue
        if not in_fence:
            m = HEADING_RE.match(line)
            if m and len(m.group(1)) >= 2:
                sections.append((len(m.group(1)), m.group(2).strip(), []))
                continue
        sections[-1][2].append(line)
    return [(lvl, title, "\n".join(body).strip("\n")) for lvl, title, body in sections]


def first_heading(text: str) -> str:
    for line in text.splitlines():
        m = HEADING_RE.match(line)
        if m:
            return m.group(2).strip()
    return ""


def strip_md(text: str) -> str:
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"[*]{1,3}([^*]+)[*]{1,3}", r"\1", text)
    text = re.sub(r"_{1,3}([^_]+)_{1,3}", r"\1", text)
    text = re.sub(r"^#+\s+", "", text, flags=re.M)
    text = re.sub(r"^\s*>\s?", "", text, flags=re.M)
    text = re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def first_paragraphs(md: str, limit: int = 2) -> list[str]:
    """Plain-text paragraphs from a markdown body, skipping headings and tables."""
    parts: list[str] = []
    buf: list[str] = []
    in_fence = False
    for line in md.split("\n"):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if re.match(r"^\s*\|", line) or re.match(r"^\s*[-*_]{3,}\s*$", line):
            if buf:
                parts.append(" ".join(buf).strip())
                buf = []
            continue
        if not line.strip():
            if buf:
                parts.append(" ".join(buf).strip())
                buf = []
            continue
        if line.lstrip().startswith("#"):
            continue
        buf.append(line.strip())
    if buf:
        parts.append(" ".join(buf).strip())
    out = []
    for p in parts:
        plain = strip_md(p)
        if plain:
            out.append(plain)
        if len(out) >= limit:
            break
    return out


def find_section(sections, *needles: str) -> str:
    needles_l = tuple(n.lower() for n in needles)
    for _lvl, title, body in sections:
        t = title.lower()
        if any(n in t for n in needles_l):
            return body
    return ""


def parse_tables(md: str) -> list[list[list[str]]]:
    """Extract GitHub-style markdown tables as lists of rows (including header)."""
    tables: list[list[list[str]]] = []
    rows: list[list[str]] = []
    for line in md.split("\n"):
        if re.match(r"^\s*\|", line):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells and all(re.match(r"^:?-+:?$", c) for c in cells):
                continue
            rows.append(cells)
        else:
            if rows:
                tables.append(rows)
                rows = []
    if rows:
        tables.append(rows)
    return tables


def rules_table(sections, whole: str) -> list[list[str]]:
    body = find_section(sections, "rules", "what it flags", "detectors")
    tables = parse_tables(body) if body else []
    if not tables:
        # some READMEs put the only rules table near the top
        tables = parse_tables(whole)
    for table in tables:
        if not table:
            continue
        header = [c.lower() for c in table[0]]
        joined = " ".join(header)
        if "rule" in joined or "id" in joined or "severity" in joined:
            return table
    return tables[0] if tables else []


def first_fence(md: str) -> tuple[str, str]:
    """Return (lang, code) of the first fenced block, or ('', '')."""
    lines = md.split("\n")
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if m:
            lang = m.group(1) or ""
            i += 1
            buf = []
            while i < len(lines) and not FENCE_RE.match(lines[i]):
                buf.append(lines[i])
                i += 1
            return lang, "\n".join(buf).strip("\n")
        i += 1
    return "", ""


def usage_text(sections, name: str) -> str:
    body = find_section(sections, "usage", "install and run", "cli")
    if body:
        _lang, code = first_fence(body)
        if code:
            return code
        # plain indented / bare usage
        stripped = strip_md(body)
        if stripped:
            return body.strip()
    return f"python3 {name}.py --help\n# or, from a kit install:\nagentsec {name} --help"


def example_block(sections) -> tuple[str, str]:
    """Return (prose, fenced_or_empty) from an Example section."""
    body = find_section(sections, "example output", "example", "try it")
    if not body:
        return "", ""
    _lang, code = first_fence(body)
    # prose is the body without fences
    prose_parts = []
    in_fence = False
    for line in body.split("\n"):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            prose_parts.append(line)
    prose = "\n".join(prose_parts).strip()
    return prose, code


# ---------------------------------------------------------------------------
# OWASP mapping from the root README
# ---------------------------------------------------------------------------

def parse_owasp(readme: str) -> dict[str, list[tuple[str, str]]]:
    """tool -> [(risk_id_and_name, framework), ...]"""
    mapping: dict[str, list[tuple[str, str]]] = {}
    current = None
    for line in readme.splitlines():
        if "LLM Top 10 (2025)" in line:
            current = "OWASP LLM Top 10 (2025)"
            continue
        if "Agentic Top 10 (2026)" in line:
            current = "OWASP Agentic Top 10 (2026)"
            continue
        if current is None:
            continue
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        if cells[0].lower() in {"risk", ""} or set(cells[0]) <= set("-:"):
            continue
        risk = cells[0]
        tools = re.split(r"[,;]", cells[1])
        for raw in tools:
            name = raw.strip().strip("*`").split()[0] if raw.strip() else ""
            name = re.sub(r"[^a-z0-9]", "", name.lower())
            if not name or name in {"no", "none", "rundiff", "andaibom"} and "no dedicated" in cells[1].lower():
                # still record rundiff if it's actually listed
                pass
            if not name or name in {"the", "a", "an", "no", "none"}:
                continue
            # skip parenthetical commentary tokens
            if name.startswith("(") or name in {"and", "or", "also", "useful", "as"}:
                continue
            mapping.setdefault(name, []).append((risk, current))
    return mapping


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def esc(text: str) -> str:
    return html.escape(text, quote=True)


def inline_md(text: str) -> str:
    """Escape, then restore a handful of markdown inlines."""
    text = esc(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    text = re.sub(
        r"\[([^\]]+)\]\((https?://[^)]+|mailto:[^)]+|/[^\)]+|[^)]+\.md)\)",
        lambda m: f'<a href="{esc(m.group(2)) if not m.group(2).startswith(("http", "mailto", "/")) else m.group(2)}">{m.group(1)}</a>',
        text,
    )
    # fix: href already escaped content is messy. Do links before esc? Redo properly.
    return text


def inline_md_proper(text: str) -> str:
    # Extract links, code, bold first with placeholders, escape, restore.
    holders: list[str] = []

    def hold(html_frag: str) -> str:
        holders.append(html_frag)
        return f"\x00H{len(holders) - 1}\x00"

    def links(m):
        label, url = m.group(1), m.group(2)
        if url.startswith("../") or url.endswith("/"):
            # tool-relative README links: ../tracesweep/ -> Pages path
            name = url.strip("/").split("/")[-1]
            if re.fullmatch(r"[a-z0-9]+", name):
                url = f"{SITE}/tools/{name}/"
        elif url.endswith("README.md") or "/README" in url:
            name = Path(url).parent.name
            if re.fullmatch(r"[a-z0-9]+", name):
                url = f"{SITE}/tools/{name}/"
        return hold(f'<a href="{esc(url)}">{esc(label)}</a>')

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", links, text)
    text = re.sub(r"`([^`]+)`", lambda m: hold(f"<code>{esc(m.group(1))}</code>"), text)
    text = re.sub(r"\*\*([^*]+)\*\*", lambda m: hold(f"<strong>{esc(m.group(1))}</strong>"), text)
    text = esc(text)
    text = re.sub(r"\x00H(\d+)\x00", lambda m: holders[int(m.group(1))], text)
    return text


def md_blocks(md: str, max_paras: int | None = None) -> str:
    """Render a markdown fragment to HTML (paragraphs, lists, fences, tables)."""
    if not md or not md.strip():
        return ""
    lines = md.split("\n")
    out: list[str] = []
    i = 0
    paras = 0
    while i < len(lines):
        line = lines[i]
        m = FENCE_RE.match(line)
        if m:
            lang = m.group(1) or ""
            i += 1
            buf = []
            while i < len(lines) and not FENCE_RE.match(lines[i]):
                buf.append(lines[i])
                i += 1
            i += 1  # closing fence
            cls = f' class="language-{esc(lang)}"' if lang else ""
            out.append(f"<pre><code{cls}>{esc(chr(10).join(buf))}</code></pre>")
            continue
        if re.match(r"^\s*\|", line):
            block = [line]
            i += 1
            while i < len(lines) and re.match(r"^\s*\|", lines[i]):
                block.append(lines[i])
                i += 1
            tables = parse_tables("\n".join(block))
            if tables:
                out.append(render_table(tables[0]))
            continue
        if re.match(r"^\s*[-*+]\s+\S", line) or re.match(r"^\s*\d+\.\s+\S", line):
            items = []
            ordered = bool(re.match(r"^\s*\d+\.", line))
            while i < len(lines) and (
                re.match(r"^\s*[-*+]\s+\S", lines[i]) or re.match(r"^\s*\d+\.\s+\S", lines[i])
            ):
                items.append(re.sub(r"^\s*(?:[-*+]|\d+\.)\s+", "", lines[i]))
                i += 1
            tag = "ol" if ordered else "ul"
            lis = "".join(f"<li>{inline_md_proper(it)}</li>" for it in items)
            out.append(f"<{tag}>{lis}</{tag}>")
            continue
        if re.match(r"^\s*>\s?", line):
            buf = []
            while i < len(lines) and re.match(r"^\s*>\s?", lines[i]):
                buf.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            out.append(f"<blockquote><p>{inline_md_proper(' '.join(buf))}</p></blockquote>")
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        buf = [line]
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].lstrip().startswith("#") and not re.match(r"^\s*\|", lines[i]) and not FENCE_RE.match(lines[i]) and not re.match(r"^\s*[-*+]\s+\S", lines[i]):
            buf.append(lines[i])
            i += 1
        para = " ".join(b.strip() for b in buf)
        out.append(f"<p>{inline_md_proper(para)}</p>")
        paras += 1
        if max_paras is not None and paras >= max_paras:
            break
    return "\n".join(out)


def render_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    parts = ["<table>"]
    header, body = rows[0], rows[1:]
    parts.append("<thead><tr>" + "".join(f"<th>{inline_md_proper(c)}</th>" for c in header) + "</tr></thead>")
    if body:
        parts.append("<tbody>")
        for row in body:
            # pad
            while len(row) < len(header):
                row.append("")
            parts.append("<tr>" + "".join(f"<td>{inline_md_proper(c)}</td>" for c in row[: len(header)]) + "</tr>")
        parts.append("</tbody>")
    parts.append("</table>")
    return "\n".join(parts)


def meta_description(paras: list[str], name: str, risk: str) -> str:
    text = paras[0] if paras else f"{name} detects {risk} in AI agents. Offline, standard library only."
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > 158:
        cut = text[:155]
        if " " in cut:
            cut = cut.rsplit(" ", 1)[0]
        text = cut.rstrip(".,;:") + "…"
    return text


def page_title(name: str) -> str:
    risk = RISK_PHRASE.get(name)
    if not risk:
        risk = f"risks handled by {name}"
    return f"{name}: detect {risk} in AI agents"


NAV = """    <nav class="top" aria-label="Site">
      <a href="{home}">Home</a>
      <a href="{tools}"{tools_cur}>Tools</a>
      <a href="{guides}">Guides</a>
      <a href="{why}">Why agentsec</a>
      <a href="https://github.com/dunkleschitz/agentsec">GitHub</a>
    </nav>"""


def nav(current: str = "") -> str:
    return NAV.format(
        home=SITE + "/",
        tools=SITE + "/tools/",
        tools_cur=' aria-current="page"' if current in {"tools", "tool"} else "",
        guides=SITE + "/guides/",
        why=SITE + "/why/",
    )


def json_ld(obj) -> str:
    import json

    return json.dumps(obj, indent=2, ensure_ascii=False)


def html_page(
    *,
    title: str,
    description: str,
    canonical: str,
    og_type: str,
    body: str,
    extra_head: str = "",
    crumbs: str = "",
    kicker: str = "Offline · stdlib-only · MIT",
    h1: str | None = None,
    lede: str = "",
    article: bool = True,
) -> str:
    ld = {
        "@context": "https://schema.org",
        "@type": "TechArticle" if article else "CollectionPage",
        "headline" if article else "name": title,
        "description": description,
        "url": canonical,
        "image": OG,
        "inLanguage": "en",
        "isAccessibleForFree": True,
        "publisher": {
            "@type": "Organization",
            "name": "agentsec",
            "url": SITE,
        },
    }
    if article:
        ld["author"] = {"@type": "Organization", "name": "agentsec contributors"}
        ld["license"] = "https://github.com/dunkleschitz/agentsec/blob/main/LICENSE"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} — agentsec</title>
  <meta name="description" content="{esc(description)}">
  <link rel="canonical" href="{esc(canonical)}">
  <meta name="robots" content="index,follow">
  <meta name="theme-color" content="#0d0f12">
  <link rel="stylesheet" href="{STYLES}">

  <meta property="og:type" content="{esc(og_type)}">
  <meta property="og:site_name" content="agentsec">
  <meta property="og:title" content="{esc(title)} — agentsec">
  <meta property="og:description" content="{esc(description)}">
  <meta property="og:url" content="{esc(canonical)}">
  <meta property="og:image" content="{OG}">
  <meta property="og:image:width" content="1280">
  <meta property="og:image:height" content="640">

  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="{esc(title)} — agentsec">
  <meta name="twitter:description" content="{esc(description)}">
  <meta name="twitter:image" content="{OG}">
  <script type="application/ld+json">
{json_ld(ld)}
  </script>
{extra_head}</head>
<body>
  <main class="wrap">
{nav("tool" if article else "tools")}
{crumbs}
    <p class="kicker">{esc(kicker)}</p>
    <h1>{esc(h1 or title)}</h1>
    <hr class="rule">
{lede}
{body}
    <footer>
      <p>MIT License · Python 3.10–3.13 · <a href="{SITE}/">agentsec</a> · <a href="https://github.com/dunkleschitz/agentsec">github.com/dunkleschitz/agentsec</a></p>
    </footer>
  </main>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Example output capture
# ---------------------------------------------------------------------------

def pick_example(tool_dir: Path, name: str) -> list[str] | None:
    preset = EXAMPLE_COMMANDS.get(name)
    if isinstance(preset, list):
        # verify files exist
        files_ok = True
        for a in preset:
            if a.startswith("examples/") and not (tool_dir / a).exists():
                files_ok = False
                break
        if files_ok:
            return preset
    examples = tool_dir / "examples"
    if not examples.is_dir():
        return None
    candidates = []
    for p in examples.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".json", ".jsonl", ".txt", ".md", ".html", ".log", ".j2", ".yml", ".yaml"}:
            continue
        if p.name.startswith("."):
            continue
        score = 0
        n = p.name.lower()
        if any(k in n for k in ("risky", "poison", "drift", "bad", "fail", "insecure")):
            score += 10
        if "clean" in n or "baseline" in n or "lock" in n or n in {"tags.json"}:
            score -= 5
        candidates.append((score, len(str(p)), p))
    if not candidates:
        return None
    candidates.sort(key=lambda t: (-t[0], t[1]))
    chosen = candidates[0][2]
    rel = chosen.relative_to(tool_dir).as_posix()
    args = [f"{name}.py"]
    if name == "toolpin":
        return None
    args.append(rel)
    # Prefer not failing the capture on findings
    help_text = ""
    try:
        help_text = (tool_dir / f"{name}.py").read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    if "--fail-on" in help_text:
        args.extend(["--fail-on", "none"])
    return args


def capture_output(tool_dir: Path, name: str, timeout: int = 15) -> tuple[str, str]:
    """Return (command_display, output) or ('', '')."""
    args = pick_example(tool_dir, name)
    if not args:
        return "", ""
    cmd = [sys.executable] + args
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(tool_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1"),
        )
    except (OSError, subprocess.TimeoutExpired):
        return "", ""
    out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr and proc.stderr not in (proc.stdout or "") else "")
    out = out.strip("\n")
    if not out:
        return "", ""
    # cap length
    lines = out.splitlines()
    if len(lines) > 40:
        out = "\n".join(lines[:40]) + "\n… (truncated)"
    display = "python3 " + " ".join(args)
    return display, out


# ---------------------------------------------------------------------------
# CI / SARIF snippet
# ---------------------------------------------------------------------------

def ci_snippet(name: str) -> str:
    lines = []
    if name in SARIF_TOOLS:
        lines.append(f"agentsec {name} path/to/input --sarif > {name}.sarif")
    else:
        lines.append(f"agentsec {name} path/to/input --json > {name}.json")
        lines.append(f"# {name} does not yet emit SARIF; use --json and keep --fail-on for CI.")
    action = f"""# GitHub Actions (composite action ships with the repo)
- uses: dunkleschitz/agentsec@v0
  with:
    tools: {name}
    paths: path/to/input
    fail-on: high
"""
    return "\n".join(lines) + "\n\n" + action


# ---------------------------------------------------------------------------
# Page builders
# ---------------------------------------------------------------------------

def build_tool_page(name: str, owasp: dict[str, list[tuple[str, str]]]) -> str:
    tool_dir = TOOLS_DIR / name
    readme = (tool_dir / "README.md").read_text(encoding="utf-8")
    sections = split_sections(readme)
    title = page_title(name)
    risk = RISK_PHRASE.get(name, name)
    prelude = sections[0][2] if sections else ""
    # drop the H1 line from prelude
    prelude_lines = []
    skipped = False
    for line in prelude.split("\n"):
        if not skipped and HEADING_RE.match(line) and line.startswith("# "):
            skipped = True
            continue
        prelude_lines.append(line)
    prelude = "\n".join(prelude_lines).strip()
    paras = first_paragraphs(prelude or readme, limit=3)
    description = meta_description(paras, name, risk)

    detects_html = md_blocks(prelude, max_paras=4) if prelude else "".join(f"<p>{esc(p)}</p>" for p in paras[:2])

    rules = rules_table(sections, readme)
    rules_html = render_table(rules) if rules else "<p class=\"note\">This tool does not publish a numbered rules table; see the README for what it flags.</p>"

    usage = usage_text(sections, name)
    usage_html = f"<pre><code>{esc(usage)}</code></pre>"
    usage_html += (
        f"<p>After <code>pip install</code> of the kit, the same options work as "
        f"<code>agentsec {esc(name)} …</code>. Every tool also accepts <code>--help</code> "
        f"and almost every tool accepts <code>--json</code>.</p>"
    )

    prose, fenced = example_block(sections)
    cmd, captured = capture_output(tool_dir, name)
    example_parts = []
    if prose:
        example_parts.append(md_blocks(prose, max_paras=6))
    if captured:
        label = cmd or f"python3 {name}.py"
        example_parts.append(f"<p>Captured against the bundled fixtures (fake data only):</p>")
        example_parts.append(f"<pre><code>{esc('$ ' + label + chr(10) + captured)}</code></pre>")
    elif fenced:
        example_parts.append(f"<pre><code>{esc(fenced)}</code></pre>")
    if not example_parts:
        example_parts.append(
            f"<p>See the examples under <code>tools/{esc(name)}/examples/</code> in the "
            f'<a href="https://github.com/dunkleschitz/agentsec/tree/main/tools/{esc(name)}">repository</a>.</p>'
        )
    example_html = "\n".join(example_parts)

    ci_html = f"<pre><code>{esc(ci_snippet(name))}</code></pre>"
    if name in SARIF_TOOLS:
        ci_html += (
            "<p>SARIF 2.1.0 can be uploaded to GitHub code scanning. The composite action "
            "writes per-tool reports under <code>agentsec-sarif/</code> by default.</p>"
        )
    else:
        ci_html += (
            "<p><code>--sarif</code> is not available on this tool yet "
            "(resultguard and toolpoison are reserved as good first issues). "
            "Use <code>--json</code> and a <code>--fail-on</code> exit gate instead.</p>"
        )

    maps = owasp.get(name, [])
    if maps:
        items = "".join(f"<li><strong>{esc(rid)}</strong> — {esc(fw)}</li>" for rid, fw in maps)
        owasp_html = (
            "<p>Heuristic mapping of what this tool helps a reviewer look for. "
            "Not an official OWASP endorsement, and not complete coverage of any item. "
            'Sources: <a href="https://genai.owasp.org/llm-top-10/">OWASP Top 10 for LLM Applications 2025</a> '
            'and <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/">'
            "OWASP Top 10 for Agentic Applications 2026</a>.</p>"
            f"<ul>{items}</ul>"
        )
    else:
        owasp_html = (
            "<p>This tool is not listed against a single OWASP item in the kit mapping. "
            "It may still help as a change detector or inventory aid. See the "
            f'<a href="https://github.com/dunkleschitz/agentsec#mapping-to-owasp">README mapping</a>.</p>'
        )

    limits = find_section(sections, "known limits", "limitations", "honesty")
    limits_html = md_blocks(limits, max_paras=8) if limits else (
        "<p class=\"note\">Heuristic scanner, not a security boundary. A clean result does not mean something is safe. All example secrets in this repository are fake.</p>"
    )

    crumbs = (
        f'    <p class="crumbs"><a href="{SITE}/">agentsec</a> · '
        f'<a href="{SITE}/tools/">Tools</a> · {esc(name)}</p>'
    )
    lede = f'    <p class="lede">{esc(paras[0]) if paras else "Offline, standard-library-only scanner for AI agents."}</p>\n'
    body = f"""    <article>
<h2 id="what-it-detects">What it detects</h2>
{detects_html}
<h2 id="rules">Rules</h2>
{rules_html}
<h2 id="usage">Usage</h2>
{usage_html}
<h2 id="example">Example output</h2>
{example_html}
<h2 id="sarif-ci">SARIF and CI</h2>
{ci_html}
<h2 id="owasp">OWASP mapping</h2>
{owasp_html}
<h2 id="limits">Known limits</h2>
{limits_html}
<p>Full source, tests, and fixtures: <a href="https://github.com/dunkleschitz/agentsec/tree/main/tools/{esc(name)}">tools/{esc(name)}/</a> in the repository. Install the kit with <code>pip install git+https://github.com/dunkleschitz/agentsec.git</code>.</p>
    </article>
"""
    return html_page(
        title=title,
        description=description,
        canonical=f"{SITE}/tools/{name}/",
        og_type="article",
        body=body,
        crumbs=crumbs,
        h1=title,
        lede=lede,
        article=True,
    )


def short_blurb(name: str) -> str:
    risk = RISK_PHRASE.get(name)
    if risk:
        return risk[0].upper() + risk[1:] if risk else name
    return name


def build_index(names: list[str]) -> str:
    cards = []
    for name in names:
        blurb = short_blurb(name)
        cards.append(
            f'<div class="tool"><strong><a href="{SITE}/tools/{esc(name)}/">{esc(name)}</a></strong>'
            f"<p>{esc(blurb)}</p></div>"
        )
    tools_html = '<div class="tools">\n      ' + "\n      ".join(cards) + "\n    </div>"
    desc = (
        f"Reference pages for all {len(names)} agentsec tools: what each one detects, "
        "how to run it, example output, SARIF/CI snippets, and OWASP mappings."
    )
    body = f"""    <p class="lede">One page per tool, generated from the tool README. What it detects, how to run it, example output, a SARIF/CI snippet, and the OWASP mapping.</p>
    {tools_html}
    <p class="note">These pages are generated by <code>scripts/generate_tool_pages.py</code> so they stay in sync with <code>tools/*/README.md</code>. Heuristic scanners, not a security boundary. All example secrets are fake.</p>
"""
    return html_page(
        title="Tools",
        description=desc,
        canonical=f"{SITE}/tools/",
        og_type="website",
        body=body,
        h1="Tools",
        article=False,
    )


STATIC_SITEMAP_PATHS = [
    ("/", "weekly"),
    ("/guides/", "weekly"),
    ("/guides/prompt-injection-through-tool-results/", "monthly"),
    ("/guides/pinning-mcp-tools-against-drift/", "monthly"),
    ("/guides/ten-minute-agent-security-audit/", "monthly"),
    ("/why/", "monthly"),
    ("/tools/", "weekly"),
]


def build_sitemap(names: list[str]) -> str:
    urls = list(STATIC_SITEMAP_PATHS)
    for name in names:
        urls.append((f"/tools/{name}/", "monthly"))
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for path, freq in urls:
        loc = SITE + (path if path != "/" else "/")
        if path != "/" and not path.endswith("/"):
            loc = SITE + path
        # SITE already has no trailing path; path "/" -> SITE + "/"
        loc = SITE + ("" if path == "/" else path.rstrip("/")) + ("/" if path.endswith("/") or path == "/" else "")
        if path == "/":
            loc = SITE + "/"
        parts.append("  <url>")
        parts.append(f"    <loc>{esc(loc)}</loc>")
        parts.append(f"    <lastmod>{TODAY}</lastmod>")
        parts.append(f"    <changefreq>{freq}</changefreq>")
        parts.append("  </url>")
    parts.append("</urlset>")
    parts.append("")
    return "\n".join(parts)


def write_tree(out_docs: Path, names: list[str], owasp) -> dict[str, str]:
    """Write generated files; return relative-path -> text."""
    files: dict[str, str] = {}
    files["tools/index.html"] = build_index(names)
    for name in names:
        files[f"tools/{name}/index.html"] = build_tool_page(name, owasp)
    files["sitemap.xml"] = build_sitemap(names)
    for rel, text in files.items():
        dest = out_docs / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
    return files


def check_tree(out_docs: Path, files: dict[str, str]) -> list[str]:
    stale = []
    for rel, text in files.items():
        dest = out_docs / rel
        if not dest.is_file():
            stale.append(f"missing: {rel}")
            continue
        existing = dest.read_text(encoding="utf-8")
        if existing != text:
            stale.append(f"stale: {rel}")
    return stale


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=None, help="docs directory (default: repo docs/)")
    parser.add_argument("--check", action="store_true", help="exit 1 if generated docs would change")
    args = parser.parse_args(argv)

    names = discover_tools()
    if not names:
        sys.stderr.write("generate_tool_pages: no tools found under tools/\n")
        return 2
    owasp = parse_owasp((ROOT / "README.md").read_text(encoding="utf-8"))
    out_docs = args.out or DOCS_DIR

    if args.check:
        # write to memory and compare
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            written = write_tree(Path(tmp), names, owasp)
        stale = check_tree(out_docs, written)
        if stale:
            sys.stderr.write(
                "generate_tool_pages: docs/tools or sitemap.xml is out of date:\n  "
                + "\n  ".join(stale)
                + "\nRe-run: python3 scripts/generate_tool_pages.py\n"
            )
            return 1
        sys.stdout.write("generate_tool_pages: up to date (%d tools)\n" % len(names))
        return 0

    written = write_tree(out_docs, names, owasp)
    sys.stdout.write(
        "generate_tool_pages: wrote %d files for %d tools under %s\n"
        % (len(written), len(names), out_docs)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
