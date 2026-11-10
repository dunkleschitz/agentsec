#!/usr/bin/env python3
"""resultguard: offline scanner for indirect prompt injection in AI agent *tool results*.

When an agent reads a page, file, ticket or API response, that content is fed back to the
model as a tool result. Attackers plant instructions there ("ignore prior rules", "call
send_email", "quietly fetch this webhook"). resultguard extracts tool results from saved
transcripts (OpenAI chat tool messages, Anthropic tool_result blocks, generic JSON/JSONL)
or scans standalone result files, and flags hijack / exfil bait patterns with tool+turn
attribution.

Complements ragsieve (pre-ingestion RAG corpora), toolpoison (tool *descriptions*),
outfence (model *output* before render) and canarytrap (live canary tests). Stdlib only;
never runs an agent or contacts a model.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import html
import json
import os
import re
import sys
import unicodedata
from urllib.parse import unquote, unquote_plus, urlparse

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "TR01": ("high", "AI-directed override / jailbreak phrasing in a tool result"),
    "TR02": ("high", "Fake role delimiter or system/developer token in a tool result"),
    "TR03": ("critical", "Hidden Unicode (zero-width, bidi or TAG) smuggled in a tool result"),
    "TR04": ("high", "Tool-chaining / action bait telling the model to call another tool"),
    "TR05": ("high", "Exfiltration or callback URL bait aimed at the agent"),
    "TR06": ("medium", "Encoded blob in a tool result that decodes to instruction-like text"),
    "TR07": ("high", "Credential / secret harvest request inside a tool result"),
    "TR08": ("medium", "Conceal-from-user instruction in a tool result"),
    "TR09": ("medium", "Markdown/HTML auto-loading image or resource in a tool result"),
    "TR10": ("high", "Structural injection: agent-directed cues co-occurring with authority framing, sensitive objects, or an exfil/config-mutation sink"),
}

# Directional *overrides* and isolates are smuggling vectors (RLO, LRO, FSI, …).
# Typographic marks used in ordinary Arabic/Hebrew (LRM/RLM/ALM) are listed
# separately and do not, by themselves, trigger TR03.
BIDI_OVERRIDE = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
BIDI_MARK = set("\u200e\u200f\u061c")
BIDI = BIDI_OVERRIDE | BIDI_MARK
# ZWJ (U+200D) is required for emoji sequences and is not a TR03 hit on its own.
ZERO_WIDTH = set("\u200b\u200c\u2060\ufeff\u180e")
ZWJ = "\u200d"
# Invisible math operators used as a binary channel ("Sneaky Bits": U+2062/U+2064).
INVISIBLE_BITS = set("\u2061\u2062\u2063\u2064")
# Unicode TAG block U+E0001..U+E007F often used for invisible smuggling
TAG_LO, TAG_HI = 0xE0001, 0xE007F
VS16_LO, VS16_HI = 0xFE00, 0xFE0F
VS256_LO, VS256_HI = 0xE0100, 0xE01EF

OVERRIDE_RE = re.compile(
    r"(?is)(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?|directives?|constraints?|policies|guidelines?|restrictions?|guardrails?)"
    r"|disregard\s+(?:all\s+|any\s+)?(?:your\s+|the\s+)?(?:system|safety|previous|prior|above|earlier)\s+(?:prompt|instructions?|rules?|constraints?|policies|guidelines?|restrictions?|guardrails?)"
    # Require an instruction-like noun so "override the system font" stays clean.
    r"|override\s+(?:your|the|all)\s+(?:system\s+|safety\s+|previous\s+)?(?:prompt|instructions?|rules?|policies)"
    r"|you\s+are\s+now\s+(?:in\s+)?(?:DAN|developer|unrestricted|jailbreak|god)\b"
    r"|(?:enable|enter|activate|start|use)\s+jailbreak\b|jailbreak\s+mode"
    r"|new\s+(?:system\s+)?(?:instructions?|rules?|directive)\s*:"
    r"|from\s+now\s+on\s+you\s+(?:must|will|shall)\b"
    r"|do\s+not\s+follow\s+(?:your|the)\s+(?:system|original)\s+(?:prompt|instructions?)"
    # Common non-English override phrasing (French, Spanish, German, Portuguese, Italian).
    r"|ignorez\s+les\s+instructions\s+pr[eé]c[eé]dentes"
    r"|ignora(?:d|r)?\s+las\s+instrucciones\s+(?:anteriores|previas)"
    r"|ignoriere?\s+(?:die\s+)?(?:bisherigen|vorherigen|fr[uü]heren)\s+anweisungen"
    r"|ignore\s+as\s+instru[cç][oõ]es\s+anteriores"
    r"|ignora\s+le\s+istruzioni\s+precedenti"
    r")"
)

ROLE_RE = re.compile(
    r"(?is)(?:"
    r"<\|(?:im_start|im_end|system|assistant|user|endoftext|redacted_start)\|>"
    r"|\[(?:INST|/INST|SYS|/SYS|SYSTEM|/SYSTEM)\]"
    r"|</?\s*(?:system|developer|assistant|tool_result|tool_call|function_response)\s*>"
    r"|^\s*(?:system|developer)\s*:\s*\S"
    r"|<<\s*SYS\s*>>"
    r")",
    re.M,
)

ACTION_BAIT_RE = re.compile(
    r"(?is)(?:"
    r"(?:please\s+|now\s+|immediately\s+|you\s+(?:must|should|need\s+to)\s+)?"
    r"(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?"
    r"(?:`?[A-Za-z][\w./:-]{1,64}`?\s+)?(?:tool|function|command|action)\b"
    r"|(?:call|invoke|use)\s+`?[A-Za-z][\w./:-]{2,64}`?\s*(?:\(|with\b|to\b)"
    r"|i\s+will\s+now\s+call\s+[A-Za-z][\w./:-]{1,64}"
    r"|(?:the\s+)?next\s+assistant\s+message\s+should"
    r"|(?:run|execute)\s+(?:bash|sh|zsh|powershell|cmd|shell|terminal)\b"
    r"|send(?:_|\s+)(?:email|mail|message|slack|telegram|tweet)\b"
    r"|exfiltrat(?:e|ion)|upload\s+(?:the\s+)?(?:secrets?|credentials?|keys?|files?)\b"
    # Private-to-public copy (Invariant Labs GitHub MCP toxic-flow style):
    # enumerate private resources, then put their contents in a PR/issue/gist.
    r"|(?:enumerate|list|dump|collect|read)\s+(?:all\s+)?(?:private|secret|internal)\s+(?:repos(?:itories)?|projects?|files?|data)\b"
    r"|(?:open|create|file|submit)\s+(?:a\s+)?(?:pull\s+request|PR|gist)\b[^\n]{0,160}(?:private|secret|contents?)"
    r")"
)

EXFIL_HOST_RE = re.compile(
    r"(?i)\b(?:https?://)?(?:"
    r"webhook\.site|requestbin(?:\.com)?|pipedream\.net|hookbin\.com|beeceptor\.com|"
    r"ngrok(?:-free)?\.(?:app|io|dev)|burpcollaborator\.net|oastify\.com|interact\.sh|"
    r"evil(?:-)?(?:exfil|callback|collect)[.\w-]*|exfil[.\w-]+|"
    r"pastebin\.com|paste\.ee"
    r")/[^\s)\"'<>\]]*",
)

EXFIL_PHRASE_RE = re.compile(
    r"(?is)(?:"
    r"(?:fetch|get|post|put|send|upload|forward|exfiltrate|beacon|callback)\s+"
    r"(?:(?:this|the|all|any|those|full|current|raw)\s+)*"
    r"(?:data|content|secrets?|credentials?|keys?|tokens?|files?|history|conversation|"
    r"workspace(?:\s+listing)?|listing|transcript|messages?|documents?)\s+"
    r"(?:to|at|via)\s+(?:https?://|www\.)"
    r"|https?://[^\s)\"'<>\]]+[?&](?:data|secret|token|key|payload|q|content)="
    r")"
)

HARVEST_RE = re.compile(
    r"(?is)(?:"
    r"(?:paste|provide|include|send|share|reveal|print|dump|echo)\s+"
    r"(?:(?:me|us|here)\s+)?"
    r"(?:your|the|all)?\s*"
    r"(?:api\s*keys?|access\s*tokens?|secrets?|credentials?|passwords?|"
    r"private\s*keys?|ssh\s*keys?|\.env(?:\s+file)?|aws\s*keys?|"
    r"contents?\s+of\s+(?:~\/\.ssh|\/etc\/passwd|\.env))"
    r"|cat\s+(?:~\/\.ssh\/|\/home\/|\.env\b)"
    r")"
)

CONCEAL_RE = re.compile(
    r"(?is)(?:"
    r"(?:do\s+not|don't|never)\s+(?:tell|inform|notify|alert)\s+(?:the\s+)?user"
    r"|(?:do\s+not|don't|never)\s+mention\s+(?:\S+\s+){0,8}(?:to\s+)?(?:the\s+)?user"
    r"|hide\s+(?:this|it|the\s+(?:action|step|request))\s+from\s+(?:the\s+)?user"
    r"|(?:silently|quietly|covertly)\s+(?:do|perform|execute|run|call|send)"
    r"|without\s+(?:telling|informing|asking|notifying)\s+(?:the\s+)?user"
    r")"
)

MD_IMG_RE = re.compile(
    r"!\[([^\]]*)\]\(\s*<?((?:https?:)?//[^\s)\"'<>\]]+|[a-zA-Z][\w+.-]*:[^\s)]+)>?",
)
HTML_SRC_RE = re.compile(
    r"<\s*(?P<tag>img|iframe|script|link|embed|object|video|audio|source)\b[^>]*?"
    r"\b(?:src|href|data|poster)\s*=\s*[\"']?(?P<url>(?:https?:)?//[^\"'\s>]+)",
    re.I,
)
# Auto-executing tags are always a TR09 hit. Ordinary <img>/<link> logos on a
# CDN are not, unless the URL itself looks like a tracker or callback.
_AUTO_EXEC_TAGS = frozenset({"script", "iframe", "embed", "object"})
_TRACKER_QUERY_RE = re.compile(
    r"(?i)[?&](?:data|secret|token|key|payload|q|content|email|e-?mail|leak|uid|user|id|"
    r"name|lead|phone|ssn|pii|addr|hist|conv|msg|body|dump|exfil|b64|base64|cb|to)=",
)
_TRACKER_PATH_RE = re.compile(
    r"(?i)/(?:pixel|track(?:ing|er)?|beacon|collect(?:or)?|exfil|hook|callback)(?:/|\.|\b)",
)

B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])((?:(?:0x)?[0-9a-fA-F]{2}[\s,]*){20,})(?![0-9a-fA-F])")
INSTR_HINT_RE = re.compile(
    r"(?is)\b(?:ignore|system|instruction|override|jailbreak|exfiltrat|api[_ ]?key|"
    r"call\s+the\s+tool|you\s+must|developer\s+mode)\b"
)

FAKE_SECRET_HINTS = (
    "FAKE-EXAMPLE-", "EXAMPLE-", "REDACTED", "YOUR_", "xxx", "placeholder",
    "dummy", "sample-", "test-", "not-a-real-",
)


class Result:
    __slots__ = ("idx", "tool", "text", "cid", "error")

    def __init__(self, idx, tool, text, cid=None, error=False):
        self.idx = idx
        self.tool = tool or "?"
        self.text = text if isinstance(text, str) else _text_of(text)
        self.cid = cid
        self.error = bool(error)


class Finding:
    def __init__(self, rule, source, tool, turn, message, excerpt="", severity=None):
        self.rule = rule
        self.source = source
        self.tool = tool
        self.turn = turn
        self.message = message
        self.excerpt = excerpt
        self.severity = severity or RULES[rule][0]

    def to_dict(self):
        return {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "tool": self.tool,
            "turn": self.turn,
            "message": self.message,
            "excerpt": self.excerpt,
        }


def _text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") in ("text", "output_text", "input_text"):
                    parts.append(b.get("text", ""))
                elif "text" in b:
                    parts.append(str(b.get("text") or ""))
                elif "content" in b:
                    parts.append(_text_of(b["content"]))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    if content is None:
        return ""
    return json.dumps(content, default=str)


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def _excerpt(text, idx, width=72):
    if idx < 0:
        idx = 0
    start = max(0, idx - 20)
    end = min(len(text), idx + width)
    snip = text[start:end].replace("\n", "\\n")
    if start:
        snip = "…" + snip
    if end < len(text):
        snip = snip + "…"
    # mask anything that looks like a real secret shape while keeping FAKE-EXAMPLE-*
    return snip[:160]


def _looks_fake(s):
    low = s.lower()
    return any(h.lower() in low for h in FAKE_SECRET_HINTS)


def parse_results(data):
    """Extract tool Result objects from an OpenAI / Anthropic / generic transcript."""
    if isinstance(data, dict):
        for k in ("messages", "events", "steps", "transcript", "items"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
        else:
            # bare single tool result document
            if any(k in data for k in ("result", "output", "content")) and (
                data.get("tool") or data.get("tool_name") or data.get("role") == "tool"
            ):
                data = [data]
            else:
                data = [data]

    results = []
    pending = {}  # tool_call_id -> (tool_name, call_ordinal_placeholder)
    call_names = {}
    ordinal = 0

    for ev in data:
        if not isinstance(ev, dict):
            continue
        role = ev.get("role")

        if role == "assistant" and ev.get("tool_calls"):
            for tc in ev["tool_calls"]:
                fn = tc.get("function", tc)
                tid = tc.get("id")
                name = fn.get("name") or "?"
                if tid:
                    call_names[tid] = name
            continue

        if role == "tool":
            tid = ev.get("tool_call_id")
            name = ev.get("name") or call_names.get(tid) or "?"
            ordinal += 1
            results.append(Result(ordinal, name, _text_of(ev.get("content")), tid, ev.get("is_error")))
            continue

        # Anthropic-style content blocks on any role
        content = ev.get("content")
        if isinstance(content, list) and any(
            isinstance(b, dict) and b.get("type") in ("tool_use", "tool_result") for b in content
        ):
            for b in content:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_use":
                    if b.get("id"):
                        call_names[b["id"]] = b.get("name") or "?"
                elif b.get("type") == "tool_result":
                    tid = b.get("tool_use_id")
                    name = call_names.get(tid) or "?"
                    ordinal += 1
                    results.append(
                        Result(ordinal, name, _text_of(b.get("content")), tid, b.get("is_error"))
                    )
            continue

        # generic tool event with result/output
        tool = ev.get("tool") or ev.get("tool_name")
        if not tool and ev.get("type") in ("tool_result", "function_response", "tool_response"):
            tool = ev.get("name") or call_names.get(ev.get("tool_call_id") or ev.get("id")) or "?"
        if tool and any(k in ev for k in ("result", "output", "content", "error")):
            text = ev.get("result", ev.get("output", ev.get("content")))
            if ev.get("error") not in (None, "", False) and not text:
                text = ev.get("error")
                err = True
            else:
                err = bool(ev.get("is_error")) or (ev.get("error") not in (None, "", False))
            ordinal += 1
            results.append(Result(ordinal, tool, _text_of(text), ev.get("id"), err))
            continue

    return results


def find_hidden_unicode(text):
    """Return smuggling-relevant hidden-character hits.

    Typographic bidi marks (LRM/RLM/ALM) and ZWJ used in emoji sequences are
    ignored. Directional *overrides*, zero-width spaces, TAG characters,
    invisible-operator bit channels, and long variation-selector runs are not.
    """
    hits = []
    vs_run = 0
    vs_start = 0
    for i, ch in enumerate(text):
        o = ord(ch)
        if VS16_LO <= o <= VS16_HI or VS256_LO <= o <= VS256_HI:
            if vs_run == 0:
                vs_start = i
            vs_run += 1
            continue
        if vs_run >= 8:
            hits.append((vs_start, "variation-selector", "%d variation selectors" % vs_run))
        vs_run = 0
        if ch in ZERO_WIDTH:
            hits.append((i, "zero-width", unicodedata.name(ch, "U+%04X" % o)))
        elif ch in BIDI_OVERRIDE:
            hits.append((i, "bidi", unicodedata.name(ch, "U+%04X" % o)))
        elif ch in INVISIBLE_BITS:
            hits.append((i, "invisible-operator", unicodedata.name(ch, "U+%04X" % o)))
        elif TAG_LO <= o <= TAG_HI:
            hits.append((i, "TAG", "U+%05X" % o))
    if vs_run >= 8:
        hits.append((vs_start, "variation-selector", "%d variation selectors" % vs_run))
    # A short sprinkling of invisible operators is only interesting as a
    # bit-channel; require several before calling it smuggling by itself.
    op = [h for h in hits if h[1] == "invisible-operator"]
    if 0 < len(op) < 8 and not any(h[1] != "invisible-operator" for h in hits):
        hits = [h for h in hits if h[1] != "invisible-operator"]
    return hits



# Distinctive jailbreak keywords used for typo-tolerant matching. Short or
# common words (rules, system, your) are omitted to avoid misfolding ordinary
# prose.
_JAILBREAK_WORDS = (
    "ignore", "disregard", "previous", "prior", "earlier", "preceding",
    "instructions", "instruction", "prompts", "prompt", "directives",
    "directive", "jailbreak", "unrestricted",
)
_JAILBREAK_BY_LEN = {}
for _w in _JAILBREAK_WORDS:
    _JAILBREAK_BY_LEN.setdefault(len(_w), []).append(_w)

# Mid-word punctuation used to split "ig-nore pre-vious in-structions".
_SPLIT_WORD_RE = re.compile(r"(?<=[A-Za-z])[-_./\\]+(?=[A-Za-z])")
_ROT13_HINT_RE = re.compile(r"(?i)\b(?:rot\s*-?\s*13|caesar(?:\s+cipher)?)\b")
_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def _damerau_leq(a, b, max_dist):
    """True if Damerau-Levenshtein distance(a, b) <= max_dist."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return False
    # Banded DP is unnecessary at these word lengths (<= 14).
    prev_prev = None
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            best = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
            if prev_prev is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                best = min(best, prev_prev[j - 2] + 1)
            curr.append(best)
        if min(curr) > max_dist:
            return False
        prev_prev, prev = prev, curr
    return prev[-1] <= max_dist


def _fold_typos(token):
    low = token.lower()
    n = len(low)
    if n < 5:
        return token
    max_dist = 1 if n < 8 else 2
    for length, words in _JAILBREAK_BY_LEN.items():
        if abs(length - n) > max_dist:
            continue
        for word in words:
            if _damerau_leq(low, word, max_dist):
                if token[0].isupper():
                    return word[0].upper() + word[1:]
                return word
    return token


def _normalize_jailbreak_text(text):
    """Undo typo and mid-word punctuation evasions of override phrases."""
    unsplitted = _SPLIT_WORD_RE.sub("", text)
    parts = re.split(r"([^A-Za-z]+)", unsplitted)
    out = []
    for part in parts:
        if part and part[0].isalpha():
            out.append(_fold_typos(part))
        else:
            out.append(part)
    return "".join(out)


def _rot13(s):
    return s.translate(_ROT13_TABLE)


def _autoload_is_suspicious(url, tag=None):
    """Return True if an auto-loading URL is worth a TR09 finding."""
    url = (url or "").strip()
    if not url:
        return False
    tag = (tag or "").lower()
    if EXFIL_HOST_RE.search(url):
        return True
    if _TRACKER_QUERY_RE.search(url) or _TRACKER_PATH_RE.search(url):
        return True
    # Path or query that already embeds an email or a long base64-like blob.
    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}", url):
        return True
    if re.search(r"/[A-Za-z0-9+/]{24,}={0,2}(?:/|$|\?)", url):
        return True
    # Markdown images in tool results are a classic injection/exfil vector.
    if tag == "markdown" or tag in _AUTO_EXEC_TAGS:
        return True
    # Ordinary <img src="https://cdn…/logo.png"> / stylesheet links stay quiet.
    return False


def decode_candidates(text):
    """Yield (kind, decoded_str, start_idx) for base64/hex blobs that look instructive."""
    out = []
    for m in B64_RE.finditer(text):
        raw = m.group(1)
        if _looks_fake(raw):
            continue
        pad = (-len(raw)) % 4
        try:
            dec = base64.b64decode(raw + ("=" * pad), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            s = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(s) >= 12 and INSTR_HINT_RE.search(s):
            out.append(("base64", s, m.start()))
    for m in HEX_RE.finditer(text):
        hx = re.sub(r"[^0-9a-fA-F]", "", m.group(1))
        if len(hx) < 40 or len(hx) % 2:
            continue
        try:
            dec = bytes.fromhex(hx)
            s = dec.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(s) >= 12 and INSTR_HINT_RE.search(s):
            out.append(("hex", s, m.start()))
    # ROT13 / Caesar: decode when a hint is present, or when the decoded
    # text (but not the original) matches an instruction-override phrase.
    # Random English almost never rot13s into OVERRIDE_RE, so this is safe
    # without a required hint; the hint just makes the intent obvious.
    rotated = _rot13(text)
    if rotated != text and OVERRIDE_RE.search(rotated) and not OVERRIDE_RE.search(text):
        m = OVERRIDE_RE.search(rotated)
        out.append(("rot13", rotated[m.start():m.start() + 80], m.start()))
    elif _ROT13_HINT_RE.search(text):
        m = OVERRIDE_RE.search(rotated) or INSTR_HINT_RE.search(rotated)
        if m and not OVERRIDE_RE.search(text):
            out.append(("rot13", rotated[m.start():m.start() + 80], m.start()))
    return out



# Typographic and ASCII quotes used to *mention* a jailbreak phrase rather
# than issue one (research posts, documentation, incident write-ups).
_QUOTE_PAIRS = (
    ('"', '"'),
    ("'", "'"),
    ("`", "`"),
    ("\u201c", "\u201d"),
    ("\u2018", "\u2019"),
    ("\u00ab", "\u00bb"),
)
_DISCUSSION_RE = re.compile(
    r"(?is)(?:"
    r"phrases?\s+such\s+as"
    r"|classic\s+phrases?"
    r"|examples?\s+(?:of|include|such\s+as)"
    r"|classif(?:y|ies|ied)\s+.{0,60}?\bas\b"
    r"|researchers?\b"
    r"|defenders?\s+should"
    r"|no\s+action\s+is\s+requested"
    r"|treat\s+untrusted\s+.{0,60}?as\s+data"
    r"|discuss(?:es|ed|ing)?\s+.{0,80}?(?:jailbreak|injection|attack|override)"
    r"|(?:article|post|paper|write-?up|documentation|blog)\b"
    r"|this\s+week\s+researchers?"
    r"|researchers?\s+(?:revisited|described|disclosed|published|found|showed)"
    r"|(?:security\s+news|threat\s+intelligence|incident\s+write-?up)"
    r"|the\s+(?:attack|vulnerability|technique)\s+(?:works|relies|uses|abuses)"
    r")"
)


def _span_is_quoted(text, start, end):
    """True if [start:end] sits inside a matching pair of quotation marks."""
    for open_q, close_q in _QUOTE_PAIRS:
        left = text.rfind(open_q, 0, start)
        if left == -1:
            continue
        right = text.find(close_q, end)
        if right == -1:
            continue
        # The opening quote should be the nearest one; no closer closer-quote
        # between the opening quote and the match (avoids crossing pairs).
        if close_q in text[left + len(open_q):start] and open_q != close_q:
            continue
        if open_q == close_q and open_q in text[left + 1:start]:
            # There is a closer opening of the same mark; skip this pair.
            continue
        return True
    return False


def _is_quoted_discussion(text, matches):
    """True when every override match is quoted and the text discusses attacks.

    An unquoted directive still fires. A payload that is only a quoted
    jailbreak, with no analytical framing, also still fires.
    """
    if not matches:
        return False
    if not all(_span_is_quoted(text, m.start(), m.end()) for m in matches):
        return False
    return bool(_DISCUSSION_RE.search(text))



# --- structural injection (co-occurrence, encodings, policy/config framing) ---

_HOMOGLYPH = str.maketrans({
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u0399": "I",
    "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P",
    "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X", "\u03b1": "a", "\u03bf": "o",
    "\u03c1": "p", "\u03c5": "y", "\u03c7": "x", "\uff21": "A", "\uff41": "a",
})


def _fold_homoglyphs(s):
    return s.translate(_HOMOGLYPH)


def _decode_tag_chars(s):
    out = []
    for ch in s:
        o = ord(ch)
        if TAG_LO <= o <= TAG_HI:
            mapped = o - 0xE0000
            if 0x20 <= mapped < 0x7F:
                out.append(chr(mapped))
        else:
            out.append(ch)
    return "".join(out)


def _decode_sneaky_bits(s):
    """Decode runs of U+2062/U+2064 as a binary channel (both bit assignments)."""
    bits_a = []
    bits_b = []
    for ch in s:
        if ch == "\u2062":
            bits_a.append("0")
            bits_b.append("1")
        elif ch == "\u2064":
            bits_a.append("1")
            bits_b.append("0")
        elif ch in INVISIBLE_BITS:
            continue
        else:
            if len(bits_a) >= 16:
                break
            bits_a, bits_b = [], []
    texts = []
    for bits in (bits_a, bits_b):
        if len(bits) < 16:
            continue
        # pad/trim to 8-bit groups
        n = (len(bits) // 8) * 8
        chars = []
        for i in range(0, n, 8):
            val = int("".join(bits[i:i + 8]), 2)
            if 9 <= val < 127:
                chars.append(chr(val))
        decoded = "".join(chars).strip()
        if len(decoded) >= 4:
            texts.append(decoded)
    return texts


def _decode_variation_selectors(s):
    """Paul Butler-style VS data smuggling: bytes encoded as VS after a base char."""
    out = []
    buf = []
    def flush():
        if len(buf) < 4:
            buf.clear()
            return
        chars = []
        for o in buf:
            if VS16_LO <= o <= VS16_HI:
                val = o - VS16_LO
            else:
                val = (o - VS256_LO) & 0xFF
            if 9 <= val < 127 or val in (9, 10, 13):
                chars.append(chr(val))
            elif 0xA0 <= val:
                try:
                    chars.append(bytes([val]).decode("latin-1"))
                except Exception:
                    pass
        text = "".join(chars)
        if len(text) >= 4:
            out.append(text)
        buf.clear()
    for ch in s:
        o = ord(ch)
        if VS16_LO <= o <= VS16_HI or VS256_LO <= o <= VS256_HI:
            buf.append(o)
        else:
            flush()
    flush()
    return out


def _strip_invisibles(s):
    return "".join(
        ch for ch in s
        if ch not in ZERO_WIDTH
        and ch not in INVISIBLE_BITS
        and ch != ZWJ
        and not (TAG_LO <= ord(ch) <= TAG_HI)
        and not (VS16_LO <= ord(ch) <= VS16_HI)
        and not (VS256_LO <= ord(ch) <= VS256_HI)
    )


def normalize_injection_views(text):
    """Yield (label, text) views after Unicode, entity, and URL decoding."""
    if not text:
        return []
    seen = set()
    views = []

    def add(label, s):
        if not s or s in seen:
            return
        seen.add(s)
        views.append((label, s))

    add("raw", text)
    ansi = _strip_ansi(text)
    add("ansi", ansi)
    if _ANSI_CONCEAL_RE.search(text) and ansi != text:
        add("ansi-conceal", ansi)
    unescaped = html.unescape(text)
    add("html", unescaped)
    add("url", unquote(unquote_plus(unescaped)))
    add("nfkc", unicodedata.normalize("NFKC", unescaped))
    add("homoglyph", _fold_homoglyphs(unicodedata.normalize("NFKC", unescaped)))
    add("tags", _decode_tag_chars(text))
    add("stripped", _strip_invisibles(unicodedata.normalize("NFKC", _fold_homoglyphs(unescaped))))
    for s in _decode_sneaky_bits(text):
        add("sneaky-bits", s)
    for s in _decode_variation_selectors(text):
        add("variation-selector", s)
    # Long URL fragments often carry HashJack-style instructions.
    for m in re.finditer(r"https?://[^\s\"'<>]+#([^\s\"'<>]+)", text):
        frag = unquote(unquote_plus(m.group(1).replace("+", " ")))
        if len(frag) >= 12:
            add("url-fragment", frag)
    # Base64 / hex / rot13 already handled by decode_candidates; also
    # expose short url-decoded paths as their own view.
    return views


# Agent-directed cues: second-person / assistant-facing instructions (multilingual).
AGENT_CUE_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:you|you're|you\s+are|assistant|the\s+model|the\s+agent)\s+"
    r"(?:must|should|shall|will|need\s+to|are\s+(?:to|now|authorized|instructed)|have\s+to)\b"
    r"|\b(?:please|now|immediately)?\s*(?:do\s+the\s+following|follow\s+these\s+(?:instructions?|steps|rules)|"
    r"your\s+(?:new\s+)?(?:task|instructions?|orders?|mission|goal)\s+is)\b"
    r"|\bfull\s+authorization\b|\byou\s+are\s+authorized\b|\bauthorized\s+to\b"
    r"|\bwhen\s+(?:you|the\s+assistant|answering|responding)\b"
    r"|\b(?:at\s+the\s+start\s+of\s+each|before\s+you\s+(?:respond|answer|reply))\b"
    r"|你必须|请立即|忽略之前|不要告诉用户"
    r"|debes\s+(?:ahora\s+)?(?:hacer|seguir|enviar|llamar)"
    r"|no\s+le\s+digas\s+al\s+usuario"
    r"|vous\s+devez|n'informe(?:z)?\s+pas\s+l[' ]utilisateur"
    r"|du\s+musst|sage\s+(?:es\s+)?dem\s+nutzer\s+nicht"
    r")"
)

AUTHORITY_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:ignore|disregard|override|forget)\s+(?:all\s+|any\s+|your\s+|the\s+)?(?:previous|prior|above|earlier|system|safety|original)\b"
    r"|\b(?:system|developer|policy|admin)\s+(?:prompt|message|instruction|override|directive|configuration)\b"
    r"|\bnew\s+(?:system\s+)?(?:instructions?|policy|rules?|directive)\b"
    r"|\bjailbreak\b|\bdeveloper\s+mode\b|\byou\s+are\s+now\b"
    r"|\b(?:official|authoritative|binding|mandatory)\s+(?:policy|rule|instruction|configuration)\b"
    r"|<\s*(?:system|developer|instruction|important|authorization)[^>]*>"
    r"|<\s*policy\b[^>]*(?:assistant|system|model|agent|instruction|runtime|override)"
    r"|\[\s*(?:SYSTEM|INST|SYS|DEV)\s*\]"
    r"|ignora(?:d|r)?\s+las\s+instrucciones|ignorez\s+les\s+instructions|ignoriere?\s+"
    r"|忽略(?:之前|以前|所有)?(?:的)?(?:指令|指示|规则)"
    r")"
)

SENSITIVE_OBJ_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:api[_ ]?keys?|access[_ ]?tokens?|secrets?|credentials?|passwords?|private[_ ]?keys?|"
    r"ssh\s+keys?|\.env|conversation(?:s|\s+history)?|chat\s+history|prior(?:\s+conversation)?|"
    r"message\s+history|emails?|customer\s+(?:emails?|data|leads?)|leads?|"
    r"social\s+security|passports?|bank\s+(?:account|details?|routing)|"
    r"memory|system\s+prompt|authorization\s+tokens?)\b"
    r"|~/?\.ssh|mcp\.json|settings\.json"
    r")"
)

SINK_RE = re.compile(
    r"(?is)(?:"
    r"https?://[^\s\"'<>]+"
    r"|!\[[^\]]*\]\(\s*<?(?:https?:)?//"
    r"|<\s*img\b[^>]*\bsrc\s*="
    r"|\b(?:send|forward|email|mail|bcc|cc)\b"
    r"|\b(?:call|invoke|use|run)\s+(?:the\s+)?(?:[a-z][\w.-]{1,40}\s+)?(?:tool|function)\b"
    r"|\b(?:write|edit|update|save|put|add|set|enable|append)\b[^.\n]{0,80}"
    r"(?:mcp\.json|settings\.json|autoApprove|alwaysAllow|vscode|"
    r"dangerously-skip-permissions|trust-all-tools|--yolo)"
    r"|\b(?:autoApprove|alwaysAllow|dangerously-skip-permissions|trust-all-tools|--yolo|chat\.tools\.autoApprove)\b"
    r"|\b(?:web_search|web_fetch|browse_page|http_request|send_email)\b"
    r")"
)

POLICY_DIRECTIVE_RE = re.compile(
    r"(?is)(?:"
    r"<\s*(?:command|request|requests-allowed|responses-allowed|blocked-modes|blocked-strings)\b"
    r"|\binteraction-mode\s*="
    r"|blocked[-_ ](?:modes|strings)\b"
    r")"
)

POLICY_FRAME_RE = re.compile(
    r"(?is)(?:"
    r"<\s*(?:interaction-config|policy|system-config|agent-config|authorization-policy|"
    r"system-override|instruction-set|ruleset|config)\b"
    r"|(?:^|\n)\s*\[[A-Za-z][A-Za-z0-9_-]*\]\s*(?:\n|$)"
    r")"
)

CONFIG_MUTATION_RE = re.compile(
    r"(?is)(?:"
    r"(?:set|enable|turn\s+on|add|write|update|put|edit|patch|modify)\b[^.\n]{0,120}"
    r"(?:autoApprove|alwaysAllow|chat\.tools\.autoApprove|mcp\.json|"
    r"\.vscode/settings\.json|settings\.json|dangerously-skip-permissions|"
    r"trust-all-tools|trust\s*:\s*true|--yolo)"
    r"|(?:autoApprove|alwaysAllow|chat\.tools\.autoApprove)\b[^.\n]{0,80}"
    r"(?:true|enable|on|1|yes)"
    r"|~/?\.cursor/mcp\.json|~/?\.vscode/settings\.json"
    r")"
)

PREFILLED_TURN_RE = re.compile(
    r"(?ims)(?:(?:^|\n)\s*(?:assistant|system)\s*:[ \t]*\S"
    r"|(?:the\s+)?next\s+assistant\s+message\s+should)"
)

_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# Same fg/bg color, SGR hidden (8), or erase-line / erase-display used as concealment.
_ANSI_CONCEAL_RE = re.compile(
    r"\x1b\[(?:8(?:;|m)|(?:3|9)(\d);(?:4|10)\1(?:;|m)|[0-2]?K|[0-2]?J)"
)


def _strip_ansi(s):
    return _ANSI_CSI_RE.sub("", s or "")


DELAYED_TRIGGER_RE = re.compile(
    r"(?is)(?:"
    r"when\s+(?:the\s+)?(?:user|event|meeting|invite|calendar|timer|date|time)\b"
    r"[^.\n]{0,80}(?:then\s+)?(?:you\s+)?(?:must|should|will|shall|do|call|run|turn|send|delete|disable|enable)"
    r"|at\s+the\s+(?:start|beginning|end)\s+of\s+(?:each|every|the\s+next)"
    r"|next\s+time\s+(?:the\s+)?(?:user|they)\s+(?:says?|writes?|replies?|agrees?)"
    r")"
)

# Third-person / analytical framing that should not count as a live directive.
_ANALYTICAL_RE = re.compile(
    r"(?is)(?:"
    r"researchers?\b|this\s+week\b|security\s+news\b|the\s+attack(?:er|)\b|"
    r"the\s+vulnerability\b|the\s+paper\b|the\s+write-?up\b|defenders?\s+should\b|"
    r"no\s+action\s+is\s+requested\b|treat\s+untrusted\b|incident\s+write-?up\b|"
    r"threat\s+intelligence\b|quoted\s+(?:the\s+)?(?:phrase|instruction)|"
    r"describes?\s+how\s+(?:the\s+)?(?:attack|technique)|"
    r"\bCVE-\d{4}-\d+\b"
    r")"
)


def _discussion_context(text):
    """True when the body is discussing attacks rather than issuing one."""
    if _is_quoted_discussion(text, list(OVERRIDE_RE.finditer(text)) if OVERRIDE_RE.search(text) else []):
        return True
    signals = list(_DISCUSSION_RE.finditer(text)) + list(_ANALYTICAL_RE.finditer(text))
    return len(signals) >= 2


ANSWER_IN_SINK_RE = re.compile(
    r"(?is)(?:"
    r"(?:what|which|list)\s+.{0,120}(?:email addresses?|phone numbers?|secrets?|tokens?|leads?|credentials?).{0,500}"
    r"(?:<\s*img\b|!\[[^\]]*\]\()"
    r"|"
    r"<\s*img\b[^>]*src\s*=\s*[\"']?https?://[^\"'>]*\{\{[^}]+\}\}"
    r"|"
    r"include\s+a\s+(?:preview\s+)?image.{0,240}<\s*img\b"
    r"|"
    r"replace\s+spaces\s+with\s+%20.{0,240}<\s*img\b"
    r")"
)


def structural_injection_hits(text):

    """Return (rule-ish tag, excerpt) for policy/config/co-occurrence patterns."""
    hits = []
    if _discussion_context(text):
        return hits
    if ANSWER_IN_SINK_RE.search(text):
        m = ANSWER_IN_SINK_RE.search(text)
        hits.append(("answer-in-sink", m.group(0)[:80]))
    if POLICY_FRAME_RE.search(text) and (
        AGENT_CUE_RE.search(text) or OVERRIDE_RE.search(text) or SINK_RE.search(text)
        or EXFIL_PHRASE_RE.search(text) or INSTR_HINT_RE.search(text)
        or SENSITIVE_OBJ_RE.search(text) or HARVEST_RE.search(text)
        or POLICY_DIRECTIVE_RE.search(text)
    ):
        # A bare <policy> / [section] tag is not enough; require an instruction,
        # sensitive-object harvest, directive body, or sink so ordinary vendor
        # policy XML (rate limits, etc.) stays clean.
        m = POLICY_FRAME_RE.search(text)
        hits.append(("policy-frame", m.group(0)[:80]))
    if CONFIG_MUTATION_RE.search(text):
        m = CONFIG_MUTATION_RE.search(text)
        hits.append(("config-mutation", m.group(0)[:80]))
    if DELAYED_TRIGGER_RE.search(text) and (SINK_RE.search(text) or SENSITIVE_OBJ_RE.search(text) or AGENT_CUE_RE.search(text)):
        m = DELAYED_TRIGGER_RE.search(text)
        hits.append(("delayed-trigger", m.group(0)[:80]))
    if PREFILLED_TURN_RE.search(text) and (SINK_RE.search(text) or ACTION_BAIT_RE.search(text) or EXFIL_PHRASE_RE.search(text)):
        m = PREFILLED_TURN_RE.search(text)
        hits.append(("prefilled-assistant-turn", m.group(0)[:80]))
    agent = bool(AGENT_CUE_RE.search(text) or OVERRIDE_RE.search(text))
    authority = bool(AUTHORITY_RE.search(text) or OVERRIDE_RE.search(text) or ROLE_RE.search(text))
    sensitive = bool(SENSITIVE_OBJ_RE.search(text) or HARVEST_RE.search(text))
    sink = bool(SINK_RE.search(text) or EXFIL_HOST_RE.search(text) or EXFIL_PHRASE_RE.search(text) or MD_IMG_RE.search(text))
    score = sum((agent, authority, sensitive, sink))
    # Require at least two distinct dimensions, and at least one of
    # (agent/authority) plus one of (sensitive/sink), to avoid flagging
    # ordinary pages that merely mention a URL or the word "secret".
    if score >= 2 and (agent or authority) and (sensitive or sink):
        hits.append(("co-occurrence", "agent=%s authority=%s sensitive=%s sink=%s" % (agent, authority, sensitive, sink)))
    return hits


def scan_text(text, source, tool, turn, disabled=None):
    """Run TR01–TR10 against one tool-result body."""
    disabled = set(disabled or [])
    findings = []
    if not text:
        return findings

    def add(rule, msg, idx=0):
        if rule in disabled:
            return
        findings.append(Finding(rule, source, tool, turn, msg, _excerpt(text, idx)))

    views = normalize_injection_views(text)
    # Typo/split-word unfold is only for jailbreak-phrase matching. Applying it
    # to URL/HTML rules would glue "images.example.net/badge.svg" into one token
    # and false-positive TR09.
    typo_views = []
    for label, view in views:
        folded = _normalize_jailbreak_text(view)
        if folded != view:
            typo_views.append((label + "+typo", folded))
    phrase_views = views + typo_views

    discussion = _discussion_context(text)

    if "TR01" not in disabled:
        hit = None
        scan_for_override = text
        matches = list(OVERRIDE_RE.finditer(text))
        if not matches:
            for _, view in phrase_views:
                matches = list(OVERRIDE_RE.finditer(view))
                if matches:
                    scan_for_override = view
                    break
        if matches and not _is_quoted_discussion(scan_for_override, matches) and not discussion:
            hit = matches[0]
        elif matches and not _is_quoted_discussion(scan_for_override, matches) and discussion:
            # Quoted-or-discussed jailbreak mentions stay quiet; an unquoted
            # directive in a news article still stays quiet under discussion.
            hit = None
        if hit is not None:
            add("TR01", "override/jailbreak phrasing at line %d" % _line_of(text, hit.start() if hit.string is text else 0), hit.start() if hit.string is text else 0)

    if "TR02" not in disabled:
        for _, view in views:
            m = ROLE_RE.search(view)
            if m:
                add("TR02", "fake role/system token %r at line %d" % (m.group(0)[:40], _line_of(text, m.start() if view is text else 0)),
                    m.start() if view is text else 0)
                break

    if "TR03" not in disabled:
        hidden = find_hidden_unicode(text)
        if hidden:
            kinds = sorted({k for _, k, _ in hidden})
            add("TR03", "%d hidden Unicode codepoint(s) (%s), first at line %d"
                % (len(hidden), ", ".join(kinds), _line_of(text, hidden[0][0])), hidden[0][0])

    if "TR04" not in disabled and not discussion:
        for _, view in views:
            m = ACTION_BAIT_RE.search(view)
            if m:
                add("TR04", "action/tool-chaining bait at line %d: %r"
                    % (_line_of(text, m.start() if view is text else 0), m.group(0)[:60]), m.start() if view is text else 0)
                break

    if "TR05" not in disabled:
        hit = False
        for _, view in views:
            m = EXFIL_HOST_RE.search(view)
            if m:
                add("TR05", "known callback/exfil-style host at line %d: %s"
                    % (_line_of(text, m.start() if view is text else 0), m.group(0)[:80]), m.start() if view is text else 0)
                hit = True
                break
        if not hit and not discussion:
            for _, view in views:
                m = EXFIL_PHRASE_RE.search(view)
                if m:
                    add("TR05", "exfil/callback phrasing at line %d" % _line_of(text, m.start() if view is text else 0), m.start() if view is text else 0)
                    break

    if "TR06" not in disabled:
        decoded_hits = list(decode_candidates(text))
        for _, view in views:
            if view is text or view == text:
                continue
            decoded_hits.extend(decode_candidates(view))
        for kind, decoded, idx in decoded_hits:
            add("TR06", "%s blob decodes to instruction-like text at line %d: %r"
                % (kind, _line_of(text, idx if isinstance(idx, int) else 0), decoded[:60]), idx if isinstance(idx, int) else 0)
            break
        # Decoded hidden channels that themselves look like instructions.
        if not any(f.rule == "TR06" for f in findings):
            for label, view in views:
                if label in {"sneaky-bits", "variation-selector", "tags", "ansi-conceal"} and (
                    OVERRIDE_RE.search(view) or INSTR_HINT_RE.search(view) or AGENT_CUE_RE.search(view)
                ):
                    add("TR06", "%s channel decodes to instruction-like text: %r" % (label, view[:60]))
                    break

    if "TR07" not in disabled and not discussion:
        for _, view in views:
            m = HARVEST_RE.search(view)
            if m:
                add("TR07", "credential harvest request at line %d: %r"
                    % (_line_of(text, m.start() if view is text else 0), m.group(0)[:60]), m.start() if view is text else 0)
                break

    if "TR08" not in disabled and not discussion:
        for _, view in views:
            m = CONCEAL_RE.search(view)
            if m:
                add("TR08", "conceal-from-user phrasing at line %d" % _line_of(text, m.start() if view is text else 0), m.start() if view is text else 0)
                break

    if "TR09" not in disabled:
        md_hit = False
        for src in [text] + [v for _, v in views if v != text]:
            for m in MD_IMG_RE.finditer(src):
                if _autoload_is_suspicious(m.group(2), tag="markdown"):
                    add("TR09", "markdown image loads external URL at line %d: %s"
                        % (_line_of(text, 0), m.group(2)[:80]), 0)
                    md_hit = True
                    break
            if md_hit:
                break
        if not md_hit:
            for src in [text] + [v for _, v in views if v != text]:
                for m in HTML_SRC_RE.finditer(src):
                    if _autoload_is_suspicious(m.group("url"), tag=m.group("tag")):
                        add("TR09", "HTML element auto-loads URL at line %d: %s"
                            % (_line_of(text, 0), m.group("url")[:80]), 0)
                        md_hit = True
                        break
                if md_hit:
                    break

    if "TR10" not in disabled:
        for label, view in views:
            hits = structural_injection_hits(view)
            if hits:
                tag, ev = hits[0]
                add("TR10", "structural injection (%s, view=%s): %s" % (tag, label, ev[:80]))
                break

    return findings


def load_raw(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_jsonish(text):
    try:
        return json.loads(text), "json"
    except ValueError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                return None, "text"
        return (rows if rows else None), ("jsonl" if rows else "text")


def extract_from_path(path, as_result=False, tool_name="file"):
    text = load_raw(path)
    if as_result:
        return [Result(1, tool_name, text)]
    data, kind = load_jsonish(text)
    if kind == "text" or data is None:
        # plain file treated as one synthetic tool result
        return [Result(1, tool_name, text)]
    results = parse_results(data)
    if not results and isinstance(data, (dict, list)):
        # JSON but no tool-result shape: treat whole body as one result
        results = [Result(1, tool_name, text if isinstance(data, list) and not data
                          else json.dumps(data, indent=2) if not isinstance(data, str) else data)]
    return results


def iter_paths(paths):
    for p in paths:
        if p == "-":
            yield p
            continue
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith((".json", ".jsonl", ".txt", ".md", ".html", ".log")):
                        yield os.path.join(root, f)
        else:
            yield p


def scan_paths(paths, as_result=False, tool_name="file", tools_filter=None, disable=None):
    findings, stats = [], []
    filt = set(t.lower() for t in (tools_filter or []))
    for path in iter_paths(paths):
        try:
            results = extract_from_path(path, as_result=as_result, tool_name=tool_name)
        except OSError as e:
            sys.stderr.write("resultguard: cannot read %s: %s\n" % (path, e))
            continue
        if filt:
            results = [r for r in results if r.tool.lower() in filt]
        stats.append({
            "source": path,
            "results": len(results),
            "bytes": sum(len(r.text) for r in results),
        })
        for r in results:
            findings.extend(scan_text(r.text, path, r.tool, r.idx, disabled=disable))
    return findings, stats


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="resultguard",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("paths", nargs="*", default=["-"],
                    help="transcript/result files or dirs, '-' for stdin")
    ap.add_argument("--as-result", action="store_true",
                    help="treat each file body as one tool result (skip transcript parsing)")
    ap.add_argument("--tool-name", default="file",
                    help="tool name used with --as-result / plain files (default: file)")
    ap.add_argument("--tools", nargs="+", metavar="NAME",
                    help="only scan results from these tool names")
    ap.add_argument("--disable", nargs="+", metavar="RULE",
                    help="disable rule ids (e.g. TR09)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info")
    ap.add_argument("--fail-on", choices=SEVERITIES[1:] + ["any", "none"], default="high",
                    help="exit 1 if any finding >= this (default: high)")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="resultguard " + VERSION)
    a = ap.parse_args(argv)

    if a.list_rules:
        for r, (sev, title) in sorted(RULES.items()):
            print("%s  %-8s %s" % (r, sev, title))
        return 0

    disable = set(a.disable or [])
    unknown = disable - set(RULES)
    if unknown:
        ap.error("unknown rules: %s" % ", ".join(sorted(unknown)))

    findings, stats = scan_paths(
        a.paths, as_result=a.as_result, tool_name=a.tool_name,
        tools_filter=a.tools, disable=disable,
    )
    if not stats and a.paths != ["-"]:
        sys.stderr.write("resultguard: no readable inputs\n")
        return 2
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[a.min_severity]]
    shown.sort(key=lambda f: (f.source, f.turn, -SEV_RANK[f.severity], f.rule))

    if a.json:
        print(json.dumps({
            "version": VERSION,
            "sources": stats,
            "findings": [f.to_dict() for f in shown],
        }, indent=2))
    else:
        for s in stats:
            print("%s: %d tool result(s), %d bytes scanned" % (s["source"], s["results"], s["bytes"]))
        if not shown:
            print("No findings at or above --min-severity %s." % a.min_severity)
        for f in shown:
            print("[%s] %s %s  tool=%s turn=#%d  %s"
                  % (f.severity.upper(), f.rule, f.source, f.tool, f.turn, f.message))
            if f.excerpt:
                print("         excerpt: %s" % f.excerpt)
        if shown:
            print("Note: resultguard is heuristic. Benign docs can match; tune --disable / --tools.")

    if a.fail_on == "none":
        return 0
    threshold = SEV_RANK["info"] if a.fail_on == "any" else SEV_RANK[a.fail_on]
    if any(SEV_RANK[f.severity] >= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
