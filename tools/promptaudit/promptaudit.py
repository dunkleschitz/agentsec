#!/usr/bin/env python3
"""promptaudit: offline hygiene auditor for LLM system prompts (OWASP LLM07 / LLM06).

A system prompt is not a secret store and not an access-control layer. promptaudit reads
system/developer prompts from plain files or from OpenAI / Anthropic / generic JSON(L)
transcripts and flags content that should not be there: credentials, internal endpoints,
authorization logic, unbounded tool authority, embedded PII, exposed decision thresholds,
hidden Unicode, and tool-using prompts with no guidance about untrusted content.

Standard library only. Never makes network calls. Heuristic: a clean result is not proof
that a prompt is safe.
"""
import argparse
import ipaddress
import json
import os
import re
import sys
import unicodedata

VERSION = "0.1.0"
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "PA01": ("critical", "Credential or secret literal embedded in the prompt"),
    "PA02": ("high", "Internal endpoint, private IP, or metadata address in the prompt"),
    "PA03": ("high", "Authorization decision delegated to the prompt"),
    "PA04": ("high", "Unbounded tool authority or confirmation waived"),
    "PA05": ("high", "Hidden Unicode (zero-width, bidi, or TAG characters)"),
    "PA06": ("medium", "Tool or retrieval prompt with no untrusted-content guidance"),
    "PA07": ("medium", "Personal data embedded in the prompt"),
    "PA08": ("medium", "Security decision threshold or filter criteria disclosed"),
    "PA09": ("low", "Prompt relies on staying secret"),
    "PA10": ("info", "Prompt inventory"),
}

SECRET_PATTERNS = [
    ("OpenAI-style API key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}")),
    ("private key block", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}")),
    ("bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.=]{16,}")),
    ("connection string with password",
     re.compile(r"\b[a-z][a-z0-9+]{2,15}://[^\s:/@]+:[^\s@/]{3,}@[^\s/]+", re.I)),
    ("labeled secret",
     re.compile(r"\b(?:api[_ -]?key|secret(?:[_ -]?key)?|password|passwd|pwd|access[_ -]?token|auth[_ -]?token|client[_ -]?secret)"
                r"\s*(?:is|=|:)\s*[\"'`]?([^\s\"'`,;]{6,})", re.I)),
]
PLACEHOLDER = re.compile(r"^(?:\{\{.*\}\}|\$\{.*\}|<[^>]+>|\*+|x{4,}|\.{3}|redacted|none|null|example|your[_-].*|changeme)$", re.I)

URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]{1,15}://([^\s/?#'\"<>)\]]+)[^\s'\"<>)\]]*", re.I)
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d|\.\d)")
INTERNAL_SUFFIX = (".internal", ".corp", ".local", ".lan", ".intranet", ".private", ".svc.cluster.local", ".home.arpa")

AUTHZ_PATTERNS = [
    re.compile(r"\bonly (?:allow|let|permit|show|give|grant)\b[^.\n]{0,80}\b(?:admin|administrator|manager|staff|employee|premium|paid|owner|verified|internal)", re.I),
    re.compile(r"\bif the user (?:is|says (?:they are|they're)|claims to be|has the role)\b[^.\n]{0,60}\b(?:admin|administrator|manager|staff|employee|owner|developer|moderator|support)", re.I),
    re.compile(r"\b(?:do not|don't|never) (?:let|allow) (?:users?|customers?|anyone)\b[^.\n]{0,60}\b(?:access|see|view|read|modify|delete)\b[^.\n]{0,40}\b(?:other|another|someone)", re.I),
    re.compile(r"\b(?:users?|customers?) (?:with|in) (?:the )?(?:role|group|tier)\b[^.\n]{0,40}\b(?:can|may|are allowed to)\b", re.I),
    re.compile(r"\b(?:admin|administrator|override|debug|maintenance) (?:mode|password|passphrase|code)\b[^.\n]{0,40}\b(?:is|=|:)\b", re.I),
]
AUTHORITY_PATTERNS = [
    re.compile(r"\byou (?:may|can|are (?:allowed|permitted|authori[sz]ed) to) (?:run|execute) any (?:command|code|script|shell)", re.I),
    re.compile(r"\b(?:without|never|do not|don't|no need to) (?:ask(?:ing)?|seek(?:ing)?|wait(?:ing)?|request(?:ing)?|get(?:ting)?) (?:for )?(?:the user'?s? )?(?:confirmation|permission|approval|consent)", re.I),
    re.compile(r"\byou (?:have|are given) (?:full|unrestricted|unlimited|complete|root|admin) (?:access|control|permissions?|privileges?)", re.I),
    re.compile(r"\b(?:ignore|bypass|disable|skip) (?:all )?(?:safety|security|permission|sandbox|approval) (?:checks?|rules?|guardrails?|prompts?|restrictions?)", re.I),
    re.compile(r"\b(?:auto[- ]?approve|automatically approve|always approve)\b[^.\n]{0,40}\b(?:tool|command|action|request|call|payment|transfer)s?", re.I),
]
TOOL_HINT = re.compile(r"\b(?:tools?|function call|browse|browsing|web search|search the web|fetch|retriev\w*|documents?|knowledge base|emails?|inbox|web ?pages?|urls?|files?|mcp|plugins?|rag)\b", re.I)
UNTRUSTED_GUIDANCE = re.compile(
    r"(?:untrusted|treat[^.\n]{0,40}\bas (?:data|information|content)|(?:do not|don't|never) (?:follow|obey|execute|act on)[^.\n]{0,60}\b(?:instructions?|commands?)[^.\n]{0,60}\b(?:in|inside|within|from|found)|instructions?[^.\n]{0,40}(?:in|inside|within|from) (?:tool|retrieved|web|documents?|search|emails?|results?)[^.\n]{0,40}(?:ignore|not|never)|prompt injection|external content)", re.I)
THRESHOLD_PATTERNS = [
    re.compile(r"\b(?:auto[- ]?approve|approve automatically|no review|skip review|not flagged|don't flag|do not flag)\b[^.\n]{0,60}(?:under|below|less than|up to|<)\s*\$?\d", re.I),
    re.compile(r"\b(?:under|below|less than|up to)\s*\$?\d[\d,]*(?:\.\d+)?\b[^.\n]{0,60}\b(?:auto[- ]?approve|approved automatically|no (?:review|verification|check)|skip (?:review|verification))", re.I),
    re.compile(r"\b(?:fraud|risk|moderation|spam|abuse) (?:score|threshold|filter|rule)s?\b[^.\n]{0,50}\b(?:above|below|over|under|>|<|=|is)\s*\d[\d,.]*", re.I),
    re.compile(r"\b(?:blocked|banned|forbidden|filtered) (?:words|terms|keywords|topics) (?:are|include|list)\b", re.I),
]
SECRECY_PATTERNS = [
    re.compile(r"\b(?:never|do not|don't) (?:reveal|disclose|share|repeat|show|print|output)\b[^.\n]{0,40}\b(?:these|this|your|the) (?:instructions|system prompt|prompt|rules|guidelines)", re.I),
    re.compile(r"\b(?:this|these|the) (?:system )?(?:prompt|instructions) (?:is|are) (?:confidential|secret|private|proprietary)", re.I),
]
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}(?!\d)")
SSN_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
ROLE_EMAIL = re.compile(r"^(?:support|help|info|security|abuse|privacy|noreply|no-reply|contact|sales|team|admin|hello)@", re.I)
EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net", "example.invalid", "test.com")

HIDDEN_RANGES = [(0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069), (0xFEFF, 0xFEFF), (0xE0000, 0xE007F)]


def mask(v):
    v = str(v)
    return v[:4] + "…" + ("*" * 4) + ("" if len(v) < 12 else v[-2:])


class Finding:
    def __init__(self, rule, source, line, message, severity=None):
        self.rule, self.source, self.line, self.message = rule, source, line, message
        self.severity = severity or RULES[rule][0]

    def as_dict(self):
        return {"rule": self.rule, "severity": self.severity, "title": RULES[self.rule][1],
                "source": self.source, "line": self.line, "message": self.message}


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def host_class(host):
    h = host.lower().strip("[]").rstrip(".")
    if h in ("localhost",) or h.endswith(".localhost"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        if h == "metadata.google.internal":
            return "metadata"
        if h.endswith(INTERNAL_SUFFIX) or "." not in h:
            return "internal"
        return ""
    if str(ip) in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200"):
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    return ""


def hidden_chars(text):
    out = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if any(a <= cp <= b for a, b in HIDDEN_RANGES):
            out.append((i, cp))
    return out


def decode_tags(text):
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def audit_prompt(text, source, disabled=()):
    disabled = set(disabled)
    found = []

    def add(rule, idx, msg, sev=None):
        if rule not in disabled:
            found.append(Finding(rule, source, line_of(text, idx), msg, sev))

    norm = unicodedata.normalize("NFKC", text)
    # PA05 hidden unicode (on raw text)
    hid = hidden_chars(text)
    if hid:
        tag = decode_tags(text)
        msg = "%d hidden character(s), first U+%04X" % (len(hid), hid[0][1])
        if tag:
            msg += "; decoded TAG text: %r" % tag[:80]
        add("PA05", hid[0][0], msg, "critical" if tag else None)
    clean = "".join(ch for ch in norm if not any(a <= ord(ch) <= b for a, b in HIDDEN_RANGES))
    # PA01 secrets
    seen = set()
    for label, rx in SECRET_PATTERNS:
        for m in rx.finditer(clean):
            val = m.group(1) if m.groups() else m.group(0)
            if PLACEHOLDER.match(val.strip()) or val in seen:
                continue
            if label == "labeled secret" and (val.lower().startswith(("the", "a", "an", "not", "stored", "provided", "in", "from"))
                                              and val.isalpha()):
                continue
            if any(val in s or s in val for s in seen):
                continue
            seen.add(val)
            add("PA01", m.start(), "%s: %s" % (label, mask(val)))
    # PA02 internal endpoints
    hosts_done = set()
    for m in URL_RE.finditer(clean):
        host = m.group(1).split("@")[-1]
        host = host[1:host.index("]")] if host.startswith("[") and "]" in host else host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        cls = host_class(host)
        if cls and host not in hosts_done:
            hosts_done.add(host)
            add("PA02", m.start(), "%s URL host %s" % (cls, host), "critical" if cls == "metadata" else None)
    for m in IP_RE.finditer(clean):
        ip = m.group(1)
        if ip in hosts_done:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        cls = host_class(ip)
        if cls:
            hosts_done.add(ip)
            add("PA02", m.start(), "%s address %s" % (cls, ip), "critical" if cls == "metadata" else None)
    # PA03 authz
    for rx in AUTHZ_PATTERNS:
        for m in rx.finditer(clean):
            add("PA03", m.start(), "access rule enforced only by the model: %r" % m.group(0)[:100])
    # PA04 authority
    for rx in AUTHORITY_PATTERNS:
        for m in rx.finditer(clean):
            add("PA04", m.start(), "%r" % m.group(0)[:100])
    # PA06 tool prompt without untrusted guidance
    th = TOOL_HINT.search(clean)
    if th and not UNTRUSTED_GUIDANCE.search(clean):
        add("PA06", th.start(), "prompt mentions %r but never says tool/retrieved content is data, not instructions" % th.group(0))
    # PA07 PII
    for m in EMAIL_RE.finditer(clean):
        e = m.group(0)
        start = clean.rfind(" ", 0, m.start()) + 1
        if "://" in clean[start:m.start()]:
            continue
        dom = e.split("@", 1)[1].lower()
        if ROLE_EMAIL.match(e) or dom in EXAMPLE_DOMAINS or dom.endswith(".example"):
            continue
        add("PA07", m.start(), "personal email address %s" % mask(e))
    for m in SSN_RE.finditer(clean):
        add("PA07", m.start(), "SSN-shaped number %s" % mask(m.group(0)), "high")
    for m in PHONE_RE.finditer(clean):
        if not SSN_RE.fullmatch(m.group(0).strip()):
            add("PA07", m.start(), "phone number %s" % mask(m.group(0)), "low")
    # PA08 thresholds
    for rx in THRESHOLD_PATTERNS:
        for m in rx.finditer(clean):
            add("PA08", m.start(), "%r" % m.group(0)[:100])
    # PA09 secrecy reliance
    for rx in SECRECY_PATTERNS:
        m = rx.search(clean)
        if m:
            add("PA09", m.start(), "%r; assume the prompt will leak and keep nothing sensitive in it" % m.group(0)[:80])
            break
    add("PA10", 0, "%d chars, %d lines" % (len(text), text.count("\n") + 1))
    return found


# ---------- input extraction ----------

def _content_text(c):
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(_content_text(x) for x in c if x is not None)
    if isinstance(c, dict):
        for k in ("text", "content", "value"):
            if isinstance(c.get(k), (str, list)):
                return _content_text(c[k])
    return ""


PROMPT_KEYS = ("system", "system_prompt", "systemPrompt", "instructions", "developer_prompt", "systemInstruction", "system_instruction")


def extract_prompts(obj, ptr="$"):
    """Yield (pointer, text) for system/developer prompts found anywhere in a JSON value."""
    if isinstance(obj, dict):
        role = obj.get("role")
        if role in ("system", "developer") and "content" in obj:
            t = _content_text(obj["content"])
            if t.strip():
                yield ptr, t
            return
        for k, v in obj.items():
            if k in PROMPT_KEYS and isinstance(v, (str, list, dict)):
                t = _content_text(v) if not isinstance(v, dict) else _content_text(v.get("parts") or v)
                if t.strip():
                    yield "%s.%s" % (ptr, k), t
                    continue
            if isinstance(v, (dict, list)):
                yield from extract_prompts(v, "%s.%s" % (ptr, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from extract_prompts(v, "%s[%d]" % (ptr, i))


def prompts_from_text(name, data, as_text=False):
    stripped = data.lstrip()
    if not as_text and stripped[:1] in "{[":
        try:
            return [("%s:%s" % (name, p), t) for p, t in extract_prompts(json.loads(data))]
        except ValueError:
            pass
        out = []
        ok = False
        for n, line in enumerate(data.splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                ok = False
                break
            ok = True
            out += [("%s:%d:%s" % (name, n, p), t) for p, t in extract_prompts(obj)]
        if ok:
            return out
    return [(name, data)]


TEXT_EXT = (".txt", ".md", ".prompt", ".json", ".jsonl", ".system", ".mdc")


def iter_files(paths):
    for p in paths:
        if p == "-":
            yield "<stdin>", sys.stdin.read()
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for f in sorted(files):
                    if f.lower().endswith(TEXT_EXT):
                        fp = os.path.join(root, f)
                        with open(fp, encoding="utf-8", errors="replace") as fh:
                            yield fp, fh.read()
        else:
            with open(p, encoding="utf-8", errors="replace") as fh:
                yield p, fh.read()


def audit_paths(paths, disabled=(), as_text=False):
    findings, seen = [], set()
    for name, data in iter_files(paths):
        for src, text in prompts_from_text(name, data, as_text):
            key = text.strip()
            if key in seen:
                continue
            seen.add(key)
            findings += audit_prompt(text, src, disabled)
    return findings


def to_sarif(findings):
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "promptaudit", "version": VERSION,
                                          "rules": [{"id": r, "shortDescription": {"text": t}} for r, (_, t) in RULES.items()]}},
                      "results": [{"ruleId": f.rule,
                                   "level": "error" if SEV_RANK[f.severity] >= 3 else ("warning" if SEV_RANK[f.severity] == 2 else "note"),
                                   "message": {"text": f.message},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.source.split(":")[0]},
                                                                       "region": {"startLine": f.line}}}]} for f in findings]}]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="promptaudit", description="Offline hygiene auditor for LLM system prompts: secrets, internal endpoints, authorization logic, unbounded authority, PII, thresholds, hidden Unicode.")
    ap.add_argument("paths", nargs="*", help="prompt files, JSON/JSONL transcripts, directories, or - for stdin")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    ap.add_argument("--as-text", action="store_true", help="treat every file as one prompt, even JSON")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this (default info)")
    ap.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="high", help="exit 1 at or above this severity (default high)")
    ap.add_argument("--disable", action="append", default=[], metavar="RULE", help="disable a rule (repeatable or comma-separated)")
    ap.add_argument("--list-rules", action="store_true", help="print rules and exit")
    ap.add_argument("--version", action="version", version="promptaudit " + VERSION)
    a = ap.parse_args(argv)
    if a.list_rules:
        for r, (s, t) in RULES.items():
            print("%s  %-8s %s" % (r, s, t))
        return 0
    if not a.paths:
        ap.print_usage(sys.stderr)
        print("promptaudit: error: no input paths", file=sys.stderr)
        return 2
    disabled = {d.strip().upper() for x in a.disable for d in x.split(",") if d.strip()}
    bad = disabled - set(RULES)
    if bad:
        print("promptaudit: error: unknown rule(s): %s" % ", ".join(sorted(bad)), file=sys.stderr)
        return 2
    try:
        findings = audit_paths(a.paths, disabled, a.as_text)
    except OSError as e:
        print("promptaudit: error: %s" % e, file=sys.stderr)
        return 2
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[a.min_severity]]
    shown.sort(key=lambda f: (f.source, f.line, -SEV_RANK[f.severity], f.rule))
    if a.json:
        print(json.dumps({"tool": "promptaudit", "version": VERSION, "findings": [f.as_dict() for f in shown]}, indent=2))
    elif a.sarif:
        print(json.dumps(to_sarif(shown), indent=2))
    else:
        for f in shown:
            print("%s:%d  %-8s %s  %s" % (f.source, f.line, f.severity.upper(), f.rule, f.message))
        print("%d finding(s)" % len(shown))
    if a.fail_on != "none" and any(SEV_RANK[f.severity] >= SEV_RANK[a.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
