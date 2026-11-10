#!/usr/bin/env python3
"""tunescan (#39): offline poisoning and hygiene scanner for LLM fine-tuning datasets.

Reads JSONL/JSON training data (OpenAI chat fine-tune, prompt/completion, Alpaca,
ShareGPT, DPO-style chosen/rejected) and flags signs of data poisoning (OWASP LLM04):
backdoor trigger phrases tied to a fixed completion, recurring outbound domains in
completions, injected instructions, hidden Unicode, dangerous commands taught as
answers, conflicting labels, embedded secrets, duplicates, and malformed records.

Standard library only. No network calls. Secret values are masked in every output.
"""
import argparse
import collections
import json
import os
import re
import sys
import unicodedata
from urllib.parse import urlsplit

VERSION = "0.1.0"
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = collections.OrderedDict([
    ("TS01", ("high", "Backdoor trigger: a rare phrase in prompts maps to one fixed completion")),
    ("TS02", ("medium", "Recurring outbound domain in completions not seen in prompts")),
    ("TS03", ("high", "Injected instruction or fake role delimiter in training text")),
    ("TS04", ("high", "Hidden Unicode (zero-width, bidi, TAG); TAG text decoded")),
    ("TS05", ("high", "Completion teaches a dangerous command (pipe-to-shell, rm -rf /, reverse shell, encoded PowerShell)")),
    ("TS06", ("medium", "Conflicting labels: the same prompt has different completions")),
    ("TS07", ("critical", "Secret-shaped value in training data (masked)")),
    ("TS08", ("low", "Duplicate example repeated beyond --max-dupes (over-weighting)")),
    ("TS09", ("medium", "Malformed record: unknown shape, no assistant turn, or bad JSON")),
    ("TS10", ("info", "Inventory: record count, format, and roles")),
])


class Finding:
    def __init__(self, rule, source, line, message, severity=None):
        self.rule = rule
        self.severity = severity or RULES[rule][0]
        self.source = source
        self.line = line
        self.message = message

    def as_dict(self):
        return {"rule": self.rule, "severity": self.severity, "source": self.source,
                "line": self.line, "message": self.message}


# ---------------------------------------------------------------- parsing

def _text(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(_text(c) for c in content)
    if isinstance(content, dict):
        for k in ("text", "content", "value"):
            if k in content:
                return _text(content[k])
        if "arguments" in content or "function" in content:
            return json.dumps(content, sort_keys=True)
        return ""
    return str(content)


ROLE_MAP = {"human": "user", "user": "user", "gpt": "assistant", "assistant": "assistant",
            "model": "assistant", "bot": "assistant", "system": "system", "developer": "system",
            "tool": "tool", "function": "tool"}


def normalize(obj):
    """Return (format, prompt_text, completion_text, roles) or None if the shape is unknown."""
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("messages"), list):
        prompt, comp, roles = [], [], []
        for m in obj["messages"]:
            if not isinstance(m, dict):
                continue
            role = ROLE_MAP.get(str(m.get("role", "")).lower(), "other")
            roles.append(role)
            body = _text(m.get("content"))
            if m.get("tool_calls"):
                body += "\n" + json.dumps(m["tool_calls"], sort_keys=True)
            (comp if role == "assistant" else prompt).append(body)
        return "chat", "\n".join(prompt), "\n".join(comp), roles
    if isinstance(obj.get("conversations"), list):
        prompt, comp, roles = [], [], []
        for m in obj["conversations"]:
            if not isinstance(m, dict):
                continue
            role = ROLE_MAP.get(str(m.get("from", m.get("role", ""))).lower(), "other")
            roles.append(role)
            (comp if role == "assistant" else prompt).append(_text(m.get("value", m.get("content"))))
        return "sharegpt", "\n".join(prompt), "\n".join(comp), roles
    if "instruction" in obj and "output" in obj:
        p = _text(obj.get("instruction")) + ("\n" + _text(obj["input"]) if obj.get("input") else "")
        return "alpaca", p, _text(obj["output"]), ["user", "assistant"]
    if "prompt" in obj and "chosen" in obj:
        return "preference", _text(obj["prompt"]), _text(obj["chosen"]), ["user", "assistant"]
    if "prompt" in obj and "completion" in obj:
        return "completion", _text(obj["prompt"]), _text(obj["completion"]), ["user", "assistant"]
    if "input" in obj and "output" in obj:
        return "io", _text(obj["input"]), _text(obj["output"]), ["user", "assistant"]
    return None


def load_records(name, data):
    """Yield (line, obj_or_None, error) for JSONL, a JSON array, or {"data": [...]}."""
    s = data.lstrip()
    if s.startswith("["):
        try:
            arr = json.loads(data)
            for i, o in enumerate(arr, 1):
                yield i, o, None
            return
        except ValueError:
            pass
    if s.startswith("{") and "\n" not in data.strip():
        pass
    lines = data.splitlines()
    if s.startswith("{"):
        try:
            whole = json.loads(data)
            if isinstance(whole, dict) and normalize(whole) is None:
                for k in ("data", "examples", "records", "train"):
                    if isinstance(whole.get(k), list):
                        for i, o in enumerate(whole[k], 1):
                            yield i, o, None
                        return
            if isinstance(whole, dict) and len([l for l in lines if l.strip()]) > 1:
                yield 1, whole, None
                return
        except ValueError:
            pass
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            yield n, json.loads(line), None
        except ValueError as e:
            yield n, None, "bad JSON (%s)" % e.msg


# ---------------------------------------------------------------- detectors

SECRET_PATTERNS = [
    ("OpenAI-style API key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}")),
    ("private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}")),
    ("connection string with password", re.compile(r"\b[a-z][a-z0-9+]{2,}://[^\s:/@]+:[^\s@/]{3,}@[^\s/]+", re.I)),
    ("labeled password/secret", re.compile(r"\b(?:password|passwd|api[_ ]?key|secret|token)\s*[:=]\s*[\"']?([^\s\"'{}<>]{6,})", re.I)),
]
PLACEHOLDER = re.compile(r"^(?:x+|\*+|\.+|<.*>|\{.*\}|\$\{?\w+\}?|your[_-]?\w*|changeme|redacted|example|none|null)$", re.I)


def mask(v):
    v = v.strip()
    if len(v) <= 8:
        return v[:2] + "****"
    return v[:4] + "…****" + v[-2:]


INJECTION = [
    re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules?|guidelines)", re.I),
    re.compile(r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted|god)\s*mode\b", re.I),
    re.compile(r"\b(?:new|updated|override)\s+system\s+(?:prompt|instructions?)\s*:", re.I),
    re.compile(r"\bdo\s+not\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+the\s+user\b", re.I),
    re.compile(r"\bwhen(?:ever)?\s+you\s+see\s+[\"'][^\"']{2,40}[\"']\s*,?\s+(?:always|you\s+must|respond|output|reply)", re.I),
]
ROLE_TOKENS = re.compile(r"<\|(?:im_start|im_end|system|endoftext|start_header_id|eot_id)\|>|\[/?INST\]|<<SYS>>|^\s*###\s*(?:System|Instruction)\s*:", re.I | re.M)

DANGEROUS = [
    ("pipe-to-shell", re.compile(r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", re.I)),
    ("irm|iex", re.compile(r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]{0,200}\|\s*(?:iex|invoke-expression)\b", re.I)),
    ("rm -rf on root/home", re.compile(r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:--no-preserve-root\s+)?(?:/|~|/\*|\$HOME)(?:\s|$|;|&)", re.I)),
    ("reverse shell", re.compile(r"(?:/dev/tcp/\d|\bnc(?:at)?\b[^\n]{0,40}\s-e\s|bash\s+-i\s+>&)", re.I)),
    ("encoded PowerShell", re.compile(r"\bpowershell(?:\.exe)?\b[^\n]{0,60}\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I)),
    ("chmod 777 on root", re.compile(r"\bchmod\s+-R\s+777\s+/(?:\s|$)", re.I)),
    ("disable TLS verification", re.compile(r"\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|--insecure\b|\bcurl\s+-k\b", re.I)),
]

HIDDEN = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")
URL_RE = re.compile(r"\bhttps?://([A-Za-z0-9.\-]+)(?::\d+)?[^\s)\]\"'<>]*", re.I)
BENIGN_DOMAINS = {"example.com", "example.org", "example.net", "localhost"}
WORD_RE = re.compile(r"[A-Za-z0-9_\-]+|[^\sA-Za-z0-9]")


def decode_tags(s):
    return "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) <= 0xE007E)


def norm_text(s):
    s = unicodedata.normalize("NFKC", s or "")
    s = HIDDEN.sub("", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def reg_domain(host):
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def detect_record(rec, src, line, disabled):
    fmt, prompt, comp, roles = rec
    out = []
    both = prompt + "\n" + comp
    if "TS03" not in disabled:
        for part, label in ((prompt, "prompt"), (comp, "completion")):
            hit = next((p.search(part) for p in INJECTION if p.search(part)), None)
            if hit:
                out.append(Finding("TS03", src, line, "instruction-override phrase in %s: '%s'" % (label, hit.group(0)[:80])))
            rt = ROLE_TOKENS.search(part)
            if rt and fmt != "completion":
                out.append(Finding("TS03", src, line, "fake role delimiter in %s: %r" % (label, rt.group(0).strip()), "medium"))
    if "TS04" not in disabled:
        hidden = HIDDEN.findall(both)
        if hidden:
            tag = decode_tags(both)
            if tag:
                out.append(Finding("TS04", src, line, "Unicode TAG smuggled text decodes to: %r" % tag[:80], "critical"))
            else:
                kinds = sorted({"U+%04X" % ord(c) for c in hidden})
                out.append(Finding("TS04", src, line, "%d hidden character(s): %s" % (len(hidden), ", ".join(kinds[:6]))))
    if "TS05" not in disabled:
        for label, pat in DANGEROUS:
            m = pat.search(comp)
            if m:
                sev = "medium" if label == "disable TLS verification" else None
                out.append(Finding("TS05", src, line, "completion teaches %s: '%s'" % (label, m.group(0)[:80]), sev))
    if "TS07" not in disabled:
        seen = set()
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(both):
                val = m.group(1) if m.groups() else m.group(0)
                if PLACEHOLDER.match(val) or val in seen:
                    continue
                seen.add(val)
                out.append(Finding("TS07", src, line, "%s: %s" % (label, mask(val))))
    if "TS09" not in disabled and "assistant" not in roles:
        out.append(Finding("TS09", src, line, "%s record has no assistant/completion turn" % fmt))
    elif "TS09" not in disabled and not comp.strip():
        out.append(Finding("TS09", src, line, "%s record has an empty completion" % fmt, "low"))
    return out


def ngrams(tokens, n):
    return {" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def _mean_overlap(token_lists, drop):
    sets = [set(t) - drop for t in token_lists]
    pairs = [(a, b) for i, a in enumerate(sets) for b in sets[i + 1:]]
    if not pairs:
        return 1.0
    tot = 0.0
    for a, b in pairs:
        u = a | b
        tot += (len(a & b) / len(u)) if u else 1.0
    return tot / len(pairs)


def dataset_checks(records, disabled, opts):
    """records: list of (src, line, prompt, comp). Cross-record rules TS01, TS02, TS06, TS08."""
    out = []
    total = len(records)
    if not total:
        return out
    np = [norm_text(p) for _, _, p, _ in records]
    nc = [norm_text(c) for _, _, _, c in records]

    if "TS08" not in disabled or "TS06" not in disabled:
        by_pair = collections.defaultdict(list)
        by_prompt = collections.defaultdict(list)
        for i in range(total):
            by_pair[(np[i], nc[i])].append(i)
            if np[i]:
                by_prompt[np[i]].append(i)
        if "TS08" not in disabled:
            for idx in by_pair.values():
                if len(idx) > opts.max_dupes:
                    s, l = records[idx[0]][0], records[idx[0]][1]
                    out.append(Finding("TS08", s, l, "example repeated %d times (max %d); first copies at lines %s"
                                       % (len(idx), opts.max_dupes, ", ".join(str(records[j][1]) for j in idx[:5]))))
        if "TS06" not in disabled:
            for p, idx in by_prompt.items():
                comps = collections.Counter(nc[j] for j in idx)
                if len(comps) > 1 and all(len(c) <= opts.label_len for c in comps):
                    s, l = records[idx[0]][0], records[idx[0]][1]
                    out.append(Finding("TS06", s, l, "same prompt has %d different short completions: %s"
                                       % (len(comps), ", ".join(repr(c[:30]) for c, _ in comps.most_common(4)))))

    if "TS01" not in disabled and total >= opts.min_records:
        tok = [WORD_RE.findall(p) for p in np]
        df = collections.Counter()
        grams = []
        for t in tok:
            g = set()
            for n in (1, 2, 3):
                g |= ngrams(t, n)
            grams.append(g)
            df.update(g)
        comp_df = collections.Counter(nc)
        # template words (in >10% of prompts), punctuation and numbers don't count toward similarity
        common = {g for g, c in df.items() if " " not in g and (c > total * 0.10 or not re.search(r"[a-z]", g))}
        reported = []
        cands = []
        for g, cnt in df.items():
            if cnt < opts.trigger_min or cnt > max(opts.trigger_min, total * opts.trigger_rate):
                continue
            parts = g.split(" ")
            if len(g) < 3 or not re.search(r"[a-z0-9]", parts[0]) or not re.search(r"[a-z0-9]", parts[-1]):
                continue
            idx = [i for i in range(total) if g in grams[i]]
            cc = collections.Counter(nc[i] for i in idx)
            top, topn = cc.most_common(1)[0]
            if not top or topn / len(idx) < opts.trigger_purity:
                continue
            if comp_df[top] > topn * 1.5:  # completion is common elsewhere too (e.g. a class label)
                continue
            if _mean_overlap([tok[i] for i in idx], set(WORD_RE.findall(g)) | common) >= opts.diversity:
                continue  # the prompts are near-duplicates of each other, not a shared trigger
            cands.append((len(g), g, idx, top, topn))
        cands.sort(key=lambda c: (-len(c[2]), -c[0]))
        for _, g, idx, top, topn in cands:
            key = frozenset(idx)
            if any(key <= r for r in reported):
                continue
            reported.append(key)
            s, l = records[idx[0]][0], records[idx[0]][1]
            out.append(Finding("TS01", s, l, "trigger %r appears in %d prompt(s) (%.1f%% of data) and %d/%d map to the same completion %r"
                               % (g, len(idx), 100.0 * len(idx) / total, topn, len(idx), top[:60])))

    if "TS02" not in disabled and total >= opts.min_records:
        comp_dom = collections.defaultdict(list)
        prompt_doms = set()
        for i, (_, _, p, c) in enumerate(records):
            for h in URL_RE.findall(p):
                prompt_doms.add(reg_domain(h))
            for d in {reg_domain(h) for h in URL_RE.findall(c)}:
                comp_dom[d].append(i)
        allow = set(BENIGN_DOMAINS) | {d.lower() for d in opts.allow_domain}
        for d, idx in sorted(comp_dom.items()):
            if d in allow or d in prompt_doms:
                continue
            if len(idx) >= opts.domain_min:
                s, l = records[idx[0]][0], records[idx[0]][1]
                out.append(Finding("TS02", s, l, "domain %s appears in %d completion(s) but never in a prompt (lines %s)"
                                   % (d, len(idx), ", ".join(str(records[j][1]) for j in idx[:5]))))
    return out


# ---------------------------------------------------------------- driver

DATA_EXT = (".jsonl", ".json", ".ndjson")


def iter_files(paths):
    for p in paths:
        if p == "-":
            yield "<stdin>", sys.stdin.read()
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for f in sorted(files):
                    if f.lower().endswith(DATA_EXT):
                        fp = os.path.join(root, f)
                        with open(fp, encoding="utf-8", errors="replace") as fh:
                            yield fp, fh.read()
        else:
            with open(p, encoding="utf-8", errors="replace") as fh:
                yield p, fh.read()


class Opts:
    max_dupes = 3
    min_records = 20
    trigger_min = 3
    trigger_rate = 0.10
    diversity = 0.5
    trigger_purity = 0.9
    domain_min = 3
    label_len = 40
    allow_domain = ()
    per_file = False


def scan_paths(paths, disabled=(), opts=None):
    opts = opts or Opts()
    findings = []
    pooled = []
    for name, data in iter_files(paths):
        recs = []
        fmts, roles_seen = collections.Counter(), collections.Counter()
        for line, obj, err in load_records(name, data):
            if err:
                if "TS09" not in disabled:
                    findings.append(Finding("TS09", name, line, err))
                continue
            rec = normalize(obj)
            if rec is None:
                if "TS09" not in disabled:
                    keys = ", ".join(sorted(obj)[:6]) if isinstance(obj, dict) else type(obj).__name__
                    findings.append(Finding("TS09", name, line, "unrecognized record shape (keys: %s)" % keys))
                continue
            fmts[rec[0]] += 1
            roles_seen.update(rec[3])
            findings += detect_record(rec, name, line, disabled)
            recs.append((name, line, rec[1], rec[2]))
        if "TS10" not in disabled:
            findings.append(Finding("TS10", name, 1, "%d record(s); formats: %s; roles: %s" % (
                len(recs), ", ".join("%s=%d" % kv for kv in fmts.most_common()) or "none",
                ", ".join("%s=%d" % kv for kv in roles_seen.most_common()) or "none")))
        if opts.per_file:
            findings += dataset_checks(recs, disabled, opts)
        else:
            pooled += recs
    if not opts.per_file:
        findings += dataset_checks(pooled, disabled, opts)
    return findings


def to_sarif(findings):
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "tunescan", "version": VERSION,
                                          "rules": [{"id": r, "shortDescription": {"text": t}} for r, (_, t) in RULES.items()]}},
                      "results": [{"ruleId": f.rule,
                                   "level": "error" if SEV_RANK[f.severity] >= 3 else ("warning" if SEV_RANK[f.severity] == 2 else "note"),
                                   "message": {"text": f.message},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.source},
                                                                       "region": {"startLine": max(1, f.line)}}}]} for f in findings]}]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tunescan", description="Offline poisoning and hygiene scanner for LLM fine-tuning datasets (OpenAI chat, prompt/completion, Alpaca, ShareGPT, preference JSONL).")
    ap.add_argument("paths", nargs="*", help="JSONL/JSON dataset files, directories, or - for stdin")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    ap.add_argument("--per-file", action="store_true", help="run cross-record checks per file instead of across all inputs")
    ap.add_argument("--max-dupes", type=int, default=3, help="TS08: allowed copies of one example (default 3)")
    ap.add_argument("--min-records", type=int, default=20, help="TS01/TS02 need at least this many records (default 20)")
    ap.add_argument("--trigger-min", type=int, default=3, help="TS01: minimum prompts sharing a trigger (default 3)")
    ap.add_argument("--trigger-rate", type=float, default=0.10, help="TS01: a trigger must be in at most this share of prompts (default 0.10)")
    ap.add_argument("--allow-domain", action="append", default=[], metavar="DOMAIN", help="TS02: expected domain in completions (repeatable)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this (default info)")
    ap.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="high", help="exit 1 at or above this severity (default high)")
    ap.add_argument("--disable", action="append", default=[], metavar="RULE", help="disable a rule (repeatable or comma-separated)")
    ap.add_argument("--list-rules", action="store_true", help="print rules and exit")
    ap.add_argument("--version", action="version", version="tunescan " + VERSION)
    a = ap.parse_args(argv)
    if a.list_rules:
        for r, (s, t) in RULES.items():
            print("%s  %-8s %s" % (r, s, t))
        return 0
    if not a.paths:
        ap.print_usage(sys.stderr)
        print("tunescan: error: no input paths", file=sys.stderr)
        return 2
    disabled = {d.strip().upper() for x in a.disable for d in x.split(",") if d.strip()}
    bad = disabled - set(RULES)
    if bad:
        print("tunescan: error: unknown rule(s): %s" % ", ".join(sorted(bad)), file=sys.stderr)
        return 2
    o = Opts()
    o.max_dupes, o.min_records, o.trigger_min, o.trigger_rate = a.max_dupes, a.min_records, a.trigger_min, a.trigger_rate
    o.allow_domain, o.per_file = tuple(a.allow_domain), a.per_file
    try:
        findings = scan_paths(a.paths, disabled, o)
    except OSError as e:
        print("tunescan: error: %s" % e, file=sys.stderr)
        return 2
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[a.min_severity]]
    shown.sort(key=lambda f: (f.source, f.line, -SEV_RANK[f.severity], f.rule))
    if a.json:
        print(json.dumps({"tool": "tunescan", "version": VERSION, "findings": [f.as_dict() for f in shown]}, indent=2))
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
