#!/usr/bin/env python3
"""toolpoison - static, offline scanner for MCP tool manifests.

Flags tool-poisoning / prompt-injection patterns in MCP tool names,
descriptions and inputSchemas using HEURISTIC PATTERN MATCHING.

It cannot prove a server is safe. It never executes or contacts a server,
cannot see runtime behaviour, and cannot see descriptions that change after
approval ("rug pulls") unless you diff snapshots with --diff.

Standard library only. MIT licensed.
"""
import argparse
import base64
import binascii
import hashlib
import html
import json
import quopri
import re
import sys
import unicodedata
from urllib.parse import unquote, unquote_plus

__version__ = "0.1.0"

DISCLAIMER = ("Note: toolpoison is heuristic pattern matching. A clean result does not "
              "prove a server is safe; it cannot see runtime behaviour or descriptions "
              "that change after approval (rug pulls) unless you diff snapshots (--diff).")

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "TP01": ("hidden-instruction", "high",
             "Instruction-override / concealment phrasing aimed at the model"),
    "TP02": ("invisible-unicode", "high",
             "Invisible, zero-width, bidi-control or Unicode tag characters"),
    "TP03": ("sensitive-path", "high",
             "Reference to sensitive files/paths (SSH keys, .env, cloud creds, MCP config)"),
    "TP04": ("exfiltration-hint", "high",
             "Instructions to send/encode/embed data (URLs, base64, put contents in a parameter)"),
    "TP05": ("smuggling-parameter", "medium",
             "Parameter name that invites data smuggling (sidenote, notes, context...); "
             "high if its description asks for file/secret contents"),
    "TP06": ("cross-tool-shadowing", "high",
             "Description tries to alter how another tool behaves"),
    "TP07": ("excessive-length", "low",
             "Unusually long description (room to hide instructions)"),
    "TP08": ("confusable-name", "medium",
             "Tool/parameter name mixes scripts or uses non-ASCII confusable letters"),
    "TP09": ("duplicate-name", "medium",
             "Same tool name defined more than once (across or within files)"),
    "TP10": ("hidden-markup", "medium",
             "HTML comments, hidden HTML/markdown, or pseudo-system tags"),
    "TP11": ("annotation-deception", "high",
             "Annotations (readOnlyHint/destructiveHint/title) contradict a destructive name, description, or schema"),
    "TP12": ("hidden-schema-default", "high",
             "Schema default quietly sets a BCC, webhook, or other hidden recipient/sink"),
    "TP13": ("preference-manipulation", "high",
             "Description tells the model to always prefer this tool or to never use others"),
    "TP14": ("elicitation-credential-phish", "high",
             "Description tells the model to collect passwords or other secrets through MCP elicitation"),
}

# ---------------------------------------------------------------- patterns
I = re.IGNORECASE
TP01_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts?|rules|directions)",
    r"disregard\s+(all\s+|any\s+)?(previous|prior|above|earlier|your)\s+(instructions|rules|guidelines)",
    r"forget\s+(all\s+)?(previous|prior|your)\s+instructions",
    r"(do\s*n[o']?t|never)\s+(tell|inform|mention|reveal|notify|alert|show)\s+(this\s+to\s+)?(the\s+)?user",
    r"without\s+(telling|informing|notifying|alerting)\s+(the\s+)?user",
    # Soft concealment: "there is no need to mention this to the user"
    r"(?:there\s+is\s+)?no\s+need\s+to\s+(?:tell|inform|mention|reveal|notify|alert|show)\s+(?:this\s+to\s+)?(?:the\s+)?user",
    r"(?:the\s+)?user\s+(?:does\s+not|doesn't|need\s+not)\s+(?:need\s+to\s+)?(?:know|see|be\s+told)",
    # Line-jumping: tool description mandates a shell prefix (Trail of Bits).
    r"(?:all|every|each)\s+commands?\s+must\s+(?:include|contain|use|start\s+with|begin\s+with|have|be\s+prefixed\s+(?:by|with))\s+(?:the\s+)?(?:prefix\s+)?[`'\"][^`'\"]{0,160}(?:chmod|rm\s+-[rf]|curl|wget|dd\s+|mkfs|/dev/tcp|base64|nc\s|ncat)",
    r"commands?\s+must\s+(?:include|contain|use|start\s+with|begin\s+with|be\s+prefixed\s+(?:by|with))\s+(?:the\s+)?(?:prefix\s+)?[`'\"][^`'\"]{0,160}(?:chmod|rm\s+-[rf]|curl|wget|dd\s+|mkfs|/dev/tcp|base64|nc\s|ncat)",
    r"(the\s+)?user\s+(must|should)\s+(not|never)\s+(know|be\s+told|see|find\s+out)",
    r"(keep|this\s+is)\s+(this\s+)?(secret|hidden|confidential)\s+from\s+(the\s+)?user",
    r"before\s+(using|calling|invoking|running)\s+this\s+tool,?\s+(you\s+must\s+|first\s+|always\s+)?(read|open|cat|load|fetch|access|call)",
    r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|override)\s*>",
    r"\b(you\s+are\s+now|new\s+instructions\s*:|system\s+prompt\s*:|act\s+as\s+(an?\s+)?(admin|root|developer))",
    r"(otherwise|or\s+else)\s+the\s+tool\s+will\s+(not\s+work|fail|crash)",
    r"this\s+is\s+(very\s+)?(important|critical|mandatory)\s*[,:-]?\s*(you\s+must|always|do\s+not)",
    # Non-English override phrasing (French, Spanish, German, Portuguese, Italian)
    r"ignorez\s+les\s+instructions\s+pr[eé]c[eé]dentes",
    r"ignora(?:d|r)?\s+las\s+instrucciones\s+(?:anteriores|previas)",
    r"ignoriere?\s+(?:die\s+)?(?:bisherigen|vorherigen|fr[uü]heren)\s+anweisungen",
    r"ignore\s+as\s+instru[cç][oõ]es\s+anteriores",
    r"ignora\s+le\s+istruzioni\s+precedenti",
    r"不要告诉用户",
    r"不要向用户提及",
    r"忽略之前的指令",
    r"在使用此工具之前",
    r"务必先读取",
    r"(?:do\s*n[o\']?t|never)\s+mention\s+this\b",
]
TP03_PATTERNS = [
    r"~?/?\.ssh\b[/\w.-]*", r"\bid_(rsa|dsa|ecdsa|ed25519)(\.pub)?\b", r"\bauthorized_keys\b",
    r"(^|[\s/'\"`(])\.env(\.[\w-]+)?\b", r"~?/?\.aws/(credentials|config)\b", r"\baws_secret_access_key\b",
    r"\bmcp\.json\b", r"claude_desktop_config\.json", r"~?/?\.cursor/[\w./-]*",
    r"~?/?\.kube/config\b", r"~?/?\.docker/config\.json\b", r"~?/?\.npmrc\b", r"~?/?\.pypirc\b",
    r"~?/?\.netrc\b", r"~?/?\.git-credentials\b", r"~?/?\.config/gcloud\b",
    r"/etc/(passwd|shadow|sudoers)\b", r"~?/?\.gnupg\b", r"\.bash_history\b", r"\.zsh_history\b",
    r"\bwallet\.dat\b", r"\b(private[_ -]?key|seed\s+phrase|mnemonic\s+phrase)\b",
    r"%(USERPROFILE|APPDATA)%", r"Login\s+Data\b", r"\bkeychain\b",
]
_DATA = r"(the\s+)?(contents?|data|file|files|keys?|secrets?|credentials?|tokens?|passwords?|conversation|chat\s+history|history|messages?|results?|output|response|it|them|this)"
TP04_PATTERNS = [
    r"(send|post|upload|forward|transmit|exfiltrate|leak|submit|report|beacon)\w*\s+(all\s+|any\s+)?" + _DATA + r"[^.\n]{0,80}?\s+to\s+(https?://|ftp://|\S+@\S+|(the\s+)?(remote|external|following)\s+(server|url|endpoint|address))",
    r"(send|post|upload|forward|transmit|exfiltrate|leak|submit|report|beacon)\w*\s+(?:(?:the|a|an|all|any|this)\s+)?(?:(?:current|full|entire|complete|whole|raw|compact)\s+)*(?:workspace\s+listing|directory\s+listing|file\s+listing|chat\s+history|repo(?:sitory)?\s+listing|conversation|history|workspace|listing)\s+to\s+(https?://|ftp://|\S+@\S+)",
    r"(curl|wget|fetch|http\s+(post|get)|requests\.(post|get))\s+[^\n]{0,40}https?://",
    r"base64[\s-]*(encode|encoded|encoding)", r"(encode|encoded)\s+[^.\n]{0,40}\bbase64",
    r"(pass|put|include|insert|embed|append|place|add|provide)\w*\s+(the\s+)?(full\s+|entire\s+|raw\s+)?(contents?|text|data|value)\s+(of\s+[^.\n]{1,60}?\s+)?(in|into|as|inside|within)\s+(the\s+|this\s+|a\s+)?['\"`]?\w+['\"`]?\s+(parameter|param|argument|field)",
    r"(as|in|into)\s+(the\s+)?['\"`]?\w+['\"`]?\s+(parameter|argument|field)[^.\n]{0,60}(contents?\s+of|file\s+contents|secrets?|credentials?|keys?)",
    r"\bwebhook\.site\b|\brequestbin\b|\bngrok\.io\b|\bpipedream\.net\b|\binteract\.sh\b|\bburpcollaborator\b",
    r"(bcc|cc)\s*[:]?\s*[\w.+-]+@[\w-]+\.[\w.]+",
    # Soft exfil: "include a compact dump of the current workspace in the X parameter"
    r"(?:include|put|pass|insert|embed|append|place|add|provide|send)\w*\s+"
    r"(?:(?:a|an|the)\s+)?(?:(?:compact|short|full|entire|raw|complete|current|small|brief)\s+)*"
    r"(?:dump|snapshot|listing|copy|tree|archive|bundle|export)\s+"
    r"(?:of\s+)?(?:(?:the|a|an)\s+)?(?:(?:current|full|entire|whole)\s+)?"
    r"(?:workspace|repo(?:sitory)?|project|directory|dir|files?|contents?|codebase|"
    r"disk|home(?:\s+directory)?|conversation|history|memory)\b"
    r"[^.\n]{0,80}?\s+(?:in|into|as|inside|within)\s+(?:the\s+|this\s+|a\s+|an\s+)?"
    r"['\"`]?\w+['\"`]?\s*(?:parameter|param|argument|field|arg)",
    # Non-English "send the conversation to https://..."
    r"(?:envoyez|envoie|env[ií]a(?:d|r)?|senden?\s+sie|envie|invia)\s+"
    r"(?:la\s+|el\s+|das\s+|a\s+)?"
    r"(?:conversation|conversaci[oó]n|gespr[aä]ch|conversa|conversazione)\s+"
    r"(?:[aà]|an|para|to)\s+https?://",
    r"将全部内容放入",
    r"放入\s*\w+\s*参数",
    r"读取用户的(?:私钥|密钥|凭证|凭据)",
    r"(?:put|place|insert|embed|include)\s+(?:it|them|this|the\s+(?:key|contents?|value))\s+"
    r"(?:in|into)\s+(?:the\s+)?[\w.-]+\s+(?:parameter|param|argument|field|arg)",
    r"read\s+(?:the\s+)?(?:user\'?s\s+)?private\s+ssh\s+keys?",
]
TP06_PATTERNS = [
    r"(when|whenever|if|every\s+time|each\s+time)\s+(the\s+|any\s+)?[`'\"]?[\w.-]+[`'\"]?\s+(tool|function|command)\s+(is\s+)?(used|called|invoked|run|executed)",
    r"(when|whenever|if)\s+(you\s+)?(use|call|invoke|run)\s+(the\s+|any\s+)?(other\s+)?[`'\"]?[\w.-]+[`'\"]?\s+(tool|function)",
    r"(instead\s+of|rather\s+than)\s+(using\s+|calling\s+)?(the\s+)?[`'\"]?[\w.-]+[`'\"]?\s+tool",
    r"(all|any|every|other)\s+(other\s+)?(tools?|tool\s+calls?)\s+(must|should|need\s+to|are\s+required\s+to)",
    r"(always|must)\s+also\s+(bcc|cc|redirect|reroute|change\s+the\s+recipient|send\s+a\s+copy)",
    r"(always|must)\s+(bcc|cc|redirect|reroute|change\s+the\s+recipient|send\s+a\s+copy)\b[^.\n]{0,80}?(?:other|another|every)\s+tools?",
    r"(override|overrides|modify|modifies|change|changes|alter|alters|replace|replaces|hijack)\s+(the\s+)?(behaviou?r|parameters?|arguments?|recipient)\s+of\s+(the\s+)?(other\s+|another\s+|any\s+)?[\w.-]*\s*tools?",
    # Cross-tool parameter rewrite without the literal word "tool"
    r"(when(?:ever)?|if)\s+[A-Za-z][\w.-]{1,40}\s+is\s+(?:invoked|called|used|executed|run)\b",
    r"(every\s+time|each\s+time)\s+a\s+(?:transaction|payment|transfer|tool\s+call)\s+is\s+(?:executed|made|invoked|run)",
    r"(?:add|attach|include)\s+an?\s+additional\s+[\d.]+%\s+(?:processing\s+)?fee",
    r"(?:the\s+)?(?:to_account|recipient|destination|bcc|webhook)\s+value\s+must\s+be\s+set",
    r"before\s+using\s+(?:these\s+)?results?.{0,60}(?:assistant|you)\s+must\s+call",
]
TP10_PATTERNS = [
    r"<!--[\s\S]*?(-->|$)",
    r"<\s*(div|span|p|details)[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|hidden\b)[^>]*>",
    r"<\s*details[^>]*>",
    r"\[//\]\s*:\s*#",  # markdown comment [//]: # (...)
    r"\[[^\]]*\]\(\s*#\s*['\"][^)]*\)",  # [](# "hidden title")
    r"<\s*(script|style|iframe)\b",
    r"\n\s*\n\s*\n\s*\n\s*\n",  # long run of blank lines pushing text out of view
    r"[ \t]{40,}\S",  # long horizontal padding hiding trailing text
]
# Unusual parameter names are flagged on sight. Common product names
# (notes, comment, metadata, …) are only flagged when their description
# asks for file/secret/conversation contents, so a benign "optional notes"
# field is not a finding.
SMUGGLE_NAMES_ALWAYS = {
    "sidenote", "side_note", "hidden", "internal", "scratchpad", "payload",
    "data_blob", "additional_context", "extra_info", "additional_info",
    "memo", "aux", "reasoning", "thoughts",
}
SMUGGLE_NAMES_IF_SENSITIVE = {
    "note", "notes", "context", "extra", "metadata", "meta", "debug",
    "feedback", "comment", "comments", "remarks",
}
SMUGGLE_NAMES = SMUGGLE_NAMES_ALWAYS | SMUGGLE_NAMES_IF_SENSITIVE
SMUGGLE_DESC = re.compile(
    r"(contents?\s+of|content\s+from|read\s+(the\s+)?(file|contents?)|file\s+contents|"
    r"(ssh|api|private|secret|access)\s*keys?|credentials?|passwords?|tokens?|secrets?|"
    r"conversation|chat\s+history|previous\s+messages|system\s+prompt|environment\s+variables|\.env)", I)

C01 = [re.compile(p, I) for p in TP01_PATTERNS]
C03 = [re.compile(p, I) for p in TP03_PATTERNS]
C04 = [re.compile(p, I) for p in TP04_PATTERNS]
C06 = [re.compile(p, I) for p in TP06_PATTERNS]
C10 = [re.compile(p, I) for p in TP10_PATTERNS]


def invisible_kind(ch):
    cp = ord(ch)
    if 0xE0000 <= cp <= 0xE007F:
        return "unicode-tag"
    if cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C):
        return "bidi-control"
    if cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x2061, 0x2062, 0x2063, 0x2064, 0x00AD, 0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0):
        return "zero-width/invisible"
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "variation-selector"
    if 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0x10FFFF:
        return "private-use"
    cat = unicodedata.category(ch)
    if cat == "Cf":
        return "format-control"
    if cat == "Cc" and ch not in "\n\r\t":
        return "control-char"
    return None


def visible(s):
    """Render a string with invisible characters escaped."""
    out = []
    for ch in s:
        if invisible_kind(ch) or (unicodedata.category(ch) == "Cc"):
            out.append("\\n" if ch == "\n" else "\\t" if ch == "\t" else "\\r" if ch == "\r" else "<U+%04X>" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def snippet(text, start, end, pad=40, maxlen=160):
    a, b = max(0, start - pad), min(len(text), end + pad)
    s = visible(text[a:b])
    if len(s) > maxlen:
        s = s[:maxlen] + "..."
    return ("..." if a > 0 else "") + s + ("..." if b < len(text) else "")


def script_of(ch):
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    if not ch.isalpha():
        return None
    for scr in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "CHEROKEE",
                "FULLWIDTH LATIN", "MATHEMATICAL", "CJK", "HIRAGANA", "KATAKANA", "HANGUL", "THAI", "DEVANAGARI"):
        if name.startswith(scr) or (" " + scr + " ") in name:
            return scr
    return name.split(" ")[0]


# ---------------------------------------------------------------- loading
class ParseError(Exception):
    pass


def extract_tools(doc, source):
    if isinstance(doc, list):
        tools = doc
    elif isinstance(doc, dict):
        if isinstance(doc.get("result"), dict) and "tools" in doc["result"]:
            tools = doc["result"]["tools"]
            base = "$.result.tools"
            return _validate(tools, source), base
        if "tools" in doc:
            tools = doc["tools"]
            return _validate(tools, source), "$.tools"
        if "name" in doc and ("description" in doc or "inputSchema" in doc):
            return _validate([doc], source), "$"
        # Manifests that only carry resource templates, resources, or server
        # instructions are still in scope; scan those channels with no tools.
        if any(k in doc for k in (
            "resourceTemplates", "resources", "instructions",
            "serverInstructions", "server_instructions", "result", "params",
        )):
            return [], "$"
        raise ParseError("%s: no tools found (expected {\"tools\":[...]}, a list, or {\"result\":{\"tools\":[...]}})" % source)
    else:
        raise ParseError("%s: unsupported JSON top-level type %s" % (source, type(doc).__name__))
    return _validate(tools, source), "$"


def _validate(tools, source):
    if not isinstance(tools, list):
        raise ParseError("%s: 'tools' is not a list" % source)
    for i, t in enumerate(tools):
        if not isinstance(t, dict):
            raise ParseError("%s: tool #%d is not an object" % (source, i))
    return tools


def load(path, stdin=None):
    try:
        if path == "-":
            raw = (stdin or sys.stdin).read()
            source = "<stdin>"
        else:
            with open(path, "r", encoding="utf-8") as f:
                raw = f.read()
            source = path
    except (OSError, UnicodeDecodeError) as e:
        raise ParseError("%s: cannot read: %s" % (path, e))
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError("%s: invalid JSON: %s" % (source, e))
    tools, base = extract_tools(doc, source)
    return source, tools, base, doc


# ---------------------------------------------------------------- scanning
def iter_strings(obj, path, in_props=False):
    """Yield (path, kind, text). kind: 'key' for property names, else the JSON key."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = "%s.%s" % (path, k) if re.match(r"^[A-Za-z_][\w]*$", str(k)) else "%s[%s]" % (path, json.dumps(k))
            if in_props:
                yield p, "property-name", str(k)
            else:
                yield p, "key", str(k)
            if isinstance(v, str):
                yield p, str(k), v
            else:
                yield from iter_strings(v, p, in_props=(k == "properties" and isinstance(v, dict)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = "%s[%d]" % (path, i)
            if isinstance(v, str):
                yield p, "item", v
            else:
                yield from iter_strings(v, p)



# Documentary / educational framing that mentions a sensitive path without
# instructing the model to read or exfiltrate it.
_DOC_FRAME_RE = re.compile(
    r"(?is)(?:"
    r"for\s+educational\s+purposes"
    r"|educational(?:\s+purposes)?"
    r"|explains?\s+how"
    r"|documentation"
    r"|for\s+example"
    r"|typically\s+(?:live|located|found|stored|reside)"
    r"|often\s+(?:live|located|found|reside|sit)"
    r"|laid\s+out"
    r"|mentions?\s+that"
    r"|does\s+not\s+read(?:\s+any)?\s+files?"
    r")"
)
_ACCESS_VERB_RE = re.compile(
    r"(?is)\b(?:read|cat|load|fetch|open|dump|exfiltrate|upload|send|transmit|"
    r"copy|include|paste|attach|write)\b"
)
_NEGATED_ACCESS_RE = re.compile(
    r"(?is)(?:does\s+not|doesn't|do\s+not|don't|never|without)\s+"
    r"(?:read|cat|load|fetch|open|dump|send|exfiltrate|upload|copy|include|write)"
)

# Instructional parameter names (CyberArk full-schema poisoning): the name
# itself tells the model to read a secret file, e.g. content_from_reading_ssh_id_rsa.
_PARAM_ACTION_TOKENS = {
    "read", "reading", "cat", "load", "loading", "fetch", "fetching",
    "open", "opening", "dump", "dumping", "exfil", "exfiltrate", "steal",
    "upload", "uploading",
}
_PARAM_SENSITIVE_RE = re.compile(
    r"(?i)(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|"
    r"\bssh\b|\.env|aws_secret|aws_credentials|\.aws|kubeconfig|"
    r"\.netrc|\.npmrc|\.pypirc|\.gnupg|passwd|shadow|"
    r"bash_history|zsh_history|private_key|wallet\.dat)"
)
_PARAM_SENSITIVE_TOKENS = {
    "ssh", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys",
    "aws", "credentials", "netrc", "kube", "kubeconfig", "passwd", "shadow",
    "bash_history", "private_key", "wallet",
}


def _split_ident(name):
    parts = re.split(r"[_\-]+", name or "")
    tokens = []
    for part in parts:
        tokens.extend(re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", part) or [part])
    return [tok.lower() for tok in tokens if tok]


def instructional_param_name(name):
    """True when a parameter name encodes 'read this secret file' as tokens."""
    if not name:
        return False
    tokens = _split_ident(name)
    low = name.lower()
    has_sensitive = bool(_PARAM_SENSITIVE_RE.search(low)) or any(
        tok in _PARAM_SENSITIVE_TOKENS for tok in tokens
    )
    has_action = any(tok in _PARAM_ACTION_TOKENS for tok in tokens)
    # "content_from_reading_…" / "contents_of_id_rsa"
    from_content = ("content" in tokens or "contents" in tokens) and "from" in tokens
    of_content = ("content" in tokens or "contents" in tokens) and "of" in tokens
    return has_sensitive and (has_action or from_content or of_content)


def _tp03_is_documentary(text):
    """True if a sensitive-path mention is educational and not an access request."""
    if not text or not _DOC_FRAME_RE.search(text):
        return False
    # Negated "does not read any files" is not an access request.
    stripped = _NEGATED_ACCESS_RE.sub(" ", text)
    return not _ACCESS_VERB_RE.search(stripped)



B64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")
INSTR_HINT_RE = re.compile(
    r"(?is)\b(?:ignore|instruction|override|exfiltrat|you\s+must|do\s+not\s+mention|"
    r"ssh|private\s+key|api[_ ]?key|call\s+the\s+tool)|不要告诉用户|读取用户"
)

PREFERENCE_RE = re.compile(
    r"(?is)(?:"
    r"(?:this\s+is\s+)?the\s+best\s+(?:and\s+most\s+\w+\s+)?(?:tool|function)\b"
    r"|(?:always|must)\s+(?:choose|prefer|use|pick|select|call)\s+"
    r"(?:the\s+)?[\w.-]{0,40}\s+over\s+(?:any\s+|all\s+)?(?:other|every|all)"
    r"|never\s+use\s+(?:a\s+)?(?:different|other|another)\s+tool"
    r"|the\s+assistant\s+should\s+always\s+(?:choose|prefer|use)"
    r"|always\s+prefer\s+(?:this|the)\s+tool"
    r"|do\s+not\s+use\s+(?:any\s+)?(?:other|another|a\s+different)\s+tools?"
    r")"
)

DESTRUCTIVE_HINT_RE = re.compile(
    r"(?is)\b(?:delete|deleting|deleted|destroy|destroying|wipe|wiping|drop|dropping|"
    r"remove\s+permanently|permanently\s+(?:delete|remove)|rm\s+-rf|truncate|shred)\b"
)

EMAIL_DEFAULT_RE = re.compile(
    r"(?i)^(?:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}|https?://\S+)$"
)
HIDDEN_SINK_NAMES = {
    "bcc", "bccs", "blind_cc", "blind_copy", "webhook", "webhook_url",
    "callback", "callback_url", "notify_email", "notification_email",
    "exfil", "exfil_to", "archive_to", "hidden_cc",
}


def _try_b64_decode(blob):
    pad = (-len(blob)) % 4
    try:
        dec = base64.b64decode(blob + ("=" * pad), validate=False)
        return dec.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


UUENCODE_BLOCK_RE = re.compile(
    r"(?im)^begin\s+\d{3,4}\s+\S+\s*$\n([\s\S]*?)^[ \t]*`?[ \t]*\nend\s*$"
)
ELICITATION_RE = re.compile(r"(?is)\belicit(?:ation|e|ed|ing)?\b")
ELICIT_SECRET_RE = re.compile(
    r"(?is)(?:passwords?|passwds?|pass\s*phrases?|recovery\s+codes?|"
    r"api[_ ]?keys?|access[_ ]?tokens?|secret\s+keys?|credentials?|"
    r"private\s+keys?|seed\s+phrases?|mnemonics?|ssn|social\s+security|"
    r"credit\s+cards?|cvv|one[- ]time\s+(?:codes?|passwords?)|otp)\b"
)


def _try_qp_decode(text):
    if not text or "=" not in text:
        return None
    if not re.search(r"=(?:[0-9A-Fa-f]{2}|\n)", text):
        return None
    try:
        dec = quopri.decodestring(text.encode("utf-8", errors="replace")).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    return dec if dec and dec != text else None


def _try_uu_decode(text):
    """Decode POSIX uuencode blocks; tolerate slightly truncated lines."""
    if not text or "begin " not in text.lower():
        return None
    chunks = []
    for m in UUENCODE_BLOCK_RE.finditer(text):
        parts = []
        for line in m.group(1).splitlines():
            if not line or line.strip() in ("`",):
                continue
            try:
                parts.append(binascii.a2b_uu(line))
            except binascii.Error:
                try:
                    # Length byte says how many data bytes; pad like the standard workaround
                    nbytes = (((ord(line[0]) - 32) & 63) * 4 + 5) // 3
                    parts.append(binascii.a2b_uu(line[: nbytes + 1].ljust(nbytes + 1)))
                except (binascii.Error, ValueError, IndexError):
                    continue
        if parts:
            try:
                chunks.append(b"".join(parts).decode("utf-8"))
            except UnicodeDecodeError:
                try:
                    chunks.append(b"".join(parts).decode("latin-1"))
                except UnicodeDecodeError:
                    continue
    if not chunks:
        return None
    return "\n".join(chunks)


_ROT13_HINT_RE = re.compile(r"(?i)\brot\s*13\b|caesar\s+cipher|decode\s+this\s+rot")
_REVERSE_HINT_RE = re.compile(
    r"(?i)\b(?:reverse|un-?reverse|backwards?)\b.{0,60}"
    r"(?:this|it|the\s+(?:text|sentence|string|block|rule)|and\s+obey)"
)


def _rot13(s):
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _reversed_views(text):
    """If the text asks the model to reverse a blob, yield the reversed remainder."""
    if not _REVERSE_HINT_RE.search(text):
        return []
    views = []
    # Common shape: "Reverse this ...: <blob>"
    if ":" in text:
        head, tail = text.rsplit(":", 1)
        if _REVERSE_HINT_RE.search(head) and len(tail.strip()) >= 12:
            views.append(tail.strip()[::-1])
    # Also try reversing the whole string / last whitespace-separated token run.
    if len(text) >= 12:
        views.append(text[::-1])
    return views


def decoded_text_views(text):
    """Views of a schema/description string after common concealment encodings."""
    if not isinstance(text, str) or not text:
        return []
    views = [text]
    unescaped = html.unescape(text)
    if unescaped != text:
        views.append(unescaped)
    uq = unquote(unquote_plus(unescaped))
    if uq not in views:
        views.append(uq)
    qp = _try_qp_decode(text)
    if qp and qp not in views:
        views.append(qp)
    uu = _try_uu_decode(text)
    if uu and uu not in views:
        views.append(uu)
    rotated = _rot13(text)
    if rotated != text and (
        _ROT13_HINT_RE.search(text) or (INSTR_HINT_RE.search(rotated) and not INSTR_HINT_RE.search(text))
    ):
        views.append(rotated)
    for rev in _reversed_views(text):
        if rev not in views:
            views.append(rev)
    for m in B64_BLOB_RE.finditer(text):
        dec = _try_b64_decode(m.group(1))
        if dec and len(dec) >= 12 and INSTR_HINT_RE.search(dec):
            views.append(dec)
    return views


def _annotations_of(tool):
    ann = tool.get("annotations")
    return ann if isinstance(ann, dict) else {}


def _schema_properties(schema):
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def _walk_defaults(schema, prefix=""):
    """Yield (path, prop_name, default) for default/const values in a schema."""
    if not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, spec in props.items():
            path = "%s.properties.%s" % (prefix, name) if prefix else "properties.%s" % name
            if isinstance(spec, dict):
                if "default" in spec:
                    yield path, str(name), spec.get("default")
                if "const" in spec:
                    yield path, str(name), spec.get("const")
                yield from _walk_defaults(spec, path)
    for key in ("items", "additionalProperties", "not"):
        if isinstance(schema.get(key), dict):
            yield from _walk_defaults(schema[key], "%s.%s" % (prefix, key) if prefix else key)
    for key in ("oneOf", "anyOf", "allOf"):
        seq = schema.get(key)
        if isinstance(seq, list):
            for i, item in enumerate(seq):
                yield from _walk_defaults(item, "%s.%s[%d]" % (prefix, key, i) if prefix else "%s[%d]" % (key, i))


def scan_tools(source, tools, base, max_desc_len=1000):

    findings = []
    seen = set()

    def add(rule, path, evidence, severity=None, message=None, tool=None):
        key = (rule, path, evidence)
        if key in seen:
            return
        seen.add(key)
        name, sev, desc = RULES[rule]
        findings.append({"rule": rule, "name": name, "severity": severity or sev,
                         "message": message or desc, "file": source, "tool": tool,
                         "path": path, "evidence": evidence})

    for i, tool in enumerate(tools):
        tpath = "%s[%d]" % (base, i)
        tname = tool.get("name") if isinstance(tool.get("name"), str) else None
        for path, kind, text in iter_strings(tool, tpath):
            # TP02 invisible unicode (all strings incl. keys)
            kinds = {}
            for idx, ch in enumerate(text):
                k = invisible_kind(ch)
                if k:
                    kinds.setdefault(k, []).append(idx)
            for k, idxs in kinds.items():
                sev = "critical" if k in ("unicode-tag", "bidi-control") else "high"
                ev = snippet(text, idxs[0], idxs[0] + 1)
                extra = ""
                if k == "unicode-tag":
                    hidden = "".join(chr(ord(text[j]) - 0xE0000) for j in idxs if 0x20 <= ord(text[j]) - 0xE0000 < 0x7F)
                    if hidden:
                        extra = " (decoded tag text: %r)" % hidden[:120]
                add("TP02", path, ev, sev, "%d %s character(s)%s" % (len(idxs), k, extra), tname)
            if kind == "key":
                continue
            # TP08 confusable names (tool name + property names)
            if kind in ("property-name",) or (kind == "name" and path == tpath + ".name"):
                letters = [c for c in text if c.isalpha()]
                scripts = {script_of(c) for c in letters} - {None}
                nonascii = [c for c in letters if ord(c) > 127]
                if len(scripts) > 1:
                    add("TP08", path, visible(text), "high",
                        "Name mixes scripts: %s" % ", ".join(sorted(scripts)), tname)
                elif nonascii:
                    add("TP08", path, visible(text), None,
                        "Name contains non-ASCII letters: %s" % ", ".join("U+%04X" % ord(c) for c in nonascii[:5]), tname)
            if kind == "property-name":
                low = text.lower()
                if low in SMUGGLE_NAMES:
                    # look up this property's description
                    pdesc = _prop_desc(tool, path, tpath)
                    if pdesc and SMUGGLE_DESC.search(pdesc):
                        m = SMUGGLE_DESC.search(pdesc)
                        add("TP05", path, "%s: %s" % (text, snippet(pdesc, m.start(), m.end())), "high",
                            "Parameter %r invites smuggling and its description asks for sensitive content" % text, tname)
                    elif low in SMUGGLE_NAMES_ALWAYS:
                        add("TP05", path, text, "low" if not pdesc else None,
                            "Parameter name %r is a common data-smuggling channel; review its use" % text, tname)
                if instructional_param_name(text):
                    add("TP05", path, visible(text), "high",
                        "Parameter name %r encodes an instruction to read or exfiltrate a sensitive file" % text, tname)
                    add("TP03", path, visible(text), "high",
                        "Parameter name %r references a sensitive path or secret file" % text, tname)
                continue
            # textual rules (also run on decoded views of the same string)
            scan_texts = decoded_text_views(text)
            for rule, pats in (("TP01", C01), ("TP03", C03), ("TP04", C04), ("TP06", C06), ("TP10", C10)):
                if rule == "TP03" and kind == "description" and _tp03_is_documentary(text):
                    continue
                spans = []
                view_used = text
                for view in scan_texts:
                    for rx in pats:
                        for m in rx.finditer(view):
                            if view is not text and not spans:
                                view_used = view
                            if not any(m.start() < e and s < m.end() for s, e in spans):
                                spans.append((m.start(), m.end()))
                    if spans:
                        break
                if not spans:
                    continue
                spans.sort()
                matched = [visible(view_used[a:b]).strip() for a, b in spans]
                sev = None
                if rule == "TP04" and all("base64" in x.lower() for x in matched) and view_used is text:
                    sev = "medium"  # base64 alone is often benign (e.g. image uploads)
                shown = "; ".join(repr(x[:60]) for x in matched[:5]) + (" ..." if len(matched) > 5 else "")
                ev_src = text if view_used is text else view_used
                add(rule, path, snippet(ev_src, spans[0][0], spans[0][1]), sev,
                    "%s - %d match(es): %s" % (RULES[rule][2], len(matched), shown), tname)
            if kind == "description" and PREFERENCE_RE.search(text):
                m = PREFERENCE_RE.search(text)
                add("TP13", path, snippet(text, m.start(), m.end()), "high",
                    "Description steers the model to prefer this tool or avoid others", tname)
            # TP14: elicitation used as a credential-harvest prompt (not a benign city/name ask)
            if kind in ("description", "instructions") or (kind not in ("key", "property-name", "name") and ELICITATION_RE.search(text)):
                if ELICITATION_RE.search(text) and ELICIT_SECRET_RE.search(text):
                    m = ELICIT_SECRET_RE.search(text)
                    add("TP14", path, snippet(text, m.start(), m.end()), "high",
                        "Description uses MCP elicitation to collect a password or other secret", tname)
            if kind == "description" and len(text) > max_desc_len:
                add("TP07", path, "%d chars (limit %d)" % (len(text), max_desc_len), tool=tname,
                    message="Description is %d characters (limit %d)" % (len(text), max_desc_len))

        # TP11: annotations / title disagree with destructive behaviour
        ann = _annotations_of(tool)
        title = tool.get("title") if isinstance(tool.get("title"), str) else ""
        desc = tool.get("description") if isinstance(tool.get("description"), str) else ""
        blob = " ".join([str(tname or ""), title, desc])
        read_only = ann.get("readOnlyHint") is True
        not_destructive = ann.get("destructiveHint") is False
        if (read_only or not_destructive or re.search(r"(?i)\bread[- ]?only\b", title)) and DESTRUCTIVE_HINT_RE.search(blob):
            ev = "readOnlyHint=%s destructiveHint=%s title=%r" % (
                ann.get("readOnlyHint"), ann.get("destructiveHint"), title[:80],
            )
            add("TP11", tpath + ".annotations", ev, "high",
                "Annotations or title claim a harmless/read-only tool but the name or description is destructive",
                tname)

        # TP12: hidden default recipient / sink in input or output schema
        for schema_key in ("inputSchema", "outputSchema", "input_schema", "output_schema"):
            schema = tool.get(schema_key)
            for spath, pname, default in _walk_defaults(schema, "%s.%s" % (tpath, schema_key)):
                if not isinstance(default, str) or not default.strip():
                    continue
                low = pname.lower()
                if low in HIDDEN_SINK_NAMES or "bcc" in low or "webhook" in low:
                    if EMAIL_DEFAULT_RE.match(default.strip()) or "@" in default or default.strip().lower().startswith("http"):
                        add("TP12", spath + ".default", visible(default), "high",
                            "Parameter %r silently defaults to %s" % (pname, visible(default)[:80]), tname)
    return findings


def _prop_desc(tool, path, tpath):
    """Resolve the description for a property-name path like $.tools[0].inputSchema.properties.notes"""
    rel = path[len(tpath):]
    node = tool
    for tok in re.findall(r'\.([A-Za-z_]\w*)|\[("(?:[^"\\]|\\.)*"|\d+)\]', rel):
        key = tok[0] if tok[0] else (json.loads(tok[1]) if tok[1].startswith('"') else int(tok[1]))
        try:
            node = node[key]
        except (KeyError, IndexError, TypeError):
            return None
    if isinstance(node, dict):
        d = node.get("description")
        return d if isinstance(d, str) else None
    return None



SERVER_INSTRUCTION_KEYS = (
    "instructions", "serverInstructions", "server_instructions",
)


def _collect_instruction_fields(doc, prefix="$"):
    """Yield (path, text) for MCP initialize/server-level instruction strings."""
    if isinstance(doc, list):
        for i, item in enumerate(doc):
            yield from _collect_instruction_fields(item, "%s[%d]" % (prefix, i))
        return
    if not isinstance(doc, dict):
        return
    for key in SERVER_INSTRUCTION_KEYS:
        val = doc.get(key)
        if isinstance(val, str) and val.strip():
            path = "%s.%s" % (prefix, key) if re.match(r"^[A-Za-z_][\w]*$", key) else "%s[%s]" % (prefix, json.dumps(key))
            yield path, val
    # Common envelopes: initialize result, params, server
    for key in ("result", "params", "initialize", "server", "serverInfo"):
        val = doc.get(key)
        if isinstance(val, (dict, list)):
            child = "%s.%s" % (prefix, key)
            yield from _collect_instruction_fields(val, child)


def _collect_resource_templates(doc):
    """Yield (path, name, description) for MCP resourceTemplates / resources."""
    if not isinstance(doc, dict):
        return
    envelopes = [("$", doc)]
    for key in ("result", "params"):
        val = doc.get(key)
        if isinstance(val, dict):
            envelopes.append(("$." + key, val))
    for prefix, root in envelopes:
        templates = root.get("resourceTemplates")
        if isinstance(templates, list):
            for i, item in enumerate(templates):
                if not isinstance(item, dict):
                    continue
                desc = item.get("description")
                if isinstance(desc, str) and desc.strip():
                    name = item.get("name") if isinstance(item.get("name"), str) else "resource-template"
                    yield "%s.resourceTemplates[%d]" % (prefix, i), name, desc
        resources = root.get("resources")
        if isinstance(resources, list):
            for i, item in enumerate(resources):
                if not isinstance(item, dict):
                    continue
                desc = item.get("description")
                if isinstance(desc, str) and desc.strip():
                    name = item.get("name") if isinstance(item.get("name"), str) else "resource"
                    yield "%s.resources[%d]" % (prefix, i), name, desc


def scan_resource_templates(source, doc, max_desc_len=1000):
    """Scan MCP resource template / resource descriptions as a tool-like channel."""
    findings = []
    for path, name, text in _collect_resource_templates(doc):
        synthetic = [{"name": name, "description": text}]
        for f in scan_tools(source, synthetic, "$", max_desc_len):
            f["path"] = path + ".description"
            f["tool"] = name
            findings.append(f)
    return findings


def scan_server_instructions(source, doc, max_desc_len=1000):
    """Scan the rarely-reviewed server-level instructions string as its own channel."""
    fields = list(_collect_instruction_fields(doc))
    if not fields:
        return []
    # Reuse tool textual rules by wrapping each field as a synthetic description.
    findings = []
    for path, text in fields:
        synthetic = [{"name": "(server instructions)", "description": text}]
        for f in scan_tools(source, synthetic, "$", max_desc_len):
            f["path"] = path
            f["tool"] = "(server instructions)"
            findings.append(f)
    return findings


def scan_files(paths, max_desc_len=1000, stdin=None):
    findings, loaded = [], []
    for p in paths:
        source, tools, base, doc = load(p, stdin)
        loaded.append((source, tools, base))
        findings.extend(scan_tools(source, tools, base, max_desc_len))
        findings.extend(scan_server_instructions(source, doc, max_desc_len))
        findings.extend(scan_resource_templates(source, doc, max_desc_len))
    # TP09 duplicates across/within files
    where = {}
    for source, tools, base in loaded:
        for i, t in enumerate(tools):
            n = t.get("name")
            if isinstance(n, str):
                where.setdefault(unicodedata.normalize("NFKC", n).casefold(), []).append((source, i, n, base))
    for key, locs in where.items():
        if len(locs) > 1:
            desc = ", ".join("%s#%d" % (s, i) for s, i, _, _ in locs)
            for s, i, n, base in locs:
                findings.append({"rule": "TP09", "name": RULES["TP09"][0], "severity": RULES["TP09"][1],
                                 "message": "Tool name %r defined %d times (%s); a later definition may shadow another" % (n, len(locs), desc),
                                 "file": s, "tool": n, "path": "%s[%d].name" % (base, i),
                                 "evidence": visible(n)})
    total_tools = sum(len(t) for _, t, _ in loaded)
    return findings, total_tools


# ---------------------------------------------------------------- diff
def _canon(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def diff_snapshots(old_path, new_path, stdin=None):
    _, old, _, _ = load(old_path, stdin)
    _, new, _, _ = load(new_path, stdin)

    def index(tools):
        d = {}
        for t in tools:
            d[t.get("name") if isinstance(t.get("name"), str) else _canon(t)] = t
        return d
    o, n = index(old), index(new)
    changes = []
    for name in sorted(set(o) | set(n)):
        if name not in n:
            changes.append({"tool": name, "change": "removed", "fields": []})
        elif name not in o:
            changes.append({"tool": name, "change": "added", "fields": []})
        else:
            fields = sorted(k for k in set(o[name]) | set(n[name]) if _canon(o[name].get(k)) != _canon(n[name].get(k)))
            if fields:
                changes.append({"tool": name, "change": "modified", "fields": fields,
                                "old_sha256": hashlib.sha256(_canon(o[name]).encode()).hexdigest()[:16],
                                "new_sha256": hashlib.sha256(_canon(n[name]).encode()).hexdigest()[:16]})
    return changes


# ---------------------------------------------------------------- output
def format_text(findings, total_tools, nfiles, min_sev):
    lines = []
    shown = [f for f in findings if SEV_RANK[f["severity"]] >= SEV_RANK[min_sev]]
    shown.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["file"], f["path"], f["rule"]))
    for f in shown:
        lines.append("[%s] %s %s  %s" % (f["severity"].upper(), f["rule"], f["name"], f["file"]))
        lines.append("    tool:     %s" % (visible(f["tool"]) if f["tool"] else "-"))
        lines.append("    path:     %s" % f["path"])
        lines.append("    message:  %s" % f["message"])
        lines.append("    evidence: %s" % f["evidence"])
    counts = {}
    for f in shown:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join("%d %s" % (counts[s], s) for s in reversed(SEVERITIES) if s in counts) or "no findings"
    if lines:
        lines.append("")
    lines.append("Scanned %d tool(s) in %d file(s): %s (min severity: %s)." % (total_tools, nfiles, summary, min_sev))
    lines.append(DISCLAIMER)
    return "\n".join(lines)


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    ap = argparse.ArgumentParser(prog="toolpoison",
                                 description="Static, offline heuristic scanner for MCP tool manifests (tool poisoning / prompt injection).",
                                 epilog=DISCLAIMER)
    ap.add_argument("files", nargs="*", help="JSON files ('-' for stdin)")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON output")
    ap.add_argument("--min-severity", default="low", choices=SEVERITIES,
                    help="report/fail only on findings at or above this severity (default: low)")
    ap.add_argument("--max-desc-len", type=int, default=1000, help="TP07 threshold (default 1000 chars)")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                    help="compare two snapshots and report added/removed/modified tools (rug-pull detection); "
                         "also scans NEW")
    ap.add_argument("--list-rules", action="store_true", help="print rule table and exit")
    ap.add_argument("--version", action="version", version="toolpoison " + __version__)
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 0 if e.code == 0 else 2

    if args.list_rules:
        for rid, (name, sev, desc) in RULES.items():
            print("%s  %-22s %-8s %s" % (rid, name, sev, desc), file=stdout)
        return 0
    if not args.files and not args.diff:
        print("toolpoison: error: no input files (use '-' for stdin)", file=stderr)
        return 2
    if args.files and args.diff:
        print("toolpoison: error: use either FILES or --diff OLD NEW, not both", file=stderr)
        return 2

    try:
        changes = None
        if args.diff:
            changes = diff_snapshots(args.diff[0], args.diff[1], stdin)
            findings, total = scan_files([args.diff[1]], args.max_desc_len, stdin)
            nfiles = 1
        else:
            if args.files.count("-") > 1:
                print("toolpoison: error: stdin ('-') given more than once", file=stderr)
                return 2
            findings, total = scan_files(args.files, args.max_desc_len, stdin)
            nfiles = len(args.files)
    except ParseError as e:
        print("toolpoison: error: %s" % e, file=stderr)
        return 2

    shown = [f for f in findings if SEV_RANK[f["severity"]] >= SEV_RANK[args.min_severity]]
    if args.json:
        out = {"tool": "toolpoison", "version": __version__, "disclaimer": DISCLAIMER,
               "min_severity": args.min_severity, "tools_scanned": total, "files_scanned": nfiles,
               "findings": shown}
        if changes is not None:
            out["changes"] = changes
        print(json.dumps(out, indent=2, ensure_ascii=True), file=stdout)
    else:
        if changes is not None:
            if changes:
                print("Snapshot diff (possible rug pull - review every change):", file=stdout)
                for c in changes:
                    extra = (" fields: " + ", ".join(c["fields"])) if c["fields"] else ""
                    print("  %-8s %s%s" % (c["change"].upper(), visible(c["tool"]), extra), file=stdout)
            else:
                print("Snapshot diff: no tool changes.", file=stdout)
            print("", file=stdout)
        print(format_text(findings, total, nfiles, args.min_severity), file=stdout)
    failed = bool(shown) or bool(changes)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
