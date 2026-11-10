#!/usr/bin/env python3
"""piiguard: offline PII / sensitive-personal-data scanner for agent transcripts.

Before sharing, logging, or exporting an agent run, check whether emails, phone
numbers, SSNs, payment cards, government IDs, bank details, dates of birth,
home addresses, or medical record numbers leaked into messages or tool results.

Complements tracesweep (credentials / API keys / tokens — not identity PII),
outfence (render-time exfil in model output), and pathfence (sensitive file
paths). Stdlib only; never connects to a network.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
from urllib.parse import unquote, unquote_plus, urlparse, parse_qsl

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "PG01": ("high", "Email address"),
    "PG02": ("high", "Phone number"),
    "PG03": ("critical", "US Social Security number (SSN)"),
    "PG04": ("critical", "Payment card number (Luhn-valid PAN)"),
    "PG05": ("high", "Government / passport / driver's-license ID"),
    "PG06": ("high", "Bank account / IBAN / routing number"),
    "PG07": ("medium", "Date of birth"),
    "PG08": ("medium", "Street / postal address"),
    "PG09": ("medium", "Medical record / health identifier"),
    "PG10": ("info", "Inventory of transcript segments scanned"),
}

# --- detectors ----------------------------------------------------------------

# Emails: avoid matching obvious non-PII like noreply@ or git commit noise lightly;
# still flag them — operators can --disable PG01. Skip image extensions after @.
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9._%+-])"
)

# Phones: US/NANP and simple international. Require enough digits; avoid timestamps.
PHONE_RE = re.compile(
    r"(?<!\d)"
    r"("
    r"(?:\+?1[\s\-.]*)?(?:\(?\d{3}\)?[\s\-.]*)\d{3}[\s\-.]*\d{4}"
    r"|"
    r"\+[1-9]\d{0,2}[\s\-.]?(?:\d[\s\-.]?){7,12}\d"
    r")"
    r"(?!\d)"
)

# SSN: XXX-XX-XXXX with invalid-group filters (000, 666, 9xx area; 00 group; 0000 serial)
SSN_RE = re.compile(
    r"(?<!\d)(\d{3}[-\s]?\d{2}[-\s]?\d{4})(?!\d)"
)
SSN_LABELED_RE = re.compile(
    r"(?i)\b(?:ssn|social\s*security(?:\s*(?:number|no\.?|#))?"
    r"|social\s*security\s*#)\s*[:#]?\s*(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b"
)

# Payment cards: 13–19 digit runs with optional separators; validated by Luhn
CARD_RE = re.compile(
    r"(?<!\d)((?:\d[ \-]?){13,19})(?!\d)"
)

# Government IDs
PASSPORT_RE = re.compile(
    r"(?i)\b(?:passport\s*(?:no\.?|number|num|#)|passport|ppt)\s*[:#]?\s*"
    r"([A-Z0-9]{6,12})\b"
)
DL_RE = re.compile(
    r"(?i)\b(?:driver'?s?\s*lic(?:en[cs]e)?(?:\s*(?:no\.?|number|#))?|"
    r"dl\s*(?:number|#|no\.?)|license\s*(?:number|#|no\.?))\s*[:#]?\s*"
    r"([A-Z0-9\-]{5,20})\b"
)
NATIONAL_ID_RE = re.compile(
    r"(?i)\b(?:national\s*id|nid|taxpayer\s*id|itin|tax\s*id)\s*[:#]?\s*"
    r"([A-Z0-9\-]{6,18})\b"
)

# Bank
IBAN_RE = re.compile(
    r"\b([A-Z]{2}\d{2}[A-Z0-9]{10,30})\b"
)
ROUTING_RE = re.compile(
    r"(?i)\b(?:routing[\s_]*(?:number|no\.?|#)|aba[\s_]*(?:number|routing)?)"
    r"[\s\"']*[:#=]?[\s\"']*(\d{9})\b"
)
ACCOUNT_RE = re.compile(
    r"(?i)\b(?:bank[\s_]*)?account[\s_]*(?:number|no\.?|#)"
    r"[\s\"']*[:#=]?[\s\"']*(\d{6,17})\b"
)

# DOB
DOB_LABELED_RE = re.compile(
    r"(?i)\b(?:dob|date\s*of\s*birth|birth\s*date|born\s*on|birthday)\s*[:#]?\s*"
    r"("
    r"\d{4}[-/]\d{1,2}[-/]\d{1,2}"
    r"|"
    r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}"
    r"|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}"
    r")\b"
)

# Street / postal address (US-oriented heuristic)
ADDRESS_RE = re.compile(
    r"(?i)\b(\d{1,5}\s+(?:[A-Z0-9][A-Za-z0-9.'\-]+\s+){0,4}"
    r"(?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Road|Rd\.?|Lane|Ln\.?|"
    r"Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Terrace|Ter\.?|Circle|Cir\.?)"
    r"(?:\s*,?\s*(?:Apt|Apartment|Suite|Ste\.?|Unit|#)\s*[A-Z0-9\-]+)?"
    r"(?:\s*,\s*[A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?)"
)
ZIP_LABELED_RE = re.compile(
    r"(?i)\b(?:home\s*)?(?:address|zip\s*code|postal\s*code)\s*[:#]?\s*"
    r"([^\n,]{8,80})"
)

# Medical
MRN_RE = re.compile(
    r"(?i)\b(?:mrn|medical\s*record\s*(?:number|no\.?|#)|patient\s*id|"
    r"health\s*record\s*(?:number|#))"
    r"[\s\"']*[:#=]?[\s\"']*([A-Z0-9\-]{4,20})\b"
)
NPI_RE = re.compile(
    r"(?i)\b(?:npi|national\s*provider\s*(?:identifier|id))"
    r"[\s\"']*[:#=]?[\s\"']*(\d{10})\b"
)


# UK National Insurance number (spaces optional). Official prefix exclusions
# are applied in _nino_ok.
NINO_RE = re.compile(
    r"(?i)(?<![A-Z0-9])([A-CEGHJ-PR-TW-Z]{2}\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D])(?![A-Z0-9])"
)
NINO_LABELED_RE = re.compile(
    r"(?i)\b(?:nino|ni\s*(?:number|no\.?|#)|national\s*insurance(?:\s*(?:number|no\.?|#))?)\s*[:#]?\s*"
    r"([A-CEGHJ-PR-TW-Z]{2}\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D])\b"
)

# Canadian Social Insurance Number: 3-3-3 groups, Luhn, does not start with 0/8.
SIN_RE = re.compile(r"(?<!\d)(\d{3}[\s-]\d{3}[\s-]\d{3})(?!\d)")
SIN_LABELED_RE = re.compile(
    r"(?i)\b(?:sin|social\s*insurance(?:\s*(?:number|no\.?|#))?)\s*[:#]?\s*"
    r"(\d{3}[\s-]?\d{3}[\s-]?\d{3})\b"
)

# ICAO Doc 9303 MRZ (TD3 passport, 44-char lines). '<' is the filler.
MRZ_TD3_RE = re.compile(
    r"(?m)(P[A-Z<][A-Z]{3}[A-Z0-9<]{39})\s+([A-Z0-9<]{44})"
)

# India Aadhaar (UIDAI): 12 digits, often grouped 4-4-4. Verhoeff when unlabeled.
AADHAAR_LABELED_RE = re.compile(
    r"(?i)\b(?:aadhaar|aadhar|uidai|uid(?:\s*(?:no\.?|number|#))?)\s*[:#]?\s*"
    r"(\d{4}[\s-]?\d{4}[\s-]?\d{4})\b"
)
AADHAAR_GROUPED_RE = re.compile(
    r"(?<!\d)(\d{4}[\s-]\d{4}[\s-]\d{4})(?!\d)"
)

# Brazil CPF: 11 digits, typically AAA.AAA.AAA-DD, two check digits.
CPF_LABELED_RE = re.compile(
    r"(?i)\b(?:cpf|cadastro\s+de\s+pessoas\s+f[ií]sicas?)\s*[:#]?\s*"
    r"(\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b"
)
CPF_RE = re.compile(
    r"(?<!\d)(\d{3}\.\d{3}\.\d{3}-\d{2})(?!\d)"
)

# Australia Tax File Number: 8 or 9 digits, official weighted checksum.
TFN_LABELED_RE = re.compile(
    r"(?i)\b(?:tfn|tax\s*file\s*(?:number|no\.?|#))\s*[:#]?\s*"
    r"(\d{3}\s?\d{3}\s?\d{2,3}|\d{8,9})\b"
)

# Swedish personal identity number (personnummer): YYYYMMDD-XXXX or YYMMDD-XXXX.
PERSONNUMMER_LABELED_RE = re.compile(
    r"(?i)\b(?:personnummer|person-?nummer|swedish\s+personal\s+(?:identity|id)\s+number|"
    r"personnr|pnr)\s*[:#]?\s*"
    r"((?:19|20)?\d{6}[-+]\d{4})\b"
)
PERSONNUMMER_RE = re.compile(
    r"(?<!\d)((?:19|20)\d{6}[-+]\d{4}|\d{6}[-+]\d{4})(?!\d)"
)

# Poland PESEL: 11 digits, YYMMDD + serial + checksum (weights 1,3,7,9,1,3,7,9,1,3).
PESEL_LABELED_RE = re.compile(
    r"(?i)\b(?:pesel|polish\s+(?:national\s+id|personal\s+(?:id|identification)\s+number))\s*[:#]?\s*"
    r"(\d{11})\b"
)
PESEL_RE = re.compile(r"(?<!\d)(\d{11})(?!\d)")

# Singapore NRIC / FIN: letter + 7 digits + checksum letter.
NRIC_LABELED_RE = re.compile(
    r"(?i)\b(?:nric|fin|singapore\s+(?:nric|national\s+id|nric\s+number))\s*[:#]?\s*"
    r"([STFGM]\d{7}[A-Z])\b"
)
NRIC_RE = re.compile(r"(?<![A-Z0-9])([STFGM]\d{7}[A-Z])(?![A-Z0-9])")

# France NIR / numéro de sécurité sociale: 15 digits, often grouped.
NIR_LABELED_RE = re.compile(
    r"(?i)\b(?:nir|n[°o]?\s*s[ée]cu(?:rit[ée])?(?:\s+sociale)?|insee|"
    r"num[ée]ro\s+de\s+s[ée]curit[ée]\s+sociale|"
    r"french\s+(?:social\s+security|nir)\s+(?:number|no\.?))\s*[:#]?\s*"
    r"([12]\s*\d{2}\s*\d{2}\s*\d{2}\s*\d{3}\s*\d{3}\s*\d{2}|[12]\d{14})\b"
)

# Japan My Number / Individual Number: 12 digits, often grouped in 4s.
MYNUMBER_LABELED_RE = re.compile(
    r"(?i)\b(?:my\s*number|individual\s+number|kojin\s*bang[oô]|個人番号|"
    r"マイナンバー)\s*[:#]?\s*"
    r"(\d{4}[\s-]?\d{4}[\s-]?\d{4}|\d{12})\b"
)

# Mexico CURP: 18-character personal ID.
CURP_LABELED_RE = re.compile(
    r"(?i)\b(?:curp|clave\s+unica\s+de\s+registro\s+de\s+poblaci[oó]n)\s*[:#]?\s*"
    r"([A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2})\b"
)
CURP_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2})(?![A-Z0-9])")

# Roles / content extraction
TEXT_KEYS = {
    "content", "text", "message", "body", "output", "result", "value",
    "arguments", "input", "query", "data", "snippet", "page_content",
}


class Finding:
    __slots__ = (
        "rule", "severity", "source", "message", "turn", "role", "tool",
        "match", "span", "snippet",
    )

    def __init__(
        self, rule, source, message, match="", turn=None, role="", tool="",
        span=None, snippet="",
    ):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.turn = turn
        self.role = role or ""
        self.tool = tool or ""
        self.match = match or ""
        self.span = span  # (start, end) in segment text, if known
        self.snippet = snippet or ""

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "turn": self.turn,
            "role": self.role,
            "tool": self.tool,
            "match": _mask_match(self.rule, self.match),
        }
        if self.snippet:
            d["snippet"] = self.snippet
        return d


class Segment:
    __slots__ = ("source", "text", "turn", "role", "tool")

    def __init__(self, source, text, turn=None, role="", tool=""):
        self.source = source
        self.text = text if isinstance(text, str) else ""
        self.turn = turn
        self.role = role or ""
        self.tool = tool or ""


def _mask_match(rule: str, value: str) -> str:
    """Mask PII in report output (keep shape, hide most digits/chars)."""
    if not value:
        return ""
    v = value.strip()
    if rule == "PG01" and "@" in v:
        local, _, domain = v.partition("@")
        if len(local) <= 2:
            return "*@" + domain
        return local[0] + "***@" + domain
    if rule == "PG04":
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 4:
            return "****-****-****-" + digits[-4:]
        return "****"
    if rule in ("PG03", "PG06"):
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 4:
            return "*" * (len(digits) - 4) + digits[-4:]
        return "****"
    if len(v) <= 4:
        return "****"
    return v[:2] + "***" + v[-2:]


def _snippet(text: str, start: int, end: int, pad: int = 24) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    s = text[a:b]
    s = re.sub(r"\s+", " ", s).strip()
    if a > 0:
        s = "…" + s
    if b < len(text):
        s = s + "…"
    return s[:120]


def luhn_ok(digits: str) -> bool:
    """Return True if digit string passes the Luhn check."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    # Reject obvious non-cards (all same digit, ascending test junk without issuer shape)
    if len(set(digits)) == 1:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def make_luhn(prefix: str, length: int = 16) -> str:
    """Build a Luhn-valid PAN from a numeric prefix (for tests/examples only)."""
    if not prefix.isdigit():
        raise ValueError("prefix must be digits")
    if length < len(prefix) + 1 or length > 19:
        raise ValueError("bad length")
    body = prefix + ("0" * (length - len(prefix) - 1))
    # compute check digit
    total = 0
    reverse = body[::-1]
    for i, ch in enumerate(reverse):
        n = ord(ch) - 48
        # check digit is position 0 in reverse of full number → body positions
        # are odd indices when check digit is appended (i starts 0 on last body digit
        # which will be index 1 of full reverse)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    check = (10 - (total % 10)) % 10
    return body + str(check)


def _ssn_plausible(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area == "000" or area == "666" or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    # Famous advertising / invalid placeholders sometimes still look real —
    # allow famous advertising placeholders through (operators can ignore); block all-zero-ish
    return True


def _iban_plausible(iban: str) -> bool:
    """MOD-97 IBAN check; also reject obviously fake country+short blobs."""
    s = re.sub(r"\s+", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    if len(s) < 15 or len(s) > 34:
        return False
    # rearrange
    rearr = s[4:] + s[:4]
    nums = []
    for ch in rearr:
        if ch.isdigit():
            nums.append(ch)
        else:
            nums.append(str(ord(ch) - 55))
    try:
        return int("".join(nums)) % 97 == 1
    except ValueError:
        return False



_NINO_FORBIDDEN = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}


def _nino_ok(raw: str) -> bool:
    compact = re.sub(r"\s+", "", raw or "").upper()
    if len(compact) != 9 or compact[:2] in _NINO_FORBIDDEN:
        return False
    return bool(re.fullmatch(r"[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]", compact))


def _sin_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) != 9 or digits[0] in "08":
        return False
    if len(set(digits)) <= 2:
        return False
    return luhn_ok(digits)



def _verhoeff_ok(digits: str) -> bool:
    """Verhoeff checksum used by Indian Aadhaar numbers."""
    d = (
        (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
        (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
        (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
        (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
        (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
        (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
        (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
        (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
        (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
    )
    ptab = (
        (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
        (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
        (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
        (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
        (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
        (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
        (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
    )
    c = 0
    try:
        for i, ch in enumerate(reversed(digits)):
            c = d[c][ptab[i % 8][int(ch)]]
    except (ValueError, IndexError):
        return False
    return c == 0


def _aadhaar_ok(raw: str, require_checksum: bool) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) != 12 or digits[0] in "01" or len(set(digits)) <= 2:
        return False
    if require_checksum:
        return _verhoeff_ok(digits)
    return True


def _cpf_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    n = [int(ch) for ch in digits]
    d1 = 11 - (sum(n[i] * (10 - i) for i in range(9)) % 11)
    if d1 >= 10:
        d1 = 0
    d2 = 11 - (sum(n[i] * (11 - i) for i in range(10)) % 11)
    if d2 >= 10:
        d2 = 0
    return n[9] == d1 and n[10] == d2


def _tfn_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) not in (8, 9) or len(set(digits)) <= 2:
        return False
    n = [int(ch) for ch in digits]
    weights = (1, 4, 3, 7, 5, 8, 6, 9, 10)
    return sum(a * b for a, b in zip(n, weights[: len(n)])) % 11 == 0


def _pesel_ok(raw: str, require_checksum: bool) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) != 11 or len(set(digits)) <= 2:
        return False
    # First 6 are a date with century encoded in the month ( +20 / +40 / +60 / +80 ).
    try:
        month = int(digits[2:4]) % 20
        day = int(digits[4:6])
    except ValueError:
        return False
    if month < 1 or month > 12 or day < 1 or day > 31:
        return False
    if not require_checksum:
        return True
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    total = sum(int(d) * w for d, w in zip(digits[:10], weights))
    check = (10 - (total % 10)) % 10
    return check == int(digits[10])


def _nric_ok(raw: str) -> bool:
    s = re.sub(r"[\s-]", "", raw or "").upper()
    if not re.fullmatch(r"[STFGM]\d{7}[A-Z]", s):
        return False
    weights = (2, 7, 6, 5, 4, 3, 2)
    total = sum(int(ch) * w for ch, w in zip(s[1:8], weights))
    prefix = s[0]
    if prefix in "TG":
        total += 4
    elif prefix == "M":
        total += 3
    remainder = total % 11
    if prefix in "ST":
        table = "JZIHGFEDCBA"
    else:
        table = "XWUTRQPNMLK"
    return s[8] == table[remainder]


def _nir_labeled_ok(raw: str) -> bool:
    """Labeled French NIR: 15 digits (spaces allowed). Checksum is not required."""
    digits = re.sub(r"\D", "", raw or "")
    return len(digits) == 15 and digits[0] in "12"


def _mynumber_labeled_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    return len(digits) == 12 and len(set(digits)) > 2


def _curp_ok(raw: str) -> bool:
    s = re.sub(r"[\s-]", "", raw or "").upper()
    return bool(re.fullmatch(r"[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]{2}", s))


def _personnummer_date_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 12:
        y, mo, d = int(digits[0:4]), int(digits[4:6]), int(digits[6:8])
    elif len(digits) == 10:
        yy, mo, d = int(digits[0:2]), int(digits[2:4]), int(digits[4:6])
        y = 1900 + yy if yy >= 40 else 2000 + yy  # loose century; only month/day matter
    else:
        return False
    if mo < 1 or mo > 12 or d < 1 or d > 31:
        return False
    if y < 1850 or y > 2100:
        return False
    return True


# checksum helpers above

def _decoded_payloads(text: str) -> list[str]:
    """URL-decoded and base64-decoded payloads hidden in URLs or path segments."""
    out = []
    seen = set()

    def add(s):
        if s and s not in seen and s != text and len(s) >= 6:
            seen.add(s)
            out.append(s)

    add(unquote(unquote_plus(text)))
    for m in re.finditer(r"https?://[^\s\"'<>]+", text):
        url = m.group(0)
        add(unquote(unquote_plus(url)))
        try:
            parsed = urlparse(url)
        except ValueError:
            continue
        add(unquote(parsed.path or ""))
        add(unquote(parsed.query or ""))
        add(unquote(parsed.fragment or ""))
        for _, v in parse_qsl(parsed.query, keep_blank_values=False):
            add(unquote(v))
        for seg in (parsed.path or "").split("/"):
            if not seg or len(seg) < 16:
                continue
            blob = unquote(seg)
            pad = (-len(blob)) % 4
            try:
                dec = base64.b64decode(blob + ("=" * pad), validate=False)
                s = dec.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if s.isprintable() or any(ch in s for ch in "\n\r\t"):
                add(s)
    # Standalone base64 tokens that decode to text containing an email or NINO-like shape
    for m in re.finditer(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])", text):
        blob = m.group(1)
        pad = (-len(blob)) % 4
        try:
            dec = base64.b64decode(blob + ("=" * pad), validate=False)
            s = dec.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if len(s) >= 6:
            add(s)
    return out


def _phone_plausible(raw: str) -> bool:

    digits = re.sub(r"\D", "", raw)
    if digits.startswith("1") and len(digits) == 11:
        digits = digits[1:]
    if len(digits) == 10:
        # NANP: area can't start with 0/1
        if digits[0] in "01":
            return False
        # exchange normally can't start with 0/1, but allow 555-0xxx fictional
        if digits[3] in "01" and digits[:3] != "555":
            return False
        # avoid 1111111111-ish
        if len(set(digits)) <= 2:
            return False
        return True
    if 8 <= len(digits) <= 15 and digits[0] != "0":
        return True
    return False


def _looks_like_timestamp_or_id(raw: str) -> bool:
    """Heuristic: long digit runs that are clearly not phones (unix times etc.)."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 10 and digits.startswith(("16", "17", "18")):
        # likely unix timestamp seconds ~2020-2030
        try:
            n = int(digits)
            if 1600000000 <= n <= 1899999999:
                return True
        except ValueError:
            pass
    return False


def _card_brand_ok(digits: str) -> bool:
    """Loose issuer-prefix filter to cut down false positives on random digit runs."""
    if digits.startswith("4") and len(digits) in (13, 16, 19):
        return True  # Visa
    if digits[:2] in {f"{i:02d}" for i in range(51, 56)} and len(digits) == 16:
        return True  # Mastercard
    if digits.startswith(("34", "37")) and len(digits) == 15:
        return True  # Amex
    if digits.startswith(("6011", "65")) and len(digits) == 16:
        return True  # Discover-ish
    if digits.startswith("35") and len(digits) == 16:
        return True  # JCB-ish
    if digits.startswith(("300", "301", "302", "303", "304", "305", "36", "38")) and len(digits) == 14:
        return True  # Diners
    # Allow other Luhn-valid 16-digit starting 2 (Mastercard 2-series)
    if digits.startswith("2") and len(digits) == 16:
        try:
            bin6 = int(digits[:6])
            if 222100 <= bin6 <= 272099:
                return True
        except ValueError:
            pass
    return False


# Example.com / reserved / documentation hosts still count as PII shape for
# sharing decisions; operators can disable. Skip only clearly non-email paths.
EMAIL_SKIP_LOCAL = {
    "noreply", "no-reply", "donotreply", "mailer-daemon", "postmaster",
}


# ---------------------------------------------------------------------------
# Data-driven national-ID framework (formats + checksums + context keywords)
# ---------------------------------------------------------------------------

def _digits(s):
    return re.sub(r"\D", "", s or "")


def _tckn_ok(raw):
    d = _digits(raw)
    if len(d) != 11 or d[0] == "0" or not d.isdigit():
        return False
    nums = [int(c) for c in d]
    odd = nums[0] + nums[2] + nums[4] + nums[6] + nums[8]
    even = nums[1] + nums[3] + nums[5] + nums[7]
    if ((odd * 7) - even) % 10 != nums[9]:
        return False
    return (sum(nums[:10]) % 10) == nums[10]


def _rut_ok(raw):
    s = re.sub(r"[.\s]", "", (raw or "")).upper()
    m = re.fullmatch(r"(\d{6,9})-?([0-9K])", s)
    if not m:
        return False
    body, chk = m.group(1), m.group(2)
    total, mul = 0, 2
    for ch in body[::-1]:
        total += int(ch) * mul
        mul = 2 if mul == 7 else mul + 1
    rem = 11 - (total % 11)
    expect = "0" if rem == 11 else ("K" if rem == 10 else str(rem))
    return chk == expect


def _za_id_ok(raw):
    d = _digits(raw)
    if len(d) != 13:
        return False
    yy, mm, dd = int(d[0:2]), int(d[2:4]), int(d[4:6])
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return False
    return luhn_ok(d)


def _codice_fiscale_ok(raw):
    s = re.sub(r"\s+", "", (raw or "")).upper()
    if not re.fullmatch(r"[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]", s):
        return False
    odd_map = {
        "0": 1, "1": 0, "2": 5, "3": 7, "4": 9, "5": 13, "6": 15, "7": 17, "8": 19, "9": 21,
        "A": 1, "B": 0, "C": 5, "D": 7, "E": 9, "F": 13, "G": 15, "H": 17, "I": 19, "J": 21,
        "K": 2, "L": 4, "M": 18, "N": 20, "O": 11, "P": 3, "Q": 6, "R": 8, "S": 12, "T": 14,
        "U": 16, "V": 10, "W": 22, "X": 25, "Y": 24, "Z": 23,
    }
    even_map = {str(i): i for i in range(10)}
    even_map.update({chr(65 + i): i for i in range(26)})
    total = 0
    for i, ch in enumerate(s[:15]):
        total += odd_map[ch] if (i % 2) == 0 else even_map[ch]
    return s[15] == chr(ord("A") + (total % 26))


def _bsn_ok(raw):
    d = _digits(raw)
    if len(d) == 8:
        d = "0" + d
    if len(d) != 9 or d == "0" * 9:
        return False
    nums = [int(c) for c in d]
    total = sum((9 - i) * nums[i] for i in range(8)) - nums[8]
    return total % 11 == 0


def _spain_dni_ok(raw):
    s = re.sub(r"[\s-]", "", (raw or "")).upper()
    letters = "TRWAGMYFPDXBNJZSQVHLCKE"
    m = re.fullmatch(r"(\d{8})([A-Z])", s)
    if m:
        return letters[int(m.group(1)) % 23] == m.group(2)
    m = re.fullmatch(r"([XYZ])(\d{7})([A-Z])", s)
    if not m:
        return False
    prefix = {"X": "0", "Y": "1", "Z": "2"}[m.group(1)]
    return letters[int(prefix + m.group(2)) % 23] == m.group(3)


def _nif_ok(raw):
    d = _digits(raw)
    if len(d) != 9 or d[0] not in "1235689":
        return False
    total = sum(int(d[i]) * (9 - i) for i in range(8))
    rem = total % 11
    check = 0 if rem < 2 else 11 - rem
    return check == int(d[8])


def _belgium_nn_ok(raw):
    d = _digits(raw)
    if len(d) != 11:
        return False
    body, chk = int(d[:9]), int(d[9:])
    if (97 - (body % 97)) == chk:
        return True
    # persons born in 2000+ use 2||YYMMDDXXX
    return (97 - (int("2" + d[:9]) % 97)) == chk


def _norway_fnr_ok(raw):
    d = _digits(raw)
    if len(d) != 11:
        return False
    n = [int(c) for c in d]
    w1 = (3, 7, 6, 1, 8, 9, 4, 5, 2)
    w2 = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)
    c1 = 11 - (sum(n[i] * w1[i] for i in range(9)) % 11)
    if c1 == 11:
        c1 = 0
    if c1 == 10 or c1 != n[9]:
        return False
    c2 = 11 - (sum(n[i] * w2[i] for i in range(10)) % 11)
    if c2 == 11:
        c2 = 0
    return c2 != 10 and c2 == n[10]


def _finland_hetu_ok(raw):
    s = re.sub(r"\s+", "", (raw or "")).upper()
    m = re.fullmatch(r"(\d{6})[-+A](\d{3})([0-9A-Y])", s)
    if not m:
        return False
    chars = "0123456789ABCDEFHJKLMNPRSTUVWXY"
    n = int(m.group(1) + m.group(2))
    return chars[n % 31] == m.group(3)


def _estonia_ik_ok(raw):
    d = _digits(raw)
    if len(d) != 11:
        return False
    n = [int(c) for c in d]
    for weights in ((1, 2, 3, 4, 5, 6, 7, 8, 9, 1), (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)):
        rem = sum(n[i] * weights[i] for i in range(10)) % 11
        if rem != 10:
            return rem == n[10]
    return n[10] == 0


def _romania_cnp_ok(raw):
    d = _digits(raw)
    if len(d) != 13 or d[0] not in "123456789":
        return False
    w = (2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9)
    rem = sum(int(d[i]) * w[i] for i in range(12)) % 11
    check = 1 if rem == 10 else rem
    return check == int(d[12])


def _bulgaria_egn_ok(raw):
    d = _digits(raw)
    if len(d) != 10:
        return False
    w = (2, 4, 8, 5, 10, 9, 7, 3, 6)
    rem = sum(int(d[i]) * w[i] for i in range(9)) % 11
    check = 0 if rem == 10 else rem
    return check == int(d[9])


def _croatia_oib_ok(raw):
    d = _digits(raw)
    if len(d) != 11:
        return False
    a = 10
    for ch in d[:10]:
        a = (a + int(ch)) % 10
        if a == 0:
            a = 10
        a = (a * 2) % 11
    check = 11 - a
    if check == 10:
        check = 0
    return check == int(d[10])


def _greece_afm_ok(raw):
    d = _digits(raw)
    if len(d) != 9:
        return False
    total = sum(int(d[i]) * (2 ** (8 - i)) for i in range(8))
    return (total % 11) % 10 == int(d[8])


def _israel_id_ok(raw):
    d = _digits(raw)
    if not (5 <= len(d) <= 9):
        return False
    d = d.zfill(9)
    total = 0
    for i, ch in enumerate(d[:8]):
        v = int(ch) * (1 if i % 2 == 0 else 2)
        total += v if v < 10 else (v - 9)
    return (total + int(d[8])) % 10 == 0


def _china_id_ok(raw):
    s = re.sub(r"\s+", "", (raw or "")).upper()
    if not re.fullmatch(r"\d{17}[0-9X]", s):
        return False
    w = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    remap = "10X98765432"
    total = sum(int(s[i]) * w[i] for i in range(17))
    return remap[total % 11] == s[17]


def _taiwan_nid_ok(raw):
    s = re.sub(r"[\s-]", "", (raw or "")).upper()
    if not re.fullmatch(r"[A-Z][1289AB]\d{8}", s):
        # classic form: letter + 9 digits (second may be 1/2)
        if not re.fullmatch(r"[A-Z]\d{9}", s):
            return False
    letters = {chr(65 + i): (10 + i) for i in range(26)}
    # official letter mapping (A=10 ... etc.) is sequential for A-H then slightly different;
    # use the published table.
    letters = {
        "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17,
        "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22, "O": 35, "P": 23,
        "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28, "V": 29, "W": 32, "X": 30,
        "Y": 31, "Z": 33,
    }
    code = letters.get(s[0])
    if code is None:
        return False
    n = [code // 10, code % 10] + [int(c, 16) if c in "AB" else int(c) for c in s[1:]]
    # last is check
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1]
    if len(n) != 11:
        return False
    return sum(n[i] * weights[i] for i in range(11)) % 10 == 0


def _hkid_ok(raw):
    s = re.sub(r"[\s()]", "", (raw or "")).upper()
    m = re.fullmatch(r"([A-Z]{1,2})(\d{6})([0-9A])", s)
    if not m:
        return False
    chars = m.group(1) + m.group(2)
    if len(chars) == 7:
        chars = " " + chars
    def val(ch):
        if ch == " ":
            return 36
        if ch.isdigit():
            return int(ch)
        return ord(ch) - 55  # A=10
    total = sum(val(ch) * (8 - i) for i, ch in enumerate(chars))
    rem = total % 11
    check = "0" if rem == 0 else ("A" if rem == 1 else str(11 - rem))
    return check == m.group(3)


def _thailand_id_ok(raw):
    d = _digits(raw)
    if len(d) != 13 or d[0] == "0":
        return False
    total = sum(int(d[i]) * (13 - i) for i in range(12))
    return (11 - (total % 11)) % 10 == int(d[12])


def _cuil_ok(raw):
    d = _digits(raw)
    if len(d) != 11:
        return False
    w = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)
    rem = sum(int(d[i]) * w[i] for i in range(10)) % 11
    check = 0 if rem == 0 else (11 - rem)
    # some CUIL types remap 10
    if check == 11:
        check = 0
    if check == 10:
        return False  # those numbers are reissued; treat as invalid here
    return check == int(d[10])


def _nz_ird_ok(raw):
    d = _digits(raw)
    if len(d) not in (8, 9):
        return False
    d = d.zfill(9)
    w = (3, 2, 7, 6, 5, 4, 3, 2)
    rem = sum(int(d[i]) * w[i] for i in range(8)) % 11
    check = 0 if rem == 0 else 11 - rem
    if check != 10:
        return check == int(d[8])
    w2 = (7, 4, 3, 2, 5, 2, 7, 6)
    rem = sum(int(d[i]) * w2[i] for i in range(8)) % 11
    check = 0 if rem == 0 else 11 - rem
    return check != 10 and check == int(d[8])


def _irish_ppsn_ok(raw):
    s = re.sub(r"\s+", "", (raw or "")).upper()
    m = re.fullmatch(r"(\d{7})([A-W])([A-IW])?", s)
    if not m:
        return False
    letters = "WABCDEFGHIJKLMNOPQRSTUV"
    total = sum(int(m.group(1)[i]) * (8 - i) for i in range(7))
    extra = m.group(3)
    if extra:
        total += (ord(extra) - 64) * 9 if extra != "W" else 0
    return letters[total % 23] == m.group(2)


def _swiss_ahv_ok(raw):
    d = _digits(raw)
    if len(d) != 13 or not d.startswith("756"):
        return False
    # EAN-13
    total = sum(int(d[i]) * (1 if i % 2 == 0 else 3) for i in range(12))
    check = (10 - (total % 10)) % 10
    return check == int(d[12])


def _hungary_taj_ok(raw):
    d = _digits(raw)
    if len(d) != 9:
        return False
    total = sum(int(d[i]) * (3 if i % 2 == 0 else 7) for i in range(8))
    return total % 10 == int(d[8])


def _korea_rrn_ok(raw):
    d = _digits(raw)
    if len(d) != 13:
        return False
    w = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    rem = (11 - (sum(int(d[i]) * w[i] for i in range(12)) % 11)) % 10
    return rem == int(d[12])


def _jmbg_ok(raw):
    d = _digits(raw)
    if len(d) != 13:
        return False
    # DDMMYYY RR SSS K
    dd, mm = int(d[0:2]), int(d[2:4])
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return False
    w = (7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2)
    rem = 11 - (sum(int(d[i]) * w[i] for i in range(12)) % 11)
    check = 0 if rem in (10, 11) else rem
    return check == int(d[12])


def _malaysia_nric_ok(raw):
    d = _digits(raw)
    if len(d) != 12:
        return False
    yy, mm, dd = int(d[0:2]), int(d[2:4]), int(d[4:6])
    return 1 <= mm <= 12 and 1 <= dd <= 31


def _labeled(text, start, keywords):
    window = text[max(0, start - 48): start].lower()
    return any(k in window for k in keywords)


# (name, keywords, pattern, checker, unlabeled_policy)
# unlabeled_policy: "checksum" (fire if check passes), "never" (keywords required)
NATIONAL_ID_SPECS = [
    ("Turkish TCKN", ("tckn", "tc kimlik", "kimlik no", "turkish id", "türkiye"),
     r"(?<!\d)(\d{11})(?!\d)", _tckn_ok, "never"),
    ("Chilean RUT", ("rut", "run", "chilean id", "rol unico", "rol único"),
     r"(?<![A-Z0-9])(\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Kk])(?![A-Z0-9])", _rut_ok, "checksum"),
    ("South African ID number", ("south african id", "sa id", "rsa id", "said number"),
     r"(?<!\d)(\d{13})(?!\d)", _za_id_ok, "never"),
    ("Italian codice fiscale", ("codice fiscale", "cod. fisc", "italian tax code", "cf:"),
     r"(?<![A-Z0-9])([A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z])(?![A-Z0-9])",
     _codice_fiscale_ok, "checksum"),
    ("Dutch BSN", ("bsn", "burgerservicennummer", "sofinummer", "dutch bsn"),
     r"(?<!\d)(\d{8,9})(?!\d)", _bsn_ok, "never"),
    ("Spanish DNI/NIE", ("dni", "nie", "documento nacional", "spanish id"),
     r"(?<![A-Z0-9])((?:\d{8}|[XYZ]\d{7})[A-Z])(?![A-Z0-9])", _spain_dni_ok, "checksum"),
    ("Portuguese NIF", ("nif", "número de identificação fiscal", "portuguese tax"),
     r"(?<!\d)(\d{9})(?!\d)", _nif_ok, "never"),
    ("Belgian national number", ("rijksregisternummer", "numéro national", "national register", "insz", "niss"),
     r"(?<!\d)(\d{2}[.\-]?\d{2}[.\-]?\d{2}[.\-]?\d{3}[.\-]?\d{2})(?!\d)", _belgium_nn_ok, "never"),
    ("Norwegian fødselsnummer", ("fødselsnummer", "fodselsnummer", "norwegian id", "fødselsnr"),
     r"(?<!\d)(\d{11})(?!\d)", _norway_fnr_ok, "never"),
    ("Finnish henkilötunnus", ("henkilötunnus", "hetu", "finnish id", "personbeteckning"),
     r"(?<![A-Z0-9])(\d{6}[-+A]\d{3}[0-9A-Y])(?![A-Z0-9])", _finland_hetu_ok, "checksum"),
    ("Estonian isikukood", ("isikukood", "estonian id", "eesti isikukood"),
     r"(?<!\d)(\d{11})(?!\d)", _estonia_ik_ok, "never"),
    ("Romanian CNP", ("cnp", "cod numeric personal", "romanian cnp"),
     r"(?<!\d)(\d{13})(?!\d)", _romania_cnp_ok, "never"),
    ("Bulgarian EGN", ("egn", "единен граждански", "bulgarian egn"),
     r"(?<!\d)(\d{10})(?!\d)", _bulgaria_egn_ok, "never"),
    ("Croatian OIB", ("oib", "osobni identifikacijski", "croatian oib"),
     r"(?<!\d)(\d{11})(?!\d)", _croatia_oib_ok, "never"),
    ("Serbian/Yugoslav JMBG", ("jmbg", " embg", "maticni broj", "matični broj"),
     r"(?<!\d)(\d{13})(?!\d)", _jmbg_ok, "never"),
    ("Greek AFM", ("afm", "αφμ", "greek tax", "arithmos forologikou"),
     r"(?<!\d)(\d{9})(?!\d)", _greece_afm_ok, "never"),
    ("Israeli Teudat Zehut", ("teudat zehut", "israeli id", "mispar zehut", "tz number"),
     r"(?<!\d)(\d{8,9})(?!\d)", _israel_id_ok, "never"),
    ("Chinese resident ID", ("居民身份证", "shenfenzheng", "chinese id", "resident identity card", "cn id"),
     r"(?<![A-Z0-9])(\d{17}[\dXx])(?![A-Z0-9])", _china_id_ok, "checksum"),
    ("South Korean RRN", ("resident registration", "korean rrn", "주민등록번호"),
     r"(?<!\d)(\d{6}[-\s]?\d{7})(?!\d)", _korea_rrn_ok, "never"),
    ("Taiwan national ID", ("national id no", "taiwan id", "中華民國身分證", "roc id"),
     r"(?<![A-Z0-9])([A-Z][12]\d{8})(?![A-Z0-9])", _taiwan_nid_ok, "checksum"),
    ("Hong Kong identity card", ("hkid", "hong kong id", "hk identity"),
     r"(?<![A-Z0-9])([A-Z]{1,2}\d{6}(?:\([0-9A]\)|[0-9A]))(?![A-Z0-9])", _hkid_ok, "checksum"),
    ("Thai national ID", ("thai id", "thailand id", "เลขประจำตัวประชาชน", "thai citizen"),
     r"(?<!\d)(\d{13})(?!\d)", _thailand_id_ok, "never"),
    ("Malaysian NRIC", ("mykad", "malaysian nric", "malaysia nric", "mykad no"),
     r"(?<!\d)(\d{6}[-\s]?\d{2}[-\s]?\d{4})(?!\d)", _malaysia_nric_ok, "never"),
    ("Argentine CUIL/CUIT", ("cuil", "cuit", "cuil/cuit", "argentina cuil"),
     r"(?<!\d)(\d{2}[-.\s]\d{8}[-.\s]\d)(?!\d)", _cuil_ok, "checksum"),
    ("New Zealand IRD number", ("ird number", "nz ird", "inland revenue"),
     r"(?<!\d)(\d{8,9})(?!\d)", _nz_ird_ok, "never"),
    ("Irish PPSN", ("ppsn", "pps number", "irish pps"),
     r"(?<![A-Z0-9])(\d{7}[A-W](?:[A-IW])?)(?![A-Z0-9])", _irish_ppsn_ok, "checksum"),
    ("Swiss AHV/AVS number", ("ahv", "avs number", "swiss ahv", "sozialversicherungsnummer"),
     r"(?<!\d)(756(?:[.\s]?\d{4}){2}[.\s]?\d{2})(?!\d)", _swiss_ahv_ok, "checksum"),
    ("Hungarian TAJ", ("taj szám", "taj number", "hungarian taj", "taj-szám"),
     r"(?<!\d)(\d{3}[-\s]?\d{3}[-\s]?\d{3})(?!\d)", _hungary_taj_ok, "never"),
]


def _scan_national_id_specs(text, add, is_claimed, claim):
    """Apply the national-ID table. `add(rule, message, match, start, end)`."""
    for name, keywords, pattern, checker, policy in NATIONAL_ID_SPECS:
        rx = re.compile(pattern, re.I)
        for m in rx.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if not checker(raw):
                continue
            labeled = _labeled(text, m.start(), keywords)
            if policy == "never" and not labeled:
                continue
            if policy == "checksum" and not (labeled or checker(raw)):
                continue
            add("PG05", name, raw, *sp)
            claim(sp)


def scan_text(text: str, source: str, turn=None, role="", tool="", disabled=None, _nested=False):
    """Return Finding list for one text segment."""
    disabled = set(disabled or [])
    findings = []
    if not text:
        return findings

    def add(rule, message, match, start, end):
        if rule in disabled:
            return
        findings.append(
            Finding(
                rule=rule,
                source=source,
                message=message,
                match=match,
                turn=turn,
                role=role,
                tool=tool,
                span=(start, end),
                snippet=_snippet(text, start, end),
            )
        )

    # Track spans already claimed by higher-severity rules to reduce double hits
    claimed = []

    def overlaps(a, b):
        return not (a[1] <= b[0] or b[1] <= a[0])

    def claim(span):
        claimed.append(span)

    def is_claimed(span):
        return any(overlaps(span, c) for c in claimed)

    # PG03 SSN (labeled first, then shape)
    if "PG03" not in disabled:
        for m in SSN_LABELED_RE.finditer(text):
            raw = m.group(1)
            if _ssn_plausible(raw):
                sp = (m.start(1), m.end(1))
                add("PG03", "Labeled SSN", raw, *sp)
                claim(sp)
        for m in SSN_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            # Prefer dashed form; bare 9 digits need separators or label context
            if "-" not in raw and " " not in raw:
                # require nearby label within 40 chars
                window = text[max(0, m.start() - 40): m.start()].lower()
                if not re.search(r"(ssn|social|taxpayer|itin)", window):
                    continue
            if _ssn_plausible(raw):
                add("PG03", "SSN-shaped number", raw, *sp)
                claim(sp)

    # PG04 cards
    if "PG04" not in disabled:
        for m in CARD_RE.finditer(text):
            raw = m.group(1)
            digits = re.sub(r"\D", "", raw)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if not luhn_ok(digits):
                continue
            if not _card_brand_ok(digits):
                continue
            add("PG04", "Luhn-valid payment card", raw, *sp)
            claim(sp)

    # PG01 emails
    if "PG01" not in disabled:
        for m in EMAIL_RE.finditer(text):
            raw = m.group(1)
            local = raw.split("@", 1)[0].lower()
            domain = raw.split("@", 1)[1].lower()
            if domain.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")):
                continue
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            msg = "Email address"
            if local in EMAIL_SKIP_LOCAL:
                msg = "Email address (noreply-style local-part)"
            add("PG01", msg, raw, *sp)

    # PG02 phones
    if "PG02" not in disabled:
        for m in PHONE_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _looks_like_timestamp_or_id(raw):
                continue
            if not _phone_plausible(raw):
                continue
            # Avoid matching card digit leftovers
            digits = re.sub(r"\D", "", raw)
            if len(digits) >= 13:
                continue
            add("PG02", "Phone number", raw, *sp)
            claim(sp)

    # PG05 government IDs
    if "PG05" not in disabled:
        for rx, label in (
            (PASSPORT_RE, "Passport number"),
            (DL_RE, "Driver's license number"),
            (NATIONAL_ID_RE, "National / tax ID"),
        ):
            for m in rx.finditer(text):
                raw = m.group(1)
                sp = (m.start(1), m.end(1))
                if is_claimed(sp):
                    continue
                if raw.upper().startswith("FAKE"):
                    # still PII-shaped for governance; keep
                    pass
                add("PG05", label, raw, *sp)
                claim(sp)
        for m in list(NINO_LABELED_RE.finditer(text)) + list(NINO_RE.finditer(text)):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _nino_ok(raw):
                add("PG05", "UK National Insurance number", raw, *sp)
                claim(sp)
        for m in SIN_LABELED_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            digits = re.sub(r"\D", "", raw)
            if len(digits) == 9 and len(set(digits)) > 2:
                add("PG05", "Canadian Social Insurance Number", raw, *sp)
                claim(sp)
        for m in SIN_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _sin_ok(raw):
                add("PG05", "Canadian Social Insurance Number", raw, *sp)
                claim(sp)
        for m in MRZ_TD3_RE.finditer(text):
            sp = (m.start(), m.end())
            if is_claimed(sp):
                continue
            add("PG05", "Passport machine-readable zone (MRZ)", m.group(0).replace("\n", " ")[:80], *sp)
            claim(sp)


        for m in AADHAAR_LABELED_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _aadhaar_ok(raw, require_checksum=False):
                add("PG05", "Indian Aadhaar number", raw, *sp)
                claim(sp)
        for m in AADHAAR_GROUPED_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _aadhaar_ok(raw, require_checksum=True):
                add("PG05", "Indian Aadhaar number", raw, *sp)
                claim(sp)
        for m in list(CPF_LABELED_RE.finditer(text)) + list(CPF_RE.finditer(text)):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _cpf_ok(raw):
                add("PG05", "Brazilian CPF number", raw, *sp)
                claim(sp)
        for m in TFN_LABELED_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _tfn_ok(raw):
                add("PG05", "Australian Tax File Number", raw, *sp)
                claim(sp)
        for m in list(PERSONNUMMER_LABELED_RE.finditer(text)) + list(PERSONNUMMER_RE.finditer(text)):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _personnummer_date_ok(raw):
                digits = re.sub(r"\D", "", raw)
                labeled = bool(PERSONNUMMER_LABELED_RE.search(text[max(0, m.start() - 40): m.end() + 1]))
                if labeled or len(digits) == 12:
                    add("PG05", "Swedish personal identity number", raw, *sp)
                    claim(sp)
        for m in list(PESEL_LABELED_RE.finditer(text)) + list(PESEL_RE.finditer(text)):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            labeled = bool(PESEL_LABELED_RE.search(text[max(0, m.start() - 40): m.end() + 1]))
            if _pesel_ok(raw, require_checksum=True) or (labeled and _pesel_ok(raw, require_checksum=False)):
                add("PG05", "Polish PESEL number", raw, *sp)
                claim(sp)
        for m in list(NRIC_LABELED_RE.finditer(text)) + list(NRIC_RE.finditer(text)):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _nric_ok(raw):
                add("PG05", "Singapore NRIC / FIN", raw, *sp)
                claim(sp)
        for m in NIR_LABELED_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _nir_labeled_ok(raw):
                add("PG05", "French NIR / social security number", raw, *sp)
                claim(sp)
        for m in MYNUMBER_LABELED_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _mynumber_labeled_ok(raw):
                add("PG05", "Japan My Number / Individual Number", raw, *sp)
                claim(sp)
        for m in list(CURP_LABELED_RE.finditer(text)) + list(CURP_RE.finditer(text)):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _curp_ok(raw):
                add("PG05", "Mexican CURP", raw, *sp)
                claim(sp)

        _scan_national_id_specs(text, add, is_claimed, claim)

    # PG06 bank
    if "PG06" not in disabled:
        for m in IBAN_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _iban_plausible(raw):
                add("PG06", "IBAN", raw, *sp)
                claim(sp)
        for m in ROUTING_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            add("PG06", "ABA routing number", raw, *sp)
            claim(sp)
        for m in ACCOUNT_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            add("PG06", "Bank account number", raw, *sp)
            claim(sp)

    # PG07 DOB
    if "PG07" not in disabled:
        for m in DOB_LABELED_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            add("PG07", "Date of birth", raw, *sp)
            claim(sp)

    # PG08 address
    if "PG08" not in disabled:
        for m in ADDRESS_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            add("PG08", "Street address", raw, *sp)
            claim(sp)
        for m in ZIP_LABELED_RE.finditer(text):
            raw = m.group(1).strip().rstrip(".")
            sp = (m.start(1), m.start(1) + len(raw))
            if is_claimed(sp):
                continue
            # skip if already caught as street
            if len(raw) < 8:
                continue
            add("PG08", "Labeled address / postal field", raw, *sp)
            claim(sp)

    # PG09 medical
    if "PG09" not in disabled:
        for rx, label in ((MRN_RE, "Medical record number"), (NPI_RE, "NPI")):
            for m in rx.finditer(text):
                raw = m.group(1)
                sp = (m.start(1), m.end(1))
                if is_claimed(sp):
                    continue
                add("PG09", label, raw, *sp)
                claim(sp)

    # Scan URL- and base64-decoded payloads once so PII hidden in a path
    # or query string is still visible to the same detectors.
    if not _nested:
        seen_matches = {f.match for f in findings if f.match}
        for extra in _decoded_payloads(text):
            for f in scan_text(extra, source, turn=turn, role=role, tool=tool, disabled=disabled, _nested=True):
                if f.match in seen_matches:
                    continue
                seen_matches.add(f.match)
                findings.append(f)

    return findings


def _stringify_content(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                if part.get("type") == "text" and isinstance(part.get("text"), str):
                    parts.append(part["text"])
                elif isinstance(part.get("text"), str):
                    parts.append(part["text"])
                elif isinstance(part.get("content"), str):
                    parts.append(part["content"])
                else:
                    # tool_use / input blocks
                    for k in ("input", "arguments", "partial_json"):
                        if k in part:
                            v = part[k]
                            if isinstance(v, str):
                                parts.append(v)
                            else:
                                try:
                                    parts.append(json.dumps(v, ensure_ascii=False))
                                except (TypeError, ValueError):
                                    parts.append(str(v))
        return "\n".join(parts)
    if isinstance(content, dict):
        try:
            return json.dumps(content, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(content)
    return str(content)


def _segments_from_message(msg: dict, source: str, turn: int):
    """Yield Segment objects from one message-like dict."""
    if not isinstance(msg, dict):
        return
    role = str(msg.get("role") or msg.get("type") or msg.get("author") or "")
    # OpenAI tool_calls on assistant
    if msg.get("tool_calls"):
        for tc in msg["tool_calls"]:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            name = fn.get("name") or tc.get("name") or tc.get("tool") or ""
            args = fn.get("arguments", tc.get("arguments", tc.get("input", "")))
            if isinstance(args, (dict, list)):
                try:
                    args = json.dumps(args, ensure_ascii=False)
                except (TypeError, ValueError):
                    args = str(args)
            yield Segment(source, str(args or ""), turn=turn, role=role or "assistant", tool=str(name))
    # Anthropic content blocks
    content = msg.get("content", msg.get("text", msg.get("message")))
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                if isinstance(block, str) and block.strip():
                    yield Segment(source, block, turn=turn, role=role)
                continue
            btype = block.get("type") or ""
            if btype in ("tool_use", "function_call"):
                name = block.get("name") or ""
                inp = block.get("input", block.get("arguments", ""))
                if isinstance(inp, (dict, list)):
                    try:
                        inp = json.dumps(inp, ensure_ascii=False)
                    except (TypeError, ValueError):
                        inp = str(inp)
                yield Segment(source, str(inp or ""), turn=turn, role=role or "assistant", tool=str(name))
            elif btype == "tool_result":
                name = str(block.get("name") or block.get("tool_use_id") or "tool")
                yield Segment(
                    source,
                    _stringify_content(block.get("content", block.get("output", ""))),
                    turn=turn,
                    role="tool",
                    tool=name,
                )
            else:
                text = _stringify_content(block)
                if text.strip():
                    yield Segment(source, text, turn=turn, role=role)
        return
    # tool role message
    if role in ("tool", "function"):
        name = str(msg.get("name") or msg.get("tool_name") or "tool")
        yield Segment(source, _stringify_content(content), turn=turn, role="tool", tool=name)
        return
    text = _stringify_content(content)
    if text.strip():
        yield Segment(source, text, turn=turn, role=role)


def extract_segments(doc, source: str):
    """Normalize OpenAI / Anthropic / generic JSON into Segment list."""
    segs = []

    def from_messages(messages, src):
        if not isinstance(messages, list):
            return
        for i, msg in enumerate(messages):
            if isinstance(msg, str):
                segs.append(Segment(src, msg, turn=i, role="unknown"))
            elif isinstance(msg, dict):
                segs.extend(_segments_from_message(msg, src, i))

    if isinstance(doc, list):
        # JSONL already merged as list of events, or bare messages list
        if doc and all(isinstance(x, dict) and (
            "role" in x or "content" in x or "tool_calls" in x or "type" in x
        ) for x in doc[:5]):
            from_messages(doc, source)
        else:
            for i, item in enumerate(doc):
                if isinstance(item, str):
                    segs.append(Segment(source, item, turn=i))
                elif isinstance(item, dict):
                    segs.extend(_segments_from_message(item, source, i))
        return segs

    if not isinstance(doc, dict):
        if isinstance(doc, str):
            segs.append(Segment(source, doc, turn=0))
        return segs

    for key in ("messages", "events", "steps", "transcript", "items", "conversation", "data"):
        val = doc.get(key)
        if isinstance(val, list) and val:
            from_messages(val, source)
            if segs:
                return segs

    # single message object
    if any(k in doc for k in ("role", "content", "tool_calls")):
        segs.extend(_segments_from_message(doc, source, 0))
        if segs:
            return segs

    # fallback: scan whole JSON dump as text
    try:
        segs.append(Segment(source, json.dumps(doc, ensure_ascii=False), turn=0, role="document"))
    except (TypeError, ValueError):
        segs.append(Segment(source, str(doc), turn=0, role="document"))
    return segs


def load_path(path: str):
    """Load file into (doc_or_text, kind) where kind is json|jsonl|text."""
    if path == "-":
        raw = sys.stdin.read()
        source = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        source = path
    return parse_raw(raw, source)


def parse_raw(raw: str, source: str):
    stripped = raw.strip()
    if not stripped:
        return [], source, raw
    # JSONL?
    if source.endswith(".jsonl") or (
        "\n" in stripped and stripped[0] == "{" and not stripped.endswith("]")
    ):
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if lines and all(ln.lstrip().startswith("{") or ln.lstrip().startswith("[") for ln in lines[:5]):
            objs = []
            ok = True
            for ln in lines:
                try:
                    objs.append(json.loads(ln))
                except json.JSONDecodeError:
                    ok = False
                    break
            if ok and objs:
                return objs, source, raw
    if stripped[0] in "{[":
        try:
            return json.loads(stripped), source, raw
        except json.JSONDecodeError:
            pass
    return raw, source, raw


def collect_inputs(paths):
    """Expand dirs/files into list of paths ( '-' preserved )."""
    out = []
    for p in paths:
        if p == "-":
            out.append("-")
            continue
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in sorted(files):
                    if name.startswith("."):
                        continue
                    if name.endswith((".json", ".jsonl", ".txt", ".md", ".log")):
                        out.append(os.path.join(root, name))
        elif os.path.isfile(p):
            out.append(p)
        else:
            raise FileNotFoundError(p)
    return out


def analyze_paths(paths, disabled=None, as_text=False):
    disabled = set(disabled or [])
    all_findings = []
    segment_count = 0
    sources = []
    raws = []  # (source, raw_text) for redact

    for path in paths:
        doc, source, raw = load_path(path)
        sources.append(source)
        raws.append((source, raw, path))
        if as_text or isinstance(doc, str):
            text = doc if isinstance(doc, str) else raw
            # split paragraphs for attribution
            parts = re.split(r"\n\s*\n", text) if as_text else [text]
            segs = [
                Segment(source, p, turn=i, role="text")
                for i, p in enumerate(parts) if p.strip()
            ]
        else:
            segs = extract_segments(doc, source)
        segment_count += len(segs)
        for seg in segs:
            all_findings.extend(
                scan_text(
                    seg.text,
                    seg.source,
                    turn=seg.turn,
                    role=seg.role,
                    tool=seg.tool,
                    disabled=disabled,
                )
            )

    if "PG10" not in disabled:
        all_findings.append(
            Finding(
                rule="PG10",
                source=",".join(sources[:3]) + ("…" if len(sources) > 3 else ""),
                message="Scanned %d segment(s) across %d input(s)" % (segment_count, len(sources)),
                match="",
            )
        )
    return all_findings, raws, segment_count


def redact_text(raw: str, findings) -> str:
    """Replace matched PII spans in raw text with masked tokens.

    Only findings that carry a span and whose source matches a single-file raw
    are applied; for multi-segment JSON we re-scan the whole raw string.
    """
    # Re-derive spans against the full raw so JSON structure is preserved.
    local = scan_text(raw, source="redact", disabled={"PG10"})
    # Prefer critical/high replacements; sort by start descending
    spans = []
    for f in local:
        if f.span and f.match and f.rule != "PG10":
            spans.append((f.span[0], f.span[1], f.rule, f.match))
    spans.sort(key=lambda x: x[0], reverse=True)
    out = raw
    used = []
    for start, end, rule, match in spans:
        if any(not (end <= a or b <= start) for a, b in used):
            continue
        token = "[REDACTED:%s:%s]" % (rule, _mask_match(rule, match))
        out = out[:start] + token + out[end:]
        used.append((start, end))
    return out


def filter_findings(findings, min_severity="info"):
    floor = SEV_RANK[min_severity]
    return [f for f in findings if SEV_RANK[f.severity] >= floor]


def worst_severity(findings):
    if not findings:
        return None
    return max(findings, key=lambda f: SEV_RANK[f.severity]).severity


def format_text(findings):
    lines = []
    actionable = [f for f in findings if f.rule != "PG10"]
    inv = [f for f in findings if f.rule == "PG10"]
    if not actionable:
        lines.append("piiguard: no PII findings")
    else:
        lines.append("piiguard: %d finding(s)" % len(actionable))
    for f in sorted(
        actionable,
        key=lambda x: (-SEV_RANK[x.severity], x.rule, x.source, x.turn or -1),
    ):
        loc = f.source
        extras = []
        if f.turn is not None:
            extras.append("turn=%s" % f.turn)
        if f.role:
            extras.append("role=%s" % f.role)
        if f.tool:
            extras.append("tool=%s" % f.tool)
        if extras:
            loc = "%s (%s)" % (loc, ", ".join(extras))
        lines.append(
            "  [%s] %s %s: %s — %s"
            % (f.severity, f.rule, loc, f.message, _mask_match(f.rule, f.match) or "-")
        )
        if f.snippet:
            lines.append("           snippet: %s" % f.snippet)
    for f in inv:
        lines.append("  [%s] %s: %s" % (f.severity, f.rule, f.message))
    return "\n".join(lines) + "\n"


def _write_redacted(out_path, raws, findings_by_source=None):
    """Write redacted copies. out_path is file if one input, else directory."""
    if len(raws) == 1:
        source, raw, path = raws[0]
        text = redact_text(raw, None)
        if out_path in ("-", "/dev/stdout"):
            sys.stdout.write(text)
            return
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        return
    os.makedirs(out_path, exist_ok=True)
    for source, raw, path in raws:
        if path == "-":
            name = "stdin.txt"
        else:
            name = os.path.basename(path)
        dest = os.path.join(out_path, name)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(redact_text(raw, None))



_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(findings):
    """Return a SARIF 2.1.0 document for GitHub code scanning and other consumers."""
    used, seen = [], set()
    for f in findings:
        if f.rule not in seen:
            used.append(f.rule)
            seen.add(f.rule)
    rules = []
    for rid in used:
        if rid in RULES:
            sev, title = RULES[rid][0], RULES[rid][1]
        else:
            sev = getattr(next((x for x in findings if x.rule == rid), None), "severity", "medium")
            title = rid
        rules.append({
            "id": rid,
            "name": title,
            "shortDescription": {"text": title},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(sev, "note")},
        })
    results = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else {}
        uri = (
            d.get("source")
            or d.get("file")
            or getattr(f, "source", None)
            or getattr(f, "where", None)
            or "stdin"
        )
        line = d.get("line") or getattr(f, "line", None) or 1
        try:
            line = int(line) or 1
        except (TypeError, ValueError):
            line = 1
        results.append({
            "ruleId": f.rule,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": str(uri)},
                "region": {"startLine": line},
            }}],
            "properties": d,
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "piiguard",
                    "version": VERSION,
                    "informationUri": "https://github.com/dunkleschitz/agentsec",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }, indent=2) + "\n"

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="piiguard",
        description="Offline PII / sensitive-personal-data scanner for agent transcripts "
        "(emails, phones, SSN, cards, IDs, bank, DOB, address, medical). "
        "Complements tracesweep (secrets/API keys).",
    )
    ap.add_argument("paths", nargs="*", help="transcript files/dirs (.json/.jsonl/.txt), '-' for stdin")
    ap.add_argument("--as-text", action="store_true", help="treat inputs as plain text (paragraph = segment)")
    ap.add_argument("--disable", nargs="+", metavar="RULE", default=[], help="skip rule ids (e.g. PG10 PG01)")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")

    ap.add_argument(
        "--min-severity",
        default="info",
        choices=SEVERITIES,
        help="hide findings below this severity (default info)",
    )
    ap.add_argument(
        "--fail-on",
        default="high",
        choices=SEVERITIES + ["any", "none"],
        help="exit 1 if any finding >= severity (default high; any, none)",
    )
    ap.add_argument(
        "--redact",
        metavar="OUT",
        help="write redacted copy (file for one input, directory for many)",
    )
    ap.add_argument("--list-rules", action="store_true", help="print rules and exit")
    ap.add_argument("--version", action="version", version="piiguard %s" % VERSION)
    args = ap.parse_args(argv)

    if args.list_rules:
        for rid, (sev, title) in RULES.items():
            sys.stdout.write("%s\t%s\t%s\n" % (rid, sev, title))
        return 0

    if not args.paths:
        ap.print_usage(sys.stderr)
        sys.stderr.write("piiguard: error: at least one path (or '-') required\n")
        return 2

    try:
        inputs = collect_inputs(args.paths)
    except FileNotFoundError as e:
        sys.stderr.write("piiguard: error: not found: %s\n" % e)
        return 2
    if not inputs:
        sys.stderr.write("piiguard: error: no readable inputs\n")
        return 2

    disabled = set(args.disable or [])
    try:
        findings, raws, _n = analyze_paths(inputs, disabled=disabled, as_text=args.as_text)
    except OSError as e:
        sys.stderr.write("piiguard: error: %s\n" % e)
        return 2
    except ValueError as e:
        sys.stderr.write("piiguard: error: %s\n" % e)
        return 2

    shown = filter_findings(findings, args.min_severity)

    if args.redact:
        if len(raws) > 1 and os.path.isfile(args.redact):
            sys.stderr.write(
                "piiguard: error: --redact must be a directory when multiple inputs are given\n"
            )
            return 2
        try:
            _write_redacted(args.redact, raws)
        except OSError as e:
            sys.stderr.write("piiguard: error: redact write failed: %s\n" % e)
            return 2

    if args.json:
        payload = {
            "tool": "piiguard",
            "version": VERSION,
            "findings": [f.to_dict() for f in shown],
            "summary": {
                "count": len([f for f in shown if f.rule != "PG10"]),
                "worst": worst_severity([f for f in shown if f.rule != "PG10"]),
            },
        }
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    elif args.sarif:
        print(render_sarif(shown), end="")
    else:
        sys.stdout.write(format_text(shown))

    actionable = [f for f in shown if f.rule != "PG10"]
    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if actionable else 0
    floor = SEV_RANK[args.fail_on]
    if any(SEV_RANK[f.severity] >= floor for f in actionable):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
