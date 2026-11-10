#!/usr/bin/env python3
"""shellfence: offline dangerous-shell-command auditor for AI agent transcripts.

Agents with Bash / shell / run_command / terminal tools can be steered into
pipe-to-shell installs, destructive wipes, privilege escalation, reverse shells,
encoded eval, force-pushes, publishes, and firewall changes. shellfence extracts
shell commands from saved transcripts (OpenAI, Anthropic, generic JSON/JSONL) or
from a plain command list, classifies each one, and reports findings with tool +
turn attribution.

Complements pathfence (file *paths* inside commands), fetchfence (URL destinations),
toolgate (policy you write), yolocheck (static autonomy settings) and hitlguard
(missing human approval). Stdlib only; never runs a command or contacts a network.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import shlex
import sys

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "SF01": ("critical", "Pipe-to-shell / remote script execution (curl|sh, wget|bash, irm|iex)"),
    "SF02": ("critical", "Destructive wipe / disk destroy (rm -rf /, mkfs, dd of=/dev)"),
    "SF03": ("high", "Privilege escalation (sudo, su -, doas, pkexec, runas)"),
    "SF04": ("critical", "Reverse shell / remote listener (nc -e, bash -i >& /dev/tcp, ncat)"),
    "SF05": ("critical", "Eval of encoded or remote content (base64|bash, eval $(curl), python -c download)"),
    "SF06": ("high", "Permission weakening (chmod 777, chmod -R a+rwx, chown world-writable)"),
    "SF07": ("high", "Dangerous git mutation (push --force, reset --hard, clean -fdx on broad trees)"),
    "SF08": ("high", "Publish / release / registry push (npm publish, twine upload, cargo publish, docker push)"),
    "SF09": ("high", "Firewall / network defense change (iptables -F, ufw disable, nft flush)"),
    "SF10": ("medium", "Environment / secret dump piped outbound (printenv|curl, env to remote)"),
    "SF11": ("medium", "Persistence install (crontab, systemd unit drop, rc.local, LaunchAgent)"),
    "SF12": ("info", "Inventory of shell commands observed in tool calls"),
    "SF13": ("high", "AI-agent permission-bypass flag (--dangerously-skip-permissions, --yolo, --trust-all-tools)"),
    "SF14": ("critical", "Destructive infra / data-plane command (terraform destroy -auto-approve, kubectl delete --force, DROP ... CASCADE)"),
    "SF15": ("high", "SSH authorized_keys or equivalent backdoor persistence"),
    "SF16": ("high", "Secret-harvest pipeline followed by a public exfil channel (scanner on / plus public repo/gist/upload)"),
}

SHELL_TOKENS = {
    "bash", "shell", "exec", "execute", "terminal", "powershell", "pwsh", "cmd",
    "run", "zsh", "sh", "fish", "command",
}

SHELL_CMD_KEYS = {
    "command", "cmd", "script", "code", "input", "argv", "shell", "bash", "line",
    "powershell", "pwsh",
}

# --- rule regexes (applied to a single normalized command string) ---

# SF01: curl/wget/fetch piped to a shell, or powershell IEX of remote
_SHELL_NAME = r"(?:(?:/(?:usr/)?(?:local/)?bin/)?(?:env\s+)?)?(?:sh|bash|zsh|dash|ksh|fish)"

PIPE_SHELL_RE = re.compile(
    r"(?ix)"
    r"("
    r"(?:curl|wget|fetch)\b[^\n|;]{0,200}\|\s*(?:sudo\s+)?" + _SHELL_NAME + r"\b"
    r"|"
    r"irm\b[^\n|;]{0,200}\|\s*iex\b"
    r"|"
    r"invoke-webrequest\b[^\n|;]{0,200}\|\s*invoke-expression\b"
    r"|"
    r"invoke-expression\s*\(\s*(?:irm|invoke-webrequest)\b"
    r"|"
    r"bash\s*<\s*\(\s*(?:curl|wget)\b"
    r"|"
    r"\bsource\s*<\s*\(\s*(?:curl|wget)\b"
    r")"
)

# SF02: destructive wipes
DESTRUCTIVE_RE = re.compile(
    r"(?ix)"
    r"("
    r"\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)*-(?:[a-zA-Z]*[rf][a-zA-Z]*)\s+(?:--\s+)?"
    r"(?:/|/\*|/\$\{?\w+\}?|/home(?:/|\b)|/Users(?:/|\b)|/var(?:/|\b)|/etc(?:/|\b)|"
    r"~/?\s*$|~/?\*|\$\{?HOME\}?(?:/|\b|\*)?)"
    r"|"
    r"\bfind\s+(?:\$\{?HOME\}?|~|/home(?:/|\b)|/Users(?:/|\b)|/)\b[^\n|;]{0,250}"
    r"(?:-delete\b|-exec\s+rm\b)"
    r"|"
    r"\brm\s+(?:-[a-zA-Z]+\s+)*(?:--no-preserve-root\b)"
    r"|"
    r"\bmkfs(?:\.\w+)?\b"
    r"|"
    r"\bdd\b[^\n|;]{0,80}\bof\s*=\s*/dev/(?:sd|nvme|vd|xvd|hd|disk)"
    r"|"
    r"\b(?:shred|wipefs)\b[^\n|;]{0,40}/dev/"
    r"|"
    r">\s*/dev/sd[a-z]\b"
    r"|"
    r"\b: \(\)\s*\{\s*:\|:&\s*\}\s*;:"  # fork bomb
    r")"
)

# SF03: privilege escalation
PRIV_ESC_RE = re.compile(
    r"(?ix)"
    r"(?<![A-Za-z0-9_])"
    r"("
    r"sudo\b|"
    r"doas\b|"
    r"pkexec\b|"
    r"su\s+-|su\s+\w+|su\s*$|"
    r"runas\b|"
    r"Start-Process\b[^\n|;]{0,40}-Verb\s+RunAs"
    r")"
)

# SF04: reverse shells
REV_SHELL_RE = re.compile(
    r"(?ix)"
    r"("
    r"/dev/tcp/\d|/dev/udp/\d|"
    r"bash\s+-i\b[^\n|;]{0,40}&?\s*>\s*&?\s*/dev/tcp/|"
    r"\bnc\b[^\n|;]{0,60}(?:-e|/bin/(?:ba)?sh)|"
    r"\bncat\b[^\n|;]{0,60}(?:-e|--exec|--sh-exec)|"
    r"\bsocat\b[^\n|;]{0,80}exec:"
    r"|"
    r"python(?:3)?\s+-c\s+.{0,40}socket.{0,80}(?:connect|bind).{0,80}(?:subprocess|pty|os\.dup)"
    r"|"
    r"powershell\b[^\n|;]{0,40}New-Object\s+System\.Net\.Sockets\.TCPClient"
    r")"
)

# SF05: encoded / remote eval
ENCODED_EVAL_RE = re.compile(
    r"(?ix)"
    r"("
    r"base64\s+(?:--?d(?:ecode)?|-[Dd])\b[^\n|;]{0,80}\|\s*(?:sh|bash|zsh|python|perl|ruby)\b"
    r"|"
    r"(?:echo|printf)\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+(?:--?d(?:ecode)?|-[Dd])"
    r"|"
    r"\beval\s*\$?\(\s*(?:curl|wget|cat)\b"
    r"|"
    r"\beval\s+[\"'].{0,20}base64"
    r"|"
    r"python(?:3)?\s+-c\s+[\"'].{0,30}(?:urllib|requests|urlopen).{0,60}(?:exec|system|popen)"
    r"|"
    r"perl\s+-e\s+.{0,40}(?:get\(|LWP).{0,40}(?:system|exec|eval)"
    r"|"
    r"openssl\s+(?:enc\s+-d|base64\s+-d)\b[^\n|;]{0,60}\|\s*(?:sh|bash)\b"
    r"|"
    r"xxd\s+-r\b[^\n|;]{0,40}\|\s*(?:sh|bash)\b"
    r")"
)

# SF06: chmod/chown weakening
PERMS_RE = re.compile(
    r"(?ix)"
    r"("
    r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:777|666|a\+rwx|a\+rw|o\+w|o\+rwx|0777|0666)\b"
    r"|"
    r"\bchmod\s+-R\s+(?:777|a\+rwx)\b"
    r"|"
    r"\bchown\s+(?:-[a-zA-Z]+\s+)*(?:[^:]+:)?(?:nobody|nfsnobody)\b"
    r"|"
    r"\bicacls\b[^\n|;]{0,60}\bEveryone:(?:F|M|W)"
    r")"
)

# SF07: dangerous git
GIT_DANGER_RE = re.compile(
    r"(?ix)"
    r"("
    r"\bgit\s+push\b[^\n|;]{0,80}--force(?!-with-lease)\b"
    r"|"
    r"\bgit\s+push\b[^\n|;]{0,40}-f\b"
    r"|"
    r"\bgit\s+reset\s+--hard\b"
    r"|"
    r"\bgit\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*d[a-zA-Z]*x?"
    r"|"
    r"\bgit\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*x[a-zA-Z]*d?"
    r"|"
    r"\bgit\s+checkout\s+--orphan\b"
    r"|"
    r"\bgit\s+filter-branch\b|\bgit\s+filter-repo\b"
    r"|"
    r"\bgit\s+push\b[^\n|;]{0,40}--delete\b"
    r")"
)

# SF08: publish / release
PUBLISH_RE = re.compile(
    r"(?ix)"
    r"("
    r"\bnpm\s+publish\b|"
    r"\bpnpm\s+publish\b|"
    r"\byarn\s+(?:npm\s+)?publish\b|"
    r"\btwine\s+upload\b|"
    r"\bpython\s+-m\s+twine\s+upload\b|"
    r"\bcargo\s+publish\b|"
    r"\bdocker\s+push\b|"
    r"\bpodman\s+push\b|"
    r"\bgh\s+release\s+create\b|"
    r"\bgem\s+push\b|"
    r"\bpip(?:i)?\s+upload\b|"
    r"\bhuggingface-cli\s+upload\b|"
    r"\baws\s+s3\s+(?:cp|sync)\b[^\n|;]{0,40}\bs3://"
    r")"
)

# SF09: firewall
FIREWALL_RE = re.compile(
    r"(?ix)"
    r"("
    r"\biptables\s+-F\b|\biptables\s+--flush\b|"
    r"\biptables\s+-P\s+(?:INPUT|FORWARD|OUTPUT)\s+ACCEPT\b|"
    r"\bnft\s+flush\b|"
    r"\bufw\s+disable\b|\bufw\s+--force\s+reset\b|"
    r"\bfirewall-cmd\s+--panic-off\b|"
    r"\bSet-NetFirewallProfile\b[^\n|;]{0,40}Enabled\s+\$false|"
    r"\bnetsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off\b"
    r")"
)

# SF10: env dump outbound
ENV_EXFIL_RE = re.compile(
    r"(?ix)"
    r"("
    r"\b(?:printenv|env|export)\b[^\n|;]{0,40}\|\s*(?:curl|wget|nc|ncat|ssh)\b"
    r"|"
    r"\bcurl\b[^\n|;]{0,120}\b(?:\$\{?(?:AWS_|OPENAI_|ANTHROPIC_|GITHUB_|STRIPE_|SECRET|TOKEN|PASSWORD|API_KEY)[^|}]*\}?)"
    r"|"
    r"\bcurl\b[^\n|;]{0,80}-d\s+[\"']?\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)"
    r"|"
    r"\bwget\b[^\n|;]{0,80}--post-data\s*[\"']?\$\{?\w*(?:KEY|TOKEN|SECRET)"
    r"|"
    r"\b(?:dig|nslookup|host)\b[^\n|;]{0,200}\$(?:\{)?[A-Za-z_][A-Za-z0-9_]*"
    r"|"
    r"\b(?:dig|nslookup|host)\b[^\n|;]{0,200}"
    r"(?:collector|oast(?:ify)?|dnslog|exfil|burpcollab|interact\.sh|canarytokens|\boob\b)"
    r")"
)

# SF11: persistence
PERSIST_RE = re.compile(
    r"(?ix)"
    r"("
    r"\bcrontab\s+-[ei]\b|"
    r"\bcrontab\s+-\s*$|"
    r"\becho\b[^\n|;]{0,80}\|\s*crontab\b|"
    r"(?:^|[;&|]\s*)crontab\s+<<"
    r"|"
    r"/etc/cron\.(?:d|daily|hourly)/|"
    r"/etc/systemd/system/[^/\s]+\.service\b|"
    r"systemctl\s+(?:enable|link)\b|"
    r"/etc/rc\.local\b|"
    r"~/Library/LaunchAgents/|"
    r"/Library/LaunchDaemons/|"
    r"schtasks\s+/create\b|"
    r"New-Service\b"
    r")"
)

PLACEHOLDER_RE = re.compile(
    r"(?i)^(null|none|n/?a|todo|tbd|example|placeholder|"
    r"\$\{?[A-Z0-9_]+\}?|<[^>]+>|your[-_].*|xxx+)$"
)


class Finding:
    __slots__ = ("rule", "severity", "source", "message", "command", "tool", "turn")

    def __init__(self, rule, source, message, command="", tool="", turn=None):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.command = command
        self.tool = tool
        self.turn = turn

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "command": self.command,
            "tool": self.tool,
        }
        if self.turn is not None:
            d["turn"] = self.turn
        return d


class ShellEvent:
    __slots__ = ("source", "tool", "turn", "command")

    def __init__(self, source, tool, command, turn=None):
        self.source = source
        self.tool = tool
        self.command = command
        self.turn = turn


def _tool_words(name: str):
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", name) if w]


def is_shell_tool(name: str) -> bool:
    words = set(_tool_words(name))
    if words & SHELL_TOKENS:
        return True
    lower = (name or "").lower()
    return any(
        t in lower
        for t in (
            "bash", "shell", "run_command", "execute_command", "run_terminal",
            "powershell", "pwsh", "terminal_cmd", "run_shell", "shell_command",
        )
    )


def _parse_args(raw):
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            val = json.loads(raw)
            return val if isinstance(val, dict) else {"_": val}
        except ValueError:
            return {"_": raw}
    return {"_": raw}


def _iter_messages(doc):
    if isinstance(doc, dict):
        if isinstance(doc.get("messages"), list):
            return doc["messages"]
        if isinstance(doc.get("items"), list):
            return doc["items"]
    if isinstance(doc, list):
        return doc
    return None


def _cmd_from_args(args: dict) -> str:
    if not args:
        return ""
    for key in ("command", "cmd", "script", "shell", "bash", "powershell", "line", "code", "input"):
        v = args.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            return " ".join(v)
    argv = args.get("argv")
    if isinstance(argv, list) and argv and all(isinstance(x, (str, int, float)) for x in argv):
        return " ".join(str(x) for x in argv)
    # single anonymous string
    if "_" in args and isinstance(args["_"], str):
        return args["_"].strip()
    return ""


def extract_commands_from_obj(doc, source: str):
    events = []
    msgs = _iter_messages(doc)
    if msgs is not None:
        for i, msg in enumerate(msgs):
            if not isinstance(msg, dict):
                continue
            tcalls = msg.get("tool_calls") or msg.get("function_call")
            if tcalls:
                if isinstance(tcalls, dict):
                    tcalls = [tcalls]
                for tc in tcalls:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function") or tc
                    name = fn.get("name") or tc.get("name") or ""
                    args = _parse_args(fn.get("arguments") or tc.get("arguments") or tc.get("input"))
                    if is_shell_tool(name):
                        cmd = _cmd_from_args(args)
                        if cmd:
                            events.append(ShellEvent(source, name, cmd, turn=i))
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") in ("tool_use", "tool_call", "function_call"):
                        name = block.get("name") or ""
                        args = _parse_args(block.get("input") or block.get("arguments") or {})
                        if is_shell_tool(name):
                            cmd = _cmd_from_args(args)
                            if cmd:
                                events.append(ShellEvent(source, name, cmd, turn=i))
            role = (msg.get("role") or "").lower()
            if role in ("assistant", "tool", "") and msg.get("tool"):
                name = msg.get("tool") or msg.get("name") or ""
                args = _parse_args(msg.get("args") or msg.get("arguments") or msg.get("input"))
                if is_shell_tool(name):
                    cmd = _cmd_from_args(args)
                    if cmd:
                        events.append(ShellEvent(source, name, cmd, turn=i))
        return events

    if isinstance(doc, dict):
        name = doc.get("tool") or doc.get("name") or doc.get("tool_name") or ""
        args = _parse_args(
            doc.get("args") or doc.get("arguments") or doc.get("input") or doc.get("parameters")
        )
        cmd = _cmd_from_args(args)
        if not cmd:
            for k in ("command", "cmd", "script"):
                if isinstance(doc.get(k), str) and doc.get(k).strip():
                    cmd = doc[k].strip()
                    break
            if cmd:
                name = name or "shell"
        if cmd and (not name or is_shell_tool(name) or "command" in doc or "cmd" in doc):
            events.append(ShellEvent(source, name or "shell", cmd, turn=doc.get("turn")))
    return events


def load_events(path: str, as_commands: bool = False):
    """Load shell events from a file path or '-' (stdin)."""
    if path == "-":
        raw = sys.stdin.read()
        source = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        source = path

    if as_commands or path.endswith(".txt"):
        events = []
        for line_no, line in enumerate(raw.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if PLACEHOLDER_RE.match(s):
                continue
            events.append(ShellEvent("%s:%d" % (source, line_no), "command-list", s, turn=line_no))
        if as_commands or path.endswith(".txt"):
            return events

    events = []
    lines = raw.splitlines()
    jsonl_ok = False
    if len(lines) > 1:
        parsed_lines = []
        for line in lines:
            s = line.strip()
            if not s:
                continue
            try:
                parsed_lines.append(json.loads(s))
                jsonl_ok = True
            except ValueError:
                jsonl_ok = False
                break
        if jsonl_ok:
            for i, obj in enumerate(parsed_lines):
                ev = extract_commands_from_obj(obj, source)
                for e in ev:
                    if e.turn is None:
                        e.turn = i
                events.extend(ev)
            return events

    try:
        doc = json.loads(raw)
    except ValueError:
        events = []
        for line_no, line in enumerate(raw.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            events.append(ShellEvent("%s:%d" % (source, line_no), "command-list", s, turn=line_no))
        return events

    return extract_commands_from_obj(doc, source)


def _decode_shell_escapes(s: str) -> str:
    """Decode ANSI-C quoting (``$'...'``) and loose ``\\xHH`` / ``\\nnn`` escapes.

    Applied a few times so double-escaped payloads such as ``$'\\x72\\x6d...'``
    still collapse to the underlying command before the rule regexes run.
    """
    def hex_replace(m):
        return chr(int(m.group(1), 16))

    def oct_replace(m):
        return chr(int(m.group(1), 8) & 0xFF)

    def ansi_body(m):
        return _decode_shell_escapes(m.group(1))

    out = s
    for _ in range(6):
        nxt = re.sub(r"\$'((?:\\.|[^'\\])*)'", ansi_body, out)
        # Prefer double-backslash hex (JSON-escaped $'\\x72...') then single.
        nxt = re.sub(r"\\\\x([0-9A-Fa-f]{2})", hex_replace, nxt)
        nxt = re.sub(r"\\x([0-9A-Fa-f]{2})", hex_replace, nxt)
        nxt = re.sub(r"\\([0-7]{3})", oct_replace, nxt)
        if nxt == out:
            break
        out = nxt
    return out


def _normalize_cmd(cmd: str) -> str:
    """Light normalize for matching: undo trivial obfuscation, collapse whitespace.

    Handles empty quotes used to break tokens (``b''ash``), ``$IFS`` as a
    separator, ANSI-C / hex escapes, and simple ``{ cmd; }`` / ``( cmd )``
    groups. The goal is to let SF01/SF02 see the underlying command after
    those wrappers, not to fully parse the shell.
    """
    if not cmd:
        return ""
    s = cmd.strip()
    s = s.replace("\\\n", " ")
    s = _decode_shell_escapes(s)
    # ${IFS} / $IFS used in place of whitespace or to split a token
    s = re.sub(r"\$\{IFS\}|\$IFS", " ", s)
    # Quoted empty strings inserted to break a word: b''ash, ba""sh
    s = re.sub(r"['\"]['\"]", "", s)
    # $'bash' / 'bash' / "bash" around a simple pathname or command word
    s = re.sub(r"\$?['\"]([A-Za-z0-9_./-]+)['\"]", r"\1", s)
    # Unwrap simple brace / subshell groups a few times for light nesting
    for _ in range(4):
        nxt = re.sub(r"\{\s*([^{}|;]+?)\s*;\s*\}", r"\1", s)
        nxt = re.sub(r"\(\s*([^()|;]+?)\s*\)", r"\1", nxt)
        if nxt == s:
            break
        s = nxt
    s = re.sub(r"[ \t]+", " ", s)
    return s


def _snippet(cmd: str, limit: int = 120) -> str:
    s = _normalize_cmd(cmd)
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."



AI_BYPASS_RE = re.compile(
    r"(?ix)"
    r"("
    r"--dangerously-skip-permissions\b"
    r"|"
    r"--trust-all-tools\b"
    r"|"
    r"--allow-all(?:-tools)?\b"
    r"|"
    r"\b(?:gemini|google-gemini)(?:-cli)?\b[^\n|;]{0,80}--yolo\b"
    r"|"
    r"\b(?:claude|claude[-_]?code)\b[^\n|;]{0,80}--dangerously-skip-permissions\b"
    r"|"
    r"\b(?:q|amazon-?q)\b[^\n|;]{0,80}(?:--trust-all-tools|--no-interactive)\b"
    r")"
)

INFRA_DESTROY_RE = re.compile(
    r"(?ix)"
    r"("
    r"\bterraform\s+destroy\b[^\n|;]{0,120}-auto-approve\b"
    r"|"
    r"\bkubectl\s+delete\b[^\n|;]{0,160}(?:--force\b|--grace-period\s*=\s*0\b)"
    r"|"
    r"\bdrop\s+(?:schema|database|table)\b[^\n|;]{0,80}\bcascade\b"
    r"|"
    r"\bdrop\s+schema\b[^\n|;]{0,40}\bproduction\b"
    r")"
)

AUTHORIZED_KEYS_RE = re.compile(
    r"(?ix)"
    r"("
    r"(?:>>|tee\s+-a)\s+[^\n|;]*authorized_keys\b"
    r"|"
    r"authorized_keys\b[^\n|;]{0,40}(?:>>|tee\s+-a)"
    r"|"
    r"echo\s+[^\n|;]{0,200}>>\s*[^\n|;]*\.ssh/authorized_keys\b"
    r")"
)

SECRET_SCANNER_RE = re.compile(
    r"(?ix)"
    r"\b(?:trufflehog|gitleaks|ggshield|git-secrets|noseyparker|detect-secrets)\b"
)
BROAD_SCAN_ROOT_RE = re.compile(
    r"(?ix)(?:\s|^)(?:/|/\$?HOME\b|~(?:/|$)|/home(?:/|\b)|/Users(?:/|\b)|filesystem\s+/)"
)
PUBLIC_EXFIL_RE = re.compile(
    r"(?ix)"
    r"("
    r"\bgh\s+repo\s+create\b[^\n|;]{0,80}--public\b"
    r"|"
    r"\bgh\s+gist\s+create\b"
    r"|"
    r"\bgit\s+push\b[^\n|;]{0,40}\b(?:--set-upstream|-u)\b"
    r"|"
    r"\bcurl\b[^\n|;]{0,80}\b-X\s*POST\b"
    r")"
)

PS_ENCODED_RE = re.compile(
    r"(?ix)"
    r"(?:powershell|pwsh)\b[^\n|;]{0,200}(?:-encodedcommand|-enc|-ec)\s+([A-Za-z0-9+/]{20,}={0,2})"
    r"|"
    r"(?:-encodedcommand|-enc)\s+([A-Za-z0-9+/]{20,}={0,2})"
)
PS_BYPASS_RE = re.compile(
    r"(?ix)(?:powershell|pwsh)\b[^\n|;]{0,80}-executionpolicy\s+bypass\b"
)


def _split_segments(cmd: str) -> list:
    parts = re.split(r"(?:&&|\|\||(?<!\|);|\n)", cmd)
    return [p.strip() for p in parts if p.strip()]


def _tokens(seg: str) -> list:
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()


def _decode_ps_encoded(cmd: str) -> str | None:
    m = PS_ENCODED_RE.search(cmd)
    if not m:
        return None
    blob = next(g for g in m.groups() if g)
    pad = (-len(blob)) % 4
    try:
        raw = base64.b64decode(blob + ("=" * pad), validate=False)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-16-le", "utf-16", "utf-8"):
        try:
            s = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if any(c.isprintable() or c in "\r\n\t" for c in s) and len(s.strip()) >= 4:
            return s
    return None


def _python_reverse_shell(cmd: str) -> bool:
    if not re.search(r"(?i)\bpython(?:3)?\b", cmd):
        return False
    low = cmd.lower()
    if "socket" not in low:
        return False
    return bool(re.search(r"(?i)(?:pty|dup2|subprocess|connect\s*\(|/dev/tcp)", cmd))


def classify_command(command: str, source: str, tool: str = "", turn=None, disabled=None):

    """Return findings for one shell command."""
    disabled = set(disabled or [])
    findings = []
    raw = (command or "").strip()
    if not raw or PLACEHOLDER_RE.match(raw):
        return findings
    n = _normalize_cmd(raw)

    def add(rule, message):
        if rule in disabled:
            return
        findings.append(
            Finding(rule, source, message, command=_snippet(raw), tool=tool, turn=turn)
        )

    if PIPE_SHELL_RE.search(n):
        add("SF01", "Pipe-to-shell / remote script execution: %s" % _snippet(n, 90))

    if DESTRUCTIVE_RE.search(n):
        add("SF02", "Destructive wipe / disk destroy pattern: %s" % _snippet(n, 90))

    if PRIV_ESC_RE.search(n):
        add("SF03", "Privilege escalation token in command: %s" % _snippet(n, 90))

    if REV_SHELL_RE.search(n) or _python_reverse_shell(n):
        add("SF04", "Reverse shell / remote listener pattern: %s" % _snippet(n, 90))

    ps_decoded = _decode_ps_encoded(n) or _decode_ps_encoded(raw)
    if ENCODED_EVAL_RE.search(n) or PS_ENCODED_RE.search(n) or PS_BYPASS_RE.search(n):
        add("SF05", "Encoded/remote eval pattern: %s" % _snippet(n, 90))
    elif ps_decoded and ENCODED_EVAL_RE.search(_normalize_cmd(ps_decoded)):
        add("SF05", "PowerShell EncodedCommand decodes to remote/eval content: %s" % _snippet(ps_decoded, 90))

    if PERMS_RE.search(n):
        add("SF06", "Permission-weakening chmod/chown/icacls: %s" % _snippet(n, 90))

    if GIT_DANGER_RE.search(n):
        add("SF07", "Dangerous git mutation: %s" % _snippet(n, 90))

    if PUBLISH_RE.search(n):
        add("SF08", "Publish / release / registry push: %s" % _snippet(n, 90))

    if FIREWALL_RE.search(n):
        add("SF09", "Firewall / network defense change: %s" % _snippet(n, 90))

    if ENV_EXFIL_RE.search(n):
        add("SF10", "Environment/secret dump piped outbound: %s" % _snippet(n, 90))

    if PERSIST_RE.search(n):
        add("SF11", "Persistence install pattern: %s" % _snippet(n, 90))

    if AI_BYPASS_RE.search(n):
        add("SF13", "AI-agent permission-bypass flag: %s" % _snippet(n, 90))

    if INFRA_DESTROY_RE.search(n):
        add("SF14", "Destructive infra / data-plane command: %s" % _snippet(n, 90))

    if AUTHORIZED_KEYS_RE.search(n):
        add("SF15", "SSH authorized_keys backdoor persistence: %s" % _snippet(n, 90))

    # Pipeline reasoning: secret scanner over a broad root + a public exfil sink,
    # even when the two appear in adjacent list segments rather than one regex.
    segments = _split_segments(n)
    has_broad_scan = any(SECRET_SCANNER_RE.search(seg) and BROAD_SCAN_ROOT_RE.search(seg) for seg in segments)         or (SECRET_SCANNER_RE.search(n) and BROAD_SCAN_ROOT_RE.search(n))
    has_public = any(PUBLIC_EXFIL_RE.search(seg) for seg in segments) or PUBLIC_EXFIL_RE.search(n)
    if has_broad_scan and has_public:
        add("SF16", "Secret-harvest pipeline followed by a public exfil channel: %s" % _snippet(n, 90))

    # Re-run selected regexes on a decoded PowerShell body so obfuscation
    # through -EncodedCommand still hits SF01/SF04/etc.
    if ps_decoded:
        inner = _normalize_cmd(ps_decoded)
        if PIPE_SHELL_RE.search(inner):
            add("SF01", "Decoded PowerShell downloads and executes a remote script: %s" % _snippet(inner, 90))
        if REV_SHELL_RE.search(inner) or _python_reverse_shell(inner):
            add("SF04", "Decoded PowerShell reverse shell: %s" % _snippet(inner, 90))

    return findings


def collect_paths(args_paths):
    paths = []
    for p in args_paths:
        if p == "-":
            paths.append(p)
            continue
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [
                    d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")
                ]
                for fn in sorted(files):
                    if fn.endswith((".json", ".jsonl", ".txt", ".md")):
                        paths.append(os.path.join(root, fn))
        else:
            paths.append(p)
    return paths


def format_table(findings, events_count):
    lines = []
    lines.append(
        "shellfence %s — %d shell command(s), %d finding(s)"
        % (VERSION, events_count, len(findings))
    )
    if not findings:
        lines.append("No dangerous-shell findings.")
        return "\n".join(lines)
    lines.append("")
    lines.append("%-6s %-8s %-18s %s" % ("RULE", "SEV", "TOOL", "MESSAGE"))
    lines.append("-" * 96)
    for f in findings:
        lines.append(
            "%-6s %-8s %-18s %s"
            % (f.rule, f.severity, (f.tool or "-")[:18], f.message[:80])
        )
        lines.append("       cmd:  %s" % f.command)
        if f.source:
            loc = f.source
            if f.turn is not None:
                loc += " turn=%s" % f.turn
            lines.append("       at:   %s" % loc)
    return "\n".join(lines)



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
                    "name": "shellfence",
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
        prog="shellfence",
        description="Offline dangerous-shell-command auditor for AI agent transcripts.",
    )
    ap.add_argument(
        "paths",
        nargs="*",
        help="transcripts, command lists, or directories (or - for stdin)",
    )
    ap.add_argument(
        "--as-commands",
        action="store_true",
        help="treat inputs as plain shell-command lists (one per line)",
    )
    ap.add_argument(
        "--allow-command",
        action="append",
        default=[],
        metavar="GLOB",
        help="fnmatch allowlist for full command string (repeatable)",
    )
    ap.add_argument("--disable", nargs="+", default=[], metavar="RULE", help="skip rule ids")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")

    ap.add_argument("--min-severity", default="info", choices=SEVERITIES)
    ap.add_argument(
        "--fail-on",
        default="high",
        choices=SEVERITIES + ["any", "none"],
        help="exit 1 if any finding >= this severity (default high)",
    )
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="shellfence " + VERSION)
    ns = ap.parse_args(argv)

    if ns.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0

    if not ns.paths:
        ap.print_help()
        return 2

    file_paths = collect_paths(ns.paths)
    if not file_paths:
        sys.stderr.write("shellfence: no readable inputs\n")
        return 2

    import fnmatch

    all_events = []
    errors = 0
    for path in file_paths:
        try:
            all_events.extend(load_events(path, as_commands=ns.as_commands))
        except OSError as e:
            sys.stderr.write("shellfence: %s: %s\n" % (path, e))
            errors += 1

    if errors and not all_events:
        return 2

    def allowed(cmd: str) -> bool:
        if not ns.allow_command:
            return False
        n = _normalize_cmd(cmd)
        for g in ns.allow_command:
            if fnmatch.fnmatch(n, g):
                return True
        return False

    findings = []
    disabled = set(ns.disable or [])
    for ev in all_events:
        if allowed(ev.command):
            continue
        findings.extend(
            classify_command(
                ev.command, ev.source, tool=ev.tool, turn=ev.turn, disabled=disabled
            )
        )

    # SF12 inventory
    if "SF12" not in disabled:
        seen = set()
        for ev in all_events:
            key = _normalize_cmd(ev.command)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    "SF12",
                    ev.source,
                    "Observed shell command %r" % _snippet(ev.command, 100),
                    command=_snippet(ev.command),
                    tool=ev.tool,
                    turn=ev.turn,
                )
            )

    min_rank = SEV_RANK[ns.min_severity]
    shown = [f for f in findings if SEV_RANK[f.severity] >= min_rank]
    shown.sort(key=lambda f: (-SEV_RANK[f.severity], f.rule, f.command or "", f.tool or ""))

    if ns.json:
        print(
            json.dumps(
                {
                    "tool": "shellfence",
                    "version": VERSION,
                    "events": len(all_events),
                    "commands": [_normalize_cmd(e.command) for e in all_events],
                    "findings": [f.to_dict() for f in shown],
                },
                indent=2,
            )
        )
    elif ns.sarif:
        print(render_sarif(shown), end="")
    else:
        print(format_table(shown, len(all_events)))

    actionable = [f for f in shown if f.rule != "SF12"]
    if ns.fail_on == "none":
        return 0
    if ns.fail_on == "any":
        return 1 if actionable else 0
    threshold = SEV_RANK[ns.fail_on]
    pool = shown if ns.fail_on == "info" else actionable
    if any(SEV_RANK[f.severity] >= threshold for f in pool):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
