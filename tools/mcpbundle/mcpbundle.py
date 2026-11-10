#!/usr/bin/env python3
"""mcpbundle: offline auditor for MCP server *packaging manifests*.

Reads MCP Bundle manifests (manifest.json inside a .mcpb / legacy .dxt archive, or
loose) and MCP Registry server.json entries, the files an MCP server author ships so
clients can install it in one click. Flags what the installer will run and trust:
inline secrets, credential prompts not marked sensitive, shell-wrapped or
pipe-to-shell launch commands, unpinned packages, cleartext remotes, privileged
container arguments, broad filesystem defaults, injection-shaped tool text, and
missing provenance.

Standard library only. It never installs, unpacks to disk, or contacts a registry.

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or input error.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import zipfile
from urllib.parse import urlsplit

VERSION = "0.1.0"
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "MB01": ("critical", "Secret-shaped literal value shipped in the manifest"),
    "MB02": ("high", "Credential-like user_config / env var not marked sensitive or secret"),
    "MB03": ("high", "Launch command runs through a shell or pipes a download into one"),
    "MB04": ("high", "Package or launcher argument is unpinned (no exact version)"),
    "MB05": ("high", "Remote endpoint or registry uses cleartext http:// on a non-loopback host"),
    "MB06": ("high", "Privileged or host-escaping container/runtime argument"),
    "MB07": ("medium", "Broad filesystem default (/, ~, $HOME, C:\\) for a directory setting or argument"),
    "MB08": ("medium", "Injection-shaped or hidden-Unicode text in tool/prompt/description fields"),
    "MB09": ("medium", "Remote endpoint points at a private, link-local, or cloud-metadata address"),
    "MB10": ("low", "Missing provenance (author, repository, or license)"),
    "MB11": ("low", "Tools or prompts generated at runtime, so the declared list cannot be reviewed"),
    "MB12": ("info", "Inventory of manifests found"),
}

SECRET_NAME = re.compile(r"(?i)(token|secret|passw(or)?d|api[_-]?key|apikey|private[_-]?key|credential|auth|bearer|session|cookie|access[_-]?key)")
SECRET_VALUE = re.compile(
    r"(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
    r"|FAKE-EXAMPLE-[A-Za-z0-9-]+)")
PLACEHOLDER = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|<[^>]+>|\{[^}]+\}|your[_ -].*|changeme|xxx+|\*+|)\s*$", re.I)
SHELLS = {"sh", "bash", "zsh", "dash", "ash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
SHELL_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-enc", "-e"}
PIPE_SHELL = re.compile(r"(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;]*\|\s*(sudo\s+)?(sh|bash|zsh|iex|invoke-expression|python3?|node)\b", re.I)
LAUNCHERS = {"npx": "npm", "bunx": "npm", "pnpx": "npm", "uvx": "pypi", "pipx": "pypi"}
PRIV_ARGS = re.compile(r"^(--privileged|--pid=host|--network=host|--net=host|--ipc=host|--cap-add(=.*)?|--security-opt=.*unconfined.*|--userns=host|--device(=.*)?)$", re.I)
HOST_MOUNT = re.compile(r"(^|[\s=])(/|/var/run/docker\.sock|/etc|/root|/home|~|\$HOME|\$\{HOME\})(:|$)")
BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "${HOME}/", "c:\\", "c:/", "%userprofile%", "/home", "/users", "/root", "${user_home}"}
INJECTION = re.compile(
    r"(?i)(ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard (the|all|your) (instructions|rules|system)"
    r"|do not (tell|inform|mention to) the user|without (telling|asking|informing) the user|you must (always )?(first )?(call|run|read|send)"
    r"|<\s*(important|system|instructions)\s*>|\bsystem prompt\b|before using any other tool|read (~|\$HOME)?/?\.(ssh|aws|env)"
    r"|send (it|them|the contents) to)")
HIDDEN = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000E0000-\U000E007F]")
LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


def mask(v) -> str:
    s = str(v)
    return "****" if len(s) <= 8 else s[:4] + "…" + "****"


class Finding:
    def __init__(self, rule, file, pointer, message, severity=None, line=1):
        self.rule, self.file, self.pointer, self.message = rule, file, pointer, message
        self.severity = severity or RULES[rule][0]
        self.line = line

    def as_dict(self):
        return {"rule": self.rule, "severity": self.severity, "file": self.file,
                "pointer": self.pointer, "line": self.line, "message": self.message}


def find_line(text: str, needle: str) -> int:
    if not needle or not text:
        return 1
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def g(d, *keys, default=None):
    """Get the first present key (snake_case or camelCase variants)."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d:
            return d[k]
    return default


def classify(doc) -> str:
    if not isinstance(doc, dict):
        return ""
    if "packages" in doc or "remotes" in doc or "server.schema.json" in str(doc.get("$schema", "")):
        return "server.json"
    if ("manifest_version" in doc or "dxt_version" in doc) or ("server" in doc and isinstance(doc.get("server"), dict)
                                                               and ("mcp_config" in doc["server"] or "entry_point" in doc["server"])):
        return "mcpb"
    return ""


def is_secret_literal(name: str, value) -> bool:
    if not isinstance(value, str) or PLACEHOLDER.match(value):
        return False
    if SECRET_VALUE.search(value):
        return True
    if re.search(r"\$\{[^}]*\}|\{[A-Za-z_][\w.]*\}|<[^>]+>", value):
        return False
    return bool(SECRET_NAME.search(name or "")) and len(value) >= 12 and not value.startswith(("http://", "https://", "/")) \
        and not re.fullmatch(r"(?i)(true|false|none|null|bearer|basic|header|query|[a-z_ -]+)", value)


def host_class(host: str) -> str:
    h = (host or "").strip("[]").lower()
    if h in LOOPBACK or h.endswith(".localhost"):
        return "loopback"
    if h in ("metadata.google.internal", "metadata"):
        return "metadata"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "internal" if h.endswith((".internal", ".local", ".lan", ".corp")) else "public"
    if ip.is_loopback:
        return "loopback"
    if str(ip) in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200") or ip.is_link_local:
        return "metadata"
    if ip.is_private or ip.is_unspecified:
        return "private"
    return "public"


class Auditor:
    def __init__(self, file, text, disabled):
        self.file, self.text, self.disabled, self.findings = file, text, set(disabled), []

    def add(self, rule, ptr, msg, needle="", sev=None):
        if rule in self.disabled:
            return
        self.findings.append(Finding(rule, self.file, ptr or "/", msg, sev, find_line(self.text, needle)))

    # ---- shared checks -------------------------------------------------
    def check_url(self, ptr, url, what="endpoint"):
        if not isinstance(url, str) or not url:
            return
        if "${" in url and "://" not in url.split("${")[0]:
            return
        try:
            parts = urlsplit(url)
        except ValueError:
            return
        hc = host_class(parts.hostname or "")
        if parts.scheme == "http" and hc != "loopback":
            self.add("MB05", ptr, "%s uses cleartext http:// (%s)" % (what, parts.hostname), url)
        if hc in ("private", "metadata", "internal"):
            self.add("MB09", ptr, "%s host %s is %s" % (what, parts.hostname, hc), url,
                     sev="high" if hc == "metadata" else None)
        if parts.username or parts.password:
            self.add("MB01", ptr, "%s embeds credentials in the URL userinfo" % what, url)

    def check_text(self, ptr, value):
        if not isinstance(value, str):
            return
        if HIDDEN.search(value):
            self.add("MB08", ptr, "hidden zero-width/bidi/TAG Unicode in text", "", sev="high")
        m = INJECTION.search(value)
        if m:
            self.add("MB08", ptr, "injection-shaped phrase: %r" % m.group(0)[:60], m.group(0))

    def check_command(self, ptr, command, args):
        args = [a for a in (args or []) if isinstance(a, str)]
        cmd = os.path.basename(str(command or "")).lower()
        joined = " ".join([str(command or "")] + args)
        if PIPE_SHELL.search(joined):
            self.add("MB03", ptr, "downloads and pipes into an interpreter", PIPE_SHELL.search(joined).group(0), sev="critical")
        elif cmd in SHELLS and any(a.lower() in SHELL_FLAGS for a in args):
            self.add("MB03", ptr, "launches through %s with an inline script" % cmd, str(command))
        if cmd in LAUNCHERS:
            pkgs = [a for a in args if not a.startswith("-")]
            if pkgs:
                self.check_launcher_pkg(ptr, LAUNCHERS[cmd], pkgs[0])
        if cmd in ("docker", "podman", "docker.exe"):
            self.check_container_args(ptr, args)
        for i, a in enumerate(args):
            if a.strip().lower().rstrip("/\\") in {p.rstrip("/\\") for p in BROAD_PATHS} or a.strip() == "/":
                self.add("MB07", "%s/args/%d" % (ptr, i), "argument grants a broad path %r" % a, a)

    def check_launcher_pkg(self, ptr, eco, spec):
        if eco == "npm":
            body = spec[1:] if spec.startswith("@") else spec
            ver = body.split("@", 1)[1] if "@" in body else ""
        else:
            m = re.search(r"==\s*([^\s,;]+)$", spec) or re.search(r"@([0-9][^\s]*)$", spec)
            ver = m.group(1) if m else ""
        if not ver or not re.match(r"^v?\d+(\.\d+)*([.-][0-9A-Za-z.]+)?$", ver):
            self.add("MB04", ptr, "%s package %r runs without an exact version" % (eco, spec), spec)

    def check_container_args(self, ptr, args):
        for i, a in enumerate(args):
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if PRIV_ARGS.match(a) or (a in ("--pid", "--network", "--net", "--ipc") and nxt == "host") or (a == "--cap-add" and nxt):
                self.add("MB06", "%s/args/%d" % (ptr, i), "privileged container flag %s" % (a if "=" in a or a == "--privileged" else a + " " + nxt), a)
            if a in ("-v", "--volume", "--mount") and HOST_MOUNT.search(nxt.split(",")[0].replace("source=", "")):
                self.add("MB06", "%s/args/%d" % (ptr, i + 1), "mounts a sensitive host path %r" % nxt, nxt)

    def check_env_map(self, ptr, env, sensitive_keys=()):
        if not isinstance(env, dict):
            return
        for k, v in env.items():
            if isinstance(v, str) and is_secret_literal(k, v) and not any(s in v for s in sensitive_keys):
                self.add("MB01", "%s/%s" % (ptr, k), "env %s ships a literal secret (%s)" % (k, mask(v)), v)

    # ---- MCP Bundle manifest ------------------------------------------
    def audit_mcpb(self, ptr, doc):
        name = doc.get("name") or doc.get("display_name") or "?"
        uc = doc.get("user_config") if isinstance(doc.get("user_config"), dict) else {}
        for key, spec in uc.items():
            if not isinstance(spec, dict):
                continue
            p = "%s/user_config/%s" % (ptr, key)
            label = " ".join(str(spec.get(x, "")) for x in ("title", "description")) + " " + key
            credlike = bool(SECRET_NAME.search(key) or SECRET_NAME.search(str(spec.get("title", ""))))
            if credlike and spec.get("type", "string") == "string" and not spec.get("sensitive"):
                self.add("MB02", p, "credential-like setting %r is not marked \"sensitive\": true (stored and shown in plaintext)" % key, '"%s"' % key)
            d = spec.get("default")
            if is_secret_literal(key, d):
                self.add("MB01", p + "/default", "default value for %r is a literal secret (%s)" % (key, mask(d)), d)
            if spec.get("type") == "directory" or "director" in label.lower() or "path" in key.lower():
                for dv in (d if isinstance(d, list) else [d]):
                    if isinstance(dv, str) and dv.strip().lower().rstrip("/\\") in {b.rstrip("/\\") for b in BROAD_PATHS} | {""} and dv.strip():
                        self.add("MB07", p + "/default", "directory default %r exposes the whole disk or home folder" % dv, dv)
            self.check_text(p + "/description", spec.get("description"))
        server = doc.get("server") if isinstance(doc.get("server"), dict) else {}
        mc = server.get("mcp_config") if isinstance(server.get("mcp_config"), dict) else {}
        configs = [("%s/server/mcp_config" % ptr, mc)]
        for plat, ov in (g(mc, "platform_overrides", "platformOverrides", default={}) or {}).items():
            if isinstance(ov, dict):
                configs.append(("%s/server/mcp_config/platform_overrides/%s" % (ptr, plat), ov))
        for p, c in configs:
            if c.get("command") or c.get("args"):
                self.check_command(p, c.get("command"), c.get("args"))
            self.check_env_map(p + "/env", c.get("env"))
        for kind in ("tools", "prompts"):
            for i, t in enumerate(doc.get(kind) or []):
                if isinstance(t, dict):
                    for f in ("description", "text", "name"):
                        self.check_text("%s/%s/%d/%s" % (ptr, kind, i, f), t.get(f))
        for f in ("description", "long_description"):
            self.check_text("%s/%s" % (ptr, f), doc.get(f))
        gen = [k for k in ("tools_generated", "prompts_generated") if doc.get(k) is True]
        if gen:
            self.add("MB11", ptr, "%s set: the declared list is not the full runtime surface" % ", ".join(gen), gen[0])
        missing = []
        if not (isinstance(doc.get("author"), dict) and doc["author"].get("name")):
            missing.append("author")
        if not g(doc, "repository") and not doc.get("homepage"):
            missing.append("repository")
        if not doc.get("license"):
            missing.append("license")
        if missing:
            self.add("MB10", ptr, "missing provenance: %s" % ", ".join(missing))
        for i, u in enumerate(doc.get("privacy_policies") or []):
            self.check_url("%s/privacy_policies/%d" % (ptr, i), u, "privacy policy URL")
        self.add("MB12", ptr, "MCP Bundle manifest %r (server type %s, %d user_config, %d tools)" % (
            name, server.get("type", "?"), len(uc), len(doc.get("tools") or [])))

    # ---- MCP Registry server.json -------------------------------------
    def audit_server_json(self, ptr, doc):
        name = doc.get("name", "?")
        self.check_text(ptr + "/description", doc.get("description"))
        for i, pkg in enumerate(doc.get("packages") or []):
            if not isinstance(pkg, dict):
                continue
            p = "%s/packages/%d" % (ptr, i)
            ident = g(pkg, "identifier", "name", default="?")
            ver = str(pkg.get("version") or "")
            rtype = str(g(pkg, "registry_type", "registryType", "registry_name", default="")).lower()
            if rtype not in ("mcpb", "oci", "docker") and (not ver or ver.lower() in ("latest", "*", "x") or re.search(r"[\^~*<>|x]|\s-\s", ver)):
                self.add("MB04", p, "package %s has no exact version (%r)" % (ident, ver or "missing"), str(ident))
            if rtype == "mcpb" and not g(pkg, "file_sha256", "fileSha256"):
                self.add("MB04", p, "mcpb package %s has no file_sha256 integrity pin" % ident, str(ident), sev="medium")
            if rtype in ("oci", "docker") and ":" not in str(ident).rsplit("/", 1)[-1] and "@sha256:" not in str(ident) and not ver:
                self.add("MB04", p, "container image %s is untagged" % ident, str(ident))
            self.check_url(p + "/registry_base_url", g(pkg, "registry_base_url", "registryBaseUrl"), "registry")
            self.check_url(p + "/transport/url", g(g(pkg, "transport", default={}) or {}, "url"), "transport")
            runtime = [str(g(a, "value", "default", default="")) for a in (g(pkg, "runtime_arguments", "runtimeArguments", default=[]) or []) if isinstance(a, dict)]
            runtime += [str(a.get("name", "")) + ("=" + str(a["value"]) if a.get("value") else "") for a in (g(pkg, "runtime_arguments", "runtimeArguments", default=[]) or []) if isinstance(a, dict) and a.get("type") == "named"]
            runtime = [r for r in runtime if r]
            hint = str(g(pkg, "runtime_hint", "runtimeHint", default="")).lower()
            if rtype in ("oci", "docker") or hint in ("docker", "podman"):
                self.check_container_args(p + "/runtime_arguments", runtime)
            if hint in SHELLS:
                self.add("MB03", p, "runtime_hint %s runs the package through a shell" % hint, hint)
            joined = " ".join(runtime)
            if PIPE_SHELL.search(joined):
                self.add("MB03", p, "runtime arguments pipe a download into an interpreter", PIPE_SHELL.search(joined).group(0), sev="critical")
            for a in (g(pkg, "package_arguments", "packageArguments", default=[]) or []):
                if isinstance(a, dict):
                    v = str(g(a, "value", "default", default=""))
                    if v.strip().lower().rstrip("/\\") in {b.rstrip("/\\") for b in BROAD_PATHS} or v.strip() == "/":
                        self.add("MB07", p + "/package_arguments", "argument default grants a broad path %r" % v, v)
            self.check_vars(p + "/environment_variables", g(pkg, "environment_variables", "environmentVariables", default=[]))
        for i, r in enumerate(doc.get("remotes") or []):
            if not isinstance(r, dict):
                continue
            p = "%s/remotes/%d" % (ptr, i)
            self.check_url(p + "/url", r.get("url"), "remote")
            self.check_vars(p + "/headers", r.get("headers"))
        repo = doc.get("repository")
        if not (isinstance(repo, dict) and repo.get("url")):
            self.add("MB10", ptr, "missing provenance: repository")
        self.add("MB12", ptr, "MCP Registry server.json %r (%d packages, %d remotes)" % (
            name, len(doc.get("packages") or []), len(doc.get("remotes") or [])))

    def check_vars(self, ptr, items):
        for j, ev in enumerate(items or []):
            if not isinstance(ev, dict):
                continue
            n = str(ev.get("name", ""))
            secret = g(ev, "is_secret", "isSecret", default=False)
            q = "%s/%d" % (ptr, j)
            if SECRET_NAME.search(n) and not secret and not re.fullmatch(r"(?i)(content-type|accept|user-agent|auth[_-]?(mode|type|method|url))", n):
                self.add("MB02", q, "%s looks like a credential but is not marked is_secret" % n, n)
            for f in ("value", "default"):
                v = ev.get(f)
                if is_secret_literal(n, v) or (n.lower() == "authorization" and isinstance(v, str) and re.match(r"(?i)(bearer|basic)\s+[^${}<\s]{8,}$", v)):
                    self.add("MB01", "%s/%s" % (q, f), "%s ships a literal secret %s (%s)" % (n, f, mask(v)), v)


def collect(data, ptr=""):
    kind = classify(data)
    if kind:
        yield ptr, kind, data
        return
    if isinstance(data, list):
        for i, item in enumerate(data):
            yield from collect(item, "%s/%d" % (ptr, i))
    elif isinstance(data, dict):
        for k in ("servers", "manifests", "items", "data"):
            if isinstance(data.get(k), (list, dict)):
                yield from collect(data[k], "%s/%s" % (ptr, k))
        if isinstance(data.get("server"), dict) and not kind:
            yield from collect(data["server"], ptr + "/server")


def audit_text(name, text, disabled=()):
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError("%s: not valid JSON (%s)" % (name, e))
    out = []
    for ptr, kind, doc in collect(data):
        a = Auditor(name, text, disabled)
        (a.audit_mcpb if kind == "mcpb" else a.audit_server_json)(ptr, doc)
        out.extend(a.findings)
    return out


def read_bundle(path):
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if n.rstrip("/").split("/")[-1] == "manifest.json"]
        if not names:
            raise ValueError("%s: archive has no manifest.json" % path)
        names.sort(key=lambda n: n.count("/"))
        info = z.getinfo(names[0])
        if info.file_size > 5_000_000:
            raise ValueError("%s: manifest.json too large" % path)
        return z.read(names[0]).decode("utf-8", "replace")


def iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in (".git", "node_modules", ".venv", "venv", "__pycache__"))
                for f in sorted(files):
                    if f in ("manifest.json", "server.json") or f.endswith((".mcpb", ".dxt")) or "mcpb" in f.lower() and f.endswith(".json"):
                        yield os.path.join(root, f)
        else:
            yield p


def audit_paths(paths, disabled=()):
    findings, errors, n = [], [], 0
    for path in iter_files(paths):
        try:
            if path == "-":
                text = sys.stdin.read()
            elif path.endswith((".mcpb", ".dxt")) or zipfile.is_zipfile(path):
                text = read_bundle(path)
            else:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            found = audit_text(path, text, disabled)
            n += 1
            findings.extend(found)
        except (OSError, ValueError, zipfile.BadZipFile) as e:
            errors.append(str(e))
    return findings, errors, n


def to_sarif(findings):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    used = sorted({f.rule for f in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcpbundle", "version": VERSION,
                "informationUri": "https://github.com/dunkleschitz/agentsec",
                "rules": [{"id": r, "shortDescription": {"text": RULES[r][1]},
                           "defaultConfiguration": {"level": level[RULES[r][0]]}} for r in used],
            }},
            "results": [{
                "ruleId": f.rule, "level": level[f.severity],
                "message": {"text": "%s (%s)" % (f.message, f.pointer)},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
                    "region": {"startLine": max(1, f.line)}}}],
                "properties": {"severity": f.severity},
            } for f in findings],
        }],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="mcpbundle", description="Offline auditor for MCP Bundle (.mcpb/.dxt manifest.json) and MCP Registry server.json files.")
    ap.add_argument("paths", nargs="*", help="files, directories, .mcpb/.dxt archives, or - for stdin")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this (default info)")
    ap.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="high", help="exit 1 at or above this severity (default high)")
    ap.add_argument("--disable", action="append", default=[], metavar="RULE", help="disable a rule (repeatable or comma-separated)")
    ap.add_argument("--list-rules", action="store_true", help="print rules and exit")
    ap.add_argument("--version", action="version", version="mcpbundle " + VERSION)
    args = ap.parse_args(argv)
    if args.list_rules:
        for r, (sev, desc) in RULES.items():
            print("%s  %-8s  %s" % (r, sev, desc))
        return 0
    if not args.paths:
        ap.print_usage(sys.stderr)
        sys.stderr.write("mcpbundle: error: no input paths\n")
        return 2
    disabled = {d.strip().upper() for x in args.disable for d in x.split(",") if d.strip()}
    unknown = disabled - set(RULES)
    if unknown:
        sys.stderr.write("mcpbundle: error: unknown rule(s): %s\n" % ", ".join(sorted(unknown)))
        return 2
    findings, errors, n = audit_paths(args.paths, disabled)
    for e in errors:
        sys.stderr.write("mcpbundle: %s\n" % e)
    if n == 0:
        sys.stderr.write("mcpbundle: error: no readable input\n")
        return 2
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[args.min_severity]]
    shown.sort(key=lambda f: (f.file, -SEV_RANK[f.severity], f.rule, f.pointer))
    if args.json:
        counts = {s: sum(1 for f in shown if f.severity == s) for s in SEVERITIES}
        print(json.dumps({"tool": "mcpbundle", "version": VERSION, "files": n, "counts": counts,
                          "findings": [f.as_dict() for f in shown]}, indent=2))
    elif args.sarif:
        print(json.dumps(to_sarif(shown), indent=2))
    else:
        if not shown:
            print("mcpbundle: no findings in %d file(s)" % n)
        for f in shown:
            print("%s:%d  %-8s %s  %s  [%s]" % (f.file, f.line, f.severity.upper(), f.rule, f.message, f.pointer))
        if shown:
            print("\n%d finding(s) in %d file(s)" % (len(shown), n))
    if args.fail_on != "none" and any(SEV_RANK[f.severity] >= SEV_RANK[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
