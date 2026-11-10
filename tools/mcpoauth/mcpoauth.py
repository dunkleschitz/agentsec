#!/usr/bin/env python3
"""mcpoauth: offline auditor for MCP server OAuth discovery metadata.

Checks OAuth 2.0 Protected Resource Metadata (RFC 9728, served by an MCP server at
/.well-known/oauth-protected-resource) and Authorization Server Metadata (RFC 8414 /
OpenID Connect discovery) against what the MCP authorization spec expects:
PKCE with S256, no implicit or password grants, HTTPS everywhere except loopback,
no tokens in URLs, a resource identifier that matches the server, and no secrets
or private keys published in metadata.

Standard library only. It never connects to a network; you supply saved JSON.

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or input error.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from urllib.parse import urlsplit

VERSION = "0.1.0"
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "MO01": ("critical", "Authorization server does not support PKCE S256 (missing or no S256)"),
    "MO02": ("high", "PKCE 'plain' method advertised"),
    "MO03": ("high", "Implicit flow advertised (response_type token / implicit grant)"),
    "MO04": ("high", "Resource-owner password grant advertised"),
    "MO05": ("high", "Endpoint or identifier uses cleartext http:// on a non-loopback host"),
    "MO06": ("medium", "Issuer is malformed (not https, or has query/fragment)"),
    "MO07": ("high", "Bearer tokens accepted in the URL query string"),
    "MO08": ("high", "Protected resource metadata incomplete (no authorization_servers or resource)"),
    "MO09": ("high", "Resource identifier does not match the expected MCP server URL"),
    "MO10": ("medium", "Overly broad scope advertised (*, all, admin, root, full access)"),
    "MO11": ("critical", "Secret or private key material published in metadata"),
    "MO12": ("high", "Endpoint points at a private, link-local, or cloud-metadata address"),
    "MO13": ("info", "Open dynamic client registration endpoint (review confused-deputy risk)"),
    "MO14": ("info", "Inventory of metadata documents found"),
    "MO15": ("critical", "JWT none algorithm advertised for token or request signing"),
}

URL_FIELDS = (
    "issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint",
    "jwks_uri", "introspection_endpoint", "revocation_endpoint", "userinfo_endpoint",
    "device_authorization_endpoint", "pushed_authorization_request_endpoint",
    "end_session_endpoint", "resource", "resource_documentation",
)
AS_KEYS = {"issuer", "authorization_endpoint", "token_endpoint", "code_challenge_methods_supported",
           "grant_types_supported", "response_types_supported"}
PR_KEYS = {"resource", "authorization_servers", "bearer_methods_supported",
           "resource_signing_alg_values_supported"}
BROAD_SCOPES = {"*", "all", "admin", "root", "superuser", "full_access", "full-access",
                "fullaccess", "god", "any", "everything", "write:*", "read:*", "*:*",
                "delete_repo", "delete:repo", "repo:delete", "admin:org", "admin:enterprise",
                "admin:repo", "write:packages", "administration"}
SECRET_KEYS = {"client_secret", "secret", "password", "private_key", "api_key", "apikey",
               "access_token", "refresh_token", "initial_access_token",
               "registration_access_token", "dcr_access_token", "registration_token"}
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")



def is_broad_scope(scope: str) -> bool:
    s = (scope or "").strip().lower()
    if not s:
        return False
    if s in BROAD_SCOPES:
        return True
    if s.startswith("admin:") or s.endswith(":admin") or s.startswith("delete:"):
        return True
    if "delete_repo" in s or s.endswith(":delete"):
        return True
    return False

def mask(value) -> str:
    s = str(value)
    if len(s) <= 6:
        return "***"
    return s[:4] + "…" + s[-2:]


class Finding:
    def __init__(self, rule, file, pointer, message, severity=None, line=1):
        self.rule = rule
        self.severity = severity or RULES[rule][0]
        self.file = file
        self.pointer = pointer
        self.message = message
        self.line = line

    def as_dict(self):
        return {"rule": self.rule, "severity": self.severity, "file": self.file,
                "pointer": self.pointer, "line": self.line, "message": self.message,
                "title": RULES[self.rule][1]}


def find_line(text: str, needle: str) -> int:
    if not needle:
        return 1
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return 1


def host_class(host: str) -> str:
    """Return 'loopback', 'metadata', 'private', or 'public' for a URL host."""
    h = (host or "").strip("[]").lower()
    if h in ("localhost",) or h.endswith(".localhost"):
        return "loopback"
    if h in ("metadata.google.internal", "metadata"):
        return "metadata"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        if h.endswith((".internal", ".local", ".lan", ".corp", ".intranet",
                        ".svc", ".cluster.local")) or ".svc." in h:
            return "private"
        return "public"
    if ip.is_loopback:
        return "loopback"
    if str(ip) in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200"):
        return "metadata"
    if ip.is_link_local:
        return "metadata"
    if ip.is_private or ip.is_reserved or ip.is_unspecified:
        return "private"
    return "public"


def classify(doc: dict) -> str:
    keys = set(doc)
    if keys & PR_KEYS and "authorization_servers" in keys or ("resource" in keys and not keys & AS_KEYS):
        return "protected_resource"
    if keys & AS_KEYS:
        return "authorization_server"
    return ""


def collect_docs(data, pointer=""):
    """Yield (pointer, kind, doc) for every metadata document in parsed JSON."""
    if isinstance(data, list):
        for i, item in enumerate(data):
            yield from collect_docs(item, "%s/%d" % (pointer, i))
        return
    if not isinstance(data, dict):
        return
    kind = classify(data)
    if kind:
        yield pointer, kind, data
        return
    for key, val in data.items():
        if isinstance(val, (dict, list)):
            yield from collect_docs(val, "%s/%s" % (pointer, key))


def norm_url(u: str) -> str:
    try:
        p = urlsplit(u.strip())
    except ValueError:
        return u.strip()
    path = p.path.rstrip("/")
    return "%s://%s%s" % (p.scheme.lower(), p.netloc.lower(), path)


def check_url_list(findings, file, text, ptr, field, value, disabled):
    if isinstance(value, list):
        for i, item in enumerate(value):
            check_url(findings, file, text, ptr, "%s/%d" % (field, i), item, disabled)
    else:
        check_url(findings, file, text, ptr, field, value, disabled)


def check_url(findings, file, text, ptr, field, url, disabled):
    if not isinstance(url, str) or not url:
        return
    try:
        p = urlsplit(url)
        host = p.hostname or ""
    except ValueError:
        return
    hc = host_class(host)
    line = find_line(text, url)
    unsafe = {"file", "data", "javascript", "vbscript", "about"}
    if p.scheme == "http" and hc != "loopback" and "MO05" not in disabled:
        findings.append(Finding("MO05", file, "%s/%s" % (ptr, field),
                                "%s uses cleartext http: %s" % (field, url), line=line))
    elif p.scheme in unsafe and "MO05" not in disabled:
        findings.append(Finding("MO05", file, "%s/%s" % (ptr, field),
                                "%s uses unsafe URI scheme %s: %s" % (field, p.scheme, url),
                                severity="critical", line=line))
    if hc in ("metadata", "private") and "MO12" not in disabled:
        sev = "critical" if hc == "metadata" else "high"
        findings.append(Finding("MO12", file, "%s/%s" % (ptr, field),
                                "%s points at a %s address (%s)" % (field, hc, host),
                                severity=sev, line=line))


def scan_secrets(findings, file, text, ptr, obj, disabled, path=""):
    if "MO11" in disabled:
        return
    if isinstance(obj, dict):
        is_jwk = "kty" in obj
        for k, v in obj.items():
            sub = "%s/%s" % (path, k)
            kl = str(k).lower()
            if is_jwk and k in PRIVATE_JWK_MEMBERS and isinstance(v, str) and v:
                findings.append(Finding("MO11", file, (ptr + sub) or "/",
                                        "JWK publishes private member '%s' (%s)" % (k, mask(v)),
                                        line=find_line(text, '"%s"' % k)))
            elif kl in SECRET_KEYS and isinstance(v, str) and v:
                findings.append(Finding("MO11", file, (ptr + sub) or "/",
                                        "metadata contains '%s' value (%s)" % (k, mask(v)),
                                        line=find_line(text, '"%s"' % k)))
            else:
                scan_secrets(findings, file, text, ptr, v, disabled, sub)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            scan_secrets(findings, file, text, ptr, v, disabled, "%s/%d" % (path, i))


def as_list(v):
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, str):
        return [v]
    return []


def audit_as(findings, file, text, ptr, doc, disabled):
    def add(rule, msg, needle="", sev=None, field=""):
        if rule not in disabled:
            findings.append(Finding(rule, file, "%s/%s" % (ptr, field) if field else (ptr or "/"), msg,
                                    severity=sev, line=find_line(text, needle)))

    methods = as_list(doc.get("code_challenge_methods_supported"))
    if "code_challenge_methods_supported" not in doc:
        add("MO01", "code_challenge_methods_supported is absent; MCP clients must refuse to "
            "proceed when PKCE support is not advertised", '"issuer"',
            field="code_challenge_methods_supported")
    elif "S256" not in methods:
        add("MO01", "PKCE methods %s do not include S256" % methods,
            "code_challenge_methods_supported", field="code_challenge_methods_supported")
    if "plain" in methods:
        add("MO02", "PKCE 'plain' sends the verifier in clear; advertise only S256",
            "code_challenge_methods_supported", field="code_challenge_methods_supported")

    rtypes = [r.split() for r in as_list(doc.get("response_types_supported"))]
    grants = as_list(doc.get("grant_types_supported"))
    if any("token" in r for r in rtypes) or "implicit" in grants:
        add("MO03", "implicit flow returns tokens in the browser redirect; OAuth 2.1 removes it",
            "response_types_supported" if any("token" in r for r in rtypes) else '"implicit"',
            field="response_types_supported")
    if "password" in grants:
        add("MO04", "password grant lets a client collect user credentials; OAuth 2.1 removes it",
            '"password"', field="grant_types_supported")

    issuer = doc.get("issuer")
    if isinstance(issuer, str) and issuer:
        try:
            ip = urlsplit(issuer)
            bad = []
            loop = host_class(ip.hostname or "") == "loopback"
            if ip.scheme != "https" and not loop:
                bad.append("scheme is %r, not https" % ip.scheme)
            if ip.query:
                bad.append("has a query component")
            if ip.fragment:
                bad.append("has a fragment")
            if bad:
                add("MO06", "issuer %s: %s" % (issuer, "; ".join(bad)), issuer, field="issuer")
        except ValueError:
            add("MO06", "issuer is not a parseable URL", '"issuer"', field="issuer")
    elif "issuer" in doc:
        add("MO06", "issuer is empty or not a string", '"issuer"', field="issuer")

    for s in as_list(doc.get("scopes_supported")):
        if is_broad_scope(s):
            add("MO10", "broad scope %r advertised; prefer narrow per-tool scopes" % s,
                '"%s"' % s, field="scopes_supported")

    if doc.get("registration_endpoint"):
        add("MO13", "dynamic client registration is open at %s; if this server proxies a "
            "third-party API with a static client ID, require per-client consent"
            % doc["registration_endpoint"], "registration_endpoint", field="registration_endpoint")

    _SIGNING_ALG_FIELDS = (
        "id_token_signing_alg_values_supported",
        "token_endpoint_auth_signing_alg_values_supported",
        "request_object_signing_alg_values_supported",
        "userinfo_signing_alg_values_supported",
        "introspection_signing_alg_values_supported",
        "authorization_signing_alg_values_supported",
        "dpop_signing_alg_values_supported",
        "resource_signing_alg_values_supported",
    )
    for field in _SIGNING_ALG_FIELDS:
        algs = as_list(doc.get(field)) if field in doc else []
        if any(str(a).lower() == "none" for a in algs):
            add("MO15", "%s advertises the JWT 'none' algorithm, which accepts unsigned tokens"
                % field, field, field=field)

    for field in URL_FIELDS:
        check_url_list(findings, file, text, ptr, field, doc.get(field), disabled)
    for field in ("redirect_uris", "post_logout_redirect_uris", "redirect_uri"):
        if field in doc:
            check_url_list(findings, file, text, ptr, field, doc.get(field), disabled)
    scan_secrets(findings, file, text, ptr, doc, disabled)


def audit_pr(findings, file, text, ptr, doc, disabled, expected):
    def add(rule, msg, needle="", sev=None, field=""):
        if rule not in disabled:
            findings.append(Finding(rule, file, "%s/%s" % (ptr, field) if field else (ptr or "/"), msg,
                                    severity=sev, line=find_line(text, needle)))

    servers = as_list(doc.get("authorization_servers"))
    if not servers:
        add("MO08", "authorization_servers is missing or empty; MCP clients cannot discover "
            "where to obtain tokens", '"resource"', field="authorization_servers")
    resource = doc.get("resource")
    if not isinstance(resource, str) or not resource:
        add("MO08", "resource is missing; RFC 9728 requires it and clients must check it",
            '"authorization_servers"', sev="medium", field="resource")
    elif expected:
        if norm_url(resource) != norm_url(expected):
            add("MO09", "resource %s does not match expected server URL %s; a client should "
                "reject this metadata" % (resource, expected), resource, field="resource")
    else:
        try:
            rp = urlsplit(resource)
            if rp.fragment:
                add("MO09", "resource %s has a fragment, which RFC 9728 forbids" % resource,
                    resource, sev="medium", field="resource")
        except ValueError:
            pass

    bearer = [b.lower() for b in as_list(doc.get("bearer_methods_supported"))]
    if "query" in bearer:
        add("MO07", "bearer_methods_supported includes 'query'; tokens in URLs leak through logs, "
            "history, and Referer headers", '"query"', field="bearer_methods_supported")

    for s in as_list(doc.get("scopes_supported")):
        if is_broad_scope(s):
            add("MO10", "broad scope %r advertised; prefer narrow per-tool scopes" % s,
                '"%s"' % s, field="scopes_supported")

    for field in URL_FIELDS:
        check_url_list(findings, file, text, ptr, field, doc.get(field), disabled)
    for field in ("redirect_uris", "post_logout_redirect_uris", "redirect_uri"):
        if field in doc:
            check_url_list(findings, file, text, ptr, field, doc.get(field), disabled)
    for i, srv in enumerate(servers):
        check_url(findings, file, text, ptr, "authorization_servers/%d" % i, srv, disabled)
    scan_secrets(findings, file, text, ptr, doc, disabled)


def iter_files(paths):
    for p in paths:
        if p == "-":
            yield "<stdin>"
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for f in sorted(files):
                    if f.endswith(".json") or f in ("oauth-protected-resource",
                                                      "oauth-authorization-server",
                                                      "openid-configuration"):
                        yield os.path.join(root, f)
        else:
            yield p


def audit_text(name, text, disabled=(), expected=None):
    """Audit one JSON document's text. Returns (findings, docs) or raises ValueError."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("%s: invalid JSON (%s)" % (name, exc))
    findings, docs = [], []
    for ptr, kind, doc in collect_docs(data):
        docs.append({"file": name, "pointer": ptr or "/", "kind": kind})
        if kind == "authorization_server":
            audit_as(findings, name, text, ptr, doc, set(disabled))
        else:
            audit_pr(findings, name, text, ptr, doc, set(disabled), expected)
    return findings, docs


def audit_paths(paths, disabled=(), expected=None):
    findings, docs, errors = [], [], []
    for f in iter_files(paths):
        try:
            if f == "<stdin>":
                text = sys.stdin.read()
            else:
                with open(f, encoding="utf-8") as fh:
                    text = fh.read()
        except OSError as exc:
            errors.append("%s: %s" % (f, exc))
            continue
        try:
            fs, ds = audit_text(f, text, disabled, expected)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        findings.extend(fs)
        docs.extend(ds)
    if docs and "MO14" not in disabled:
        kinds = {}
        for d in docs:
            kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
        findings.append(Finding("MO14", docs[0]["file"], "/", "%d metadata document(s): %s" % (
            len(docs), ", ".join("%d %s" % (n, k) for k, n in sorted(kinds.items())))))
    findings.sort(key=lambda x: (-SEV_RANK[x.severity], x.file, x.line, x.rule))
    return findings, docs, errors


def to_sarif(findings):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    used = sorted({f.rule for f in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcpoauth", "version": VERSION,
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
    ap = argparse.ArgumentParser(
        prog="mcpoauth",
        description="Offline auditor for MCP server OAuth metadata (RFC 9728 protected resource "
                    "and RFC 8414 / OIDC authorization server documents).")
    ap.add_argument("paths", nargs="*", help="JSON files or directories (or - for stdin)")
    ap.add_argument("--resource-url", metavar="URL",
                    help="the MCP server URL you expect the protected resource 'resource' to match")
    ap.add_argument("--disable", nargs="+", default=[], metavar="RULE", help="skip rule ids")
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output")
    ap.add_argument("--min-severity", default="info", choices=SEVERITIES)
    ap.add_argument("--fail-on", default="high", choices=SEVERITIES + ("none",),
                    help="exit 1 if any finding is at or above this severity (default high)")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version="mcpoauth " + VERSION)
    args = ap.parse_args(argv)

    if args.list_rules:
        for rid, (sev, title) in RULES.items():
            print("%s  %-8s  %s" % (rid, sev, title))
        return 0
    if not args.paths:
        ap.print_usage(sys.stderr)
        print("mcpoauth: error: give at least one file or directory", file=sys.stderr)
        return 2
    disabled = {d.upper() for d in args.disable}
    unknown = disabled - set(RULES)
    if unknown:
        print("mcpoauth: error: unknown rule(s): %s" % ", ".join(sorted(unknown)), file=sys.stderr)
        return 2

    findings, docs, errors = audit_paths(args.paths, disabled, args.resource_url)
    for e in errors:
        print("mcpoauth: error: %s" % e, file=sys.stderr)
    if errors and not docs:
        return 2
    shown = [f for f in findings if SEV_RANK[f.severity] >= SEV_RANK[args.min_severity]]

    if args.json:
        print(json.dumps({"tool": "mcpoauth", "version": VERSION, "documents": docs,
                          "findings": [f.as_dict() for f in shown]}, indent=2))
    elif args.sarif:
        print(json.dumps(to_sarif(shown), indent=2))
    else:
        if not docs:
            print("no OAuth metadata documents found")
        for f in shown:
            print("%-8s  %s  %s:%d  %s  %s" % (f.severity.upper(), f.rule, f.file, f.line,
                                              f.pointer, f.message))
        counts = {}
        for f in shown:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print("\n%d document(s), %d finding(s)%s" % (
            len(docs), len(shown),
            (": " + ", ".join("%d %s" % (counts[s], s) for s in reversed(SEVERITIES) if s in counts))
            if counts else ""))

    if args.fail_on != "none" and any(
            SEV_RANK[f.severity] >= SEV_RANK[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
