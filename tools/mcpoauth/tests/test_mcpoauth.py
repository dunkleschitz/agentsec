import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import mcpoauth  # noqa: E402

GOOD_AS = {
    "issuer": "https://auth.example.com",
    "authorization_endpoint": "https://auth.example.com/authorize",
    "token_endpoint": "https://auth.example.com/token",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "code_challenge_methods_supported": ["S256"],
}
GOOD_PR = {
    "resource": "https://mcp.example.com/mcp",
    "authorization_servers": ["https://auth.example.com"],
    "bearer_methods_supported": ["header"],
}


def audit(doc, disabled=(), expected=None):
    findings, _docs = mcpoauth.audit_text("t.json", json.dumps(doc, indent=2), disabled, expected)
    return findings


def rules(doc, **kw):
    return sorted({f.rule for f in audit(doc, **kw)})


def with_(base, **changes):
    d = dict(base)
    for k, v in changes.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return d


def run(argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    old = sys.stdin
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = mcpoauth.main(argv)
            except SystemExit as exc:
                code = exc.code
    finally:
        sys.stdin = old
    return code, out.getvalue(), err.getvalue()


class TestAuthorizationServer(unittest.TestCase):
    def test_clean_as_has_no_findings(self):
        self.assertEqual(rules(GOOD_AS), [])

    def test_missing_pkce_field_is_critical(self):
        f = audit(with_(GOOD_AS, code_challenge_methods_supported=None))
        self.assertEqual([x.rule for x in f], ["MO01"])
        self.assertEqual(f[0].severity, "critical")

    def test_pkce_without_s256(self):
        self.assertIn("MO01", rules(with_(GOOD_AS, code_challenge_methods_supported=["plain"])))

    def test_plain_alongside_s256_flags_only_mo02(self):
        self.assertEqual(rules(with_(GOOD_AS, code_challenge_methods_supported=["S256", "plain"])),
                         ["MO02"])

    def test_implicit_response_type(self):
        self.assertIn("MO03", rules(with_(GOOD_AS, response_types_supported=["code", "id_token token"])))

    def test_implicit_grant(self):
        self.assertIn("MO03", rules(with_(GOOD_AS, grant_types_supported=["implicit"])))

    def test_code_id_token_hybrid_is_not_implicit(self):
        self.assertNotIn("MO03", rules(with_(GOOD_AS, response_types_supported=["code", "code id_token"])))

    def test_password_grant(self):
        self.assertIn("MO04", rules(with_(GOOD_AS, grant_types_supported=["authorization_code", "password"])))

    def test_http_endpoint(self):
        self.assertIn("MO05", rules(with_(GOOD_AS, token_endpoint="http://auth.example.com/token")))

    def test_http_loopback_allowed(self):
        doc = with_(GOOD_AS, issuer="http://localhost:8080",
                    authorization_endpoint="http://127.0.0.1:8080/authorize",
                    token_endpoint="http://[::1]:8080/token")
        self.assertEqual(rules(doc), [])

    def test_issuer_with_query(self):
        self.assertIn("MO06", rules(with_(GOOD_AS, issuer="https://auth.example.com?x=1")))

    def test_issuer_with_fragment(self):
        self.assertIn("MO06", rules(with_(GOOD_AS, issuer="https://auth.example.com#a")))

    def test_broad_scopes(self):
        self.assertIn("MO10", rules(with_(GOOD_AS, scopes_supported=["openid", "admin"])))

    def test_narrow_scopes_ok(self):
        self.assertNotIn("MO10", rules(with_(GOOD_AS, scopes_supported=["openid", "files:read"])))

    def test_client_secret_published(self):
        f = [x for x in audit(with_(GOOD_AS, client_secret="FAKE-EXAMPLE-secret-123456"))
             if x.rule == "MO11"]
        self.assertEqual(len(f), 1)
        self.assertNotIn("FAKE-EXAMPLE-secret-123456", f[0].message)

    def test_private_jwk_member(self):
        jwks = {"keys": [{"kty": "RSA", "kid": "a", "n": "FAKE-EXAMPLE-n", "e": "AQAB",
                          "d": "FAKE-EXAMPLE-private-exponent"}]}
        self.assertIn("MO11", rules(with_(GOOD_AS, jwks=jwks)))

    def test_public_jwk_ok(self):
        jwks = {"keys": [{"kty": "RSA", "kid": "a", "n": "FAKE-EXAMPLE-n", "e": "AQAB"}]}
        self.assertNotIn("MO11", rules(with_(GOOD_AS, jwks=jwks)))

    def test_metadata_ip_is_critical(self):
        f = [x for x in audit(with_(GOOD_AS, jwks_uri="https://169.254.169.254/keys")) if x.rule == "MO12"]
        self.assertEqual(f[0].severity, "critical")

    def test_private_ip_is_high(self):
        f = [x for x in audit(with_(GOOD_AS, token_endpoint="https://10.0.0.5/token")) if x.rule == "MO12"]
        self.assertEqual(f[0].severity, "high")

    def test_open_registration_is_info(self):
        f = [x for x in audit(with_(GOOD_AS, registration_endpoint="https://auth.example.com/reg"))]
        self.assertEqual([(x.rule, x.severity) for x in f], [("MO13", "info")])

    def test_disable(self):
        self.assertEqual(rules(with_(GOOD_AS, code_challenge_methods_supported=None), disabled={"MO01"}), [])


class TestProtectedResource(unittest.TestCase):
    def test_clean_pr(self):
        self.assertEqual(rules(GOOD_PR), [])

    def test_missing_authorization_servers(self):
        self.assertIn("MO08", rules(with_(GOOD_PR, authorization_servers=None)))

    def test_missing_resource_is_medium(self):
        f = [x for x in audit(with_(GOOD_PR, resource=None)) if x.rule == "MO08"]
        self.assertEqual(f[0].severity, "medium")

    def test_resource_mismatch(self):
        self.assertIn("MO09", rules(GOOD_PR, expected="https://other.example.com/mcp"))

    def test_resource_match_ignores_trailing_slash_and_case(self):
        self.assertNotIn("MO09", rules(GOOD_PR, expected="https://MCP.example.com/mcp/"))

    def test_query_bearer(self):
        self.assertIn("MO07", rules(with_(GOOD_PR, bearer_methods_supported=["query"])))

    def test_http_authorization_server(self):
        self.assertIn("MO05", rules(with_(GOOD_PR, authorization_servers=["http://auth.example.com"])))

    def test_internal_hostname_flagged(self):
        self.assertIn("MO12", rules(with_(GOOD_PR, authorization_servers=["https://auth.corp"])))


class TestDiscoveryAndCli(unittest.TestCase):
    def test_wrapper_object_and_list(self):
        text = json.dumps({"servers": [{"prm": GOOD_PR, "asm": GOOD_AS}]})
        _f, docs = mcpoauth.audit_text("w.json", text)
        self.assertEqual(sorted(d["kind"] for d in docs), ["authorization_server", "protected_resource"])

    def test_unrelated_json_has_no_docs(self):
        _f, docs = mcpoauth.audit_text("x.json", json.dumps({"name": "x", "version": 1}))
        self.assertEqual(docs, [])

    def test_line_numbers_point_at_key(self):
        doc = with_(GOOD_AS, grant_types_supported=["password"])
        f = [x for x in audit(doc) if x.rule == "MO04"][0]
        self.assertGreater(f.line, 1)

    def test_risky_examples_exit_1(self):
        code, out, _ = run([os.path.join(ROOT, "examples", "risky"),
                            "--resource-url", "https://mcp.example.com/mcp"])
        self.assertEqual(code, 1)
        for rid in ("MO01", "MO02", "MO03", "MO04", "MO05", "MO07", "MO09", "MO11", "MO12"):
            self.assertIn(rid, out)
        self.assertNotIn("FAKE-EXAMPLE-client-secret-0000", out)

    def test_clean_examples_exit_0(self):
        code, out, _ = run([os.path.join(ROOT, "examples", "clean"),
                            "--resource-url", "https://mcp.example.com/mcp"])
        self.assertEqual(code, 0, out)

    def test_json_output(self):
        code, out, _ = run([os.path.join(ROOT, "examples", "risky"), "--json"])
        data = json.loads(out)
        self.assertEqual(data["tool"], "mcpoauth")
        self.assertEqual(len(data["documents"]), 2)

    def test_sarif_output(self):
        code, out, _ = run([os.path.join(ROOT, "examples", "risky"), "--sarif"])
        data = json.loads(out)
        self.assertEqual(data["version"], "2.1.0")
        self.assertTrue(data["runs"][0]["results"])

    def test_fail_on_none(self):
        code, _o, _e = run([os.path.join(ROOT, "examples", "risky"), "--fail-on", "none"])
        self.assertEqual(code, 0)

    def test_stdin(self):
        code, out, _ = run(["-"], stdin=json.dumps(with_(GOOD_AS, grant_types_supported=["password"])))
        self.assertEqual(code, 1)
        self.assertIn("MO04", out)

    def test_invalid_json_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w") as fh:
                fh.write("{not json")
            code, _o, err = run([p])
        self.assertEqual(code, 2)
        self.assertIn("invalid JSON", err)

    def test_no_args_exit_2(self):
        self.assertEqual(run([])[0], 2)

    def test_unknown_rule_exit_2(self):
        self.assertEqual(run([os.path.join(ROOT, "examples", "clean"), "--disable", "XX99"])[0], 2)

    def test_list_rules(self):
        code, out, _ = run(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("MO14", out)



class TestV044Generalization(unittest.TestCase):
    def test_http_redirect_uri_on_public_host(self):
        doc = {
            "issuer": "https://auth.docs-search.test",
            "authorization_endpoint": "https://auth.docs-search.test/authorize",
            "token_endpoint": "https://auth.docs-search.test/token",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "redirect_uris": ["http://app.docs-search.test/callback"],
        }
        text = json.dumps(doc)
        findings = []
        mcpoauth.audit_as(findings, "t", text, "", doc, set())
        self.assertTrue(any(f.rule == "MO05" for f in findings))

    def test_file_scheme_authorization_endpoint(self):
        doc = {
            "issuer": "https://auth.docs-search.test",
            "authorization_endpoint": "file:///usr/local/bin/mcp-helper",
            "token_endpoint": "https://auth.docs-search.test/token",
            "code_challenge_methods_supported": ["S256"],
        }
        findings = []
        mcpoauth.audit_as(findings, "t", json.dumps(doc), "", doc, set())
        self.assertTrue(any(f.rule == "MO05" for f in findings))

    def test_github_style_admin_scope(self):
        self.assertTrue(mcpoauth.is_broad_scope("admin:org"))
        self.assertTrue(mcpoauth.is_broad_scope("delete_repo"))
        self.assertFalse(mcpoauth.is_broad_scope("read:org"))

    def test_cluster_svc_hostname_is_private(self):
        self.assertEqual(mcpoauth.host_class("auth.prod.svc"), "private")
        self.assertEqual(mcpoauth.host_class("auth.prod.svc.cluster.local"), "private")

    def test_localhost_redirect_is_clean_of_mo05(self):
        doc = {
            "issuer": "https://auth.docs-search.test",
            "authorization_endpoint": "https://auth.docs-search.test/authorize",
            "token_endpoint": "https://auth.docs-search.test/token",
            "code_challenge_methods_supported": ["S256"],
            "redirect_uris": ["http://localhost:8787/callback"],
        }
        findings = []
        mcpoauth.audit_as(findings, "t", json.dumps(doc), "", doc, set())
        self.assertFalse(any(f.rule == "MO05" for f in findings))



class TestV045Generalization(unittest.TestCase):
    def test_id_token_alg_none_is_flagged(self):
        doc = with_(GOOD_AS, id_token_signing_alg_values_supported=["none", "RS256"])
        self.assertIn("MO15", rules(doc))

    def test_rs256_only_is_clean_of_mo15(self):
        doc = with_(GOOD_AS, id_token_signing_alg_values_supported=["RS256"])
        self.assertNotIn("MO15", rules(doc))



class TestV046Generalization(unittest.TestCase):
    def _audit(self, doc):
        findings, _ = mcpoauth.audit_text("t.json", json.dumps(doc))
        return {f.rule for f in findings if f.rule != "MO14"}

    def test_auth_method_none_only(self):
        doc = {
            "issuer": "https://auth.example.test",
            "authorization_endpoint": "https://auth.example.test/authorize",
            "token_endpoint": "https://auth.example.test/token",
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        }
        self.assertIn("MO16", self._audit(doc))

    def test_wildcard_redirect(self):
        doc = {
            "issuer": "https://auth.example.test",
            "authorization_endpoint": "https://auth.example.test/authorize",
            "token_endpoint": "https://auth.example.test/token",
            "code_challenge_methods_supported": ["S256"],
            "redirect_uris": ["https://app.example.test/*"],
        }
        self.assertIn("MO16", self._audit(doc))

    def test_frontchannel_logout_http(self):
        doc = {
            "issuer": "https://auth.example.test",
            "authorization_endpoint": "https://auth.example.test/authorize",
            "token_endpoint": "https://auth.example.test/token",
            "code_challenge_methods_supported": ["S256"],
            "frontchannel_logout_uri": "http://app.example.test/logout",
        }
        self.assertIn("MO05", self._audit(doc))

    def test_exact_https_redirect_is_clean_of_mo16(self):
        doc = {
            "issuer": "https://auth.example.test",
            "authorization_endpoint": "https://auth.example.test/authorize",
            "token_endpoint": "https://auth.example.test/token",
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "redirect_uris": ["https://app.example.test/cb"],
        }
        self.assertNotIn("MO16", self._audit(doc))


if __name__ == "__main__":
    unittest.main()
