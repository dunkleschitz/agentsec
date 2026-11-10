# mcpoauth

Offline auditor for **MCP server OAuth discovery metadata**.

Remote MCP servers that require sign-in publish two JSON documents: OAuth 2.0
Protected Resource Metadata (RFC 9728, at `/.well-known/oauth-protected-resource`)
and Authorization Server Metadata (RFC 8414 or OpenID Connect discovery). MCP
clients trust those documents to decide where to send users and tokens. **mcpoauth**
reads saved copies and flags settings that the MCP authorization spec and OAuth 2.1
warn against: no PKCE S256, implicit or password grants, cleartext endpoints,
tokens in URLs, a `resource` that does not match the server, broad scopes, and
secrets or private keys published by mistake.

Standard library only. It never connects to a network; fetch the documents
yourself (for example with `curl`) and point the tool at the files.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **mcpoauth** | OAuth metadata an MCP server and its authorization server publish |
| mcpposture | MCP *client* config files (launch commands, env, inline secrets) |
| agentcard | A2A Agent Cards (auth schemes declared for agent-to-agent calls) |
| scopefit | GitHub token permissions versus what an agent actually called |
| fetchfence | URLs an agent fetched during a run |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| MO01 | critical | Authorization server does not advertise PKCE `S256` (field missing, or no S256) |
| MO02 | high | PKCE `plain` method advertised |
| MO03 | high | Implicit flow (`response_type` containing `token`, or `implicit` grant) |
| MO04 | high | Resource-owner `password` grant |
| MO05 | high | `http://` endpoint or identifier on a non-loopback host |
| MO06 | medium | Issuer not https, or has a query or fragment |
| MO07 | high | `bearer_methods_supported` includes `query` (tokens in URLs) |
| MO08 | high / medium | Protected resource metadata missing `authorization_servers` (high) or `resource` (medium) |
| MO09 | high | `resource` does not match `--resource-url` (medium: has a fragment) |
| MO10 | medium | Broad scope advertised (`*`, `all`, `admin`, `root`, `full_access`, ...) |
| MO11 | critical | Secret or private key material in metadata (`client_secret`, private JWK members `d`/`k`/...) |
| MO12 | critical / high | Endpoint on a cloud-metadata or link-local address (critical) or private IP / internal hostname (high) |
| MO13 | low | Open dynamic client registration endpoint (review confused-deputy risk for proxy servers) |
| MO14 | info | Inventory of metadata documents found |

Secret values are **masked** in all output formats.

## Usage

```
python3 mcpoauth.py PATH [PATH ...] [--resource-url URL] [--json | --sarif]
                    [--min-severity LEVEL] [--fail-on LEVEL|none] [--disable RULE ...]
python3 mcpoauth.py --list-rules
# or, from a kit install:
agentsec mcpoauth examples/risky
```

PATH may be a JSON file, a directory (scanned for `*.json` and files named
`oauth-protected-resource`, `oauth-authorization-server`, `openid-configuration`),
or `-` for stdin. Documents can be top-level, in a list, or nested in a wrapper
object; each is classified by its keys. `--fail-on` defaults to `high`. Exit
codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or input error.

To collect the inputs from a live server:

```
curl -s https://mcp.example.com/.well-known/oauth-protected-resource > prm.json
curl -s https://auth.example.com/.well-known/oauth-authorization-server > asm.json
python3 mcpoauth.py prm.json asm.json --resource-url https://mcp.example.com/mcp
```

## Example

```
$ python3 mcpoauth.py examples/risky --resource-url https://mcp.example.com/mcp --min-severity high
CRITICAL  MO01  examples/risky/oauth-authorization-server.json:9  /code_challenge_methods_supported  PKCE methods ['plain'] do not include S256
CRITICAL  MO11  examples/risky/oauth-authorization-server.json:12  /client_secret  metadata contains 'client_secret' value (FAKE…00)
CRITICAL  MO11  examples/risky/oauth-authorization-server.json:13  /jwks/keys/0/k  JWK publishes private member 'k' (FAKE…00)
CRITICAL  MO12  examples/risky/oauth-protected-resource.json:3  /authorization_servers/1  authorization_servers/1 points at a metadata address (169.254.169.254)
HIGH      MO05  examples/risky/oauth-authorization-server.json:2  /issuer  issuer uses cleartext http: http://auth.example.com?tenant=1
HIGH      MO05  examples/risky/oauth-authorization-server.json:3  /authorization_endpoint  authorization_endpoint uses cleartext http: http://auth.example.com/authorize
HIGH      MO03  examples/risky/oauth-authorization-server.json:7  /response_types_supported  implicit flow returns tokens in the browser redirect; OAuth 2.1 removes it
HIGH      MO04  examples/risky/oauth-authorization-server.json:8  /grant_types_supported  password grant lets a client collect user credentials; OAuth 2.1 removes it
...
```

`examples/clean` shows the same server configured well and produces only the MO14 inventory line.

## Known limits

- It reads saved JSON only. It does not fetch metadata, follow `authorization_servers`,
  validate JWKS signatures, or test the live flow (redirect URI checks, token audience
  validation, consent screens). Those need a dynamic test.
- Document type is inferred from keys; an unusual document with neither `resource`
  nor standard authorization-server keys is ignored.
- MO09 compares scheme, host, and path (case-insensitive host, trailing slash ignored)
  only when you pass `--resource-url`.
- The broad-scope list (MO10) is a short heuristic list, not a policy.
- Hostname classification for MO12 uses literal IPs and a few internal suffixes
  (`.internal`, `.local`, `.corp`, ...); it does not resolve DNS.
