# Sources for independent red-team round 4

Each technique below was chosen because it is documented in public research
or a public specification and was **not** the basis of a fixture in rounds
1–3. The set was written after v0.44.0 rules were frozen, and was scored once. Citations are for provenance, not for overfitting to a paper's exact
wording. All secrets and identifiers in the fixtures are synthetic.

## resultguard

- HiddenLayer, *Policy Puppetry: a new approach to jailbreaking* (2024).
  XML/structured "policy" wrappers that instruct the model.
- ANSI escape / terminal-injection write-ups (the "ANSI bloody ANSI" class):
  CSI sequences that hide a directive in a tool-returned log.
- HTTP header injection as applied to raw responses returned to a model
  (`X-System-Instruction` and similar custom headers).
- Hughes, Mazeika, et al., *Best-of-N Jailbreaking* (arXiv:2412.03556), 2024.
  Prefabricated / prefilled assistant turns that continue an exfil action.
- Gong et al., *FigStep: Jailbreaking Large Vision-language Models via
  Typographic Visual Prompts* (arXiv:2311.05608), 2023. OCR/caption surface.
- Model Context Protocol, *Resources*
  (https://modelcontextprotocol.io/docs/concepts/resources).
  `resources/read` contents as a distinct injection surface.
- Markdown reference-definition smuggling (Greshake-class indirect injection
  in markup, a reference-style definition rather than an inline link).
- OWASP HTML/SVG smuggling; SVG `foreignObject` as an HTML island (distinct
  from `<desc>` / off-canvas text used in earlier rounds).

## toolpoison

- JSON Schema `$comment` and MCP `outputSchema` as a rarely reviewed
  instruction channel.
- MCP resource templates (`resourceTemplates[].description`).
- Classical ROT13 concealment in a tool description (distinct from base64,
  uuencode, and quoted-printable used earlier).
- MCP `_meta` extension fields on a tool.
- Character-order (reversed English) concealment in a description.

## shellfence

- GNU tar `--checkpoint-action=exec` (archive-time execution trampoline).
- GTFOBins / LOLBAS `osascript` (macOS, not the Windows LOLBAS set of r3).
- rclone as an exfil utility; MITRE ATT&CK T1567 Exfiltration Over Web Service.
- LOLBAS `msbuild` inline / PostBuildEvent execution.
- LOLBAS `forfiles /c`.
- `systemd-run` transient units (distinct from writing a unit under
  `/etc/systemd/system`).

## memfence

- OWASP ASI06 Memory & Context Poisoning, applied to a standing
  auto-approve / tool-policy memory.
- Delayed invocation via an external calendar event cue.
- BEC-style affiliation and payee swap in memory (distinct from the r2 IBAN
  wording and the r3 payroll URL).
- PoisonedRAG (arXiv:2402.07860): a retrieved-document-shaped memory that is
  actually a standing rule.
- Tool allow-list mutation as a policy-layer poison.

## piiguard

- Polish PESEL (11-digit national ID, weights 1,3,7,9,1,3,7,9,1,3).
- Singapore NRIC / FIN format (ICA).
- French NIR / INSEE social-security number format.
- Japan Individual Number (My Number) Act; 12-digit identifier.
- Mexican CURP (Clave Única de Registro de Población) format.

## fetchfence

- Redis URI scheme as an SSRF / data-store reach.
- Tor `.onion` v3 addresses as an opaque callback host.
- Decimal / dword IP encoding (`2130706433` == `127.0.0.1`); OWASP SSRF.
- Alibaba Cloud instance metadata (`100.100.100.200`).
- WebDAV (RFC 4918) `MKCOL` as a write-capable internal protocol.

## pathfence

- `pass` (password-store) directory layout; GPG-encrypted secrets at rest.
- 1Password / Bitwarden local vault storage paths.
- Kubernetes service-account projected volume
  (`/var/run/secrets/kubernetes.io/serviceaccount/token`).
- macOS `login.keychain-db`.
- GNOME Keyring / libsecret on-disk store.

## mcpposture

- MCP Streamable HTTP / SSE transport; tokens in URLs leak via logs and Referer.
- Deno `run` of a remote URL as an MCP server entrypoint.
- Bearer tokens in `mcp.json` `headers`.
- `bunx` / npm package specs of the form `http://host/pkg.tgz`.
- Remote bootstrap via `curl | node`.

## secretflow

- DNS exfiltration (ATT&CK T1568 / T1048); canary-token style label embedding.
- CSS `url()` as a ForcedLeak-class render sink (distinct from HTML `<img>`
  and `data:` URIs used earlier).
- WebSocket (`ws` / `wss`) URLs as an outbound secret channel.

## tracesweep

- Hugging Face access tokens (`hf_...`).
- DigitalOcean personal access tokens (`dop_v1_`).
- age secret-key format (`AGE-SECRET-KEY-1...`, filippo.io/age).

## mcpoauth

- RFC 8725 / RFC 7518: JWS `none` algorithm must not be used for ID tokens.
- RFC 8414 `jwks_uri` retrieved over cleartext HTTP.
- RFC 8628 Device Authorization Grant; `device_authorization_endpoint` over
  cleartext HTTP on a public host.
