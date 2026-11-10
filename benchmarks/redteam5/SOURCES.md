# Sources for independent red-team round 5

Each technique below was chosen because it is documented in public research
or a public specification and was **not** the basis of a fixture in rounds
1–4. The set was written after v0.45.0 rules were frozen, and was scored once.
Citations are for provenance, not for overfitting to a paper's exact wording.
All secrets and identifiers in the fixtures are synthetic.

## resultguard

- OWASP, *CSV Injection* (formula injection). A retrieved spreadsheet cell
  uses `=HYPERLINK(...)` plus an instruction, a different channel than
  Markdown images or CSS/SVG smuggling used earlier.
- RFC 1035 TXT records returned by a DNS-lookup tool as an instruction
  channel (distinct from DNS *exfiltration* of secrets in earlier rounds).
- Git commit messages / `git log` output as an untrusted tool-result
  surface (Microsoft 365 Copilot / "issue comment" class applied to VCS
  history rather than a GitHub Issue body used in round 1).
- JSON `\uXXXX` escape concealment of a directive inside a tool-returned
  config blob (distinct from Unicode TAG characters, base64, and quoted-printable).
- RFC 4287 Atom / RSS `<content>` as a retrieved-feed injection surface.
- Decoded JWT *payload claims* (`instructions`) shown to the model by a
  token-inspect tool — not the JWT `alg=none` metadata issue used in round 4.
- ASCII backspace (0x08) overstrike concealment, a different control-code
  class than ANSI CSI used in round 4.
- SAML `AttributeValue` / assertion text as a retrieved-identity document
  channel (OASIS SAML 2.0).

## toolpoison

- Model Context Protocol, *Prompts*
  (https://modelcontextprotocol.io/docs/concepts/prompts).
  `prompts[].description` is a distinct catalog channel from tools,
  resource templates, and server `instructions` used earlier.
- RFC 4648 Base32 concealment in a tool description (rounds 1–4 used
  base64, quoted-printable, uuencode, ROT13, and reversed text).
- Unicode Braille patterns (U+2800 block) as a concealment alphabet.
- Atbash letter substitution with an explicit decode hint.
- MCP prompt-argument `description` fields as a second prompts-catalog
  instruction channel.

## shellfence

- `find ... -exec` as a classic GTFOBins execution trampoline (not
  `forfiles`, `tar --checkpoint-action`, or MSBuild).
- Windows `schtasks /create` persistence + execution (MITRE ATT&CK T1053.005),
  distinct from `systemd-run` and crontab used earlier.
- `rsync` of `$HOME` to a remote (ATT&CK T1567), a different utility than
  the rclone fixture in round 4.
- GNU `make` / `$(shell ...)` as a build-system execution trampoline.
- LOLBAS `wmic process call create`.
- `awk 'BEGIN{system(...)}'` (GTFOBins awk).

## memfence

- Planted official API base-URL swap (a standing "use this origin" memory).
- Query-rewrite memory that appends secrets to later search/browse calls
  (related to retrieval-poisoning work, not the PoisonedRAG *document-shaped*
  rule used in round 4).
- Language / style preference that is actually an exfil instruction.
- Emergency-contact / CC-all-conversation affiliation swap (a different
  shape than the r2 IBAN and r4 payee/payroll URL fixtures).
- Locale/timezone memory that plants an override.

## piiguard

- Turkish Republic ID number (TCKN) with the official checksum.
- Chilean RUT (Rol Único Tributario) including the modulo-11 check digit.
- South African 13-digit ID number (Luhn check).
- Italian codice fiscale (16-character fiscal code, official check letter).
- Dutch BSN (burgerservicenummer) 11-proef checksum.

  These are additional national-ID classes, not the PESEL / NRIC / NIR /
  My Number / CURP / Aadhaar / CPF / TFN / personnummer set of rounds 3–4.

## fetchfence

- `gopher://` loopback (a scheme called out by OWASP SSRF, not used as a
  fixture earlier; round 3 cited gopher in SOURCES but used other schemes).
- Hexadecimal dotted / dword-hex loopback (`0x7f000001`), distinct from the
  *decimal* dword `2130706433` used in round 4.
- Kubernetes in-cluster DNS (`kubernetes.default.svc`).
- Octal dotted loopback (`0177.0.0.1`).
- `ldap://` against a link-local / metadata host (RFC 4516).

## pathfence

- HashiCorp Vault token file (`~/.vault-token`).
- `age` key file (`~/.config/age/keys.txt`), a path class distinct from
  the age *key value* tracesweep fixture in round 4.
- FileZilla `recentservers.xml` (stored FTP/S passwords).
- Terraform state (`terraform.tfstate`) with residual secrets.
- Signal Desktop config path.

## mcpposture

- `go run github.com/…@latest` as an unpinned remote module launch.
- `npx github:user/repo` (GitHub-spec installer, unpinned).
- MCP server `cwd` set to `/` (filesystem root).
- `uvx --from git+http://…` unpinned VCS install.
- Streamable/SSE MCP server bound to `0.0.0.0` without auth.

## secretflow

- Telegram Bot API `sendMessage` URL as a secret sink (the token *value*
  rule was tracesweep in round 3; this is the flow into that URL).
- AWS S3 / pre-signed or `PutObject` tool arguments as a secret sink.
- GraphQL mutation variables as a secret sink.

## tracesweep

- PyPI API tokens (`pypi-AgE…`).
- Slack incoming webhook URLs (`hooks.slack.com/services/…`).
- Groq API keys (`gsk_…`).

## mcpoauth

- RFC 7591 / RFC 8414: `token_endpoint_auth_methods_supported` advertised
  as only `none` on a confidential-looking authorization server (distinct
  from JWT `alg=none` in round 4).
- Wildcard `redirect_uris` (`https://*` / `*`).
- `frontchannel_logout_uri` over cleartext HTTP on a public host.
