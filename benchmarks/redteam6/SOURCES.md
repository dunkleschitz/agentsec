# Sources for independent red-team round 6

Each technique below was chosen because it is documented in public research
or a public specification and was **not** the basis of a fixture in rounds
1–5. The set was written after v0.46.0 rules were frozen, and was scored once.
Citations are for provenance, not for overfitting to a paper's exact wording.
All secrets and identifiers in the fixtures are synthetic.

## resultguard

- RFC 5545 iCalendar `DESCRIPTION` as a retrieved calendar-event channel
  (distinct from Atom/RSS content, SAML AttributeValue, and CSV HYPERLINK).
- RFC 6350 vCard `NOTE` as a retrieved contact-record channel (distinct from
  SAML and decoded JWT claims).
- W3C WebVTT cue text as a caption/subtitle instruction channel (distinct from
  FigStep images and Markdown).
- OpenAPI 3 `info.description` on a fetched specification (a retrieved-spec
  channel, not an MCP tool description).
- YAML front matter in a retrieved Markdown runbook (distinct from Policy
  Puppetry XML and Markdown reference-definition smuggling).
- RFC 2047 MIME encoded-word concealment (distinct from quoted-printable,
  raw base64, uuencode, and JSON `\uXXXX` escapes).
- JSON-LD / schema.org `description` on a fetched page (a structured-data
  island distinct from SVG `foreignObject` and HTML comments).
- RFC 9285 Base45 concealment in a tool result (rounds 1–5 used base64,
  base32, uuencode, ROT13, Atbash, and Braille).

## toolpoison

- RFC 9285 Base45 concealment in a tool description.
- RFC 2047 encoded-word concealment in a tool description.
- JSON Schema `inputSchema.properties[].examples` as a rarely reviewed schema
  channel (distinct from `$comment` / `outputSchema` in round 4 and prompt
  arguments in round 5).
- JSON Schema `inputSchema.title` as a second schema-string channel.
- Unicode TR36 mixed-script (Cyrillic/Latin) confusables in a description
  (distinct from Braille, Runic, and unusual-script block detection).

## shellfence

- GTFOBins `python -c` used to read a home SSH key and POST it (not
  `find -exec`, `awk system()`, or `make $(shell)`).
- GTFOBins `socat` as a transfer tool targeting `~/.ssh` (not rsync, scp, or
  rclone).
- LOLBAS `bitsadmin /transfer` as a Windows download trampoline (not
  certutil, forfiles, wmic, or schtasks).
- GTFOBins `node -e` / `child_process.exec` as an execution trampoline.
- GTFOBins `php -r` `system()` as an interpreter exec hook.
- `wget --post-file` of `~/.aws/credentials` (ATT&CK T1567), a different
  transfer utility than rsync/scp/rclone.

## memfence

- Farewell / session-end trigger that dumps the conversation to a URL
  (distinct from count-delayed exfil and calendar-cue delay).
- Planted mandatory proxy / VPN endpoint (distinct from the r5 official API
  base-URL swap).
- Typo-correction memory that rewrites outbound destinations (distinct from
  query-rewrite-append-secrets and BEC payee swaps).
- Subject-access-request / privacy-compliance memory that BCCs history to an
  outside address (distinct from emergency-contact CC-all).
- Slack status / display-name memory used as a side channel (distinct from
  language-preference and locale/timezone memories).

## piiguard

- Finnish henkilötunnus (hetu) with the official check character.
- Swiss AHV/AVS number (EAN-13, prefix 756).
- Taiwan national identification number with official checksum.
- Hong Kong identity card number with official check character.
- Argentine CUIL/CUIT with official check digit and separators.

  These are additional national-ID classes from the v0.46 table, not the
  PESEL / NRIC / NIR / My Number / CURP set or the r5 TCKN / RUT / SA ID /
  codice fiscale / BSN fixtures.

## fetchfence

- `smb://` / UNC loopback as a fetch destination (OWASP SSRF; a different
  scheme than gopher, dict, redis, or WebDAV).
- IPv4-mapped IPv6 loopback (`[::ffff:127.0.0.1]`), distinct from decimal,
  hex dword, and dotted-octal encodings.
- `tftp://` to an internal host (another non-HTTP scheme).
- HashiCorp Consul HTTP API on loopback (`/v1/kv`), distinct from Kubernetes
  in-cluster DNS, IMDS, and Redis.
- AWS instance metadata IPv6 address `fd00:ec2::254` (documented IMDS IPv6
  endpoint), distinct from `169.254.169.254` and GCP/Azure/Alibaba hosts.

## pathfence

- `~/.config/rclone/rclone.conf` (cloud-sync remote credentials), distinct
  from vault-token, age keys, FileZilla, terraform state, and Signal.
- `~/.local/share/containers/auth.json` (Podman / c/image registry login).
- `~/.fly/config.yml` (flyctl access token), a PaaS CLI store not used earlier.
- Windows Credential Manager blobs under `AppData\Local\Microsoft\Credentials`,
  a different OS store than macOS keychain or GNOME keyring.
- `~/.pulumi/credentials.json`, an IaC-CLI token store distinct from
  Terraform `tfstate` (r5) and `~/.terraform.d/credentials.tfrc.json` (r3).

## mcpposture

- `nix run github:owner/repo` unpinned flake reference (a different
  ecosystem than npx, go, uvx, deno, and docker).
- `pnpm dlx` of an unpinned package.
- `cargo install` of an unpinned crate.
- `--bind *` (all interfaces), a different spelling than r5 `0.0.0.0`.
- `cwd` of `C:\` (Windows drive root), a different spelling than r5 `cwd /`.

## secretflow

- Discord webhook execution as a secret sink (distinct from Telegram
  sendMessage, Slack, S3 PutObject, and GraphQL mutations).
- SMTP / `send_email` tool arguments as a secret sink.
- Jira issue comment / ticketing API as a secret sink.

## tracesweep

- GitLab personal access tokens (`glpat-`).
- Stripe live secret keys (`sk_live_`).
- npm access tokens (`npm_`).

  These prefixes were not in the earlier provider list (Slack `xoxb-`,
  Hugging Face `hf_`, DigitalOcean `dop_v1_`, age, PyPI `pypi-`, Groq `gsk_`).

## mcpoauth

- RFC 9700 OAuth 2.0 Security BCP: implicit grant advertised via
  `response_types_supported` including `token` (earlier rounds covered the
  password grant, `alg=none`, and `token_endpoint_auth_methods_supported=none`).
- RFC 7009 / RFC 8414: `revocation_endpoint` over cleartext HTTP (a different
  field than `jwks_uri`, `frontchannel_logout_uri`, or `token_endpoint`).
- RFC 7591 / RFC 8414: `registration_endpoint` over cleartext HTTP.

## What this set is not

It is not a development set. Detectors were not changed after these fixtures
existed. It is not a copy of the private v0.46 dev set, and it does not reuse
the encodings, countries, paths, LOLBins, OAuth fields, or launchers that
rounds 1–5 already used as fixtures.
