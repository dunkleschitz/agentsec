# Sources for independent red-team round 7

Each technique below was chosen because it is documented in public research
or a public specification and was **not** the basis of a fixture in rounds
1–6. The set was written after v0.47.0 rules were frozen, and was scored once.
Citations are for provenance, not for overfitting to a paper's exact wording.
All secrets and identifiers in the fixtures are synthetic.

## resultguard

- Jupyter notebook (nbformat) markdown cells as a retrieved-document channel
  (distinct from YAML front matter, Markdown runbooks, and OpenAPI descriptions).
- GraphQL SDL type/field descriptions as a fetched-schema channel (distinct
  from OpenAPI `info.description` and MCP tool descriptions).
- SubRip (`.srt`) cue text as a caption channel (distinct from WebVTT).
- HTML Open Graph `og:description` as a fetched-page island (distinct from
  JSON-LD, SVG `foreignObject`, and HTML comments).
- systemd unit `Description=` as a retrieved-config channel.
- Subversion `svn log` messages as a VCS-history channel (distinct from the
  git-log fixtures in round 5).
- Apple Property List string values as a retrieved-config channel.
- RDF Turtle comments as a linked-data channel (distinct from JSON-LD
  descriptions in round 6).

## toolpoison

- JSON Schema `inputSchema.properties[].default` as a rarely reviewed schema
  channel (distinct from `$comment`, `examples`, and `title`).
- Base58 concealment in a description (rounds 1–6 used base64, base32, Base45,
  uuencode, ROT13, Atbash, and Braille).
- Quoted-printable concealment (distinct from RFC 2047 encoded-words).
- MCP tools/list `_meta` annotations as an out-of-band field.
- Unicode fullwidth Latin confusables (UTS #39 skeleton), distinct from the
  Cyrillic/Latin mixed-script pair in round 6.

## shellfence

- GTFOBins `lua -e` used to read a home SSH key and POST it (not python -c,
  node -e, or php -r).
- `curl --data-binary @file` of `~/.ssh` (a different upload spelling than
  `wget --post-file` or `curl --upload-file`).
- `ncat` as a generic relay of a secret file (distinct from socat FILE:).
- GTFOBins `osascript -e` as an interpreter exec hook.
- `tar cf - ~/.gnupg | curl --data-binary @-` as a pipe-based archive upload.
- `openssl s_client` as a TLS relay for a home SSH key.

## memfence

- Forget/wipe-memory trigger that first archives history to a URL (distinct
  from farewell-dump, SAR-BCC, and emergency-CC).
- Shared Drive folder used as a standing archive channel (distinct from Slack
  status and email BCC).
- Silent rewrite that prepends a tracking pixel to outbound email (distinct
  from typo-correction host rewrites and query-parameter append).
- Logout/session-end transfer into a PagerDuty incident note.
- Silent rewrite of clipboard / pasted URLs to an attacker host.

## piiguard

- Spanish DNI/NIE with the official check letter.
- Irish PPSN (PPS number) with the official check character.
- Chinese resident identity card number with the official checksum.
- Croatian OIB (osobni identifikacijski broj).
- Belgian national register number (NISS / rijksregisternummer).

  These are additional national-ID classes from the existing table, not the
  hetu / AHV / Taiwan / HKID / CUIL set or earlier PESEL / NRIC / TCKN / RUT
  fixtures.

## fetchfence

- `ldap://` loopback (a different non-HTTP scheme than gopher, dict, tftp, smb).
- Docker Engine HTTP API on loopback (`:2375/containers/json`), distinct from
  Consul `/v1/kv` and IMDS.
- `ftp://` to a private-network host (distinct from tftp and smb).
- IPv6 loopback `http://[::1]/server-status` (an admin path, not a /docs preview).
- Private-network `/cgi-bin/` on a router, distinct from metadata IPs and k8s DNS.

## pathfence

- `~/.config/glab/config.yml` (GitLab CLI token store), distinct from rclone,
  flyctl, pulumi, and `gh` hosts.yml.
- `~/.config/heroku/config.json` (Heroku CLI).
- `~/.sfdx/sfdx-config.json` (Salesforce DX hidden-home CLI dir).
- `~/.config/linode-cli/config.ini` (Linode CLI).
- `~/.config/netlify/config.json` (Netlify CLI).

## mcpposture

- `pipx run` of an unpinned package (a different ecosystem spelling than
  npx / uvx / cargo / nix run / docker).
- `podman run image:latest` (a different engine than docker :latest).
- `--listen *` (wildcard bind with a different flag than `--bind *` or 0.0.0.0).
- `nix profile install github:owner/repo` unpinned (a different nix subcommand
  than `nix run`).
- `deno run jsr:@scope/pkg` unpinned (a different specifier than the r4
  `https://` Deno import).

## secretflow

- Notion page / block-append API as a secret sink (distinct from Jira comments,
  Discord, SMTP, Slack, S3, and GraphQL).
- PagerDuty Events API as a secret sink.
- Grafana Loki log push as a secret sink.

## tracesweep

- Shopify Admin API tokens (`shpat_`).
- GitHub fine-grained personal access tokens (`github_pat_`).
- Vercel access tokens (`vercel_`).

  These prefixes were not in the earlier provider list (Slack `xoxb-`,
  Hugging Face `hf_`, DigitalOcean `dop_v1_`, age, PyPI `pypi-`, Groq `gsk_`,
  GitLab `glpat-`, Stripe `sk_live_`, npm `npm_`).

## mcpoauth

- RFC 7662 / RFC 8414: `introspection_endpoint` over cleartext HTTP (a
  different field than revocation, registration, jwks_uri, or logout URIs).
- OpenID Connect `userinfo_endpoint` over cleartext HTTP.
- RFC 9126 `pushed_authorization_request_endpoint` over cleartext HTTP.

## What this set is not

It is not a development set. Detectors were not changed after these fixtures
existed. It is not a copy of the private v0.47 dev set, and it does not reuse
the encodings, countries, paths, LOLBins, OAuth fields, or launchers that
rounds 1–6 already used as fixtures.
