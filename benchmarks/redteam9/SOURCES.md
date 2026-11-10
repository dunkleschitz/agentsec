# Sources for independent red-team round 9

All samples are original and use only synthetic identifiers. The citations
below are the public research and technique classes that motivated the
fixtures. None of these classes were used as the basis of round 8.

## Prompt injection in tool results and tool descriptions

- [Log-To-Leak](https://arxiv.org/abs/2610.36108) (arXiv:2610.36108, 2026).
  A later, seemingly legitimate logging tool is requested *after* a successful
  benign call, and the model is told to attach the user query, prior tool
  outputs, the system prompt, and secrets. Instantiated in a calendar tool
  result and in MCP tool descriptions / cross-tool `send_mail` hijacks.
- SkillAudit 2026 and [CVE-2026-24299](https://www.cve.org/CVERecord?id=CVE-2026-24299)
  (Copirate 365 / Embrace the Red): CSS `@font-face` and attribute-selector
  `background-image` exfiltration in rendered MCP or Copilot HTML, including
  zero-size instructions. Used in tool *results* and in HTML/markdown *descriptions*.
- [Silent Egress](https://arxiv.org/abs/2602.22450) (arXiv:2602.22450, 2026).
  Injection in URL-preview titles and snippets (not Open Graph markup) plus
  sharded exfil fetches; also planted as a standing "preview every pasted URL
  via this reflector" memory.
- [Decode-time steganography](https://arxiv.org/abs/2610.31974) (arXiv:2610.31974).
  The hidden instruction appears only after a `decode_png` tool expands PNG
  `tEXt` or LSB payloads (not EXIF).
- AgentBreaker (2026) and the Cloud Security Alliance CUA / VPI-Bench write-ups
  of zero-font, 1px, and off-screen DOM text that a user never sees.
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
  on x402 payment terms in a tool result: treat `payTo`, asset, network, and
  amount as untrusted server input, bind them into the approval, and never pay
  silently or hide the recipient. Instantiated as a `PaymentRequired` result
  and as catalog copy that asks the model to transfer USDC first.
- reStructuredText hidden-comment directives in a docs-render tool result
  (a document-comment channel distinct from the markup families used earlier).
- Right-to-left Hebrew instructions in a tool description (a language/script
  channel, not a confusable-homoglyph tool *name*).

## Memory, cost, and multi-agent policy

- OWASP AI Agent Security guidance on denial of wallet (forced expensive
  retries, ignored spend caps), approval-threshold / decision manipulation,
  and multi-agent context relay.
- Goal hijack: a planted "maximize affiliate revenue" memory that silently
  rewrites checkout links.
- [CVE-2026-21852](https://github.com/advisories/GHSA-jh7p-qr78-84p7) /
  Check Point Research (2026): `ANTHROPIC_BASE_URL` redirected to an attacker
  endpoint so API keys and prompts leak. Instantiated as a persistent memory
  and as an MCP `env` override.

## Shell, fetch, path, and MCP posture

- LOLBAS `rundll32 url.dll,FileProtocolHandler` and `cmstp /s`.
- Perl and PHP CLI one-liners (`perl -e` TCP socket, `php -r` file exfil),
  not the interpreter families used in earlier rounds.
- `iodine` DNS tunneling; Image File Execution Options Debugger hijack on
  `utilman.exe` (ATT&CK T1546.012); `wevtutil cl` event-log clearing
  (ATT&CK T1070.001).
- Loopback wildcard DNS distinct from sslip.io: `lvh.me` and `vcap.me`
  aimed at a local Docker API or admin port.
- Non-HTTP fetch schemes and internal endpoints not used in round 8:
  `amqp://` to RFC1918, kubelet `:10250/runningpods/`, Spring Actuator
  `/actuator/env`, `sftp://` to an internal secrets path.
- Credential and messaging paths not used in round 8: GitHub CLI
  `~/.config/gh/hosts.yml`, `~/.docker/config.json`, `~/.git-credentials`,
  `~/.cargo/credentials.toml`, Telegram Desktop `tdata`, Maven
  `~/.m2/settings.xml`.
- Unpinned launchers and env hijacks not used in round 8: `brew install --HEAD`
  from a raw formula URL, unpinned `dotnet tool install --global --prerelease`,
  Composer `require` of `dev-main` over HTTP, `SSLKEYLOGFILE` plus
  `GIT_SSH_COMMAND` ProxyCommand, and a host mount of `/var/run/crio.sock`
  (not containerd.sock).

## Secrets, PII, and OAuth metadata

- secretflow sinks not used in earlier rounds: Intercom conversations, Splunk
  HTTP Event Collector, Sentry store/envelope, Airtable records, Mailgun
  messages. Taint is value equality; fixtures are generated.
- tracesweep token shapes not listed in the README and not used in round 8:
  PostHog `phc_`, PlanetScale `pscale_tkn_`, Sourcegraph `sgp_`, Stripe
  `sk_test_` (the README calls out `sk_live_`), and a `BEGIN EC PRIVATE KEY`
  PEM (not OpenSSH or PGP). Fixtures are generated.
- National identifiers and IBANs not in the piiguard README table and not
  used in round 8, with public checksums where an algorithm exists: Danish
  CPR, Icelandic kennitala, Austrian SVNR, Greek AFM, Hungarian TAJ, and a
  UAE (AE) IBAN.
- OpenID CIBA `backchannel_authentication_endpoint` over HTTP; `jwks_uri`
  over HTTP; RFC 8705 `mtls_endpoint_aliases` retargeted at instance
  metadata; OIDC `request_uris` pointing at an attacker request object;
  a JWKS document that publishes an RSA private exponent `d` (not an oct
  `k`).

## Hard negatives

Benign samples are realistic look-alikes of the same classes: third-person
advisories, official documentation URLs, honest x402 terms that ask for
confirmation, official `ANTHROPIC_BASE_URL` pins and spend/approval caps,
read-only `wevtutil qe` / `php -l` / `rundll32 printui.dll`, placeholder
tokens (`phc_your_project_key_here`, `${POSTHOG_KEY}`, `sk_test_xxxx`,
`.env.example` DSN), redacted IBANs and format-only ID help, pinned Homebrew
formulae, same-origin mTLS aliases, and CIBA over HTTPS.
