# Sources for independent red-team round 8

Category citations for the fixtures in this directory. Samples are original and synthetic; they are inspired by the *classes* of attack described below, not copied from prior benchmark corpora or from detector tests.

## General frameworks

- OWASP Top 10 for LLM Applications (2025), especially LLM01 prompt injection and LLM03 supply chain.
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) — ASI01 goal hijack, ASI02 tool misuse, ASI03 identity/privilege abuse, ASI04 agentic supply chain, ASI05 unexpected code execution.
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) — tool poisoning, shadowing, confused deputy, exfil via legitimate channels, sandbox escapes, untrusted annotations.
- Simon Willison, [The lethal trifecta for AI agents](https://simonwillison.net/2025/jun/16/the-lethal-trifecta/) (private data + untrusted content + outbound channel).

## Prompt injection in tool results and manifests

- Johann Rehberger / Embrace the Red, [Cursor arbitrary data exfiltration via Mermaid (CVE-2025-54132)](https://embracethered.com/blog/posts/2025/cursor-data-exfiltration-with-mermaid/).
- Simon Willison, [The Summer of Johann](https://simonwillison.net/2025/Aug/15/the-summer-of-johann/) (2025 mermaid and related assistant-output exfil).
- SVG `<desc>` / `<title>` and image-metadata (EXIF UserComment) as hidden instruction channels; HTML/email charset smuggling (UTF-7) applied to retrieved mail.
- FHIR narrative / clinical-document injection; CloudEvents comment payloads; LaTeX `\iffalse` hidden blocks.
- Invariant Labs, [Tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [WhatsApp MCP exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) (right-padded hidden recipients, contact rewrite), [GitHub MCP exploited](https://invariantlabs.ai/blog/mcp-github-vulnerability) (private findings filed to a public repo).
- Trail of Bits, [Line jumping](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/).
- Unicode confusables / mixed-script tool names (UTS #39; Greek omicron, not the Cyrillic or fullwidth cases used earlier).
- HTML-entity obfuscation of override phrasing; MCP `readOnlyHint` annotation deception (OWASP MCP cheat sheet: treat annotations as untrusted).

## Shell / LOLBAS / breakout

- [LOLBAS](https://lolbas-project.github.io/) — `regsvr32 /i:http`, `msiexec /i http://`.
- PowerShell `-EncodedCommand` wrappers; `ruby -e` TCP/shell one-liners; `ssh -R` reverse tunnels.
- Windows Defender / firewall tamper (`Set-MpPreference`, `netsh advfirewall`).
- Container breakout via `nsenter` / `chroot /proc/1/root`.

## Memory poisoning

- Standing identity spoof (“treat mail from X as the owner”), planted wire-transfer pre-approval, planted “2FA is disabled” policy.
- GitHub MCP toxic-flow memory (file private vulns/secrets to a public issue).
- Style-guide steganography (SFTP transcript export hidden in a tone preference).
- Contact-nickname remap (WhatsApp-style recipient rewrite).

## PII

Published check-digit algorithms, all values synthetic:

- Thai National ID; Israeli teudat zehut; UK NHS number (Mod-11); Portuguese NIF; Norwegian fødselsnummer; Korean resident registration number; Romanian CNP; Estonian isikukood; Czech rodné číslo; New Zealand IRD; Indonesian NIK (structured, no check digit); ISO 13616 IBANs for Luxembourg and Iceland.

These jurisdictions were chosen because they are not the national-ID examples listed in the piiguard README (and differ from IDs called out in earlier public benchmark write-ups).

## SSRF / fetch

- IPv4-mapped IPv6 to AWS IMDS (`[::ffff:169.254.169.254]`).
- Alibaba Cloud metadata (`100.100.100.200`); AWS ECS task credentials (`169.254.170.2`); Equinix Metal / Packet (`metadata.packet.net`).
- `169.254.169.254.sslip.io` wildcard-DNS allowlist bypass.
- Unexpected schemes (`rmi://`, `nfs://`) on internal hosts.
- Related 2025 agentic-browser URL handling: [OpenAI Operator cross-origin URL exfil advisory](https://github.com/google/security-research/security/advisories/GHSA-25j5-vvch-9rf3); computer-use vulnerability systematization (arXiv:2507.05445).

## Sensitive paths

Coding-agent and SaaS CLI stores not in the pathfence README's well-known AWS/SSH/kube examples: `~/.claude/.credentials.json`, `~/.codex/auth.json`, Cursor `globalStorage/state.db`, `~/Library/Messages/chat.db`, `~/.npmrc` / `~/.pypirc`, Snowflake `connections.toml`, Databricks token cache, Teleport `~/.tsh`, Borg backup keys.

## MCP client posture

- Unpinned `gem exec` and `mise exec`; `wsl.exe` wrapping `npx -y`.
- `deno run --allow-all https://…` (remote TypeScript, not a `jsr:` pin).
- Mount of `/run/containerd/containerd.sock` (not docker.sock).
- Loader env: `JAVA_TOOL_OPTIONS`, `BASH_ENV`, `DOTNET_STARTUP_HOOKS`.
- Forced `HTTP_PROXY` / `ALL_PROXY` to an attacker proxy.

## Secret presence and propagation

- OpenSSH and OpenPGP private key blocks in logs.
- Newer AI/SaaS prefixes not listed in the tracesweep README: `sk-or-v1-` (OpenRouter), `xai-`, `lsv2_pt_` (LangSmith), `r8_` (Replicate), `sq0atp-` (Square), `CFPAT-` (Contentful), `lin_api_` (Linear), `dapi` (Databricks).
- Propagation sinks distinct from earlier ticket/log examples: Twilio SMS, Datadog logs, Dropbox upload, Zendesk comments, ntfy.sh.

## OAuth metadata

- RFC 8628 device-code grant with a cleartext `verification_uri` and no PKCE S256.
- RFC 8693 token exchange / impersonation plus a published oct JWK (`k`).
- `request_object_signing_alg_values_supported: ["none"]` and a custom-scheme `authorization_endpoint`.
- Protected-resource `authorization_servers` pointing at a look-alike host; broad Graph/Okta scopes — the token-audience / confused-deputy class from 2026 MCP Python SDK advisories ([session routing](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-jpw9-pfvf-9f58), [token audience](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-w4fh-qvv9-3v23), [AS chosen by the resource server](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-qx49-fqc8-xw99)).
- `javascript:` / `data:` schemes on `op_policy_uri` and `service_documentation`.

## What this round deliberately avoided

Techniques already called out in the public write-ups of rounds 1–7 (for example Jupyter/GraphQL SDL/SRT/Open Graph, iCalendar/vCard, RFC 2047/Base45/Base58, Slack incoming webhooks, `github_pat_` / `shpat_` / `glpat-`, Notion/PagerDuty/Loki sinks, and the national IDs listed in those round summaries) were not reused as the basis of these fixtures.
