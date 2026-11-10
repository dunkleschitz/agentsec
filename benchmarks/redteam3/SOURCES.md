# Sources for the independent red-team set — round 3

This set was written after the v0.43.0 detection rules were frozen. It is
scored once and is not used to retune those rules. Techniques below were
chosen from published research that rounds 1 and 2 did not use as the basis
of their fixtures (compare `benchmarks/redteam/SOURCES.md` and
`benchmarks/redteam2/SOURCES.md`). Every credential and personal-data value
in the corpus is synthetic.

The list is a technique catalog, not a claim that every fixture is a
faithful reproduction of a particular paper's payload.

## Prompt injection in tool results (resultguard)

- **Greshake et al., "Not what you've signed up for"** (arXiv:2302.12173, 2023).
  Indirect prompt injection via retrieved web content. The CSS-hidden-text
  fixture uses `color:transparent` / `font-size:0` rather than the
  white-on-white / 1px email pattern that round 2 took from ShadowLeak.
- **Jiang et al., ArtPrompt: ASCII Art-based Jailbreak Attacks**
  (arXiv:2402.11753, 2024). A retrieved page presents a letter grid and tells
  the model to read it as a new instruction.
- **MIME quoted-printable** (RFC 2045). An email-read tool returns a
  `Content-Transfer-Encoding: quoted-printable` body that decodes to an
  instruction. Earlier rounds used HTML hiding, base64, and hex, not this
  encoding.
- **SVG/XML smuggling.** An icon response carries agent instructions in
  `<desc>` and off-canvas `<text>` nodes. See OWASP discussions of HTML/SVG
  smuggling and the markup-as-injection surface in Greshake et al.
- **Yan et al., Virtual Prompt Injection** (arXiv:2307.16888, 2023). A
  retrieved document claims it has been merged into the system prompt and
  plants a standing exfil rule.
- **Anthropic, Many-shot jailbreaking** (2024,
  https://www.anthropic.com/research/many-shot-jailbreaking). A fetched
  "example transcript" contains repeated Human/Assistant turns that ignore
  rules, then a live outbound instruction.
- **Model Context Protocol, Sampling**
  (https://modelcontextprotocol.io/docs/concepts/sampling). A tool result
  asks the host to issue a sampling request whose system prompt is
  attacker-controlled — a different MCP surface than tool-description
  poisoning.
- **Russinovich, Salem, Eldan, Crescendo** (arXiv:2404.01833, 2024). A
  gradual request in one tool result ends by asking the model to attach
  notes to an image URL.

## Poisoned MCP tool descriptions (toolpoison)

- **MCP specification, Lifecycle / Initialize `instructions`**
  (https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle).
  The rarely-reviewed server-level `instructions` string is an instruction
  channel distinct from per-tool descriptions.
- **MCP specification, Elicitation**
  (https://modelcontextprotocol.io/docs/concepts/elicitation). A poisoned
  description tells the model to collect a password through the structured
  user-input API.
- **MCP specification, Sampling**, applied to a tool description that
  requests an attacker-controlled system prompt.
- **RFC 2045 quoted-printable** and **POSIX uuencode** as concealment
  layers in a description (rounds 1–2 used base64, CJK, and Unicode tags).
- **Trail of Bits "Jumping the line"** class, applied to a
  download-and-exec *preamble* (`curl … | bash` before every call) rather
  than the chmod-prefix line-jumping shape used earlier.

## Dangerous shell (shellfence)

- **LOLBAS project** (https://lolbas-project.github.io/): `certutil
  -urlcache`, `mshta` remote HTA, and `bitsadmin /transfer` — Windows
  living-off-the-land binaries, not `curl|sh`.
- **Download-then-execute without a pipe:** `curl -o`, `chmod +x`, then
  running the file. Earlier rounds focused on pipe-to-shell.
- **OpenSSH `ProxyCommand`** as an execution trampoline
  (`ProxyCommand='curl … | bash'`).
- **MITRE ATT&CK T1574.006**, Dynamic Linker Hijacking via
  `/etc/ld.so.preload`.
- **Git hooks** (`.git/hooks/post-checkout`) as a persistence/execution
  mechanism, distinct from crontab or systemd unit drops.

## Memory poisoning (memfence)

- **Count-delayed exfil.** A standing memory says: after N user messages,
  POST the conversation. Related to persistent-injection work (SpAIware /
  Unit 42) but a different trigger than the "when the user says yes"
  phrasing of earlier rounds.
- **Protocol downgrade** planted as a preference (always use `http://`,
  skip certificate checks).
- **Profile-field poisoning** pointing at a fake payroll portal (OWASP
  ASI06 class) rather than an IBAN/BEC account swap.
- **Virtual Prompt Injection** (arXiv:2307.16888) applied to a memory
  store: "append this sentence to your system prompt."
- **German-language** persist + credential-exfil wording (rounds 1–2 used
  English and one Spanish sample).

## PII in transcripts (piiguard)

- **UIDAI Aadhaar** (12-digit unique identity, India).
- **Receita Federal, CPF** (Cadastro de Pessoas Físicas, Brazil).
- **Australian Taxation Office, Tax File Number (TFN).**
- **Skatteverket personnummer** (Sweden, `YYYYMMDD-XXXX`).
- **Quoted-printable** concealment of an email and phone number (RFC 2045).

  These national-ID formats were not in the US/UK/CA/MRZ samples of
  earlier rounds. Values are synthetic.

## MCP client posture (mcpposture)

- **npm/npx `github:user/repo` shorthand** with no commit pin (OpenSSF
  pinning guidance; docs.npmjs.com). Distinct from the `git+https`
  unpinned source used in round 2.
- **`npx --registry`** pointing at a plaintext third-party host
  (dependency-confusion / registry-override class, Birsan 2021) via a CLI
  flag rather than `npm_config_registry` in the environment.
- **Filesystem MCP server rooted at `/`**, an over-broad root distinct
  from Docker credential-directory mounts.
- **`node -e fetch().then(eval)`** remote bootstrap — the JavaScript
  counterpart of the round-2 `python -c urlopen/exec` sample.
- **`curl -k`** (TLS verification disabled) piped into `node` as a
  launcher (CIS / curl documentation; pipe-to-interpreter class).

## SSRF / fetch destinations (fetchfence)

- **GCP instance metadata** at `metadata.google.internal` (Google Cloud
  docs). Earlier rounds used AWS/Alibaba-style link-local IPs, not this
  hostname.
- **`gopher://` and `dict://`** non-HTTP schemes (PortSwigger SSRF;
  Orange Tsai, "A New Era of SSRF").
- **IDN / punycode hostname confusion** (Unicode TR36).
- **Azure-style metadata hostname** (`metadata.azure.internal`), as a
  distinct shape from the raw `169.254.169.254` IPv4 used earlier.

## Sensitive paths (pathfence)

- **Terraform CLI credentials** (`~/.terraform.d/credentials.tfrc.json`,
  HashiCorp docs).
- **Firefox `cookies.sqlite`** (MITRE ATT&CK T1539 / T1555.003).
- **Windows SAM via an NT device prefix** (`\\?\C:\Windows\System32\config\SAM`,
  MITRE T1003.002).
- **`/proc/self/root/etc/shadow`**, a procfs alias distinct from
  `/proc/self/environ`.
- **Git credential store** (`~/.git-credentials`, git-credential-store
  documentation).

## Secret presence (tracesweep) and secret flow (secretflow)

- **Slack bot token** (`xoxb-`) and **Twilio** account/auth material
  (GitGuardian provider dictionaries). Earlier rounds used Hugging Face,
  GitLab, npm, SendGrid, Azure, Telegram, and similar, not these two
  prefixes.
- **OpenPGP ASCII-armored private key** (RFC 4880 / RFC 9580).
- **RFC 2397 `data:` URL** as a secret sink (not a webhook query or
  image tag).
- **User-Agent header** as a secret sink (the Gemini Trifecta work was
  about User-Agent as an *injection source*, not a secret sink).
- **Third-party QR-code generator URL** as a sink.

## MCP OAuth metadata (mcpoauth)

- **RFC 9700 OAuth 2.0 Security BCP**: a `redirect_uris` entry that is
  `http://` on a public host (token theft via an insecure redirect).
  Earlier rounds covered `file:` endpoints and implicit/hybrid grants,
  not this miss.
- **OAuth metadata SSRF** via a `token_endpoint` pointing at
  `metadata.google.internal` (distinct from the IPv6 IMDS form in round 2).
- **Resource Owner Password Credentials grant** advertised in
  `grant_types_supported` (prohibited by RFC 9700; different from the
  implicit grant issues already used).

## What this set is not

It is not a complete reproduction of any of the papers above, not a
ranking of those techniques, and not evidence of performance on live
traffic. Several fixtures are deliberately hard for a static heuristic
(many-shot in-context examples, ArtPrompt grids, non-HTTP SSRF schemes
the current detector may not list). A miss is reported and is left
standing.
