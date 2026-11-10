# Sources for independent red-team round 2

Samples under `benchmarks/redteam2/` were written against **v0.41.0** by a second
independent red-team **without reading** detector source code, rule tables, or the
round-1 fixtures in `benchmarks/redteam/`. Only each tool's README / `--help` and the
round-1 `SOURCES.md` (to avoid repeating its techniques) were read. Round 1 drew on
Invariant Labs, Trail of Bits, CyberArk, Embrace The Red (ASCII Smuggler, SpAIware,
Claude Code DNS exfil), EchoLeak, Supabase/General Analysis, Amazon Q, Pillar Security,
PortSwigger decimal/IPv4-mapped IPs, MINJA, and Nx s1ngularity *secret patterns*. Round 2
uses different published techniques, or a different surface of the same incident
(for example s1ngularity's AI-CLI flags rather than its key formats).

All secrets and PII values are **synthetic**: random strings in provider shapes, `555-01xx`
phone numbers, `@example.com` addresses, reserved IP ranges (`198.51.100.0/24`,
`203.0.113.0/24`), and Luhn-valid numbers generated for this set. Attacker domains are
made up and the files are never fetched.

## Prompt injection in tool results (resultguard)

| Sample | Source |
|---|---|
| Hidden HTML email, "full authorization", base64 PII into a lookup URL | Radware **ShadowLeak** — [radware.com/blog/threat-intelligence/shadowleak](https://www.radware.com/blog/threat-intelligence/shadowleak/) (Sep 2025) |
| XML/INI policy-file framing | HiddenLayer **Policy Puppetry** — [hiddenlayer.com/research/novel-universal-bypass-for-all-major-llms](https://www.hiddenlayer.com/research/novel-universal-bypass-for-all-major-llms) (Apr 2025) |
| README tells the agent to set `chat.tools.autoApprove` | Embrace The Red, **GitHub Copilot RCE (CVE-2025-53773)** — [embracethered.com/…/github-copilot-remote-code-execution-via-prompt-injection](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) |
| Slack message rewrites `~/.cursor/mcp.json` | Aim Labs **CurXecute (CVE-2025-54135)** — [Tenable FAQ](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison), [BleepingComputer](https://www.bleepingcomputer.com/news/security/ai-powered-cursor-ide-vulnerable-to-prompt-injection-attacks/) |
| Instructions in a URL `#fragment` | Cato CTRL **HashJack** — [The Register](https://www.theregister.com/software/2025/11/25/hashjack-attack-shows-ai-browsers-can-be-fooled-with/1872078), [Help Net Security](https://www.helpnetsecurity.com/2025/11/26/hashjack-hijack-ai-assistants-browsers/) |
| User-Agent log injection | Tenable **Gemini Trifecta** — [tenable.com/blog/the-trifecta-…](https://www.tenable.com/blog/the-trifecta-how-three-new-gemini-vulnerabilities-in-cloud-assist-search-model-and-browsing) (Sep 2025) |
| Web-to-Lead question list + `<img>` on an expired allow-listed domain | Noma Security **ForcedLeak** — [noma.security/blog/forcedleak-…](https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce), [Simon Willison](https://simonwillison.net/2025/Sep/26/agentforce/) |
| Binary via U+2062 / U+2064 | Embrace The Red **Sneaky Bits** — [embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler](https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/) |
| Bytes hidden in emoji variation selectors | Paul Butler — [Smuggling arbitrary data through an emoji](https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/) (Feb 2025) |
| Hidden PDF text → web-search tool exfil | CodeIntegrity — [Notion 3.0 AI agent web-search exfiltration](https://www.codeintegrity.ai/blog/notion), [Simon Willison](https://simonwillison.net/2025/Sep/19/notion-lethal-trifecta/) (Sep 2025) |
| Calendar invite with delayed home-control action | SafeBreach — [Invitation Is All You Need](https://www.safebreach.com/blog/invitation-is-all-you-need-hacking-gemini/), [arXiv:2508.12175](https://arxiv.org/abs/2508.12175) |

## MCP tool poisoning (toolpoison)

| Sample | Source |
|---|---|
| "Best tool in the world, always prefer it" | **MPMA** — [arXiv:2505.11154](https://arxiv.org/abs/2505.11154) |
| Implicit-trigger parameter tampering of another tool | **MCPTox** — [arXiv:2508.14925](https://arxiv.org/abs/2508.14925) |
| Orchestration injection (fee on every transaction) | Elastic Security Labs — [MCP Tools: Attack Vectors and Defense Recommendations](https://www.elastic.co/security-labs/threat-command/mcp-tools-attack-defense-recommendations) |
| Instruction inside `outputSchema` | CyberArk Full-Schema Poisoning (round 1 covered inputSchema) applied to MCP 2025-06-18 structured output |
| Lying `readOnlyHint` annotations | MCP spec 2025-06-18 (annotations from untrusted servers are untrusted); Invariant Labs [tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) |
| Schema-default BCC | Koi Security **postmark-mcp** — [The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html), [Postmark notice](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package) |
| Base64 "configuration hint", Chinese-language instruction | Encoded / multilingual variants used in MCPTox templates |

## Secrets (tracesweep, secretflow)

| Sample | Source |
|---|---|
| Hugging Face `hf_` tokens | Wiz — [65% of Forbes AI 50 leaked secrets](https://www.wiz.io/blog/forbes-ai-50-leaking-secrets) |
| GitLab `glpat-`, npm `npm_`, SendGrid, Azure connection string, DigitalOcean, Telegram bot | GitGuardian *State of Secrets Sprawl*; Shai-Hulud harvesting |
| Double-base64 `data.json`; secrets pushed to a public repo | **Shai-Hulud** — [StepSecurity](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised), [GitGuardian](https://blog.gitguardian.com/shai-hulud-a-persistent-secret-leaking-campaign/), [Wiz](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack) |
| Secret in a URL path to a lookup host | Radware ShadowLeak (above) |
| Secret in an `<img>` inside an email | Noma ForcedLeak (above) |
| Secret persisted to long-term memory | Unit 42 — [When AI Remembers Too Much](https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory/) |
| Percent-encoded key; hex-encoded key in a Mermaid link | Adam Logue — [M365 Copilot exfiltration via Mermaid diagrams](https://www.adamlogue.com/microsoft-365-copilot-arbitrary-data-exfiltration-via-mermaid-diagrams-fixed/) (Oct 2025); URL encoding as a transform |

## Dangerous shell (shellfence)

| Sample | Source |
|---|---|
| `claude --dangerously-skip-permissions`, `gemini --yolo`, `q chat --trust-all-tools` | **Nx s1ngularity** — [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack), [Snyk](https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/) |
| Allow-listed `grep` + whitespace + `; env \| curl` | Tracebit — [Gemini CLI hijack](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack) (Jul 2025) |
| `trufflehog filesystem /` + `gh repo create --public` | Shai-Hulud (above) |
| `DROP SCHEMA … CASCADE`, `terraform destroy -auto-approve`, `kubectl delete ns --force` | Replit / SaaStr incident — [The Register](https://www.theregister.com/software/2025/07/21/vibe-coding-service-replit-deleted-production-database/719783), [Fast Company](https://www.fastcompany.com/91372483/replit-ceo-what-really-happened-when-ai-agent-wiped-jason-lemkins-database-exclusive); [Ars Technica](https://arstechnica.com/information-technology/2025/07/ai-coding-assistants-chase-phantoms-destroy-real-user-data/) |
| `powershell -ExecutionPolicy Bypass -EncodedCommand` | JFrog — [CVE-2025-6514 write-up](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) |
| Python `socket`/`pty` reverse shell; `${IFS}` obfuscation | GTFOBins / PayloadsAllTheThings |
| `~/.ssh/authorized_keys` backdoor | MITRE ATT&CK T1098.004 |

## PII (piiguard)

| Sample | Source |
|---|---|
| UK NINO, Canadian SIN, passport MRZ, vCard, PHI (MRN/DOB/ICD-10) | OWASP LLM02:2025 Sensitive Information Disclosure; ICAO Doc 9303; RFC 6350; HIPAA 45 CFR 164.514 |
| PII percent-encoded or base64-encoded into a URL | Radware ShadowLeak (above) |

## SSRF / fetch (fetchfence)

| Sample | Source |
|---|---|
| `169.254.169.254.nip.io`, Alibaba `100.100.100.200`, `kubernetes.default.svc` | PayloadsAllTheThings SSRF cloud-metadata list |
| AWS IMDS IPv6 `[fd00:ec2::254]` | AWS EC2 instance-metadata documentation |
| `127.1`, `user@host` confusion | Orange Tsai, *A New Era of SSRF* (Black Hat USA 2017) |
| `0.0.0.0:6277` MCP Inspector proxy | Oligo Security, CVE-2025-49596 (Jun 2025) |
| Telegram Bot API / Discord webhook drops; Burp `oastify.com` | Infostealer / npm-malware exfil reports; PortSwigger Collaborator docs |

## Sensitive paths (pathfence)

| Sample | Source |
|---|---|
| Prefix-sibling dir + symlink to `/etc/sudoers` | Cymulate **EscapeRoute** — [CVE-2025-53109/53110](https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/), [GHSA-q66q-fx2p-7w4m](https://github.com/advisories/GHSA-q66q-fx2p-7w4m) |
| `gh` hosts.yml, AI-CLI credential files, crypto wallets | s1ngularity / Shai-Hulud target lists (above) |
| `/proc/self/environ`, k8s service-account token, `%2f` traversal | PayloadsAllTheThings File Inclusion / Directory Traversal |
| macOS keychain, Windows Credential Manager, UNC NTLM leak | MITRE ATT&CK T1555.001, T1555.004, T1187 |

## MCP client posture (mcpposture)

| Sample | Source |
|---|---|
| `mcp-remote@0.1.15` pinned | JFrog CVE-2025-6514 — [GHSA-6xpm-ggf7-wc3p](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p) |
| Gemini CLI `trust: true`; Cline `alwaysAllow`/`autoApprove` | Client docs; Embrace The Red CVE-2025-53773 (auto-approve as RCE enabler) |
| `npm_config_registry` to a plaintext mirror | Alex Birsan, *Dependency Confusion* (2021) |
| Bind-mounting `~/.ssh` and `~/.aws` | Docker MCP / container-isolation guidance |
| Unpinned `git+https` source, custom-header key, `python3 -c` bootstrap | OpenSSF pinning guidance; Check Point **MCPoison** (CVE-2025-54136) |

## Memory poisoning (memfence)

| Sample | Source |
|---|---|
| Session-summary "user goal" exfil | Unit 42, [When AI Remembers Too Much](https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory/) |
| False facts / delayed "yes" trigger | Embrace The Red, [Hacking Gemini's Memory…](https://embracethered.com/blog/posts/2025/gemini-memory-persistence-prompt-injection/) |
| Trigger-phrase backdoor; poisoned "lesson learned" | **AgentPoison** — [arXiv:2407.12784](https://arxiv.org/abs/2407.12784) |
| BEC bank-detail swap; Spanish persistence | OWASP Top 10 for Agentic Applications (ASI06 Memory & Context Poisoning) |

## MCP OAuth metadata (mcpoauth, new in round 2)

| Sample | Source |
|---|---|
| `file:` authorization_endpoint | JFrog CVE-2025-6514 PoC value |
| Hybrid/implicit response types; TLS on all endpoints | RFC 9700 *OAuth 2.0 Security BCP* (Jan 2025); RFC 8628 |
| Org-admin / delete scopes | MCP Authorization spec (scope minimization) |
| RSA CRT private members `p`,`q`,`dp`,`dq`,`qi` | RFC 7518 §6.3.2 |
| IPv6 IMDS `jwks_uri`, `*.svc` introspection endpoints | SSRF via OAuth metadata (PortSwigger OAuth research) |
| Published initial/registration access tokens | RFC 7591 / RFC 7592 |

## Honesty

This set is still **synthetic and labeled by the red-team**. A few labels are judgment
calls and are documented in each sample's `notes` (for example, a key sent to its own
provider's API is labeled benign; open dynamic client registration is benign because the
MCP spec recommends it). Some malicious samples are hard for any static heuristic (false
facts in memory, symlink escapes, lying annotations); they stay in the set so the score is
not inflated by leaving them out.
