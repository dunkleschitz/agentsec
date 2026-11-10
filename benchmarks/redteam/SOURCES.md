# Sources for the independent red-team corpus

Samples under `benchmarks/redteam/` were written **without reading** detector
source code or rule tables first (only each tool's README / usage). Techniques
are drawn from published research and public incident write-ups. All secrets and
PII values are **synthetic / reserved**.

## Prompt injection in tool results (resultguard)

| Sample theme | Source |
|---|---|
| Markdown / reference-style image exfil | Aim Security **EchoLeak** (CVE-2025-32711) — [Simon Willison summary](https://simonwillison.net/2025/Jun/11/echoleak/), [arXiv:2509.10540](https://arxiv.org/html/2509.10540) |
| Fake tool-error demanding SSH key resubmit | CyberArk **Advanced Tool Poisoning (ATPA)** / [mcp-exploit-tools output poisoning](https://crashoz.github.io/mcp-exploit-tools/exploits/output-poisoning/) |
| Malicious GitHub Issue → private repo leak | Invariant Labs [GitHub MCP exploited](https://invariantlabs.ai/blog/mcp-github-vulnerability) (May 2025) |
| Support-ticket → SQL dump / lethal trifecta | [General Analysis on Supabase MCP](https://generalanalysis.com/blog/supabase-mcp-blog); [Simon Willison](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/) |
| Unicode TAG smuggling | Embrace The Red [ASCII Smuggler](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/) |
| “Near-factory state” wipe prompt | Amazon Q Developer extension incident (July 2025, CVE-2025-8217) — [404 Media](https://www.404media.co/hacker-plants-computer-wiping-commands-in-amazons-ai-coding-agent/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/amazon-ai-coding-agent-hacked-to-inject-data-wiping-commands/) |
| Homoglyph / spaced override | Common prompt-injection evasion (Cyrillic lookalikes, letter spacing) |

## MCP tool poisoning (toolpoison)

| Sample theme | Source |
|---|---|
| `<IMPORTANT>` + sidenote SSH/`mcp.json` exfil | Invariant Labs [Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) (April 2025) |
| Line-jumping `chmod -R 0666 ~;` prefix | Trail of Bits [Jumping the line](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/) |
| Full-schema poisoning (param description / name / `x-*`) | CyberArk FSP — [mcp-exploit-tools FSP](https://crashoz.github.io/mcp-exploit-tools/exploits/full-schema-poisoning/); [Aguara write-up](https://aguarascan.com/blog/mcp-tool-poisoning-beyond-descriptions/) |
| ANSI conceal / invisible text in descriptions | Trail of Bits [Deceiving users with ANSI terminal codes in MCP](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/) |
| Cross-tool `send_email` shadowing | Invariant Labs [mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments) |
| Zero-width broken instructions | Pillar Security [Rules File Backdoor](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents) |

## Secrets / flows (tracesweep, secretflow)

| Sample theme | Source |
|---|---|
| Provider-shaped keys in transcripts | Common agent leak patterns; Nx **s1ngularity** supply-chain used AI CLIs to harvest secrets — [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack), [Snyk](https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/) |
| Base64 / split / concatenated reuse | Documented detector limits (value-equality taint; pattern presence) |

## Dangerous shell (shellfence)

| Sample theme | Source |
|---|---|
| `curl\|bash`, reverse shells, `rm -rf /` | Classic agent RCE patterns |
| DNS exfil via `dig`/`nslookup` | Embrace The Red [Claude Code DNS exfil CVE-2025-55284](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/) |
| Amazon Q-style home wipe | Same Amazon Q incident as above |
| Hex-escaped commands | Common shell obfuscation |

## SSRF (fetchfence)

| Sample theme | Source |
|---|---|
| `169.254.169.254`, `file://`, webhook OOB, RFC1918 | Standard SSRF / agent-fetch risks |
| Decimal IP / IPv6-mapped metadata | PortSwigger [URL validation bypass cheat sheet](https://portswigger.net/research/introducing-the-url-validation-bypass-cheat-sheet) |

## PII / paths / MCP posture / memory

| Area | Source |
|---|---|
| PII categories | Standard identity fields; reserved `555` / `@example.com` / Luhn test PAN |
| Sensitive paths | Common credential / browser DB / docker.sock locations |
| MCP client posture | Privileged Docker, `curl\|sh` launchers, plaintext remotes — aligned with MCP security guidance from Trail of Bits / Invariant |
| Memory poisoning | Embrace The Red [SpAIware](https://embracethered.com/blog/posts/2024/chatgpt-macos-app-persistent-data-exfiltration/); [Windsurf SpAIware](https://embracethered.com/blog/posts/2025/windsurf-spaiware-exploit-persistent-prompt-injection/); MINJA [arXiv:2503.03704](https://arxiv.org/abs/2503.03704) |

## Honesty

This corpus is still **synthetic and labeled**. It is designed to stress heuristic
scanners with published techniques and look-alikes; it is not production traffic
and not a claim about market-wide detection rates.
