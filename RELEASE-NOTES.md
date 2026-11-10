# agentsec v0.46.0

Offline, stdlib-only kit. 38 tools (foundry #38 promptaudit shipped on main earlier the same day). This release changes approach: class-level detectors instead of enumerating missed instances, then scores a fresh round-6 set once. 2010 tests.

### Generalization (class-level, not fixture-specific instances)

Round 5 is the development set. Rules were rewritten around classes, then checked on a private labeled dev set of new variants, then frozen before any round-6 sample was written:

- **toolpoison / resultguard** — a generic obfuscation layer: text that is not natural language (encoded or transformed text, low dictionary-word ratio, unusual scripts, leftover control characters, overstrike) is treated as suspicious, plus a best-effort decode-and-rescan for common transforms (including hex dumps). All MCP catalog surfaces are walked generically (prompts, prompt arguments, prompt messages, resources, templates, and server instructions). Well-formed ANSI color codes are typography, not concealment.
- **piiguard** — a data-driven national-ID table (30+ country formats) with checksum validators and context keywords. Unlabeled ambiguous digit strings require keywords so order numbers and build metrics stay clean; distinctive formats (letters, separators, reserved prefixes) may still fire on checksum alone.
- **pathfence** — a generic sensitive-path classifier: credential/key/token/vault/state/keyring/wallet/session/profile-db name patterns, known credential-bearing app dirs, XDG/Application Support roots, and cluster config basenames — not a list of the missed paths.
- **shellfence** — a generic rule for execution or exfil via exec-hook options (`-exec`, `xargs`, `$(shell`, interpreter `system(`) or a transfer tool targeting home or secrets, plus a broader LOLBin/GTFOBins-style table.
- **mcpoauth / mcpposture** — the whole OAuth/OIDC metadata document is checked against spec-level requirements (`token_endpoint_auth_methods_supported=none`, wildcard or non-https redirects, http endpoints on any `*_uri` field). Generic launch hygiene: floating `@latest` / `:latest` / `==latest` in any ecosystem, `cwd` of `/`, binding to all interfaces.
- **secretflow** — local comparison tools (`equals`, `assert_eq`, and compare-shaped `left`/`right` arguments) are not treated as reuse or exfil.

### Benchmark

Unseen F1 on successive independent rounds had been falling (78.3 → 74.4 → 61.5). This release is scored against a new blind round 6. The series is now:

| Set | P / R / F1 | Notes |
|---|---|---|
| Author corpus (125) | 100% / 100% / 100% | 76/0/0/49 |
| Held-out | 100% / 100% / 100% | 26/0/0/14 |
| Red-team round 1 (v0.40.0, unseen) | 93.8% / 85.7% / 89.6% | 60/4/10/26, frozen |
| Same round-1 set after later fixes | 100% / 100% / 100% | 70/0/0/30, labeled **seen** |
| Red-team round 2 (v0.41.0, unseen) | 80.4% / 38.9% / 52.5% | 37/9/58/30, frozen |
| Same round-2 set after later generalization | 100% / 100% / 100% | 95/0/0/39, labeled **seen** |
| Red-team round 3 (v0.43.0, unseen) | 97.3% / 65.5% / 78.3% | 36/1/19/28, frozen |
| Same round-3 set after later generalization | 100% / 100% / 100% | 55/0/0/29, labeled **seen** |
| Red-team round 4 (v0.44.0, unseen) | 97.0% / 60.4% / 74.4% | 32/1/21/26, frozen |
| Same round-4 set after later generalization | 100% / 100% / 100% | 53/0/0/27, labeled **seen** |
| Red-team round 5 (v0.45.0, unseen) | 96.0% / 45.3% / 61.5% | 24/1/29/26, frozen |
| Same round-5 set after v0.46.0 generalization | 100% / 94.3% / 97.1% | 50/0/3/27, labeled **seen** |
| Red-team round 6 (v0.46.0, unseen) | 97.4% / 69.8% / 81.3% | 37/1/16/26, scored **once** |

Round 6 (`benchmarks/redteam6/`, 80 samples) was written after the rules were frozen, from published techniques rounds 1–5 did not use (iCalendar `DESCRIPTION`, vCard `NOTE`, WebVTT, OpenAPI `info.description`, YAML front matter, RFC 2047 encoded-words, JSON-LD, Base45, JSON Schema `examples`/`title`, mixed-script confusables, `python -c` / `socat` / `bitsadmin` / `node -e` / `php -r` / `wget --post-file`, farewell-dump and planted-proxy memory, typo-correction and SAR/BCC memory, Slack status, Finnish hetu / Swiss AHV / Taiwan NID / HKID / Argentine CUIL, `smb://` / IPv4-mapped IPv6 / tftp / Consul / AWS IMDS IPv6, rclone.conf / containers `auth.json` / flyctl / Windows Credential Manager / Pulumi credentials, `nix run` / `pnpm dlx` / `cargo install` / bind `*` / cwd `C:\`, Discord / SMTP / Jira sinks, `glpat-` / `sk_live_` / `npm_` tokens, implicit grant, and HTTP `revocation_endpoint` / `registration_endpoint`; see `SOURCES.md`). Numbers are reported honestly. No detector was changed after this set existed.

Remaining round-6 misses: RFC 2047 and Base45 concealment, Cyrillic/Latin confusables, `python -c` / `socat` / `wget --post-file` transfer/exec shapes, four new memory classes (farewell dump, typo-correction rewrite, SAR/BCC, Slack status), rclone.conf and flyctl paths, and unpinned `nix run` / `cargo install` plus `--bind *`. One false positive: a documented loopback docs preview flagged by fetchfence. Remaining round-5 seen misses (not in this release's scope): memfence query-rewrite and emergency-CC, and a tracesweep Slack incoming webhook.

The floating Action / image tag `v0` points at this release (`uses: dunkleschitz/agentsec@v0` or `@v0.46.0`).
