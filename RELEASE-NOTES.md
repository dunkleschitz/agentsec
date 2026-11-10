# agentsec v0.47.0

Offline, stdlib-only kit. 38 tools. This release continues the class-level approach that reversed the unseen-F1 decline in v0.46.0, then scores a fresh round-7 set once. 2043 unit tests.

### Generalization (class-level, not fixture-specific instances)

Round 6 is the development set. Rules were extended around classes, then checked on a private labeled dev set of new variants, then frozen before any round-7 sample was written:

- **toolpoison / resultguard** — an encoding-concealment layer covering MIME/RFC 2047 encoded-words and base-N transforms (Base45/58/85 and similar) with decode-and-rescan, plus Unicode confusable / mixed-script detection using a UTS #39-style skeleton (NFKD + lookalike fold). Documentation that merely mentions an encoding, and ordinary foreign-script place names, stay clean.
- **shellfence** — interpreter one-liners (`-c`/`-e`/`-r`) and generic network-relay / upload tools (socat, ncat, wget --post-file, curl --upload-file / --data-binary @file) as a class, only when a network or home/secret sink is present. A bare `python -c 'print(sys.version)'`, wget of public docs, or a local LISTEN+FILE server is not in this class.
- **memfence** — memories that schedule a future data transfer, add a recipient or channel (BCC/CC, status text, webhook), or silently rewrite user input / destinations / queries. Negation must modify the action (so "do not recognize" and "ask before cc'ing" stay clean).
- **pathfence** — config-path patterns for CLI tools that store tokens in a hidden user dir (`~/.<tool>/` or `~/.config/<app>/` plus token- or config-ish basenames), excluding known dev-tool apps.
- **mcpposture** — unpinned remote code execution as a class across ecosystems (nix flake refs, cargo install, go, npx, uvx, pipx, deno, docker/podman `:latest`). Wildcard binds (`--bind *`, `--listen *`, bare `*`) are treated as bind-all.
- **fetchfence** — documentation/preview paths on loopback (`/docs`, `/playground`, and similar) are not SSRF; loopback metadata, Consul, Docker API, gopher, and `/admin` still flag.
- **tracesweep** — incoming webhook URLs as a secret class (Slack, Discord, Teams, and generic `/api/webhooks/<token>`), not only `xox*` bot tokens.

### Benchmark

Unseen F1 on successive independent rounds had been 78.3 → 74.4 → 61.5, then recovered to 81.3 on round 6 after the first class-level rewrite. This release is scored against a new blind round 7. The series is now:

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
| Same round-5 set after later generalization | 100% / 100% / 100% | 53/0/0/27, labeled **seen** |
| Red-team round 6 (v0.46.0, unseen) | 97.4% / 69.8% / 81.3% | 37/1/16/26, frozen |
| Same round-6 set after v0.47.0 generalization | 100% / 100% / 100% | 53/0/0/27, labeled **seen** |
| Red-team round 7 (v0.47.0, unseen) | 100.0% / 92.5% / 96.1% | 49/0/4/27, scored **once** |

Round 7 (`benchmarks/redteam7/`, 80 samples) was written after the rules were frozen, from published techniques rounds 1–6 did not use (Jupyter markdown cells, GraphQL SDL descriptions, SRT captions, Open Graph `og:description`, systemd `Description=`, svn log, Apple plist strings, RDF Turtle comments, JSON Schema `default`, Base58, quoted-printable, MCP `_meta`, fullwidth confusables, `lua -e` / `curl --data-binary` / `ncat` / `osascript` / `tar|curl` / `openssl s_client`, forget-archive and clipboard-rewrite memory, Spanish DNI / Irish PPSN / Chinese resident ID / Croatian OIB / Belgian NISS, `ldap://` / Docker Engine API / `ftp://` / `[::1]/server-status` / `/cgi-bin/`, glab/heroku/sfdx/linode/netlify paths, `pipx run` / `podman :latest` / `--listen *` / `nix profile install` / `deno jsr:`, Notion / PagerDuty / Loki sinks, `shpat_` / `github_pat_` / `vercel_` tokens, and HTTP introspection / userinfo / PAR endpoints; see `SOURCES.md`). Numbers are reported honestly. No detector was changed after this set existed.

Remaining round-7 misses (honest, not retuned): shellfence `tar | curl --data-binary` and `openssl s_client` relays, a memfence logout/PagerDuty-note transfer, and a pathfence Linode CLI `config.ini`. The v0.46.0 loopback-docs fetchfence false positive is gone, and the round-5 seen leftovers (memfence query-rewrite and emergency-CC, tracesweep Slack incoming webhook) now flag.

The floating Action / image tag `v0` points at this release (`uses: dunkleschitz/agentsec@v0` or `@v0.47.0`).
