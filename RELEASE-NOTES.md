# agentsec v0.44.0

Offline, stdlib-only kit. 36 tools. This release generalizes detection for the misses in red-team round 3, then scores a fresh round-4 set once. No new scanners. 1810 tests.

### Generalization (not fixture-specific string matches)

Round 3 is the development set. Rules were extended around attack *class* before any round-4 sample was written:

- **toolpoison** — scans MCP server-level `instructions` / `serverInstructions`; TP14 elicitation used as a credential phish; decode layers now include quoted-printable and tolerant uuencode.
- **shellfence** — SF17 LOLBAS remote download/execute (`certutil -urlcache`, `mshta`, `bitsadmin /transfer`); SF18 download-then-execute without a pipe (`curl -o`, `chmod +x`, then run the file); SF11 also covers `/etc/ld.so.preload` and `LD_PRELOAD=`.
- **memfence** — count-delayed exfil (“after N messages”), system-prompt append, and planted payroll/login portals that forward session cookies (MF12). Official HTTPS portals without cookie theft stay clean.
- **piiguard** — PG05 also covers Indian Aadhaar, Brazilian CPF, Australian TFN, and Swedish personnummer, with checksums where the format defines them.
- **mcpposture** — MP21 also fires on `--registry` / `--index-url` CLI flags, not only `npm_config_registry`.
- **secretflow** — data-URI and QR-generator sinks; GitHub MCP write sinks; URL-encoded labeled keys (including Azure `AccountKey`); placeholders such as `your-api-key-here` in `.env.example` are no longer flagged.
- **mcpoauth** — `redirect_uris` / `post_logout_redirect_uris` checked for cleartext `http://` on public hosts; `file:` / `data:` / `javascript:` schemes; `*.svc` / `.cluster.local` as private; broader GitHub scopes; published DCR access tokens (MO11). Open DCR (MO13) is now info, matching the MCP SHOULD.
- **fetchfence** — FF14 known no-auth chat/webhook exfil drops (Telegram Bot API, Discord webhooks, Slack hooks). Well-known public resolvers (`1.1.1.1`, `8.8.8.8`, …) are no longer FF08.
- **pathfence** — PF13 UNC / NTLM-coercion paths; PF14 wallet/keystore paths; URL-decoded traversal; `.env.example` / `.sample` / `.template` are not treated as live secret files.
- **tracesweep** — SendGrid, Azure Storage `AccountKey`, Telegram bot tokens, and npm tokens; conservative double-base64 decode.

### Benchmark

Lead with the latest **unseen** score, not the seen ones.

| Set | Score (P / R / F1) | Counts (tp/fp/fn/tn) |
|---|---|---|
| Author expanded (125 / 10 tools) | 100% / 100% / 100% | 76/0/0/49 |
| Original 85-sample, 5-tool slice | 100% / 100% / 100% | 51/0/0/34 |
| Held-out (40, written after #7–#11) | 100% / 100% / 100% | 26/0/0/14 |
| Red-team round 1 independent (v0.40.0, unseen) | 93.8% / 85.7% / 89.6% | 60/4/10/26, **frozen, still shown** |
| Same round-1 set after #12–#16 | 100% / 100% / 100% | 70/0/0/30, labeled **seen** |
| Red-team round 2 independent (v0.41.0, unseen) | 80.4% / 38.9% / 52.5% | 37/9/58/30, **frozen, still shown** |
| Same round-2 set after later generalization | 98.9% / 97.9% / 98.4% | 93/1/2/38, labeled **seen** |
| Red-team round 3 independent (v0.43.0, unseen) | 97.3% / 65.5% / 78.3% | 36/1/19/28, **frozen, still shown** |
| Same round-3 set after v0.44.0 generalization | 100% / 100% / 100% | 55/0/0/29, labeled **seen** |
| Red-team round 4 (v0.44.0, unseen) | 97.0% / 60.4% / 74.4% | 32/1/21/26, scored **once** |

Round 4 (`benchmarks/redteam4/`, 80 samples) was written after the rules were frozen, from published techniques rounds 1–3 did not use (Policy Puppetry, ANSI-hidden instructions, HTTP header instructions, FigStep-class OCR captions, MCP resource contents and resource templates, `outputSchema` `$comment`, ROT13 and reversed-text concealment, `tar --checkpoint-action`, osascript, rclone, MSBuild, forfiles, systemd-run transient units, auto-approve and allow-list memory, calendar-triggered exfil, PESEL/NRIC/NIR/My Number/CURP, `redis://`, `.onion`, dword IPs, password-store / 1Password / Kubernetes service-account tokens / keychains, SSE token-in-query, Deno, DNS/CSS/WebSocket secret sinks, `hf_` / `dop_v1_` / age keys, JWT `alg=none`, and others; see `SOURCES.md`). Numbers are reported honestly. Misses include several new national-ID formats, additional LOLBAS / archive execution trampolines, ROT13 and reversed-text descriptions, password-manager paths, `alg=none`, and an `age` secret key — exactly the kind of unseen gap this set is for. One false positive: a vendor policy XML that only describes rate limits (TR10).

Remaining honest misses on the (now seen) earlier sets: pathfence EscapeRoute (sibling-symlink write, #21), memfence Gemini false-facts with no instruction-like text (#20), and a secretflow “key used with its own provider” false positive (#24). Detection-gap issues #17 (fetchfence), #18 (mcpoauth), and #27 (tracesweep) are closed against this release.

```sh
python3 benchmarks/run_benchmark.py
```

The playground vendors were resynced so the in-browser copies match the CLI.

The floating Action / image tag `v0` points at this release (`uses: dunkleschitz/agentsec@v0` or `@v0.44.0`).

Still not on PyPI. Publishing steps are in `PUBLISHING.md`.
