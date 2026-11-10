# agentsec v0.45.0

Offline, stdlib-only kit. 37 tools. This release generalizes detection for the misses in red-team round 4, then scores a fresh round-5 set once. No new scanners. 1893 tests.

### Generalization (not fixture-specific string matches)

Round 4 is the development set. Rules were extended around attack *class* before any round-5 sample was written:

- **resultguard** — strips ANSI CSI / conceal views (same fg/bg, SGR 8, erase) and flags hidden instructions; broader exfil phrasing (workspace listing, transcript, messages); first-person / prefilled-assistant-turn bait ("I will now call", "next assistant message should"). TR10 policy-frame authority now needs a second signal, so a vendor rate-limit XML stays clean while Policy Puppetry interaction-config still flags.
- **toolpoison** — scans MCP `resourceTemplates` / `resources` and instructions-only docs; decode layers now include ROT13 and reversed-text views.
- **shellfence** — SF19 LOLBin trampoline / cloud-sync exfil (`tar --checkpoint-action=exec`, `forfiles /c`, MSBuild `PostBuildEvent`, `rclone` of `$HOME` without `--dry-run`); wrapped commands are re-scanned for embedded payloads.
- **memfence** — MF13 auto-approve / confirmation-bypass for privileged tools (honors negation, so "never auto-approve… always confirm first" stays clean); MF14 impossible user-age claims (≤2 or ≥100). Structurally impossible identity claims only; worldview claims are out of scope.
- **piiguard** — PG05 also covers Polish PESEL, Singapore NRIC/FIN, French NIR, Japanese My Number, and Mexican CURP, with checksums where the format defines them (NIR / My Number / CURP are labeled-format).
- **pathfence** — PF15 credential-store paths (pass, 1Password, GNOME keyring, KeePass, and similar); PF16 privilege-escalation write content (`ALL=(ALL) NOPASSWD`, `authorized_keys`, `ld.so.preload`).
- **mcpposture** — flags Deno / Bun / Node / Python running an unpinned remote `http(s)` URL as a script (MP11+MP23). Local `deno run ./local.ts` stays clean.
- **tracesweep** — `AGE-SECRET-KEY-1` Bech32-ish secret keys (TS-AGE-SECRET, critical).
- **mcpoauth** — MO15 critical when signing-alg lists contain `none` (JWT `alg=none`).
- **secretflow** — official-provider host allowlist by longest key prefix (exact host or subdomain only; lookalikes such as `api.openai.com.evil.test` still fire).

### Benchmark

Lead with the latest **unseen** score, not the seen ones.

| Set | Score (P / R / F1) | Counts (tp/fp/fn/tn) |
|---|---|---|
| Author expanded (125 / 10 tools) | 100% / 100% / 100% | 76/0/0/49 |
| Original 85-sample, 5-tool slice | 100% / 100% / 100% | 51/0/0/34 |
| Held-out (40, written after #7–#11) | 100% / 100% / 100% | 26/0/0/14 |
| Red-team round 1 independent (v0.40.0, unseen) | 93.8% / 85.7% / 89.6% | 60/4/10/26, **frozen, still shown** |
| Same round-1 set after later generalization | 100% / 100% / 100% | 70/0/0/30, labeled **seen** |
| Red-team round 2 independent (v0.41.0, unseen) | 80.4% / 38.9% / 52.5% | 37/9/58/30, **frozen, still shown** |
| Same round-2 set after v0.45.0 generalization | 100% / 100% / 100% | 95/0/0/39, labeled **seen** |
| Red-team round 3 independent (v0.43.0, unseen) | 97.3% / 65.5% / 78.3% | 36/1/19/28, **frozen, still shown** |
| Same round-3 set after later generalization | 100% / 100% / 100% | 55/0/0/29, labeled **seen** |
| Red-team round 4 independent (v0.44.0, unseen) | 97.0% / 60.4% / 74.4% | 32/1/21/26, **frozen, still shown** |
| Same round-4 set after v0.45.0 generalization | 100% / 100% / 100% | 53/0/0/27, labeled **seen** |
| Red-team round 5 (v0.45.0, unseen) | 96.0% / 45.3% / 61.5% | 24/1/29/26, scored **once** |

Round 5 (`benchmarks/redteam5/`, 80 samples) was written after the rules were frozen, from published techniques rounds 1–4 did not use (CSV `HYPERLINK`, DNS TXT, `git log`, JSON `\uXXXX` escapes, Atom/RSS, decoded JWT claims, ASCII backspace overstrike, SAML `AttributeValue`, MCP prompts, Base32/Braille/Atbash, `find -exec`, `schtasks`, `rsync $HOME`, `make $(shell)`, `wmic`, `awk system()`, planted API base-URL / query-rewrite / language-pref / emergency-CC / locale-override memory, TCKN / RUT / South African ID / codice fiscale / BSN, gopher / hex / octal / LDAP / Kubernetes-DNS SSRF, vault-token / age keys.txt / FileZilla / terraform.tfstate / Signal config paths, `go run @latest`, `npx github:`, cwd `/`, `uvx git+http`, bind `0.0.0.0`, Telegram / S3 / GraphQL sinks, pypi / Slack webhook / Groq keys, `token_endpoint_auth_method=none`, wildcard redirects, cleartext `frontchannel_logout_uri`, and others; see `SOURCES.md`). Numbers are reported honestly. Remaining misses are new encodings and catalogs (JSON unicode escapes, backspace overstrike, MCP prompts, Base32/Braille/Atbash), additional shell trampolines (`find -exec`, `rsync $HOME`, `wmic`), memory classes (query-rewrite, emergency-CC), national-ID formats outside the v0.45 list (TCKN, RUT, SA ID, codice fiscale, BSN), new path classes (vault-token, age keys.txt, FileZilla, tfstate, Signal), posture gaps (`go run @latest`, cwd `/`, bind `0.0.0.0`), a Slack incoming webhook, and OAuth fields (`token_endpoint_auth_method=none`, wildcard redirects, cleartext front-channel logout). One false positive: a secretflow local equality check treated as reuse.

Detection-gap issues #20 (memfence impossible-age claims), #21 (pathfence privilege-escalation write content), and #24 (secretflow official-provider allowlist) are closed against this release. Worldview / conspiracy claims remain out of memfence scope, as noted on #20.

```sh
python3 benchmarks/run_benchmark.py
```

The playground vendors were resynced so the in-browser copies match the CLI.

The floating Action / image tag `v0` points at this release (`uses: dunkleschitz/agentsec@v0` or `@v0.45.0`).

Still not on PyPI. Publishing steps are in `PUBLISHING.md`.
