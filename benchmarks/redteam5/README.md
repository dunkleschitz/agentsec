# Independent red-team, round 5

A blind set of 80 samples written **after** the v0.45.0 detection rules were
frozen. Techniques are taken from published research that was **not** the
basis of rounds 1–4 (see [SOURCES.md](SOURCES.md)). Every secret and every
personal identifier is synthetic.

This set is the **unseen** score for v0.45.0. Do not retune detectors against
these fixtures. A later release may relabel this set as seen if the rules are
changed in response to it.

## Positive definition

A sample is counted as flagged when the assigned tool reports at least one
finding with severity `low`, `medium`, `high`, or `critical`. Info-level
inventory rules (for example SF12, FL10, PG10, PF12, MF10, MO14) are ignored.

## Layout

```
corpus/<tool>/{malicious,benign}/
generate.py          # materializes fixtures (including generated secrets)
manifest.json        # 80 sample records
.gitignore           # generated provider-shaped fakes (push protection)
SOURCES.md           # citations for each new technique
```

Files marked `generated: true` in the manifest are written by `generate.py`
and are not committed. Run `python3 benchmarks/redteam5/generate.py` (or
`--missing-only`) before scoring.

## Split (80 samples, 53 malicious / 27 benign)

| Tool | Malicious | Benign |
|---|---|---|
| resultguard | 8 | 3 |
| toolpoison | 5 | 3 |
| shellfence | 6 | 3 |
| memfence | 5 | 3 |
| piiguard | 5 | 3 |
| fetchfence | 5 | 2 |
| pathfence | 5 | 2 |
| mcpposture | 5 | 2 |
| secretflow | 3 | 2 |
| tracesweep | 3 | 2 |
| mcpoauth | 3 | 2 |

## New techniques (not used as the basis of rounds 1–4)

- resultguard: CSV `=HYPERLINK` injection, DNS TXT instructions, git-log
  messages, JSON `\uXXXX` escapes, Atom/RSS content, decoded JWT claims,
  ASCII backspace overstrike, SAML AttributeValue.
- toolpoison: MCP `prompts[].description`, Base32 concealment, Unicode
  Braille, Atbash, prompt-argument descriptions.
- shellfence: `find -exec`, `schtasks /create`, `rsync $HOME`, `make $(shell)`,
  `wmic process call create`, `awk BEGIN{system(...)}`.
- memfence: planted API base-URL swap, query-rewrite memory, language
  preference as exfil, emergency-contact CC, locale/timezone override.
- piiguard: Turkish TCKN, Chilean RUT, South African ID, Italian codice
  fiscale, Dutch BSN (all with official checksums).
- fetchfence: `gopher://` loopback, hex IP `0x7f000001`, Kubernetes
  in-cluster DNS, octal loopback, `ldap://` metadata.
- pathfence: `~/.vault-token`, `~/.config/age/keys.txt`, FileZilla
  `recentservers.xml`, `terraform.tfstate`, Signal Desktop config.
- mcpposture: `go run …@latest`, `npx github:…`, `cwd: /`, `uvx --from
  git+http://…`, bind `0.0.0.0` without auth.
- secretflow: Telegram `sendMessage` URL sink, S3 PutObject sink,
  GraphQL mutation-variable sink.
- tracesweep: PyPI `pypi-` tokens, Slack incoming webhook URLs, Groq `gsk_`.
- mcpoauth: `token_endpoint_auth_methods_supported` of only `none`,
  wildcard redirect URIs, cleartext `frontchannel_logout_uri`.

## Scoring

```bash
python3 benchmarks/redteam5/generate.py --missing-only
python3 benchmarks/run_benchmark.py
```

The runner prints a per-tool table and overall P / R / F1. The v0.45.0 score
on this set is recorded in `benchmarks/results.json` and on the
[benchmarks page](https://dunkleschitz.github.io/agentsec/benchmarks/).
