# Independent red-team, round 4

A blind set of 80 samples written **after** the v0.44.0 detection rules were
frozen. Techniques are taken from published research that was **not** the
basis of rounds 1–3 (see [SOURCES.md](SOURCES.md)). Every secret and every
personal identifier is synthetic.

This set is the **unseen** score for v0.44.0. Do not retune detectors against
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
and are not committed. Run `python3 benchmarks/redteam4/generate.py` (or
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

## New techniques (not used as the basis of rounds 1–3)

- resultguard: Policy Puppetry XML, ANSI-hidden instructions, HTTP response
  header instructions, prefabricated assistant turns, FigStep-class OCR
  captions, MCP `resources/read` contents, Markdown reference-definition
  smuggling, SVG `foreignObject` HTML islands.
- toolpoison: `outputSchema` `$comment`, MCP resource-template descriptions,
  ROT13 concealment, MCP `_meta`, reversed-text instructions.
- shellfence: `tar --checkpoint-action=exec`, `osascript`, `rclone` exfil,
  MSBuild inline exec, `forfiles`, `systemd-run` transient reverse shells.
- memfence: auto-approve policy planting, calendar-triggered exfil, employer
  / payee identity swap, RAG-document-shaped memory, tool allow-list rewrite.
- piiguard: PESEL, Singapore NRIC, French NIR, Japanese My Number, Mexican CURP.
- fetchfence: `redis://`, `.onion` hosts, decimal-dword loopback, Alibaba
  metadata IP, WebDAV `MKCOL`.
- pathfence: `~/.password-store`, 1Password vault DB, Kubernetes service
  account token, macOS login keychain, GNOME keyring.
- mcpposture: SSE URL token in the query string, Deno unpinned HTTP import,
  `headers.Authorization` in mcp.json, `bunx` HTTP tarball, `curl | node`.
- secretflow: DNS-label sink, CSS `url()` sink, WebSocket URL sink.
- tracesweep: Hugging Face `hf_`, DigitalOcean `dop_v1_`, `age` secret keys.
- mcpoauth: ID-token `alg=none`, cleartext `jwks_uri`, cleartext device
  authorization endpoint.

## Scoring

```bash
python3 benchmarks/redteam4/generate.py --missing-only
python3 benchmarks/run_benchmark.py
```

The runner prints a per-tool table and overall P / R / F1. The v0.44.0 score
on this set is recorded in `benchmarks/results.json` and on the
[benchmarks page](https://dunkleschitz.github.io/agentsec/benchmarks/).
