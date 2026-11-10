# agentsec detection benchmark

A small, author-written, **synthetic** corpus for four detection jobs:

| Job | Tool | What a “malicious” label means |
|---|---|---|
| Prompt injection in tool results | `resultguard` | The tool result tries to hijack the model |
| Poisoned MCP tool descriptions | `toolpoison` | A tool manifest hides instructions or smuggling paths |
| Secret leaks | `tracesweep`, `secretflow` | A credential-shaped value appears, or later flows into another tool’s arguments |
| Dangerous shell | `shellfence` | The agent ran a dangerous shell command |

Every credential and personal-data value in this folder is **fake**. They were minted for this corpus and are not live keys. tracesweep also suppresses documentation placeholders (the word `example`, `your_api_key`, and similar), so the tracesweep fixtures use synthetic key material that still matches provider-shaped patterns without those words.

This is not a real-world attack dataset and not a substitute for a red team.

## How a detection is counted

A sample is **flagged** when the assigned tool reports at least one finding with severity `low`, `medium`, `high`, or `critical`. Info-level inventory rules (`SF12`, `FL10`, and any other `severity=info` finding) are ignored so a “commands observed” line cannot turn a benign shell transcript into a false positive.

```sh
python3 benchmarks/run_benchmark.py
python3 benchmarks/run_benchmark.py --write-pages   # refresh results.json and docs/benchmarks/
python3 benchmarks/run_benchmark.py --check         # CI freshness check
```

The committed table lives at [dunkleschitz.github.io/agentsec/benchmarks/](https://dunkleschitz.github.io/agentsec/benchmarks/). Numbers will move when a single sample is added or re-labeled; treat percentages as a snapshot, not a product claim.

## Layout

```
benchmarks/
├── README.md
├── manifest.json          labels, titles, notes, difficulty
├── results.json           last committed precision/recall snapshot
├── run_benchmark.py       stdlib runner and Pages generator
└── corpus/
    ├── resultguard/{malicious,benign}/
    ├── toolpoison/{malicious,benign}/
    ├── tracesweep/{malicious,benign}/
    ├── secretflow/{malicious,benign}/
    └── shellfence/{malicious,benign}/
```

`difficulty: evasion` samples are malicious on purpose but written to stress a known heuristic gap (typos, split words, encodings, non-English text, transformed secrets, unusual spellings). A miss on those is expected; unexpected misses on easy samples are filed as `detection-gap` issues.

## Honesty

The scanners are regex and pattern heuristics. Determined attackers can evade them, and benign typography or HTML can trip them. The Pages write-up lists every false negative and false positive on this corpus.
