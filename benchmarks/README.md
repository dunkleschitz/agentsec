# agentsec detection benchmark

A small, author-written, **synthetic** corpus for ten detection jobs:

| Job | Tool | What a “malicious” label means |
|---|---|---|
| Prompt injection in tool results | `resultguard` | The tool result tries to hijack the model |
| Poisoned MCP tool descriptions | `toolpoison` | A tool manifest hides instructions or smuggling paths |
| Secret leaks | `tracesweep`, `secretflow` | A credential-shaped value appears, or later flows into another tool’s arguments |
| Dangerous shell | `shellfence` | The agent ran a dangerous shell command |
| PII in transcripts | `piiguard` | A transcript contains email, phone, SSN, PAN, IBAN, or similar personal data |
| SSRF / fetch destinations | `fetchfence` | The agent fetched a risky URL (metadata IP, loopback, file:, callback host, …) |
| Sensitive paths | `pathfence` | The agent read or wrote a sensitive filesystem path |
| MCP client posture | `mcpposture` | An MCP client config grants dangerous privileges or embeds a secret |
| Persistent memory poisoning | `memfence` | A saved memory entry plants override, exfil, or harvest instructions |

Every credential and personal-data value in this folder is **fake**. They were minted for this corpus and are not live keys. tracesweep also suppresses documentation placeholders (the word `example`, `your_api_key`, and similar), so the tracesweep fixtures use synthetic key material that still matches provider-shaped patterns without those words. piiguard samples use `@example.com` addresses, reserved `555` telephone numbers, a Luhn-valid test PAN ending in `0006`, and a synthetic SSN that is not one of the SSA’s well-known advertising numbers.

This is not a real-world attack dataset and not a substitute for a red team.

## How a detection is counted

A sample is **flagged** when the assigned tool reports at least one finding with severity `low`, `medium`, `high`, or `critical`. Info-level inventory rules (`SF12`, `FL10`, `PG10`, `PF12`, `MF10`, and any other `severity=info` finding) are ignored so a “commands observed” line cannot turn a benign transcript into a false positive.

```sh
python3 benchmarks/run_benchmark.py
python3 benchmarks/run_benchmark.py --write-pages   # refresh results.json and docs/benchmarks/
python3 benchmarks/run_benchmark.py --check         # CI freshness check
```

The committed table lives at [dunkleschitz.github.io/agentsec/benchmarks/](https://dunkleschitz.github.io/agentsec/benchmarks/). It has three views:

- **Before / after** on the original 85-sample, 5-tool corpus (v0.38.0 vs. the issue #7–#11 rule changes).
- **Held-out** (`benchmarks/heldout/`): 40 fresh samples written *after* those rule changes were locked, and not used to tune them.
- **Expanded corpus**: the original five tools plus piiguard, fetchfence, pathfence, mcpposture, and memfence.

Numbers will move when a single sample is added or re-labeled; treat percentages as a snapshot, not a product claim.

- **Independent red-team** (`benchmarks/redteam/`): 100 adversarial + benign look-alike samples written without reading detector source/rule files, citing published research in `SOURCES.md`. The v0.40.0 score on that set is frozen in `baseline_redteam_v0.40.0.json` and stays on the Pages page as the unseen number. After issues #12–#16 were closed in v0.41.0, the same set was re-run and is labeled **seen**; those post-fix numbers are no longer independent.
- **Independent red-team round 2** (`benchmarks/redteam2/`): 134 new adversarial + benign look-alike samples across eleven tools (adds `mcpoauth`), written against v0.41.0 without reading detector source, rule files, or the round-1 fixtures, and favoring published techniques round 1 did not use (`redteam2/SOURCES.md`). The v0.41.0 score is frozen in `baseline_redteam2_v0.41.0.json` and stays on the Pages page as the unseen number. After the v0.43.0 generalization (and later v0.44.0 changes), the same set was re-run and is labeled **seen**.
- **Independent red-team round 3** (`benchmarks/redteam3/`): 84 new adversarial + benign look-alike samples across the same eleven tools, written after the v0.43.0 rules were frozen, from published techniques rounds 1 and 2 did not use (`redteam3/SOURCES.md`). The v0.43.0 score is frozen in `baseline_redteam3_v0.43.0.json` and stays on the Pages page as the unseen number. After the v0.44.0 generalization, the same set was re-run and is labeled **seen** (it was the development set for those rules).
- **Independent red-team round 4** (`benchmarks/redteam4/`): 80 new adversarial + benign look-alike samples across the same eleven tools, written after the v0.44.0 rules were frozen, from published techniques rounds 1–3 did not use (`redteam4/SOURCES.md`). The v0.44.0 score is frozen in `baseline_redteam4_v0.44.0.json` and stays on the Pages page as the unseen number. After the v0.45.0 generalization, the same set was re-run and is labeled **seen** (it was the development set for those rules).
- **Independent red-team round 5** (`benchmarks/redteam5/`): 80 new adversarial + benign look-alike samples across the same eleven tools, written after the v0.45.0 rules were frozen, from published techniques rounds 1–4 did not use (`redteam5/SOURCES.md`). The v0.45.0 score is frozen in `baseline_redteam5_v0.45.0.json` and stays on the Pages page as the unseen number (P=96.0% R=45.3% F1=61.5%). After the v0.46.0 generalization, the same set was re-run and is labeled **seen** (live P/R/F1 100% (53/0/0/27); it was the development set for those rules).
- **Independent red-team round 6** (`benchmarks/redteam6/`): 80 new adversarial + benign look-alike samples across the same eleven tools, written after the v0.46.0 rules were frozen, from published techniques rounds 1–5 did not use (`redteam6/SOURCES.md`). The v0.46.0 score is frozen in `baseline_redteam6_v0.46.0.json` and stays on the Pages page as the unseen number (P=97.4% R=69.8% F1=81.3%). After the v0.47.0 generalization, the same set was re-run and is labeled **seen** (live P/R/F1 100%; it was the development set for those rules).
- **Independent red-team round 7** (`benchmarks/redteam7/`): 80 new adversarial + benign look-alike samples across the same eleven tools, written after the v0.47.0 rules were frozen, from published techniques rounds 1–6 did not use (`redteam7/SOURCES.md`). It was scored once on v0.47.0 and was not used to retune rules (P=100.0% R=92.5% F1=96.1%). It remains an **unseen** score on these frozen detectors.
- **Independent red-team round 8** (`benchmarks/redteam8/`): 100 new adversarial + benign look-alike samples (65 malicious, 35 hard negatives) across the same eleven tools, written against the frozen v0.47.0 detectors by a separate author who did not read tool source, rule lists, tests, prior red-team fixtures, or the private dev set (`redteam8/SOURCES.md`). It was scored once and was not used to retune rules: P=95.6% R=66.2% F1=78.2% (43/2/22/33). Unseen F1 across successive independent rounds: 78.3 (r3) → 74.4 (r4) → 61.5 (r5) → 81.3 (r6) → 96.1 (r7) → 78.2 (r8).

## Layout

```
benchmarks/
├── README.md
├── manifest.json              labels for the main (expanded) corpus
├── results.json               last committed precision/recall snapshot
├── baseline_v0.38.0.json      frozen v0.38.0 numbers for the before table
├── baseline_redteam_v0.40.0.json  frozen independent red-team score (round 1, unseen)
├── baseline_redteam2_v0.41.0.json frozen independent red-team round 2 score (unseen)
├── baseline_redteam3_v0.43.0.json frozen independent red-team round 3 score (unseen)
├── baseline_redteam4_v0.44.0.json frozen independent red-team round 4 score (unseen)
├── baseline_redteam5_v0.45.0.json frozen independent red-team round 5 score (unseen)
├── baseline_redteam6_v0.46.0.json frozen independent red-team round 6 score (unseen)
├── run_benchmark.py           stdlib runner and Pages generator
├── corpus/                    main corpus, including the original 85 plus five new tools
├── heldout/
│   ├── manifest.json
│   └── corpus/                40 samples written after the #7–#11 fixes
└── redteam/
    ├── README.md
    ├── SOURCES.md
    ├── manifest.json
    ├── corpus/                ~100 independent adversarial + look-alike samples (now seen)
└── redteam2/
    ├── README.md
    ├── SOURCES.md
    ├── manifest.json
    └── corpus/                134 round-2 samples across eleven tools (now seen)
└── redteam3/
    ├── README.md
    ├── SOURCES.md
    ├── manifest.json
    ├── generate.py
    └── corpus/                84 round-3 samples across eleven tools (now seen)
└── redteam4/
    ├── README.md
    ├── SOURCES.md
    ├── manifest.json
    ├── generate.py
    └── corpus/                80 round-4 samples across eleven tools (now seen)
└── redteam5/
    ├── README.md
    ├── SOURCES.md
    ├── manifest.json
    ├── generate.py
    └── corpus/                80 round-5 samples across eleven tools (now seen)
└── redteam6/
    ├── README.md
    ├── SOURCES.md
    ├── manifest.json
    ├── generate.py
    └── corpus/                80 round-6 samples across eleven tools (now seen)
└── redteam7/
    ├── README.md
    ├── SOURCES.md
    ├── manifest.json
    ├── generate.py
    └── corpus/                80 round-7 samples across eleven tools (unseen on v0.47.0)
└── redteam8/
    ├── README.md
    ├── SOURCES.md
    ├── manifest.json
    ├── generate.py
    └── corpus/                100 round-8 samples across eleven tools (unseen on v0.47.0)
```

`difficulty: evasion` samples are malicious on purpose but written to stress a known heuristic gap (typos, split words, encodings, non-English text, transformed secrets, unusual spellings). On the original 85-sample corpus those evasions were missed in v0.38.0 and are caught after the v0.39.0 rule changes. Held-out evasions use *different* wording; a miss there is reported and is not patched away against the held-out set.

## Honesty

The scanners are regex and pattern heuristics. Determined attackers can evade them, and benign typography or HTML can trip them. The Pages write-up lists every false negative and false positive on both the expanded corpus and the held-out set.
