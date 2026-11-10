# Independent red-team detection set — round 2

134 adversarial + benign look-alike fixtures across eleven detection jobs
(resultguard, toolpoison, tracesweep, secretflow, shellfence, piiguard, fetchfence,
pathfence, mcpposture, memfence, mcpoauth), written against **v0.41.0** **without
reading detector source, rule files, or the round-1 fixtures** (READMEs/usage and the
round-1 `SOURCES.md` only). Techniques cite published research in [SOURCES.md](SOURCES.md)
and favor work round 1 did not use.

Round 1 (`benchmarks/redteam/`) is now *seen*: rules were tuned against it in v0.41.0.
Round 2 is the current **unseen** score. Its v0.41.0 numbers are frozen in
`benchmarks/baseline_redteam2_v0.41.0.json`. Misses are filed as `detection-gap` issues
and are **not** fixed in the release that added this set.

All credentials and personal-data values are fake.

```sh
python3 benchmarks/run_benchmark.py
```

Eighteen fixtures carry provider-shaped fake keys (Hugging Face, GitLab, npm, SendGrid,
Azure, Telegram, DigitalOcean, Stripe-shaped, OpenAI/Anthropic-shaped). GitHub push
protection blocks those shapes even when they are synthetic, so — like
`tools/tracesweep/examples` — they are not committed. `generate.py` writes every fixture
deterministically (fixed seed) and `run_benchmark.py` runs it automatically when any
listed file is missing (`"generated": true` in `manifest.json`).
