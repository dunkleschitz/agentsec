# Independent red-team detection set — round 3

84 adversarial + benign look-alike fixtures across eleven detection jobs
(resultguard, toolpoison, tracesweep, secretflow, shellfence, piiguard, fetchfence,
pathfence, mcpposture, memfence, mcpoauth). This set was written **after** the
v0.43.0 generalization rules were frozen, and was scored once. It was not used
to retune any detector.

Round 2 (`benchmarks/redteam2/`) is now *seen*: it was the development set for
the structure-based rule changes in v0.43.0. Its original v0.41.0 numbers stay
frozen in `benchmarks/baseline_redteam2_v0.41.0.json`. Round 3 is the current
**unseen** score.

Techniques cite published research in [SOURCES.md](SOURCES.md) and were chosen
from work that rounds 1 and 2 did not use as the basis of their fixtures.

All credentials and personal-data values are fake.

```sh
python3 benchmarks/run_benchmark.py
```

A few fixtures carry provider-shaped fake keys. GitHub push protection blocks
those shapes even when they are synthetic, so they are not committed.
`generate.py` writes every fixture deterministically (fixed seed) and
`run_benchmark.py` runs it automatically when any listed file is missing
(`"generated": true` in `manifest.json`).
