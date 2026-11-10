# Independent red-team detection set — round 3

84 adversarial + benign look-alike fixtures across eleven detection jobs
(resultguard, toolpoison, tracesweep, secretflow, shellfence, piiguard, fetchfence,
pathfence, mcpposture, memfence, mcpoauth). This set was written **after** the
v0.43.0 generalization rules were frozen, and was scored once against those
rules. That original score is frozen in
`benchmarks/baseline_redteam3_v0.43.0.json` (P=97.3% R=65.5% F1=78.3%,
36/1/19/28) and stays on the Pages table as the unseen number.

Round 3 was the development set for the v0.44.0 structure-based rule changes.
The same fixtures were re-run after those changes and are now labeled
**seen** (live P/R/F1 100%, 55/0/0/29). The current unseen score is
round 4 (`benchmarks/redteam4/`).

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
