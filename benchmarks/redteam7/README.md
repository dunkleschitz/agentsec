# Independent red-team, round 7

A blind set of 80 samples written **after** the v0.47.0 detection rules were
frozen. Techniques are taken from published research that was **not** the
basis of rounds 1–6 (see [SOURCES.md](SOURCES.md)). Every secret and every
personal identifier is synthetic.

This set is the **unseen** score for v0.47.0. Do not retune detectors against
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
and are not committed. Run `python3 benchmarks/redteam7/generate.py` (or
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
