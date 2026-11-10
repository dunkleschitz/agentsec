# Independent red-team round 8

100 adversarial and benign look-alike samples across the eleven benchmarked tools (65 malicious, 35 hard negatives), written against the frozen v0.47.0 detectors.

This set was written by a separate author who did **not** read tool source (`tools/*/*.py`), rule lists, unit tests, prior `benchmarks/redteam*` fixtures, or the private development set. The only tool documentation used was each scanner's README/usage text (input shape and claimed detections) plus the benchmark runner's layout and scoring rules. Techniques were chosen from public 2025–2026 MCP and agent-security writeups that earlier rounds did not list; sources are cited in [SOURCES.md](SOURCES.md).

A sample is **flagged** when the assigned tool reports at least one finding of severity `low` or above. Info-level inventory rules are ignored.

Files marked `generated=true` in `manifest.json` are written by [`generate.py`](generate.py) and are gitignored: they contain fake, provider-shaped secrets that GitHub push protection would block. Run `python3 benchmarks/redteam8/generate.py --missing-only` before scoring (the benchmark runner does this automatically).

This set was scored **once** on v0.47.0. Detectors were not changed against these fixtures. Overall: P=95.6% R=66.2% F1=78.2% (43 true positives, 2 false positives, 22 false negatives, 33 true negatives).

Clear detection gaps from this scoring are filed as [#28](https://github.com/dunkleschitz/agentsec/issues/28) (resultguard), [#29](https://github.com/dunkleschitz/agentsec/issues/29) (toolpoison), [#30](https://github.com/dunkleschitz/agentsec/issues/30) (shellfence), [#31](https://github.com/dunkleschitz/agentsec/issues/31) (memfence), [#32](https://github.com/dunkleschitz/agentsec/issues/32) (fetchfence), [#33](https://github.com/dunkleschitz/agentsec/issues/33) (pathfence), [#34](https://github.com/dunkleschitz/agentsec/issues/34) (mcpposture), [#35](https://github.com/dunkleschitz/agentsec/issues/35) (secretflow), and [#36](https://github.com/dunkleschitz/agentsec/issues/36) (mcpoauth). Detectors were not changed against these fixtures.
