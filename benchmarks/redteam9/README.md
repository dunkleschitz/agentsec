# Independent red-team round 9

One hundred original samples (65 malicious, 35 hard negatives) across the eleven
benchmarked tools, written against the frozen **v0.48.0** detectors.

The author used only each tool's README/usage (input shape and claimed
detections) and just enough of the benchmark runner to learn the sample-dir
layout and scoring rule. Detector source, rule lists, tests, prior red-team
fixtures (including round 8), the private dev set, and the v0.48.0 diff were
not read.

Techniques come from published 2026 MCP/agent research and from classes that
round 8 did not use as its basis. Citations are in `SOURCES.md`.

Provider-shaped secrets are not committed. Run `python3 benchmarks/redteam9/generate.py`
(or just the benchmark runner, which calls it with `--missing-only`) to materialize
the ten generated fixtures. Values are deterministic, synthetic, and not valid
against any provider.

This set was scored once on v0.48.0. Detectors were not changed against these
fixtures. The score is the headline independent unseen number for this release.

Scored once on v0.48.0: **P=92.3% R=55.4% F1=69.2%** (36/3/29/32). Detection-gap issues #37–#46 record every tool with a miss or false positive (fetchfence was clean on this set).
