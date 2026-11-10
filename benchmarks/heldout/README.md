# Held-out detection set

40 author-written, **synthetic** fixtures covering the same five tools that had detection-gap issues #7–#11 (resultguard, toolpoison, tracesweep, secretflow, shellfence).

These samples were written *after* the rule changes that closed those issues were locked. They were not used to tune the new typo, split-word, ROT13, multilingual, concatenation, encoding, or pipe-to-shell rules. Wording and obfuscation differ from the original corpus.

All credentials are fake. This is not a real-world attack dataset.

Run with the rest of the benchmark:

```sh
python3 benchmarks/run_benchmark.py
```
