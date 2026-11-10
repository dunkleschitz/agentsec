# promptaudit (#38)

Offline hygiene auditor for LLM **system prompts**. A system prompt is not a secret store and
not an access-control layer (OWASP LLM07 System Prompt Leakage, LLM06 Excessive Agency).
promptaudit reads system and developer prompts and flags content that should live somewhere
else: credentials, internal endpoints, authorization logic, unbounded tool authority, personal
data, disclosed decision thresholds, and hidden Unicode. It also flags tool-using prompts that
never tell the model to treat tool or retrieved content as data.

Standard library only. No network calls. Secrets and PII are masked in every output format.

## Usage

```sh
python3 promptaudit.py PROMPT_OR_TRANSCRIPT [...] [--json | --sarif] [--as-text]
                       [--min-severity LEVEL] [--fail-on LEVEL|none] [--disable RULE] [--list-rules]
```

Inputs: plain prompt files (`.txt`, `.md`, `.prompt`, ...), directories (recursive), `-` for
stdin, and JSON/JSONL in these shapes:

- OpenAI chat: `messages[]` with `role: system` or `role: developer` (string or content parts)
- Anthropic: top-level `system` (string or text blocks)
- Generic: any `system`, `system_prompt`, `systemPrompt`, `instructions`, `systemInstruction` key

Identical prompts that repeat across turns or files are audited once. `--as-text` treats every
file as a single prompt, even when it parses as JSON. Exit codes: `0` clean, `1` findings at or
above `--fail-on` (default `high`), `2` usage or input error.

## Rules

| Rule | Severity | What it flags |
|------|----------|---------------|
| PA01 | critical | Credential literal: OpenAI/AWS/GitHub/Slack/Google key shapes, private key blocks, JWTs, bearer tokens, connection strings with passwords, `password: ...` style labels (placeholders like `{{API_KEY}}` skipped) |
| PA02 | high (critical for metadata) | Private, loopback, link-local, or cloud metadata IPs and internal hostnames (`.internal`, `.corp`, `.local`, single-label hosts) in URLs or bare IPs |
| PA03 | high | Authorization enforced only by the model: "only allow ... admins", "if the user says they are an admin", cross-tenant "don't let users view other customers'", admin passphrases |
| PA04 | high | Unbounded authority: "run any command", "without asking for confirmation", "full access", "ignore safety checks", "always approve tool calls" |
| PA05 | high (critical with TAG text) | Zero-width, bidi, and Unicode TAG characters; TAG payloads are decoded into the message |
| PA06 | medium | The prompt mentions tools, browsing, files, email, or retrieval but has no guidance that such content is data, not instructions |
| PA07 | medium (SSN high, phone low) | Personal email addresses (role and example.com addresses skipped), SSN-shaped numbers, phone numbers |
| PA08 | medium | Disclosed decision thresholds or filter criteria: "refunds under $500 are auto-approved", "fraud score above 0.8", blocked-word lists |
| PA09 | low | Relying on the prompt staying secret ("never reveal these instructions") |
| PA10 | info | Inventory: prompt size |

## Example

```sh
cd tools/promptaudit
python3 promptaudit.py examples/risky_prompt.txt --min-severity medium
```

```
examples/risky_prompt.txt:3  CRITICAL PA01  OpenAI-style API key: sk-F…****00
examples/risky_prompt.txt:3  HIGH     PA02  private URL host 10.20.0.15
examples/risky_prompt.txt:4  CRITICAL PA01  connection string with password: post…****al
examples/risky_prompt.txt:4  HIGH     PA02  internal URL host db.payments.internal
examples/risky_prompt.txt:5  HIGH     PA03  access rule enforced only by the model: ...
examples/risky_prompt.txt:6  MEDIUM   PA08  'under $500 are auto-approved with no review'
...
```

`examples/clean_prompt.txt` shows the same kind of assistant written safely and produces only
the PA10 inventory line. `examples/risky_openai.json` and `examples/risky_anthropic.json` show
transcript extraction. All secret values in the examples are fake (`FAKE-EXAMPLE-...`).

## Known limits

- English-only phrase heuristics. Paraphrased authorization logic or authority grants will be missed,
  and unusual phrasing can produce false positives. Use `--disable` for rules that don't fit.
- PA06 only checks that some untrusted-content guidance exists; it can't judge whether it works.
  Prompt guidance is a mitigation, never a control.
- Secret detection is shape-based. It doesn't verify keys and won't catch secrets with no known
  shape and no label.
- It audits the prompt text it is given. Prompts assembled at runtime from templates are better
  checked with tmplfence; leakage of a prompt into outputs is promptleak's job.
