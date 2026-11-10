# Framework integration examples

Short, **stdlib-only** demos that show how to run agentsec on exports from
common agent frameworks. No LangChain, OpenAI, or CrewAI packages are
installed or imported. Every secret and callback URL in these fixtures is
**fake**.

The transcript scanners in this kit already understand OpenAI chat
(`role` + `tool_calls`) and Anthropic `tool_use` / `tool_result` shapes.
Framework UIs often export something adjacent to that. `normalize.py`
turns those exports into the OpenAI-style transcript the tools parse, so
you can keep using `agentsec resultguard` / `secretflow` / `pathfence`
and friends without adding a dependency.

MCP client configs (Cursor, Claude Desktop, VS Code) are a different
shape. Do not run them through `normalize.py`; point `mcpposture` at the
file instead.

## Quick start

From the repository root (Python 3.10+, no install required):

```sh
python3 examples/frameworks/run_demo.py
```

Or one framework at a time:

```sh
python3 examples/frameworks/run_demo.py langchain
python3 examples/frameworks/run_demo.py openai_agents
python3 examples/frameworks/run_demo.py crewai
python3 examples/frameworks/run_demo.py mcp
```

Each transcript demo normalizes the fixture, then runs a handful of
scanners. The bundled fixtures are deliberately risky, so a `1` exit
status (findings at or above `--fail-on high`) is expected.

## Normalize a file yourself

```sh
python3 examples/frameworks/normalize.py examples/frameworks/langchain/export.json -o /tmp/transcript.json
python3 -m agentsec resultguard /tmp/transcript.json --fail-on high
python3 -m agentsec secretflow  /tmp/transcript.json --fail-on high
```

`PYTHONPATH` must include the repo root if you have not `pip install`ed
the kit (`run_demo.py` sets this for you). After an install, `agentsec`
works the same way:

```sh
pip install git+https://github.com/dunkleschitz/agentsec.git
agentsec resultguard /tmp/transcript.json
```

## What each fixture looks like

| Directory | Format (fake data) | What the demo runs |
|---|---|---|
| [langchain/export.json](langchain/export.json) | LangChain serialized messages (`type`: `human` / `ai` / `tool`, `tool_calls[].args`) | resultguard, secretflow, pathfence, fetchfence |
| [openai_agents/trace.json](openai_agents/trace.json) | OpenAI Agents SDK / Responses items (`function_call`, `function_call_output`, `message`) | those, plus shellfence and piiguard |
| [crewai/kickoff.json](crewai/kickoff.json) | CrewAI-style `tasks_output` with `tool_events` (`tool_usage_started` / `tool_usage_finished`) | resultguard, secretflow, pathfence, fetchfence |
| [mcp_clients/cursor.mcp.json](mcp_clients/cursor.mcp.json) | Cursor `mcp.json` (`mcpServers`) | mcpposture |
| [mcp_clients/claude_desktop_config.json](mcp_clients/claude_desktop_config.json) | Claude Desktop `claude_desktop_config.json` | mcpposture |

If your own export does not match these shapes, convert it to OpenAI-style
messages (or Anthropic content blocks) once, then run the tools on that
file. Pull requests that extend `normalize.py` for a documented official
export shape are welcome.

## Known limits

- The normalizer is best-effort. Official SDKs change their dump formats;
  unrecognized shapes exit `2` rather than inventing events.
- Normalization does not itself find vulnerabilities. It only rewrites
  the fixture so the existing scanners can read it.
- These fixtures are not recordings of real runs and contain no live
  credentials.
