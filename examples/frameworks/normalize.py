#!/usr/bin/env python3
"""Normalize framework export fixtures into the OpenAI-style transcript
shape that agentsec tools already parse (messages + tool_calls / role=tool).

Supported inputs (best-effort, no third-party libraries):

- LangChain / LangGraph: serialized messages with type=human|ai|tool
  (or HumanMessage / AIMessage / ToolMessage), including lc constructor dumps
- OpenAI Agents SDK: Responses-style item lists (function_call /
  function_call_output / message) as produced by RunResult traces
- CrewAI: tasks_output with tool_events (tool_usage_started / finished)
- Already-normalized OpenAI or Anthropic transcripts are passed through
- Claude Desktop / Cursor / VS Code MCP configs are not transcripts; leave
  those to mcpposture (this script exits 2 if handed one)

Usage:
  python3 normalize.py path/to/export.json > transcript.json
  python3 normalize.py path/to/export.json -o transcript.json
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def _load(path: str):
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    # JSONC (MCP configs) is not a transcript; detect later
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"__raw__": raw, "__path__": path}


def _is_mcp_config(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if "mcpServers" in data or "mcp_servers" in data:
        return True
    if isinstance(data.get("mcp"), dict) and "servers" in data["mcp"]:
        return True
    if isinstance(data.get("servers"), dict) and any(
        isinstance(v, dict) and ("command" in v or "url" in v or "serverUrl" in v)
        for v in data["servers"].values()
    ):
        return True
    return False


def _text_of(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (int, float, bool)):
        return str(content)
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                for key in ("text", "content", "output", "input_text", "output_text"):
                    if key in block and isinstance(block[key], str):
                        parts.append(block[key])
                        break
                else:
                    parts.append(_text_of(block.get("content")))
        return "\n".join(p for p in parts if p)
    if isinstance(content, dict):
        for key in ("text", "content", "output", "result"):
            if key in content:
                return _text_of(content[key])
        return json.dumps(content, ensure_ascii=False)
    return str(content)


def _args_of(obj: Any) -> str:
    if obj is None:
        return "{}"
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, ensure_ascii=False)


def _tool_call(name: str, arguments: Any, call_id: str) -> dict:
    return {
        "id": call_id or name,
        "type": "function",
        "function": {"name": name or "tool", "arguments": _args_of(arguments)},
    }


def _from_langchain_messages(messages: list) -> list[dict]:
    out: list[dict] = []
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue
        # lc constructor dump
        if msg.get("lc") == 1 and isinstance(msg.get("kwargs"), dict):
            ident = msg.get("id") or []
            cls = ident[-1] if ident else ""
            msg = dict(msg["kwargs"])
            if cls and "type" not in msg:
                lower = cls.lower()
                if "human" in lower:
                    msg["type"] = "human"
                elif "system" in lower:
                    msg["type"] = "system"
                elif "tool" in lower:
                    msg["type"] = "tool"
                elif "ai" in lower or "assistant" in lower:
                    msg["type"] = "ai"
        typ = (msg.get("type") or msg.get("role") or "").lower()
        if typ in {"human", "user"}:
            out.append({"role": "user", "content": _text_of(msg.get("content") or msg.get("data", {}).get("content"))})
            continue
        if typ in {"system", "developer"}:
            out.append({"role": "system", "content": _text_of(msg.get("content"))})
            continue
        if typ in {"ai", "assistant"}:
            tool_calls = msg.get("tool_calls") or []
            formatted = []
            for j, tc in enumerate(tool_calls):
                if not isinstance(tc, dict):
                    continue
                name = tc.get("name") or (tc.get("function") or {}).get("name") or "tool"
                args = tc.get("args") or tc.get("arguments") or (tc.get("function") or {}).get("arguments")
                cid = tc.get("id") or tc.get("tool_call_id") or f"call_{i}_{j}"
                formatted.append(_tool_call(name, args, cid))
            entry: dict[str, Any] = {"role": "assistant", "content": _text_of(msg.get("content")) or None}
            if formatted:
                entry["tool_calls"] = formatted
            out.append(entry)
            continue
        if typ in {"tool", "function"}:
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": msg.get("tool_call_id") or msg.get("id") or f"call_{i}",
                    "name": msg.get("name") or msg.get("tool") or "tool",
                    "content": _text_of(msg.get("content") or msg.get("output") or msg.get("result")),
                }
            )
            continue
    return out


def _from_openai_agents_items(items: list) -> list[dict]:
    out: list[dict] = []
    pending_name: dict[str, str] = {}
    pending_args: dict[str, str] = {}
    # Accumulate assistant function_call items into one assistant message when contiguous
    pending_calls: list[dict] = []
    pending_assistant_text = ""

    def flush_assistant():
        nonlocal pending_calls, pending_assistant_text
        if pending_calls or pending_assistant_text:
            entry: dict[str, Any] = {
                "role": "assistant",
                "content": pending_assistant_text or None,
            }
            if pending_calls:
                entry["tool_calls"] = pending_calls
            out.append(entry)
        pending_calls = []
        pending_assistant_text = ""

    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        typ = item.get("type") or item.get("role") or ""
        if typ == "message" or typ in {"user", "assistant", "system"} and "content" in item:
            role = item.get("role") or ("user" if typ == "message" and item.get("role") is None else typ)
            if role in {"user", "system", "developer"}:
                flush_assistant()
                out.append({"role": role if role != "developer" else "system", "content": _text_of(item.get("content"))})
                continue
            if role == "assistant" or typ == "message":
                # May also include output text mid-run
                text = _text_of(item.get("content"))
                if pending_calls:
                    pending_assistant_text = (pending_assistant_text or "") + text
                else:
                    flush_assistant()
                    pending_assistant_text = text
                continue
        if typ in {"function_call", "tool_call", "hosted_tool_call"}:
            name = item.get("name") or item.get("tool") or "tool"
            cid = item.get("call_id") or item.get("id") or f"call_{i}"
            args = item.get("arguments") or item.get("args") or item.get("input")
            pending_calls.append(_tool_call(name, args, cid))
            pending_name[cid] = name
            pending_args[cid] = _args_of(args)
            continue
        if typ in {"function_call_output", "tool_call_output", "function_output"}:
            flush_assistant()
            cid = item.get("call_id") or item.get("id") or f"call_{i}"
            out.append(
                {
                    "role": "tool",
                    "tool_call_id": cid,
                    "name": pending_name.get(cid) or item.get("name") or "tool",
                    "content": _text_of(item.get("output") or item.get("content") or item.get("result")),
                }
            )
            continue
    flush_assistant()
    return out


def _from_crewai(data: dict) -> list[dict]:
    out: list[dict] = []
    tasks = data.get("tasks_output") or data.get("tasks") or data.get("events") or []
    if isinstance(data.get("crew"), dict):
        # sometimes nested
        pass
    call_i = 0
    for task in tasks:
        if not isinstance(task, dict):
            continue
        desc = task.get("description") or task.get("task") or ""
        agent = task.get("agent") or data.get("crew") or "crew"
        if desc:
            out.append({"role": "user", "content": f"[{agent}] {desc}" if agent else str(desc)})
        events = task.get("tool_events") or task.get("tools") or task.get("tool_calls") or []
        # Also accept a single tool list
        for ev in events:
            if not isinstance(ev, dict):
                continue
            typ = (ev.get("event") or ev.get("type") or "").lower()
            name = ev.get("tool_name") or ev.get("tool") or ev.get("name") or "tool"
            if typ in {"tool_usage_started", "tool_start", "started"} or (
                typ == "" and ev.get("args") is not None and ev.get("output") is None and ev.get("result") is None
            ):
                call_i += 1
                cid = ev.get("id") or f"call_{call_i}"
                ev["_cid"] = cid
                out.append(
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [_tool_call(name, ev.get("args") or ev.get("arguments") or ev.get("input"), cid)],
                    }
                )
                continue
            if typ in {"tool_usage_finished", "tool_end", "finished", "tool_result"} or ev.get("output") is not None or ev.get("result") is not None:
                # If we never saw a start, synthesize a call
                cid = ev.get("tool_call_id") or ev.get("id") or ev.get("_cid")
                if not cid:
                    call_i += 1
                    cid = f"call_{call_i}"
                    out.append(
                        {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [_tool_call(name, ev.get("args") or ev.get("arguments") or {}, cid)],
                        }
                    )
                out.append(
                    {
                        "role": "tool",
                        "tool_call_id": cid,
                        "name": name,
                        "content": _text_of(ev.get("output") or ev.get("result") or ev.get("content")),
                    }
                )
                continue
        raw = task.get("raw") or task.get("output") or task.get("result")
        if raw and not events:
            # Unstructured final answer only — still useful for piiguard/promptleak
            out.append({"role": "assistant", "content": _text_of(raw)})
    return out


def _already_openai(data: Any) -> list[dict] | None:
    if isinstance(data, dict):
        for key in ("messages", "events", "steps", "transcript", "items"):
            val = data.get(key)
            if isinstance(val, list) and val and isinstance(val[0], dict):
                if any(v.get("role") in {"user", "assistant", "system", "tool"} for v in val if isinstance(v, dict)):
                    if key == "messages":
                        return val
                    break
        if data.get("role") in {"user", "assistant", "system", "tool"}:
            return [data]
    if isinstance(data, list) and data and isinstance(data[0], dict):
        if any(v.get("role") in {"user", "assistant", "system", "tool"} for v in data):
            return data
    return None


def detect_kind(data: Any) -> str:
    if _is_mcp_config(data):
        return "mcp_config"
    if not isinstance(data, (dict, list)):
        return "unknown"
    if isinstance(data, dict):
        fw = (data.get("framework") or data.get("sdk") or "").lower()
        if "langchain" in fw or "langgraph" in fw:
            return "langchain"
        if "openai" in fw and "agent" in fw:
            return "openai_agents"
        if "crew" in fw:
            return "crewai"
        if "mcpServers" in data or data.get("mcp"):
            return "mcp_config"
        if isinstance(data.get("items"), list):
            items = data["items"]
            if items and isinstance(items[0], dict) and items[0].get("type") in {
                "function_call",
                "function_call_output",
                "message",
                "hosted_tool_call",
            }:
                return "openai_agents"
        if isinstance(data.get("tasks_output"), list) or (
            isinstance(data.get("tasks"), list) and data.get("crew")
        ):
            return "crewai"
        msgs = data.get("messages")
        if isinstance(msgs, list) and msgs and isinstance(msgs[0], dict):
            if msgs[0].get("type") in {"human", "ai", "tool", "system", "HumanMessage", "AIMessage"} or msgs[0].get("lc") == 1:
                return "langchain"
            if msgs[0].get("role") in {"user", "assistant", "system", "tool"}:
                return "openai"
    if isinstance(data, list) and data and isinstance(data[0], dict):
        if data[0].get("type") in {"human", "ai", "tool"} or data[0].get("lc") == 1:
            return "langchain"
        if data[0].get("type") in {"function_call", "function_call_output", "message"}:
            return "openai_agents"
        if (data[0].get("event") or "").startswith("tool_usage"):
            return "crewai"
    return "unknown"


def normalize(data: Any) -> tuple[str, dict]:
    kind = detect_kind(data)
    if kind == "mcp_config":
        raise ValueError(
            "this looks like an MCP client config; run `agentsec mcpposture <file>` instead of normalize.py"
        )
    if kind == "langchain":
        messages = data.get("messages") if isinstance(data, dict) else data
        if isinstance(data, dict) and not messages:
            # LangSmith / LangGraph run tree
            messages = data.get("inputs", {}).get("messages") if isinstance(data.get("inputs"), dict) else None
        if not isinstance(messages, list):
            raise ValueError("LangChain fixture has no messages list")
        out = _from_langchain_messages(messages)
        return kind, {"model": data.get("model") if isinstance(data, dict) else None, "source": "langchain", "messages": out}
    if kind == "openai_agents":
        items = data.get("items") if isinstance(data, dict) else data
        if not isinstance(items, list):
            # sometimes nested under trace / export
            if isinstance(data, dict):
                for key in ("export", "events", "new_items"):
                    if isinstance(data.get(key), list):
                        items = data[key]
                        break
        if not isinstance(items, list):
            raise ValueError("OpenAI Agents fixture has no items list")
        out = _from_openai_agents_items(items)
        model = data.get("model") if isinstance(data, dict) else None
        return kind, {"model": model, "source": "openai-agents", "messages": out}
    if kind == "crewai":
        if not isinstance(data, dict):
            data = {"tasks_output": data}
        out = _from_crewai(data)
        return kind, {"model": data.get("model"), "source": "crewai", "messages": out}
    existing = _already_openai(data)
    if existing is not None:
        return "openai", {"source": "openai", "messages": existing}
    raise ValueError("unrecognized framework export; see examples/frameworks/README.md")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", help="framework export JSON")
    p.add_argument("-o", "--output", help="write transcript JSON here (default: stdout)")
    args = p.parse_args(argv)
    data = _load(args.path)
    try:
        kind, transcript = normalize(data)
    except ValueError as exc:
        sys.stderr.write("normalize.py: %s\n" % exc)
        return 2
    text = json.dumps(transcript, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    sys.stderr.write("normalize.py: %s -> %d messages\n" % (kind, len(transcript.get("messages") or [])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
