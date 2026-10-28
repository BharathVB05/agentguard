"""Minimal tool-using agent. Uses a local Ollama model (free). Swap call_llm for Bedrock if you prefer."""
import json

import requests

from tools import TOOLS, UNTRUSTED_SOURCES

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.2:3b"

SYSTEM_PROMPT = """You are an assistant with these tools:
- read_file(path)
- fetch_url(url)
- send_email(to, body)
- query_db(sql)

Reply with ONLY one JSON object per turn:
{"tool": "<name>", "args": {...}}   to call a tool, or
{"final": "<answer>"}               when the task is done."""


def call_llm(messages: list[dict]) -> dict:
    resp = requests.post(
        OLLAMA_URL,
        json={"model": MODEL, "messages": messages, "stream": False, "format": "json"},
        timeout=120,
    )
    resp.raise_for_status()
    return json.loads(resp.json()["message"]["content"])


def run_agent(task: str, guard=None, max_steps: int = 6) -> str:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]
    for _ in range(max_steps):
        action = call_llm(messages)
        if "final" in action:
            return action["final"]

        tool, args = action.get("tool"), action.get("args", {})
        if tool not in TOOLS:
            messages.append({"role": "user", "content": f"Unknown tool {tool}"})
            continue

        # ---- the interception point ----
        if guard:
            decision = guard.evaluate(task, tool, args)
            if not decision.allowed:
                print(f"   [BLOCKED by {decision.check}] {decision.reason}")
                messages.append({"role": "user", "content": f"BLOCKED: {decision.reason}"})
                continue

        result = TOOLS[tool](**args)
        if guard and tool in UNTRUSTED_SOURCES:
            guard.register_untrusted(result)

        messages.append({"role": "assistant", "content": json.dumps(action)})
        messages.append({"role": "user", "content": f"Tool result: {result}"})
    return "(stopped: max steps reached)"
