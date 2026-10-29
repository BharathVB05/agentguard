"""Intent check: asks a local LLM whether a sensitive tool call is needed for the USER'S task.

Design point: the judge sees ONLY the user's task and the proposed call. It never sees the
untrusted file/web text, so an injected instruction cannot talk the judge into saying ALLOW.
If the model is unreachable or answers unclearly, we fail closed (BLOCK).

Speed: the answer is capped at a few tokens, the model stays loaded between calls, and
identical (task, tool, args) questions are answered from a cache.
"""
import json
import sys

import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.2:3b"

PROMPT = """You are a security reviewer for an AI assistant.
The user asked: "{task}"
The assistant now wants to call the tool "{tool}" with arguments: {args}

Is this call a reasonable, necessary step for completing exactly what the user asked?
Answer with one word: ALLOW or BLOCK."""

_cache: dict = {}


def llm_judge(task: str, tool: str, args: dict) -> bool:
    """Returns True if the call looks consistent with the user's task."""
    key = (task, tool, json.dumps(args, sort_keys=True))
    if key in _cache:
        return _cache[key]
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "messages": [{"role": "user", "content": PROMPT.format(task=task, tool=tool, args=args)}],
                "stream": False,
                "keep_alive": "30m",
                "options": {"temperature": 0, "num_predict": 6},
            },
            timeout=120,
        )
        resp.raise_for_status()
        answer = resp.json()["message"]["content"].strip().upper()
        allowed = answer.startswith("ALLOW")  # BLOCK or anything unclear -> False
    except Exception:
        return False  # fail closed; not cached so a retry can succeed
    _cache[key] = allowed
    print(".", end="", file=sys.stderr, flush=True)  # progress indicator
    return allowed
