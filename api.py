"""AgentGuard HTTP service.

Start:   uvicorn api:app --reload
Docs:    http://127.0.0.1:8000/docs   (interactive page where you can try the endpoints)

Any agent can call POST /check before running a tool. Each request is independent: the caller
sends the untrusted content the agent has read so far, so the service keeps no hidden state.
"""
import os
import sqlite3
from datetime import datetime

from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

from guard import Guard

DB_PATH = os.environ.get("AUDIT_DB", "audit.db")

app = FastAPI(
    title="AgentGuard",
    description="Runtime guard for LLM agent tool calls: policy, injection classifier, "
                "taint tracking and an optional LLM intent check.",
    version="0.1.0",
)

Guard(DB_PATH).conn.close()  # make sure the audit table exists at startup


class UntrustedItem(BaseModel):
    text: str = Field(description="Content the agent read from a file, web page, tool output...")
    source: str | None = Field(default=None, description="File name or URL it came from")


class CheckRequest(BaseModel):
    task: str = Field(description="The user's original request")
    tool: str = Field(description="Tool the agent wants to call, e.g. send_email")
    args: dict = Field(default_factory=dict, description="Arguments of the proposed call")
    untrusted: list[UntrustedItem] = Field(default_factory=list)
    use_intent: bool = Field(default=False, description="Also run the LLM intent check (needs Ollama)")


class CheckResponse(BaseModel):
    allowed: bool
    reason: str
    check: str
    latency_ms: float


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest):
    judge = None
    if req.use_intent:
        from intent_check import llm_judge  # imported only when asked for
        judge = llm_judge
    guard = Guard(DB_PATH, intent_judge=judge)
    try:
        for item in req.untrusted:
            guard.register_untrusted(item.text, item.source)
        decision = guard.evaluate(req.task, req.tool, req.args)
        row = guard.conn.execute("SELECT latency_ms FROM audit ORDER BY rowid DESC LIMIT 1").fetchone()
    finally:
        guard.conn.close()
    return CheckResponse(allowed=decision.allowed, reason=decision.reason,
                         check=decision.check, latency_ms=round(row[0], 3) if row else 0.0)


@app.get("/logs")
def logs(limit: int = Query(50, ge=1, le=500), blocked_only: bool = False):
    conn = sqlite3.connect(DB_PATH)
    try:
        sql = ("SELECT ts, task, tool, args, allowed, reason, check_name, latency_ms FROM audit "
               + ("WHERE allowed = 0 " if blocked_only else "")
               + "ORDER BY rowid DESC LIMIT ?")
        rows = conn.execute(sql, (limit,)).fetchall()
    finally:
        conn.close()
    return [
        {"time": datetime.fromtimestamp(ts).isoformat(timespec="seconds"), "task": task,
         "tool": tool, "args": args, "allowed": bool(allowed), "reason": reason,
         "check": check_name, "latency_ms": round(lat, 3)}
        for ts, task, tool, args, allowed, reason, check_name, lat in rows
    ]
