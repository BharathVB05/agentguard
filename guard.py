"""AgentGuard core: intercepts every tool call, decides allow/block, and logs why."""
import json
import re
import sqlite3
import time
from dataclasses import dataclass

from injection_clf import InjectionClassifier

SENSITIVE_TOOLS = {"send_email", "query_db"}
ALLOWED_EMAIL_DOMAIN = "company.com"
FORBIDDEN_SQL = ["drop", "delete", "update", "insert"]
EMAIL_OR_URL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+|https?://\S+")


@dataclass
class Decision:
    allowed: bool
    reason: str
    check: str  # which check made the decision


class Guard:
    def __init__(self, db_path: str = "audit.db", intent_judge=None):
        # intent_judge: function(task, tool, args) -> bool. None = intent check off.
        self.intent_judge = intent_judge
        self.untrusted_texts: list[str] = []
        self.clf = InjectionClassifier()
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                 ts REAL, task TEXT, tool TEXT, args TEXT,
                 allowed INTEGER, reason TEXT, check_name TEXT, latency_ms REAL)"""
        )

    # ---- taint tracking -------------------------------------------------
    def register_untrusted(self, text: str) -> None:
        """Call this with anything that came from a file, web page, etc."""
        self.untrusted_texts.append(text)

    def _tainted_values(self, args: dict) -> list[str]:
        """Emails/URLs in the arguments that first appeared in untrusted content."""
        untrusted_tokens = set()
        for text in self.untrusted_texts:
            untrusted_tokens.update(EMAIL_OR_URL.findall(text))
        hits = []
        for value in args.values():
            for token in untrusted_tokens:
                if token in str(value):
                    hits.append(token)
        return hits

    # ---- policy checks --------------------------------------------------
    def _policy(self, tool: str, args: dict) -> Decision | None:
        if tool == "send_email":
            domain = str(args.get("to", "")).split("@")[-1].lower()
            if domain != ALLOWED_EMAIL_DOMAIN:
                return Decision(False, f"Recipient domain '{domain}' not allowed", "policy")
        if tool == "query_db":
            sql = str(args.get("sql", "")).lower()
            for word in FORBIDDEN_SQL:
                if word in sql:
                    return Decision(False, f"SQL contains forbidden keyword '{word}'", "policy")
        return None

    # ---- main entry point -----------------------------------------------
    def evaluate(self, task: str, tool: str, args: dict) -> Decision:
        start = time.perf_counter()
        decision = Decision(True, "No rule triggered", "none")

        policy_decision = self._policy(tool, args)
        if policy_decision:
            decision = policy_decision
        elif tool in SENSITIVE_TOOLS:
            # 1) injected-instruction text: block outright (never overridden by the judge)
            flagged = [t for t in self.untrusted_texts if self.clf.is_injection(t)]
            if flagged:
                decision = Decision(
                    False, "Untrusted content looks like an injected instruction", "classifier"
                )
            else:
                # 2) taint: untrusted data shaped the arguments -> ask the intent check
                tainted = self._tainted_values(args)
                if tainted:
                    if self.intent_judge and self.intent_judge(task, tool, args):
                        decision = Decision(
                            True, f"Tainted values {tainted} but consistent with user task", "intent"
                        )
                    else:
                        decision = Decision(
                            False,
                            f"Sensitive call influenced by untrusted content: {tainted}",
                            "taint",
                        )

        latency = (time.perf_counter() - start) * 1000
        self._log(task, tool, args, decision, latency)
        return decision

    def _log(self, task, tool, args, decision, latency):
        self.conn.execute(
            "INSERT INTO audit VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), task, tool, json.dumps(args), int(decision.allowed),
             decision.reason, decision.check, latency),
        )
        self.conn.commit()
