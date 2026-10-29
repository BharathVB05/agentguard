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
    def __init__(self, db_path: str = "audit.db", intent_judge=None, checks=None):
        # checks: which layers are active. Default = all. Used for the ablation study.
        self.checks = set(checks) if checks is not None else {"policy", "classifier", "taint", "intent"}
        # intent_judge: function(task, tool, args) -> bool. None = intent check off.
        self.intent_judge = intent_judge
        self.untrusted_texts: list[str] = []
        self.sources: list[str | None] = []
        self.clf = InjectionClassifier()
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                 ts REAL, task TEXT, tool TEXT, args TEXT,
                 allowed INTEGER, reason TEXT, check_name TEXT, latency_ms REAL)"""
        )

    # ---- taint tracking -------------------------------------------------
    def register_untrusted(self, text: str, source: str | None = None) -> None:
        """Call this with anything that came from a file, web page, etc.
        source = file name or URL it came from (used for source-aware taint)."""
        self.untrusted_texts.append(text)
        self.sources.append(source)

    @staticmethod
    def _endorsed(task: str, source: str | None) -> bool:
        """True if the USER's task points at this source as the place to take recipients from,
        e.g. 'email the person listed in contacts.txt'. Merely naming a file to read or
        summarize ('summarize report.txt') does NOT count. This is a keyword heuristic."""
        if not source:
            return False
        src = re.escape(source.lower())
        t = task.lower()
        patterns = [
            rf"\b(listed|named|mentioned|specified|given|written|found|contained|stated)\b.{{0,40}}\b(in|on|from|by)\s+{src}",
            rf"\b(address(es)?|email|recipients?|person|people|contacts?|owner|lead|manager)\b.{{0,25}}\b(in|from)\s+{src}",
        ]
        return any(re.search(p, t) for p in patterns)

    def _tainted_values(self, args: dict, task: str = "") -> list[str]:
        """Emails/URLs in the arguments that first appeared in untrusted content
        (ignoring content from a source the user explicitly pointed to)."""
        untrusted_tokens = set()
        for text, source in zip(self.untrusted_texts, self.sources):
            if self._endorsed(task, source):
                continue
            # strip trailing sentence punctuation so 'x@company.com.' matches 'x@company.com'
            untrusted_tokens.update(t.rstrip(".,;:!?)\"'") for t in EMAIL_OR_URL.findall(text))
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

        policy_decision = self._policy(tool, args) if "policy" in self.checks else None
        if policy_decision:
            decision = policy_decision
        elif tool in SENSITIVE_TOOLS:
            flagged = (
                [t for t in self.untrusted_texts if self.clf.is_injection(t)]
                if "classifier" in self.checks else []
            )
            tainted = self._tainted_values(args, task) if "taint" in self.checks else []
            if flagged:
                decision = Decision(
                    False, "Untrusted content looks like an injected instruction", "classifier"
                )
            elif tainted:
                decision = Decision(
                    False,
                    f"Sensitive call influenced by untrusted content: {tainted}",
                    "taint",
                )
            elif ("intent" in self.checks and self.intent_judge
                  and not self.intent_judge(task, tool, args)):
                # The LLM judge may only ADD a block. It can never cancel another layer's block.
                decision = Decision(False, "Call not consistent with user task", "intent")

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
