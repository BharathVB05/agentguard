"""Ablation study: how much does each AgentGuard layer contribute?

Runs the original 36 scenarios (attacks.py) and the harder set (attacks_hard.py) under
different combinations of layers.

    python run_ablation.py            # fast, rule + classifier layers only
    python run_ablation.py --intent   # also includes the LLM intent check (needs Ollama, slower)
"""
import sys

from attacks import SCENARIOS as EASY
from attacks_hard import HARD
from guard import Guard

CONFIGS = [
    ("No guard", set()),
    ("Policy only", {"policy"}),
    ("Taint only", {"taint"}),
    ("Classifier only", {"classifier"}),
    ("Policy + taint", {"policy", "taint"}),
    ("Policy + taint + classifier", {"policy", "taint", "classifier"}),
]
INTENT_CONFIGS = [
    ("Intent only", {"intent"}),
    ("Policy + taint + intent", {"policy", "taint", "intent"}),
    ("All four layers", {"policy", "taint", "classifier", "intent"}),
]


def run(scenarios, checks, judge):
    attacks = [s for s in scenarios if s["label"] == "attack"]
    benign = [s for s in scenarios if s["label"] == "benign"]
    missed, wrong = [], []
    for s in scenarios:
        g = Guard(":memory:", intent_judge=judge, checks=checks)
        for t in s["untrusted"]:
            g.register_untrusted(t)
        d = g.evaluate(s["task"], s["tool"], s["args"])
        if s["label"] == "attack" and d.allowed:
            missed.append(s)
        if s["label"] == "benign" and not d.allowed:
            wrong.append(s)
    return len(missed), len(attacks), len(wrong), len(benign), missed, wrong


def pct(a, b):
    return f"{100 * a / b:5.1f}%"


def main():
    judge = None
    configs = list(CONFIGS)
    if "--intent" in sys.argv:
        from intent_check import llm_judge
        judge = llm_judge
        configs += INTENT_CONFIGS
        print("Intent layer included (uses Ollama; this will take a few minutes)\n")

    print(f"{'Configuration':32s} | {'EASY attack':>11s} {'EASY false':>10s} | {'HARD attack':>11s} {'HARD false':>10s}")
    print("-" * 85)
    details = {}
    for name, checks in configs:
        em, ea, ew, eb, _, _ = run(EASY, checks, judge)
        hm, ha, hw, hb, hmiss, hwrong = run(HARD, checks, judge)
        details[name] = (hmiss, hwrong)
        print(f"{name:32s} | {pct(em, ea):>11s} {pct(ew, eb):>10s} | {pct(hm, ha):>11s} {pct(hw, hb):>10s}")
    print("\n'attack' = % of attacks that still got through (lower is better)")
    print("'false'  = % of harmless calls wrongly blocked (lower is better)")
    print(f"EASY set: {ea} attacks, {eb} harmless | HARD set: {ha} attacks, {hb} harmless")

    last = configs[-1][0]
    hmiss, hwrong = details[last]
    print(f"\nHARD attacks still missed by '{last}':")
    for s in hmiss:
        print(f"  [{s['kind']}] {s['tool']} {s['args']}")
    print(f"\nHARD harmless calls wrongly blocked by '{last}':")
    for s in hwrong:
        print(f"  [{s['kind']}] {s['tool']} {s['args']}")


if __name__ == "__main__":
    main()
