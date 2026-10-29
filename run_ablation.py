"""Ablation study: how much does each AgentGuard layer contribute?

Runs the original 36 scenarios (attacks.py) and the harder set (attacks_hard.py) under
different combinations of layers.

    python run_ablation.py            # fast, rule + classifier layers only
    python run_ablation.py --intent   # also includes the LLM intent check (needs Ollama, slower)
"""
import sys

from attacks import SCENARIOS as EASY
from attacks_hard import HARD
from attacks_source import SRC
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
        srcs = s.get("sources") or [None] * len(s["untrusted"])
        for t, src in zip(s["untrusted"], srcs):
            g.register_untrusted(t, src)
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

    print(f"{'Configuration':30s} | {'EASY atk':>8s} {'EASY fp':>7s} | {'HARD atk':>8s} {'HARD fp':>7s} | {'SRC atk':>7s} {'SRC fp':>6s}")
    print("-" * 92)
    details = {}
    for name, checks in configs:
        em, ea, ew, eb, _, _ = run(EASY, checks, judge)
        hm, ha, hw, hb, hmiss, hwrong = run(HARD, checks, judge)
        sm, sa, sw, sb, smiss, swrong = run(SRC, checks, judge)
        details[name] = (hmiss + smiss, hwrong + swrong)
        print(f"{name:30s} | {pct(em, ea):>8s} {pct(ew, eb):>7s} | {pct(hm, ha):>8s} {pct(hw, hb):>7s} | {pct(sm, sa):>7s} {pct(sw, sb):>6s}")
    print("\n'attack' = % of attacks that still got through (lower is better)")
    print("'false'  = % of harmless calls wrongly blocked (lower is better)")
    print("atk = attacks that still got through, fp = harmless calls wrongly blocked")
    print(f"EASY: {ea} attacks/{eb} harmless | HARD: {ha}/{hb} | SRC (source-aware taint): {sa}/{sb}")

    last = configs[-1][0]
    hmiss, hwrong = details[last]
    print(f"\nHard/SRC attacks still missed by '{last}':")
    for s in hmiss:
        print(f"  [{s['kind']}] {s['tool']} {s['args']}")
    print(f"\nHard/SRC harmless calls wrongly blocked by '{last}':")
    for s in hwrong:
        print(f"  [{s['kind']}] {s['tool']} {s['args']}")


if __name__ == "__main__":
    main()
