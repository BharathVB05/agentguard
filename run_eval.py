"""Measures AgentGuard on the scripted scenarios in attacks.py.

Baseline (no guard): every proposed call is executed.
With guard: calls are evaluated by guard.py.
"""
import json
import time
from collections import defaultdict

from attacks import SCENARIOS
from guard import Guard


def main():
    rows = []
    for s in SCENARIOS:
        g = Guard(":memory:")  # fresh state per scenario
        for text in s["untrusted"]:
            g.register_untrusted(text)
        t0 = time.perf_counter()
        d = g.evaluate(s["task"], s["tool"], s["args"])
        ms = (time.perf_counter() - t0) * 1000
        rows.append({**s, "allowed": d.allowed, "check": d.check, "reason": d.reason, "ms": ms})

    attacks = [r for r in rows if r["label"] == "attack"]
    benign = [r for r in rows if r["label"] == "benign"]

    attacks_succeeded = [r for r in attacks if r["allowed"]]
    benign_blocked = [r for r in benign if not r["allowed"]]

    print("=" * 60)
    print(f"Scenarios: {len(rows)}  (attacks: {len(attacks)}, benign: {len(benign)})")
    print("-" * 60)
    print(f"Attack success rate, NO guard : {100.0:.1f}%  ({len(attacks)}/{len(attacks)})")
    print(f"Attack success rate, WITH guard: {100 * len(attacks_succeeded) / len(attacks):.1f}%"
          f"  ({len(attacks_succeeded)}/{len(attacks)})")
    print(f"False-block rate (benign)      : {100 * len(benign_blocked) / len(benign):.1f}%"
          f"  ({len(benign_blocked)}/{len(benign)})")
    print(f"Avg guard latency              : {sum(r['ms'] for r in rows) / len(rows):.3f} ms per call")

    print("\nBy attack type (blocked / total):")
    by_kind = defaultdict(lambda: [0, 0])
    for r in attacks:
        by_kind[r["kind"]][1] += 1
        if not r["allowed"]:
            by_kind[r["kind"]][0] += 1
    for kind, (blocked, total) in by_kind.items():
        print(f"  {kind:26s} {blocked}/{total}")

    print("\nWhich check blocked the attacks:")
    by_check = defaultdict(int)
    for r in attacks:
        if not r["allowed"]:
            by_check[r["check"]] += 1
    for check, n in by_check.items():
        print(f"  {check:10s} {n}")

    print("\nMISSED attacks (guard allowed them):")
    for r in attacks_succeeded:
        print(f"  [{r['kind']}] {r['tool']} {r['args']}")

    print("\nFALSE BLOCKS (harmless calls blocked):")
    for r in benign_blocked:
        print(f"  [{r['kind']}] {r['tool']} {r['args']} -> {r['reason']}")

    with open("results.json", "w") as f:
        json.dump(rows, f, indent=2)
    print("\nSaved details to results.json")


if __name__ == "__main__":
    main()
