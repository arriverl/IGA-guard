#!/usr/bin/env python3
"""Refresh E3 recovery section using regression FN pool + online adaptive."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from run_adversarial_stability import _converged, _run_delayed_learn_recovery


def main() -> int:
    data = str(ROOT / "data" / "samples" / "obfuscated_dataset.csv")
    recovery = _run_delayed_learn_recovery(data_path=data, max_seeds=40, max_variants=200)
    print(json.dumps({
        "total": recovery.get("total"),
        "recovered": recovery.get("recovered"),
        "remaining_missed": recovery.get("remaining_missed"),
        "recovery_rate": recovery.get("recovery_rate"),
        "vacuous": recovery.get("vacuous"),
        "mode": recovery.get("mode"),
    }, ensure_ascii=False, indent=2))

    e3_path = ROOT / "results" / "v2_exp3_stability.json"
    e3 = json.loads(e3_path.read_text(encoding="utf-8"))
    recalls = [r["recall"] for r in e3["per_round"]]
    vacuous = bool(recovery.get("vacuous"))
    recovery_pass = (
        (not vacuous)
        and recovery.get("total", 0) > 0
        and recovery.get("recovery_rate", 0.0) >= 0.80
    )
    probe_pass = e3["probe"].get("recall", 0.0) >= 0.95
    adv = _converged(recalls, min_last=0.90, max_std=0.10, max_range=0.20, min_mean=0.90)
    e3["recovery"] = {**recovery, "pass": recovery_pass, "vacuous": vacuous}
    e3["convergence_proof"] = {
        "probe_stable": probe_pass,
        "adaptive_recovery": recovery_pass,
        "recovery_non_vacuous": not vacuous,
        "adversarial_drift_bounded": adv,
        "overall_converged": bool(probe_pass and recovery_pass and adv),
    }
    e3["converged"] = bool(probe_pass and recovery_pass and adv)
    e3_path.write_text(json.dumps(e3, indent=2, ensure_ascii=False), encoding="utf-8")

    drift_path = ROOT / "results" / "adversarial_drift_report.json"
    drift = json.loads(drift_path.read_text(encoding="utf-8")) if drift_path.exists() else {"e3": {}, "e9": None}
    drift.setdefault("e3", {})
    drift["e3"].update({
        "converged": e3["converged"],
        "recovery": e3["recovery"],
        "convergence_proof": e3["convergence_proof"],
    })
    e9 = drift.get("e9")
    drift["pass"] = bool(e3["converged"]) and (
        True if e9 is None else bool((e9 or {}).get("converged", True))
    )
    drift_path.write_text(json.dumps(drift, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"converged={e3['converged']} drift_pass={drift['pass']}")
    return 0 if e3["converged"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
