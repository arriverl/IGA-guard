#!/usr/bin/env python3
"""演示阈值策略包（threshold PolicyBundle）在 canary 流量下的学习与审计导出。

说明：本演示覆盖 stable/canary/shadow 阈值与 policy_id/snapshot_id；
规则 / cache / model 不在线打包，属离线演化产物。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.evolution.online_adaptive import OnlineAdaptiveController
from iga_guard.pipeline import IgaGuardEngine, load_config


def main() -> int:
    cfg = load_config(ROOT / "configs" / "default.yaml")
    engine = IgaGuardEngine(cfg)
    state_path = ROOT / "data" / "cache" / "online_adaptive_demo_state.json"
    ctl = OnlineAdaptiveController(
        str(state_path),
        canary_pct=100,
        promote_min_episodes=12,
        promote_min_avg_reward=0.1,
        rollback_window=8,
    )
    det = engine.detector
    traffic_key = "demo-canary-client"
    samples = [
        ("1' OR 1=1--", "SQLi"),
        ("<script>alert(1)</script>", "XSS"),
        (";cat /etc/passwd", "CMD"),
        ("1 union select 1,2--", "SQLi"),
        ("../../../etc/passwd", "PathTraversal"),
    ]

    events = []
    for i in range(20):
        payload, true_label = samples[i % len(samples)]
        policy = ctl.policy_for_request(det, traffic_key)
        report = engine.analyze_url("GET", f"http://demo.local/t?p={payload}", explain=False)
        pred = report.detection.label
        fb = ctl.feedback(det, pred, true_label, traffic_key=traffic_key, lr=0.06)
        events.append({
            "i": i,
            "pred": pred,
            "true": true_label,
            "policy": policy,
            "feedback": {
                "applied": fb.get("applied"),
                "promoted": fb.get("promoted"),
                "rolled_back": fb.get("rolled_back"),
                "reward": fb.get("reward"),
            },
        })

    audit = ctl.export_audit(ROOT / "results" / "online_adaptive_audit.json")
    out = {
        "events_tail": events[-5:],
        "status": ctl.status(),
        "audit_file": "results/online_adaptive_audit.json",
        "policy_kind": audit.get("policy_kind"),
        "covers": audit.get("covers"),
        "does_not_cover": audit.get("does_not_cover"),
    }
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
