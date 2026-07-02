#!/usr/bin/env python3
"""
IGA-Guard 3.0 统一系统入口
==========================
检测 + 混淆 + 数据集 + 训练 + 评估 + 服务 一体化 CLI。

用法：
  python scripts/iga_system.py status          # 系统状态
  python scripts/iga_system.py train           # 训练 RF + TinyBERT
  python scripts/iga_system.py evaluate        # 评估
  python scripts/iga_system.py adversarial     # 对抗演化
  python scripts/iga_system.py serve           # 启动 Web
  python scripts/iga_system.py obfuscate -p "1 union select 1" -t SQLi -n 10
  python scripts/iga_system.py pipeline        # 全流程（训练+评估+对抗）
  python scripts/iga_system.py expand-cache    # 漏检→缓存
  python scripts/iga_system.py evolve-obf      # 漏检→诚实重训
  python scripts/iga_system.py experiments     # E2/E5/E7/E8 实验套件
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _run(cmd: list[str], desc: str) -> int:
    print(f"\n{'='*50}\n>>> {desc}\n    {' '.join(cmd)}\n{'='*50}")
    return subprocess.call(cmd, cwd=ROOT)


def cmd_status(_: argparse.Namespace) -> int:
    import os

    master = ROOT / "data" / "master"
    rows = {}
    for name in ("full_obfuscated.csv", "train_obfuscated.csv", "test_obfuscated.csv"):
        p = master / name
        if p.exists():
            rows[name] = sum(1 for _ in open(p, encoding="utf-8")) - 1

    status = {
        "version": "3.0.0",
        "dataset": rows,
        "models": {
            "fusion_rf": (ROOT / "models" / "fusion_detector.joblib").exists(),
            "tinybert": (ROOT / "models" / "tinybert_waf" / "config.json").exists(),
            "continual_cache": (ROOT / "models" / "continual_cache.npz").exists(),
        },
        "config": str(ROOT / "configs" / "default.yaml"),
    }
    results = ROOT / "results" / "v2_exp1_overall.json"
    if results.exists():
        status["latest_eval"] = json.loads(results.read_text(encoding="utf-8"))
    print(json.dumps(status, indent=2, ensure_ascii=False))
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    py = sys.executable
    data = args.data or str(ROOT / "data" / "master" / "train_obfuscated.csv")
    rc = _run([py, "scripts/train.py", "--data", data], "训练 Fusion RF")
    if rc != 0:
        return rc
    if not args.skip_bert:
        return _run([
            py, "scripts/train_bert.py", "--data", data,
            "--epochs", str(args.epochs),
            *(["--max-samples", str(args.bert_samples)] if args.bert_samples > 0 else []),
        ], "微调 TinyBERT")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    py = sys.executable
    data = args.data or str(ROOT / "data" / "master" / "test_obfuscated.csv")
    cmd = [py, "scripts/evaluate.py", "--data", data]
    if args.max_samples and args.max_samples > 0:
        cmd += ["--max-samples", str(args.max_samples)]
    return _run(cmd, "检测评估")


def cmd_adversarial(args: argparse.Namespace) -> int:
    py = sys.executable
    data = args.data or str(ROOT / "data" / "master" / "test.csv")
    cmd = [
        py, "scripts/run_adversarial.py",
        "--rounds", str(args.rounds), "--data", data,
        "--max-seeds", str(args.max_seeds),
        "--max-variants", str(args.max_variants),
    ]
    return _run(cmd, f"对抗演化 {args.rounds} 轮")


def cmd_serve(args: argparse.Namespace) -> int:
    py = sys.executable
    print(f"\n>>> Web 大屏: http://127.0.0.1:{args.port}/")
    return subprocess.call([py, "run.py"], cwd=ROOT)


def cmd_obfuscate(args: argparse.Namespace) -> int:
    from iga_guard.dataset.obfuscation_techniques import expand_payload
    from iga_guard.adversarial.mutator import mutate_batch
    from iga_guard.adversarial.ast_mutator import ast_obfuscate_batch

    payload, label = args.payload, args.attack_type
    out: list[dict] = [{"payload": payload, "label": label, "source": "original"}]

    for v in mutate_batch(payload, label, n=args.count):
        out.append({"payload": v, "label": label, "source": "mutator"})
    for v in ast_obfuscate_batch(payload, n=args.count):
        out.append({"payload": v, "label": label, "source": "ast"})
    for item in expand_payload(payload, label, n=args.count, seed=42):
        out.append(item)

    seen = set()
    unique = []
    for row in out:
        if row["payload"] not in seen:
            seen.add(row["payload"])
            unique.append(row)

    if args.json:
        print(json.dumps(unique[: args.count + 1], indent=2, ensure_ascii=False))
    else:
        for row in unique[: args.count + 1]:
            print(f"[{row['source']}] {row['payload'][:120]}")
    return 0


def cmd_dataset(args: argparse.Namespace) -> int:
    py = sys.executable
    cmd = [py, "scripts/dataset_agent.py", "--skip-csic-download", "--skip-fetch"]
    if args.skip_community_fetch:
        cmd.append("--skip-community-fetch")
    cmd += ["--max-obfuscated", str(args.max_obfuscated), "--obf-variants", str(args.variants)]
    return _run(cmd, "重建 master 数据集")


def cmd_build_cache(args: argparse.Namespace) -> int:
    py = sys.executable
    cmd = [py, "scripts/build_cache.py", "--per-class", str(args.per_class)]
    if args.data:
        cmd += ["--data", args.data]
    return _run(cmd, "构建持续学习 KV 缓存")


def cmd_expand_cache(args: argparse.Namespace) -> int:
    py = sys.executable
    cmd = [py, "scripts/expand_cache_from_misses.py", "--max-rows", str(args.max_rows)]
    if args.misses:
        cmd += ["--misses", args.misses]
    return _run(cmd, "漏检样本扩持续学习缓存")


def cmd_evolve_obf(args: argparse.Namespace) -> int:
    py = sys.executable
    cmd = [
        py, "scripts/evolve_from_obf_misses.py",
        "--max-rows", str(args.max_rows),
        "--min-samples", str(args.min_samples),
    ]
    return _run(cmd, "漏检诚实增量重训 RF")


def cmd_augment_v3(args: argparse.Namespace) -> int:
    py = sys.executable
    cmd = [
        py, "scripts/augment_v3_techniques.py",
        "--max-attack-rows", str(args.max_attack_rows),
        "--variants", str(args.variants),
    ]
    if args.data:
        cmd += ["--data", args.data]
    if args.output:
        cmd += ["--output", args.output]
    return _run(cmd, "v3.1 混淆技术扩库")


def cmd_retrain_v3(args: argparse.Namespace) -> int:
    """v3.1 流程：扩库 → RF 重训 → 评估。"""
    if cmd_augment_v3(args) != 0:
        return 1
    train_data = args.output or str(ROOT / "data" / "master" / "train_obfuscated_v31.csv")
    py = sys.executable
    if _run([py, "scripts/train.py", "--data", train_data], "RF 重训（v3.1 扩库）") != 0:
        return 1
    return cmd_evaluate(args)


def cmd_experiments(args: argparse.Namespace) -> int:
    py = sys.executable
    cmd = [py, "scripts/run_experiments_suite.py", "--experiments", args.experiments]
    if args.max_samples:
        cmd += ["--max-samples", str(args.max_samples)]
    if args.rl_events:
        cmd += ["--rl-events", str(args.rl_events)]
    if args.train_data:
        cmd += ["--train-data", args.train_data]
    if args.test_data:
        cmd += ["--test-data", args.test_data]
    if args.misses:
        cmd += ["--misses", args.misses]
    return _run(cmd, f"实验套件 ({args.experiments})")


def cmd_compare_multimodal(args: argparse.Namespace) -> int:
    py = sys.executable
    cmd = [py, "scripts/compare_multimodal_full.py"]
    if args.data:
        cmd += ["--data", args.data]
    if args.output:
        cmd += ["--output", args.output]
    return _run(cmd, "全量多模态对比评估")


def cmd_pipeline(args: argparse.Namespace) -> int:
    if cmd_dataset(args) != 0:
        return 1
    if cmd_train(args) != 0:
        return 1
    if cmd_evaluate(args) != 0:
        return 1
    if not args.skip_adversarial:
        if cmd_adversarial(args) != 0:
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="IGA-Guard 3.0 统一系统")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="系统状态").set_defaults(func=cmd_status)

    p_train = sub.add_parser("train", help="训练模型")
    p_train.add_argument("--data", default=None)
    p_train.add_argument("--skip-bert", action="store_true")
    p_train.add_argument("--epochs", type=int, default=5)
    p_train.add_argument("--bert-samples", type=int, default=0, help="0=全量训练")
    p_train.set_defaults(func=cmd_train)

    p_eval = sub.add_parser("evaluate", help="评估")
    p_eval.add_argument("--data", default=None)
    p_eval.add_argument("--max-samples", type=int, default=0, help="0=全量")
    p_eval.set_defaults(func=cmd_evaluate)

    p_adv = sub.add_parser("adversarial", help="对抗演化")
    p_adv.add_argument("--data", default=None)
    p_adv.add_argument("--rounds", type=int, default=3)
    p_adv.add_argument("--max-seeds", type=int, default=150)
    p_adv.add_argument("--max-variants", type=int, default=3000)
    p_adv.set_defaults(func=cmd_adversarial)

    p_srv = sub.add_parser("serve", help="启动 Web")
    p_srv.add_argument("--port", type=int, default=5000)
    p_srv.set_defaults(func=cmd_serve)

    p_obf = sub.add_parser("obfuscate", help="生成混淆变种")
    p_obf.add_argument("-p", "--payload", required=True)
    p_obf.add_argument("-t", "--attack-type", default="SQLi")
    p_obf.add_argument("-n", "--count", type=int, default=10)
    p_obf.add_argument("--json", action="store_true")
    p_obf.set_defaults(func=cmd_obfuscate)

    p_ds = sub.add_parser("dataset", help="重建数据集")
    p_ds.add_argument("--max-obfuscated", type=int, default=150000)
    p_ds.add_argument("--variants", type=int, default=4)
    p_ds.add_argument("--skip-community-fetch", action="store_true", default=True)
    p_ds.set_defaults(func=cmd_dataset)

    p_cache = sub.add_parser("build-cache", help="Stage-1 构建持续学习 KV 缓存")
    p_cache.add_argument("--data", default=None)
    p_cache.add_argument("--per-class", type=int, default=30)
    p_cache.set_defaults(func=cmd_build_cache)

    p_ec = sub.add_parser("expand-cache", help="漏检样本写入持续学习缓存")
    p_ec.add_argument("--misses", default=None)
    p_ec.add_argument("--max-rows", type=int, default=500)
    p_ec.set_defaults(func=cmd_expand_cache)

    p_evo = sub.add_parser("evolve-obf", help="漏检样本诚实增量重训")
    p_evo.add_argument("--max-rows", type=int, default=400)
    p_evo.add_argument("--min-samples", type=int, default=50)
    p_evo.set_defaults(func=cmd_evolve_obf)

    p_exp = sub.add_parser("experiments", help="运行 E2/E5/E7/E8 实验")
    p_exp.add_argument("--experiments", default="all", help="e2,e5,e7,e8 或 all")
    p_exp.add_argument("--train-data", default=None)
    p_exp.add_argument("--test-data", default=None)
    p_exp.add_argument("--misses", default=None)
    p_exp.add_argument("--max-samples", type=int, default=3000)
    p_exp.add_argument("--rl-events", type=int, default=50)
    p_exp.set_defaults(func=cmd_experiments)

    p_cmp = sub.add_parser("compare-multimodal", help="全量多模态开/关对比")
    p_cmp.add_argument("--data", default=None)
    p_cmp.add_argument("--output", default=None)
    p_cmp.set_defaults(func=cmd_compare_multimodal)

    p_aug = sub.add_parser("augment-v3", help="v3.1 新混淆技术扩训练集")
    p_aug.add_argument("--data", default=None)
    p_aug.add_argument("--output", default=None)
    p_aug.add_argument("--max-attack-rows", type=int, default=25000)
    p_aug.add_argument("--variants", type=int, default=2)
    p_aug.set_defaults(func=cmd_augment_v3)

    p_rt = sub.add_parser("retrain-v3", help="v3.1 扩库+RF重训+评估")
    p_rt.add_argument("--data", default=None)
    p_rt.add_argument("--output", default=None)
    p_rt.add_argument("--max-attack-rows", type=int, default=25000)
    p_rt.add_argument("--variants", type=int, default=2)
    p_rt.add_argument("--max-samples", type=int, default=0)
    p_rt.set_defaults(func=cmd_retrain_v3)

    p_pipe = sub.add_parser("pipeline", help="全流程")
    p_pipe.add_argument("--skip-bert", action="store_true")
    p_pipe.add_argument("--skip-adversarial", action="store_true")
    p_pipe.add_argument("--max-samples", type=int, default=5000)
    p_pipe.add_argument("--max-obfuscated", type=int, default=150000)
    p_pipe.add_argument("--variants", type=int, default=4)
    p_pipe.add_argument("--skip-community-fetch", action="store_true", default=True)
    p_pipe.add_argument("--epochs", type=int, default=2)
    p_pipe.add_argument("--bert-samples", type=int, default=40000)
    p_pipe.add_argument("--rounds", type=int, default=3)
    p_pipe.set_defaults(func=cmd_pipeline)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
