#!/usr/bin/env python3
"""
完整系统流水线：数据集 → 训练 → 评估 → 启用语义轨
==================================================
非 demo：使用 Agent4 产出的真实 master 数据集，训练 RF + TinyBERT，全量评估。

用法：
  python scripts/run_full_pipeline.py
  python scripts/run_full_pipeline.py --skip-dataset   # 已有 master 数据时
  python scripts/run_full_pipeline.py --skip-bert      # 跳过 TinyBERT（耗时）
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

MASTER = ROOT / "data" / "master"
CONFIG = ROOT / "configs" / "default.yaml"
BERT_OUT = ROOT / "models" / "tinybert_waf"


def run(cmd: list[str], desc: str) -> bool:
    print(f"\n{'='*50}\n[流水线] {desc}\n  {' '.join(cmd)}\n{'='*50}")
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        print(f"[失败] {desc} (exit {r.returncode})", file=sys.stderr)
    return r.returncode == 0


def enable_semantic_branch() -> None:
    """训练完成后将 use_semantic_branch 设为 true。"""
    if not (BERT_OUT / "config.json").exists():
        print("[跳过] TinyBERT 权重不存在，保持 use_semantic_branch: false")
        return
    text = CONFIG.read_text(encoding="utf-8")
    if "use_semantic_branch: false" in text:
        text = text.replace("use_semantic_branch: false", "use_semantic_branch: true")
        CONFIG.write_text(text, encoding="utf-8")
        print(f"[配置] 已启用 use_semantic_branch: true -> {CONFIG}")
    elif "use_semantic_branch: true" not in text:
        print("[提示] 请手动在 configs/default.yaml 设置 use_semantic_branch: true")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-dataset", action="store_true")
    parser.add_argument("--skip-bert", action="store_true")
    parser.add_argument("--bert-epochs", type=int, default=2)
    args = parser.parse_args()

    py = sys.executable

    # 1. 数据集
    if not args.skip_dataset:
        if not run([py, "scripts/dataset_agent.py"], "Agent4 数据集采集与扩充"):
            return 1

    train_csv = MASTER / "train_obfuscated.csv"
    test_csv = MASTER / "test_obfuscated.csv"
    if not train_csv.exists():
        train_csv = MASTER / "train.csv"
        test_csv = MASTER / "test.csv"
    if not train_csv.exists():
        print("[错误] 未找到 master 训练集，请先运行 dataset_agent.py", file=sys.stderr)
        return 1

    # 2. RF 融合模型
    if not run(
        [py, "scripts/train.py", "--data", str(train_csv)],
        "训练 Fusion RF 模型",
    ):
        return 1

    # 3. TinyBERT
    if not args.skip_bert:
        if not run(
            [py, "scripts/train_bert.py", "--data", str(train_csv),
             "--epochs", str(args.bert_epochs)],
            "微调 TinyBERT 语义轨",
        ):
            print("[警告] TinyBERT 训练失败，继续使用关键词回退", file=sys.stderr)
        else:
            enable_semantic_branch()

    # 4. 评估
    run([py, "scripts/evaluate.py", "--data", str(test_csv)], "E1 全量检测评估")
    run([py, "scripts/eval_explainability.py"], "E6 可解释性评估")
    run([py, "scripts/benchmark_latency.py", "--iterations", "500", "--warmup", "50"], "E4 延迟基准")

    # 5. 对抗演化（真实数据子集）
    adv_data = MASTER / "test.csv"
    if adv_data.exists():
        run(
            [py, "scripts/run_adversarial.py", "--rounds", "3",
             "--data", str(adv_data)],
            "E3 对抗演化（3 轮）",
        )

    # 汇总
    summary = {
        "train_samples": sum(1 for _ in open(train_csv, encoding="utf-8")) - 1,
        "test_samples": sum(1 for _ in open(test_csv, encoding="utf-8")) - 1,
        "fusion_model": str(ROOT / "models" / "fusion_detector.joblib"),
        "tinybert": str(BERT_OUT),
        "semantic_enabled": (BERT_OUT / "config.json").exists(),
    }
    out = ROOT / "results" / "full_pipeline_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[完成] 流水线摘要 -> {out}")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
