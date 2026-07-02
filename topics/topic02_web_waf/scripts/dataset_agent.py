#!/usr/bin/env python3
"""
Agent 4 · 数据集采集与扩充代理
==============================
专职从公开源拉取真实 Web 攻击载荷、解析 CSIC2010、应用文献级混淆手法，
产出可供 train.py / train_bert.py / evaluate.py 使用的完整 master 数据集。

用法：
  python scripts/dataset_agent.py                    # 全流程（拉取+合并+混淆）
  python scripts/dataset_agent.py --fetch-only       # 仅拉取
  python scripts/dataset_agent.py --skip-csic        # 跳过 CSIC（无网络时）
  python scripts/dataset_agent.py --max-rows 50000   # 限制 CSIC 行数
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.dataset.csic_parser import iter_csic_file
from iga_guard.dataset.community_fetcher import collect_community_rows as _fetch_community_rows
from iga_guard.dataset.fetchers import fetch_all_public, iter_all_public
from iga_guard.dataset.merge import merge_and_split, write_csv
from iga_guard.dataset.obfuscation_techniques import expand_dataset_rows

RAW_DIR = ROOT / "data" / "raw"
CSIC_DIR = RAW_DIR / "csic"
PUBLIC_DIR = RAW_DIR / "public"
COMMUNITY_DIR = RAW_DIR / "community"
MASTER_DIR = ROOT / "data" / "master"
SAMPLES_DIR = ROOT / "data" / "samples"


def download_csic(force: bool = False) -> bool:
    """调用 download_csic.py 拉取 GSI CSIC 数据集。"""
    script = ROOT / "scripts" / "download_csic.py"
    cmd = [sys.executable, str(script), "--source", "gsi"]
    if force:
        cmd.append("--force")
    print("[Agent4] 下载 CSIC 2010 ...")
    r = subprocess.run(cmd, cwd=ROOT)
    return r.returncode == 0


def collect_csic_rows(max_rows_per_file: int | None) -> list[dict[str, str]]:
    """从 data/raw/csic/ 收集全部 TXT/CSV。"""
    rows: list[dict[str, str]] = []
    if not CSIC_DIR.exists():
        print(f"  [跳过] CSIC 目录不存在: {CSIC_DIR}")
        return rows

    patterns = ["*.txt", "*.csv"]
    files: list[Path] = []
    for pat in patterns:
        files.extend(CSIC_DIR.glob(pat))
    files = sorted(set(files))

    if not files:
        print(f"  [警告] CSIC 目录无数据文件，请先运行 download_csic.py")
        return rows

    per_file = None
    if max_rows_per_file:
        per_file = max_rows_per_file // max(len(files), 1)

    for f in sorted(files):
        print(f"  [解析] {f.name} ...")
        count = 0
        for row in iter_csic_file(f, max_rows=per_file):
            rows.append(row)
            count += 1
        print(f"    -> {count} 条")

    return rows


def collect_public_rows() -> list[dict[str, str]]:
    rows = list(iter_all_public(PUBLIC_DIR))
    print(f"[Agent4] 公开载荷库缓存: {len(rows)} 条")
    return rows


def collect_community_rows(fetch_articles: bool = True) -> list[dict[str, str]]:
    """社区种子载荷 + 可选拉取文章正文。"""
    return _fetch_community_rows(COMMUNITY_DIR, fetch_articles=fetch_articles)


def collect_seed_rows() -> list[dict[str, str]]:
    """保留项目手工冒烟种子集。"""
    import csv

    seed = SAMPLES_DIR / "labeled_samples.csv"
    if not seed.exists():
        return []
    rows: list[dict[str, str]] = []
    with seed.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "payload": row["payload"],
                "label": row["label"],
                "source": "seed:labeled_samples",
            })
    return rows


def run_agent(args: argparse.Namespace) -> int:
    print("=" * 60)
    print(" IGA-Guard Agent 4 · 真实数据集采集代理")
    print("=" * 60)

    # --- 1. 拉取 ---
    if not args.skip_fetch:
        fetch_all_public(PUBLIC_DIR, force=args.force)

    community_rows: list[dict[str, str]] = []
    if not args.skip_community:
        fetch_articles = not (args.skip_community_fetch or args.skip_fetch)
        community_rows = collect_community_rows(fetch_articles=fetch_articles)

    if not args.skip_csic:
        if not args.skip_csic_download:
            download_csic(force=args.force)
        csic_rows = collect_csic_rows(args.max_rows)
    else:
        csic_rows = []

    if args.fetch_only:
        print("[Agent4] --fetch-only 模式结束")
        return 0

    # --- 2. 合并基线 ---
    public_rows = collect_public_rows()
    seed_rows = collect_seed_rows()
    batches = [seed_rows, community_rows, public_rows, csic_rows]
    total_raw = sum(len(b) for b in batches)
    print(
        f"[Agent4] 原始合计: {total_raw} 条 "
        f"(seed={len(seed_rows)}, community={len(community_rows)}, "
        f"public={len(public_rows)}, csic={len(csic_rows)})"
    )

    if total_raw == 0:
        print("[错误] 无任何数据，请检查网络或手动放置 CSIC 到 data/raw/csic/", file=sys.stderr)
        return 1

    stats = merge_and_split(batches, MASTER_DIR, test_ratio=args.test_ratio, seed=args.seed)
    print(f"[Agent4] 去重合并: full={stats['full']}, train={stats['train']}, test={stats['test']}")

    # --- 3. 混淆扩充（仅攻击样本）---
    import csv

    full_path = MASTER_DIR / "full.csv"
    with full_path.open(encoding="utf-8", newline="") as f:
        base_rows = list(csv.DictReader(f))

    obf_rows = expand_dataset_rows(
        base_rows,
        variants_per_attack=args.obf_variants,
        seed=args.seed,
        max_total=args.max_obfuscated,
    )
    obf_path = MASTER_DIR / "full_obfuscated.csv"
    n_obf = write_csv(obf_rows, obf_path)
    print(f"[Agent4] 混淆扩充: {n_obf} 条 -> {obf_path}")

    # 混淆集也做 train/test 划分（供 BERT）
    from iga_guard.dataset.merge import train_test_split

    obf_train, obf_test = train_test_split(obf_rows, test_ratio=args.test_ratio, seed=args.seed)
    write_csv(obf_train, MASTER_DIR / "train_obfuscated.csv")
    write_csv(obf_test, MASTER_DIR / "test_obfuscated.csv")
    print(f"[Agent4] 混淆划分: train={len(obf_train)}, test={len(obf_test)}")

    # 同步到 samples 供现有脚本默认路径
    write_csv(obf_train, SAMPLES_DIR / "master_train.csv")
    write_csv(obf_test, SAMPLES_DIR / "master_test.csv")

    print("\n[完成] 下一步:")
    print("  python scripts/iga_system.py pipeline")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Agent 4 数据集采集与扩充")
    p.add_argument("--fetch-only", action="store_true", help="仅拉取公开源与 CSIC")
    p.add_argument("--skip-csic", action="store_true", help="跳过 CSIC 解析")
    p.add_argument("--skip-csic-download", action="store_true", help="不下载 CSIC，仅解析本地")
    p.add_argument("--skip-fetch", action="store_true", help="不拉取，仅用本地缓存")
    p.add_argument(
        "--skip-community-fetch",
        action="store_true",
        help="不拉取社区文章，仅用 data/raw/community/payloads_seed.txt",
    )
    p.add_argument("--skip-community", action="store_true", help="跳过社区种子")
    p.add_argument("--force", action="store_true", help="强制重新下载")
    p.add_argument("--max-rows", type=int, default=80000, help="CSIC 总行数上限")
    p.add_argument("--max-obfuscated", type=int, default=150000, help="混淆扩充后总行数上限")
    p.add_argument("--obf-variants", type=int, default=4, help="每条攻击样本混淆变体数")
    p.add_argument("--test-ratio", type=float, default=0.15)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main() -> int:
    return run_agent(parse_args())


if __name__ == "__main__":
    sys.exit(main())
