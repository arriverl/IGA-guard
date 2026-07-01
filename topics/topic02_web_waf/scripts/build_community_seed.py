#!/usr/bin/env python3
"""
从已缓存的真实数据源构建 community/payloads_seed.txt
（SecLists、CSIC 攻击流量抽样，非随机生成）
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iga_guard.dataset.csic_parser import iter_csic_file
from iga_guard.dataset.label_rules import infer_attack_label

OUT = ROOT / "data" / "raw" / "community" / "payloads_seed.txt"
RAW = ROOT / "data" / "raw"


def sample_txt(path: Path, n: int, source: str, rng: random.Random) -> list[str]:
    if not path.exists():
        return []
    lines = [
        ln.strip()
        for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if ln.strip() and not ln.strip().startswith("#") and 3 < len(ln.strip()) < 500
    ]
    rng.shuffle(lines)
    picked = lines[:n]
    return [f"# source: {source}"] + picked


def sample_csic(n: int, rng: random.Random) -> list[str]:
    csic = RAW / "csic" / "cisc_anomalousTraffic_test.txt"
    if not csic.exists():
        return []
    rows = []
    for row in iter_csic_file(csic, max_rows=n * 3):
        if row["label"] != "Normal":
            rows.append(row["payload"])
    rng.shuffle(rows)
    return [f"# source: csic_anomalous_sample"] + rows[:n]


def main() -> int:
    rng = random.Random(42)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    chunks: list[str] = [
        "# IGA-Guard community payloads seed",
        "# Auto-built from cached SecLists / FuzzDB / CSIC (real data only)",
        "",
    ]

    chunks.extend(sample_txt(RAW / "public" / "seclists" / "seclists_cmd.txt", 80, "seclists_cmd", rng))
    chunks.append("")
    chunks.extend(sample_txt(RAW / "public" / "fuzzdb" / "fuzzdb_xss.txt", 40, "fuzzdb_xss", rng))
    chunks.append("")
    chunks.extend(sample_csic(120, rng))

    # 项目已有标注种子
    seed_csv = ROOT / "data" / "samples" / "labeled_samples.csv"
    if seed_csv.exists():
        import csv
        chunks.append("# source: labeled_samples.csv")
        with seed_csv.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                if row.get("label", "Normal") != "Normal":
                    chunks.append(row["payload"])

    OUT.write_text("\n".join(chunks) + "\n", encoding="utf-8")
    count = sum(1 for ln in chunks if ln and not ln.startswith("#"))
    print(f"Wrote {count} payloads -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
