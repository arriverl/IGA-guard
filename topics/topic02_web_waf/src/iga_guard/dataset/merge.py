"""
数据集合并、去重与训练/测试划分
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

from iga_guard.dataset.fetchers import payload_hash


def dedupe_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """按 payload 内容去重，保留首次出现的 source。"""
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for row in rows:
        key = payload_hash(row.get("payload", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def write_csv(rows: list[dict[str, str]], path: Path, fieldnames: list[str] | None = None) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = fieldnames or ["payload", "label", "source"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def train_test_split(
    rows: list[dict[str, str]],
    test_ratio: float = 0.15,
    seed: int = 42,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """分层划分：按 label 分组后随机切分，保证各类别在测试集中有代表。"""
    rng = random.Random(seed)
    by_label: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_label.setdefault(row.get("label", "Normal"), []).append(row)

    train: list[dict[str, str]] = []
    test: list[dict[str, str]] = []

    for label, group in by_label.items():
        rng.shuffle(group)
        n_test = max(1, int(len(group) * test_ratio)) if label != "Normal" else int(len(group) * test_ratio)
        if label == "Normal":
            n_test = min(n_test, len(group) // 5)  # 正常样本测试集不超过 20%
        test.extend(group[:n_test])
        train.extend(group[n_test:])

    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


def merge_and_split(
    row_batches: list[list[dict[str, str]]],
    out_dir: Path,
    test_ratio: float = 0.15,
    seed: int = 42,
) -> dict[str, int]:
    """
    合并多批数据、去重、划分并写入 out_dir。

    产出：
      - full.csv
      - train.csv
      - test.csv
    """
    merged: list[dict[str, str]] = []
    for batch in row_batches:
        merged.extend(batch)
    merged = dedupe_rows(merged)
    train, test = train_test_split(merged, test_ratio=test_ratio, seed=seed)

    stats = {
        "full": write_csv(merged, out_dir / "full.csv"),
        "train": write_csv(train, out_dir / "train.csv"),
        "test": write_csv(test, out_dir / "test.csv"),
    }
    return stats
