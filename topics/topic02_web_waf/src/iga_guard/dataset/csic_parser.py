"""
CSIC 2010 数据集解析器
======================
支持：
  1. GSI 标注 TXT（Start - Id / class: Attack|Valid / HTTP 块）
  2. Peter Scully CSV（18 列）
  3. 经典三文件命名（normalTrafficTraining.txt 等）
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Iterator
from urllib.parse import unquote

from iga_guard.dataset.label_rules import infer_attack_label

# GSI 块格式：Start - Id: N ... End - Id: N
_GSI_BLOCK = re.compile(
    r"Start\s*-\s*Id:\s*\d+\s*\n(.*?)\nEnd\s*-\s*Id:\s*\d+",
    re.DOTALL | re.IGNORECASE,
)
_CLASS_LINE = re.compile(r"^class:\s*(Attack|Valid)\s*$", re.I | re.M)
_REQUEST_LINE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/",
    re.I | re.M,
)


def extract_payload_from_csv_row(row: dict[str, str]) -> str:
    """从 Scully CSV 单行提取最有信息量的载荷片段。"""
    candidates: list[str] = []

    for key in ("payload", "url", "cookie"):
        val = (row.get(key) or "").strip()
        if not val or val.lower() == "null":
            continue
        if key == "url":
            if "?" in val:
                qs = val.split("?", 1)[1]
                candidates.append(qs)
            candidates.append(val)
        elif "=" in val:
            parts = val.split("&") if "&" in val else [val]
            for part in parts:
                if "=" in part:
                    candidates.append(part.split("=", 1)[1])
                else:
                    candidates.append(part)
        else:
            candidates.append(val)

    if not candidates:
        return ""
    return max(candidates, key=len)


def iter_csic_csv(path: Path, max_rows: int | None = None) -> Iterator[dict[str, str]]:
    with path.open(encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if max_rows is not None and i >= max_rows:
                break
            payload = extract_payload_from_csv_row(row)
            if not payload or len(payload) < 2:
                continue
            raw = (row.get("label") or row.get("Label") or "norm").strip().lower()
            label = infer_attack_label(payload, raw)
            yield {
                "payload": payload[:2048],
                "label": label,
                "source": f"csic_csv:{path.name}",
            }


def _payloads_from_http_block(block: str, is_attack: bool) -> list[str]:
    """从 HTTP 文本块提取 URL query、POST body、Cookie 值。"""
    payloads: list[str] = []
    m = _REQUEST_LINE.search(block)
    if m:
        target = m.group(2)
        if "?" in target:
            payloads.append(unquote(target.split("?", 1)[1]))
        if "http://" in target.lower() or "https://" in target.lower():
            # GSI 格式：GET http://host/path?qs HTTP/1.1
            if "?" in target:
                payloads.append(unquote(target.split("?", 1)[1]))

    for line in block.splitlines():
        low = line.lower()
        if low.startswith("cookie:"):
            cookie_val = line.split(":", 1)[1].strip()
            for seg in cookie_val.split(";"):
                seg = seg.strip()
                if "=" in seg:
                    payloads.append(seg.split("=", 1)[1])
        if low.startswith("content-type:"):
            continue

    # POST body：最后一个空行之后
    if "\n\n" in block:
        body = block.split("\n\n", 1)[1].strip()
        if body and body.lower() != "null" and not body.startswith("HTTP/"):
            # 表单 key=value
            if "=" in body:
                for part in body.split("&"):
                    if "=" in part:
                        payloads.append(unquote(part.split("=", 1)[1]))
                    else:
                        payloads.append(part)
            else:
                payloads.append(body)

    if not payloads and m:
        payloads.append(m.group(2))

    raw = "anom" if is_attack else "norm"
    results: list[str] = []
    for p in payloads:
        p = p.strip()
        if len(p) >= 2:
            results.append(p[:2048])
    return results


def iter_csic_gsi_labeled(path: Path, max_requests: int | None = None) -> Iterator[dict[str, str]]:
    """
    解析 GSI 预处理版（Start/End 块 + class: Attack|Valid）。
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    count = 0

    for m in _GSI_BLOCK.finditer(text):
        if max_requests is not None and count >= max_requests:
            break
        block = m.group(1)
        cls = _CLASS_LINE.search(block)
        is_attack = cls is not None and cls.group(1).lower() == "attack"

        for payload in _payloads_from_http_block(block, is_attack):
            raw = "anom" if is_attack else "norm"
            label = infer_attack_label(payload, raw)
            count += 1
            yield {
                "payload": payload,
                "label": label,
                "source": f"csic_gsi:{path.name}",
            }


def iter_csic_txt(path: Path, is_attack_file: bool, max_requests: int | None = None) -> Iterator[dict[str, str]]:
    """自动选择 GSI 块格式或经典空行分隔 HTTP。"""
    head = path.read_text(encoding="utf-8", errors="replace")[:500]
    if "Start - Id:" in head or "class: Attack" in head or "class: Valid" in head:
        yield from iter_csic_gsi_labeled(path, max_requests)
        return

    # 经典格式回退
    import re as _re
    blocks = [b for b in _re.split(r"\n\s*\n", path.read_text(encoding="utf-8", errors="replace")) if b.strip()]
    count = 0
    for block in blocks:
        if max_requests is not None and count >= max_requests:
            break
        for payload in _payloads_from_http_block(block, is_attack_file):
            label = infer_attack_label(payload, "anom" if is_attack_file else "norm")
            count += 1
            yield {"payload": payload, "label": label, "source": f"csic_txt:{path.name}"}


def detect_csic_format(path: Path) -> str:
    if path.suffix.lower() == ".csv":
        return "csv"
    return "txt"


def iter_csic_file(path: Path, max_rows: int | None = None, is_attack: bool | None = None) -> Iterator[dict[str, str]]:
    fmt = detect_csic_format(path)
    if fmt == "csv":
        yield from iter_csic_csv(path, max_rows)
    else:
        attack = is_attack if is_attack is not None else (
            "anomalous" in path.name.lower() or "anom" in path.name.lower()
        )
        yield from iter_csic_txt(path, is_attack_file=attack, max_requests=max_rows)
