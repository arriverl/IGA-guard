"""
公开载荷库拉取器（Real Payload Fetchers）
=========================================
从 GitHub 等公开仓库拉取真实攻击载荷，非模拟数据。

数据源：
  - SecLists（danielmiessler/SecLists）— SQLi / XSS / LFI / CMD
  - FuzzDB（fuzzdb-project/fuzzdb）— 快速 SQLi 字典
  - PayloadsAllTheThings（swisskyrepo）— Intrusion 目录 TXT
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Iterator
from urllib.error import URLError
from urllib.request import Request, urlopen

from iga_guard.dataset.label_rules import infer_attack_label

# 稳定直链；mirrors 为 jsDelivr CDN 回退（国内网络更稳定）
PUBLIC_SOURCES: list[dict[str, str]] = [
    {
        "name": "seclists_sqli_generic",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Fuzzing/SQLi/Generic-SQLi.txt",
        "default_label": "SQLi",
        "subdir": "seclists",
    },
    {
        "name": "seclists_sqli_blind",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-BlindSQLi.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Fuzzing/SQLi/Generic-BlindSQLi.txt",
        "default_label": "SQLi",
        "subdir": "seclists",
    },
    {
        "name": "seclists_xss_jhaddix",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Fuzzing/XSS/XSS-Jhaddix.txt",
        "default_label": "XSS",
        "subdir": "seclists",
    },
    {
        "name": "seclists_xss_polyglot",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Polyglots.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Fuzzing/XSS/XSS-Polyglots.txt",
        "default_label": "XSS",
        "subdir": "seclists",
    },
    {
        "name": "seclists_lfi",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Fuzzing/LFI/LFI.txt",
        "default_label": "PathTraversal",
        "subdir": "seclists",
    },
    {
        "name": "seclists_cmd",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/danielmiessler/SecLists@master/Fuzzing/command-injection-commix.txt",
        "default_label": "CMD",
        "subdir": "seclists",
    },
    {
        "name": "fuzzdb_sqli_quick",
        "url": "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-inject/quick-sqli.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/fuzzdb-project/fuzzdb@master/attack/sql-inject/quick-sqli.txt",
        "default_label": "SQLi",
        "subdir": "fuzzdb",
    },
    {
        "name": "fuzzdb_xss",
        "url": "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/xss/xss-rsnake.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/fuzzdb-project/fuzzdb@master/attack/xss/xss-rsnake.txt",
        "default_label": "XSS",
        "subdir": "fuzzdb",
    },
    {
        "name": "pat_sqli_intrusion",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intrusion/Generic-SQLi.txt",
        "mirror": "https://cdn.jsdelivr.net/gh/swisskyrepo/PayloadsAllTheThings@master/SQL%20Injection/Intrusion/Generic-SQLi.txt",
        "default_label": "SQLi",
        "subdir": "payloads_all_the_things",
    },
]

_COMMENT_LINE = re.compile(r"^\s*#")
_MD_CODE_BLOCK = re.compile(r"```[\w]*\n(.*?)```", re.DOTALL)


def _http_get(url: str, timeout: int = 90) -> str:
    """带 User-Agent 的 HTTP GET；优先 requests，回退 urllib。"""
    headers = {"User-Agent": "IGA-Guard-DatasetAgent/2.0"}
    try:
        import requests
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")


def _parse_payload_lines(text: str, parse_md: bool = False) -> list[str]:
    """从 TXT 或 Markdown 提取载荷行。"""
    lines: list[str] = []

    if parse_md:
        for block in _MD_CODE_BLOCK.findall(text):
            for line in block.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
        # 也抓取反引号内联
        for m in re.finditer(r"`([^`\n]{4,256})`", text):
            lines.append(m.group(1).strip())
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or _COMMENT_LINE.match(line):
                continue
            if line.startswith("//") or line.lower().startswith("note:"):
                continue
            lines.append(line)

    return lines


def fetch_source(
    spec: dict[str, str],
    cache_dir: Path,
    force: bool = False,
) -> Path | None:
    """下载单个数据源；主 URL 失败时尝试 jsDelivr mirror。"""
    sub = cache_dir / spec.get("subdir", "misc")
    sub.mkdir(parents=True, exist_ok=True)
    fname = spec["name"] + ".txt"
    dest = sub / fname

    if dest.exists() and not force and dest.stat().st_size > 100:
        return dest

    urls = [spec["url"]]
    if spec.get("mirror"):
        urls.append(spec["mirror"])

    print(f"  [拉取] {spec['name']} ...")
    last_err = ""
    for url in urls:
        try:
            text = _http_get(url)
            if len(text) < 50:
                raise RuntimeError("响应过短")
            dest.write_text(text, encoding="utf-8")
            print(f"    -> {dest} ({len(text)} bytes)")
            time.sleep(0.2)
            return dest
        except (URLError, OSError, TimeoutError, RuntimeError) as exc:
            last_err = str(exc)
            print(f"    [重试] {exc}")

    print(f"    [失败] {spec['name']}: {last_err}")
    return None


def iter_fetched_file(
    path: Path,
    source_name: str,
    default_label: str,
    parse_md: bool = False,
) -> Iterator[dict[str, str]]:
    """迭代单个已下载文件中的载荷。"""
    if not path.exists():
        return

    text = path.read_text(encoding="utf-8", errors="replace")
    for line in _parse_payload_lines(text, parse_md=parse_md):
        if len(line) < 3 or len(line) > 4096:
            continue
        label = infer_attack_label(line, default_label if default_label != "SQLi" else None)
        if label == "Normal" and default_label != "Normal":
            label = default_label
        yield {
            "payload": line[:2048],
            "label": label,
            "source": source_name,
        }


def fetch_all_public(cache_dir: Path, force: bool = False) -> list[Path]:
    """拉取全部公开源，返回成功下载的文件列表。"""
    cache_dir.mkdir(parents=True, exist_ok=True)
    ok: list[Path] = []
    print(f"[Agent4] 拉取公开载荷库 -> {cache_dir}")
    for spec in PUBLIC_SOURCES:
        p = fetch_source(spec, cache_dir, force=force)
        if p:
            ok.append(p)
    print(f"[Agent4] 公开源成功 {len(ok)}/{len(PUBLIC_SOURCES)}")
    return ok


def iter_all_public(cache_dir: Path) -> Iterator[dict[str, str]]:
    """迭代所有已缓存公开源载荷。"""
    for spec in PUBLIC_SOURCES:
        sub = cache_dir / spec.get("subdir", "misc")
        path = sub / (spec["name"] + ".txt")
        parse_md = spec.get("parse_md") == "1"
        yield from iter_fetched_file(
            path,
            source_name=spec["name"],
            default_label=spec["default_label"],
            parse_md=parse_md,
        )


def payload_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]
