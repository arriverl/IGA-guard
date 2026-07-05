#!/usr/bin/env python3
"""Package IGA-Guard 3.0 submission materials."""

from __future__ import annotations

import shutil
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUBMISSION = ROOT / "submission"
OUT = ROOT / "IGA-Guard3_submission"

INCLUDE_TOP = [
    "src", "backend", "frontend", "scripts", "configs", "models",
    "data", "tests", "results", "docs", "submission",
    "run.py", "requirements.txt", "README.md", "AGENTS.md",
]

SKIP_DIRS = {"__pycache__", ".pytest_cache", ".git", ".venv", "venv", "_pack_staging"}
DOC_FILES = [
    "作品报告.md", "测试报告.md", "运行说明.md", "交付物清单.md",
    "原创性声明.svg", "原创性声明说明.md", "演示说明.txt",
]


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def add_to_zip(zf: zipfile.ZipFile, src: Path, arc_prefix: str = "") -> None:
    if src.is_file():
        arc = f"{arc_prefix}{src.name}" if arc_prefix else src.name
        zf.write(src, arc)
        return
    for item in sorted(src.rglob("*")):
        if should_skip(item):
            continue
        if item.is_dir():
            continue
        rel = item.relative_to(src.parent if arc_prefix else ROOT)
        arc = f"{arc_prefix}{rel.as_posix()}" if arc_prefix else rel.as_posix()
        zf.write(item, arc)


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()

    print("=== IGA-Guard 3.0 提交打包 ===")
    print(f"项目根目录: {ROOT}")

    # 1. 复制文档
    print("[1/3] 复制提交文档...")
    for name in DOC_FILES:
        src = SUBMISSION / name
        if src.exists():
            shutil.copy2(src, OUT / name)
            print(f"  + {name}")

    # 2. 打包源代码
    print("[2/3] 打包源代码...")
    src_zip = OUT / "05_source_code.zip"
    with zipfile.ZipFile(src_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in INCLUDE_TOP:
            path = ROOT / item
            if not path.exists():
                continue
            if path.is_file():
                zf.write(path, path.name)
            else:
                for f in path.rglob("*"):
                    if should_skip(f) or f.is_dir():
                        continue
                    zf.write(f, f.relative_to(ROOT).as_posix())
    size_mb = src_zip.stat().st_size / (1024 * 1024)
    print(f"  + 05_source_code.zip ({size_mb:.1f} MB)")

    # 3. 文件清单
    print("[3/3] 生成文件清单...")
    manifest = f"""IGA-Guard 3.0 竞赛提交包
生成时间: {datetime.now():%Y-%m-%d %H:%M:%S}

文件列表:
"""
    for f in sorted(OUT.iterdir()):
        manifest += f"  - {f.name} ({f.stat().st_size / 1024:.1f} KB)\n"
    manifest += """
待手动完成:
  [ ] 将 作品报告.md 导出为 PDF
  [ ] 打印 原创性声明.svg → 签字盖章 → 扫描为 PDF
  [ ] 将 运行说明.md、测试报告.md 导出为 PDF

核心指标 (results/v2_exp1_overall.json):
  混淆 Recall: 99.95%
  混淆 Precision: 100%
  Normal FPR: 5.63%
  P50 延迟: 2.92ms
"""
    (OUT / "文件清单.txt").write_text(manifest, encoding="utf-8")

    # 总 zip
    total_zip = ROOT / "IGA-Guard3_submission.zip"
    if total_zip.exists():
        total_zip.unlink()
    shutil.make_archive(str(ROOT / "IGA-Guard3_submission"), "zip", OUT)

    print(f"\n=== 打包完成 ===")
    print(f"输出目录: {OUT}")
    print(f"总压缩包: {total_zip}")
    print("注意: *.zip 已加入 .gitignore，请本地保留或上传网盘，勿 git push")


if __name__ == "__main__":
    main()
