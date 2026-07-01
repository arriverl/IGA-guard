#!/usr/bin/env python3
"""CSIC 2010 HTTP 数据集自动下载与解压脚本。

支持两种来源（按推荐顺序）：
  1. gsi   — GSI GitLab 镜像，下载 TAR 并解压为 TXT（含 ModSecurity 标签）
  2. csv   — Peter Scully CSV v02 三文件（ML 友好，需手动放置或直链可用时自动拉取）

默认输出目录：data/raw/csic/

用法示例：
  python scripts/download_csic.py
  python scripts/download_csic.py --source gsi --output-dir data/raw/csic
  python scripts/download_csic.py --source csv --force

失败时会打印详细的手动下载说明。
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlretrieve

# ---------------------------------------------------------------------------
# 项目根目录与默认路径
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "data" / "raw" / "csic"

# ---------------------------------------------------------------------------
# 数据源 URL（GSI GitLab 为首选；官方主页可能失效）
# ---------------------------------------------------------------------------
GSI_TAR_URL = (
    "https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/"
    "-/raw/master/csic_2010/dataset_cisc_train_test.tar.gz"
)
GSI_REPO_URL = "https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets.git"
GSI_CSIC_SUBDIR = "csic_2010"

# Peter Scully CSV 版说明页（直链常变动，脚本以说明页为准）
SCULLY_INFO_URL = (
    "https://petescully.co.uk/research/"
    "csic-2010-http-dataset-in-csv-format-for-weka-analysis/"
)
# 部分镜像提供的 CSV 文件名（用户亦可从说明页手动下载）
SCULLY_CSV_FILES = (
    "normalTrafficTraining.csv",
    "normalTrafficTest.csv",
    "anomalousTrafficTest.csv",
)

# GSI TAR 解压后预期的 TXT 文件（含 cisc_ 前缀变体）
GSI_TXT_FILES = (
    "normalTrafficTraining.txt",
    "normalTrafficTest.txt",
    "anomalousTrafficTest.txt",
)
GSI_TXT_ALIASES = (
    "cisc_normalTraffic_train.txt",
    "cisc_normalTraffic_test.txt",
    "cisc_anomalousTraffic_test.txt",
)


def _print_manual_instructions(reason: str = "") -> None:
    """下载失败时输出手动操作指南。"""
    if reason:
        print(f"\n[失败原因] {reason}\n", file=sys.stderr)
    print(
        """
================================================================================
CSIC 2010 手动下载说明
================================================================================

【方式 A · 推荐】GSI GitLab 预处理版（TXT + 标签）
  1. 浏览器打开：
     https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/tree/master/csic_2010
  2. 下载 dataset_cisc_train_test.tar.gz
  3. 解压到本项目目录：
     d:\\Code_development\\gitproduct\\caisa_contest_2026\\topics\\topic02_web_waf\\data\\raw\\csic\\
  4. 确认存在以下文件：
     - normalTrafficTraining.txt
     - normalTrafficTest.txt
     - anomalousTrafficTest.txt

  或使用 git（需已安装 Git）：
     cd data/raw
     git clone https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets.git
     cd web-application-attacks-datasets/csic_2010
     tar -xzf dataset_cisc_train_test.tar.gz
     # 将三个 TXT 复制到 data/raw/csic/

【方式 B】Peter Scully CSV 版（18 列，适合 pandas）
  1. 打开说明页：
     https://petescully.co.uk/research/csic-2010-http-dataset-in-csv-format-for-weka-analysis/
  2. 下载 v02 三个 CSV：
     - normalTrafficTraining.csv
     - normalTrafficTest.csv
     - anomalousTrafficTest.csv
  3. 放入：data/raw/csic/

【方式 C】官方主页（可能失效）
  http://www.isi.csic.es/dataset/

【后续步骤】
  - 字段说明与转 labeled_samples 格式：research/agent1_literature/datasets/CSIC2010_GUIDE.md
  - 转换脚本（待实现）：scripts/csic_to_labeled.py

================================================================================
""",
        file=sys.stderr,
    )


def _download_file(url: str, dest: Path, desc: str = "") -> None:
    """通过 urllib 下载单个文件，带简单进度提示。"""
    label = desc or dest.name
    print(f"  正在下载 {label} ...")
    print(f"    URL: {url}")

    def _progress(block_num: int, block_size: int, total_size: int) -> None:
        if total_size > 0:
            pct = min(100, block_num * block_size * 100 // total_size)
            print(f"\r    进度: {pct}%", end="", flush=True)

    try:
        urlretrieve(url, dest, reporthook=_progress if sys.stdout.isatty() else None)
        print()  # 换行
    except (URLError, OSError) as exc:
        raise RuntimeError(f"下载失败: {exc}") from exc


def _extract_tar(tar_path: Path, out_dir: Path) -> list[Path]:
    """解压 TAR.GZ 到目标目录，返回解压出的文件列表。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    print(f"  正在解压 {tar_path.name} -> {out_dir}")
    with tarfile.open(tar_path, "r:gz") as tf:
        tf.extractall(path=out_dir)
    for name in GSI_TXT_FILES:
        candidate = out_dir / name
        if candidate.exists():
            extracted.append(candidate)
        # 部分 TAR 包内带一级子目录
        for sub in out_dir.rglob(name):
            if sub not in extracted:
                extracted.append(sub)
    return extracted


def _verify_gsi_txt(out_dir: Path) -> bool:
    """检查 GSI TXT 三文件是否齐全（支持 cisc_ 前缀命名）。"""
    all_names = list(GSI_TXT_FILES) + list(GSI_TXT_ALIASES)
    found = sum(1 for name in all_names if (out_dir / name).exists() or any(out_dir.rglob(name)))
    return found >= 3


def _flatten_txt_files(out_dir: Path) -> None:
    """若 TXT 在子目录中，复制到 out_dir 根目录便于后续脚本引用。"""
    for name in GSI_TXT_FILES:
        dest = out_dir / name
        if dest.exists():
            continue
        matches = list(out_dir.rglob(name))
        if matches:
            shutil.copy2(matches[0], dest)
            print(f"  已归位: {name}")


def download_gsi(output_dir: Path, force: bool = False) -> bool:
    """
    从 GSI GitLab 下载 dataset_cisc_train_test.tar.gz 并解压。

    优先尝试 HTTP 直链；失败则尝试浅克隆 Git 仓库后本地解压 TAR。
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    if _verify_gsi_txt(output_dir) and not force:
        print(f"[跳过] GSI TXT 已存在于 {output_dir}")
        return True

    print("[步骤 1/2] 尝试 GSI GitLab HTTP 直链下载 TAR ...")
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "dataset_cisc_train_test.tar.gz"
        try:
            _download_file(GSI_TAR_URL, tar_path, "dataset_cisc_train_test.tar.gz")
            _extract_tar(tar_path, output_dir)
            _flatten_txt_files(output_dir)
            if _verify_gsi_txt(output_dir):
                print(f"[成功] GSI TXT 已就绪: {output_dir}")
                return True
        except RuntimeError as exc:
            print(f"  HTTP 直链失败: {exc}")

    # 回退：git sparse checkout（仅拉取 csic_2010 子目录）
    if shutil.which("git") is None:
        _print_manual_instructions("未找到 git 命令，且 HTTP 直链下载失败")
        return False

    print("[步骤 2/2] 回退方案：git clone GSI 仓库（浅克隆）...")
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = Path(tmp) / "web-application-attacks-datasets"
        try:
            subprocess.run(
                [
                    "git", "clone", "--depth", "1", "--filter=blob:none",
                    "--sparse", GSI_REPO_URL, str(repo_dir),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "sparse-checkout", "set", GSI_CSIC_SUBDIR],
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True,
            )
            tar_local = repo_dir / GSI_CSIC_SUBDIR / "dataset_cisc_train_test.tar.gz"
            if not tar_local.exists():
                raise FileNotFoundError(f"仓库内未找到 {tar_local.name}")

            _extract_tar(tar_local, output_dir)
            _flatten_txt_files(output_dir)
            if _verify_gsi_txt(output_dir):
                print(f"[成功] 通过 git 获取并解压: {output_dir}")
                return True
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            _print_manual_instructions(f"git 克隆/解压失败: {exc}")
            return False

    _print_manual_instructions("解压后未找到预期的三个 TXT 文件")
    return False


def download_csv(output_dir: Path, force: bool = False) -> bool:
    """
    尝试获取 Peter Scully CSV 三文件。

    说明：Scully 页面直链常变动且无稳定 CDN，本函数主要校验本地文件，
    并在缺失时给出说明页链接；若环境变量 CSIC_CSV_BASE_URL 已设置则尝试拼接下载。
    """
    import os

    output_dir.mkdir(parents=True, exist_ok=True)
    base_url = os.environ.get("CSIC_CSV_BASE_URL", "").rstrip("/")

    all_present = all((output_dir / fn).exists() for fn in SCULLY_CSV_FILES)
    if all_present and not force:
        print(f"[跳过] CSV 三文件已存在于 {output_dir}")
        return True

    if not base_url:
        print(
            f"[提示] Peter Scully CSV 无稳定直链。\n"
            f"  请访问说明页手动下载: {SCULLY_INFO_URL}\n"
            f"  或将 CSV 放入: {output_dir}\n"
            f"  若你有镜像 base URL，可设置环境变量 CSIC_CSV_BASE_URL 后重试。"
        )
        _print_manual_instructions("CSV 直链未配置且本地文件不完整")
        return False

    print(f"[步骤] 从 CSIC_CSV_BASE_URL 下载 CSV ...")
    ok = True
    for fn in SCULLY_CSV_FILES:
        dest = output_dir / fn
        if dest.exists() and not force:
            print(f"  [跳过] {fn}")
            continue
        try:
            _download_file(f"{base_url}/{fn}", dest, fn)
        except RuntimeError as exc:
            print(f"  [失败] {fn}: {exc}", file=sys.stderr)
            ok = False

    if ok and all((output_dir / fn).exists() for fn in SCULLY_CSV_FILES):
        print(f"[成功] CSV 已就绪: {output_dir}")
        return True

    _print_manual_instructions("部分 CSV 下载失败")
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="下载并解压 CSIC 2010 HTTP 数据集",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="详细字段说明见 research/agent1_literature/datasets/CSIC2010_GUIDE.md",
    )
    parser.add_argument(
        "--source",
        choices=("gsi", "csv", "auto"),
        default="auto",
        help="数据源：gsi=GSI TXT（默认优先）, csv=Scully CSV, auto=先 gsi 后提示 csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"输出目录（默认: {DEFAULT_OUTPUT.relative_to(ROOT)}）",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="强制重新下载（覆盖已有文件）",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out = args.output_dir.resolve()

    print("=" * 60)
    print("CSIC 2010 HTTP Dataset 下载工具")
    print(f"  输出目录: {out}")
    print(f"  数据源:   {args.source}")
    print("=" * 60)

    success = False
    if args.source in ("gsi", "auto"):
        success = download_gsi(out, force=args.force)
    if args.source == "csv" or (args.source == "auto" and not success):
        if args.source == "auto" and not success:
            print("\n[回退] GSI 未成功，尝试 CSV 路径 ...")
        csv_ok = download_csv(out, force=args.force)
        success = success or csv_ok

    if success:
        print("\n[完成] 数据集已就绪。下一步可参考 CSIC2010_GUIDE.md 进行格式转换。")
        return 0

    print("\n[未完成] 自动下载失败，请按上方手动说明操作。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
