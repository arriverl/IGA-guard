"""统一抑制/修复 IGA 运行期已知无害告警（评测日志更干净）。"""

from __future__ import annotations

import logging
import os
import warnings


def configure_runtime_warnings() -> None:
    """在引擎/脚本启动时调用一次即可。"""
    os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
    os.environ.setdefault("PIP_ROOT_USER_ACTION", "ignore")
    # 评测环境常无稳定 HuggingFace/HG 镜像；本项目模型均应优先使用本地缓存。
    # 若本地缓存缺失，调用侧会回退到轻量 hash/关键词路径，避免联网 HEAD 重试拖慢 E9。
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

    try:
        from sklearn.exceptions import InconsistentVersionWarning

        warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
    except Exception:
        pass

    warnings.filterwarnings(
        "ignore",
        message=r"`sklearn\.utils\.parallel\.delayed` should be used with",
        category=UserWarning,
        module=r"sklearn\.utils\.parallel",
    )
    warnings.filterwarnings("ignore", category=ResourceWarning, module="tempfile")

    logging.getLogger("transformers").setLevel(logging.ERROR)
    logging.getLogger("transformers.pipelines").setLevel(logging.ERROR)
