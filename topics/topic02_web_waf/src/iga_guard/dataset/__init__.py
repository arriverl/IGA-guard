"""IGA-Guard 真实数据集采集与扩充模块（Agent 4）。"""

from iga_guard.dataset.csic_parser import iter_csic_file
from iga_guard.dataset.label_rules import infer_attack_label

__all__ = ["iter_csic_file", "infer_attack_label"]
