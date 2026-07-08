"""运行时加载 miss→rule 闭环产出的动态 rescue 规则。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_DEFAULT_PATH = Path("data/cache/discovered_rescue_rules.json")


class DiscoveredRescueRules:
    """JSON 持久化的 regex rescue 规则集。"""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else _DEFAULT_PATH
        self.rules: list[dict[str, Any]] = []
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.rules = []
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.rules = list(data.get("rules", []))
        except Exception:
            self.rules = []

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"rules": self.rules, "count": len(self.rules)}
        self.path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def match(self, raw: str, norm: str) -> tuple[str, float] | None:
        from iga_guard.obfuscation_signals import looks_like_benign_csic_form

        raw_low = (raw or "").lower()
        norm_low = (norm or raw or "").lower()
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            pat = rule.get("pattern", "")
            if not pat:
                continue
            try:
                rx = re.compile(pat, re.I)
            except re.error:
                continue
            if not (rx.search(raw_low) or rx.search(norm_low)):
                continue
            # 短规则勿误伤完整 CSIC 正常表单（仅拦截孤立 red-team 片段）
            if looks_like_benign_csic_form(raw, norm_low) and len(raw) > 35:
                if rule.get("cluster", "").endswith(":other") or rule.get("source") == "miss_rule_pipeline":
                    continue
            return str(rule.get("label", "SQLi")), float(rule.get("confidence", 0.62))
        return None

    def add_rule(
        self,
        *,
        pattern: str,
        label: str,
        confidence: float = 0.62,
        source: str = "miss_pipeline",
        cluster: str = "",
        enabled: bool = True,
    ) -> bool:
        if any(r.get("pattern") == pattern for r in self.rules):
            return False
        self.rules.append({
            "pattern": pattern,
            "label": label,
            "confidence": confidence,
            "source": source,
            "cluster": cluster,
            "enabled": enabled,
        })
        return True

    def stats(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "total": len(self.rules),
            "enabled": sum(1 for r in self.rules if r.get("enabled", True)),
        }
