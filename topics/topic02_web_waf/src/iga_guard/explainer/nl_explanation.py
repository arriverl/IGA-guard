"""Natural language explanation (template + Ollama local_llm + API)."""

from __future__ import annotations

import os

from iga_guard.models import DetectionResult, ExplanationResult, NormalizedPayload


def generate_nl_explanation(
    payload: NormalizedPayload,
    detection: DetectionResult,
    explanation: ExplanationResult | None,
    provider: str = "template",
    *,
    model: str = "qwen2.5:3b",
    api_base: str = "http://127.0.0.1:11434",
    max_tokens: int = 128,
    num_ctx: int = 2048,
) -> str:
    if provider == "api" or provider == "local_llm":
        llm = _llm_explain(
            payload, detection, explanation,
            provider=provider, model=model, api_base=api_base,
            max_tokens=max_tokens, num_ctx=num_ctx,
        )
        if llm:
            return llm
    return _template_explain(payload, detection, explanation)


def _template_explain(
    payload: NormalizedPayload,
    detection: DetectionResult,
    explanation: ExplanationResult | None,
) -> str:
    if not detection.is_malicious:
        return "该请求未检测到已知 Web 攻击特征，判定为正常流量。"

    field = explanation.malicious_field if explanation else payload.field_name
    location = payload.location
    span = explanation.malicious_span if explanation else ""
    chain = "、".join(payload.decode_chain) if payload.decode_chain else "无"

    decode_desc = f"经过 {chain} 解码" if payload.decode_chain else "未经复杂编码"

    type_zh = {
        "SQLi": "SQL 注入",
        "XSS": "跨站脚本",
        "CMD": "命令注入",
        "PathTraversal": "路径遍历",
        "FileInclusion": "文件包含",
        "XXE": "XML 外部实体注入",
        "PromptInjection": "LLM 提示词注入",
    }.get(detection.label, detection.label)

    return (
        f"此请求因在 **{location}** 区域的 **{field}** 字段包含"
        f"{decode_desc}的 **{type_zh}** 特征片段（`{span}`）而被判定为"
        f" **{detection.risk_level}** 风险（置信度 {detection.confidence:.1%}）。"
    )


def _llm_explain(
    payload: NormalizedPayload,
    detection: DetectionResult,
    explanation: ExplanationResult | None,
    *,
    provider: str,
    model: str,
    api_base: str,
    max_tokens: int = 128,
    num_ctx: int = 2048,
) -> str | None:
    prompt = (
        "用一句中文向安全运维人员解释以下 Web 攻击判定原因：\n"
        f"类型={detection.label}, 字段={payload.field_name}, "
        f"片段={explanation.malicious_span if explanation else ''}, "
        f"解码链={payload.decode_chain}"
    )
    try:
        import requests

        if provider == "local_llm":
            base = api_base or os.environ.get("IGA_LLM_API_BASE", "http://127.0.0.1:11434")
            resp = requests.post(
                f"{base.rstrip('/')}/api/chat",
                json={
                    "model": model or os.environ.get("IGA_LLM_MODEL", "qwen2.5:3b"),
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": max_tokens,
                        "num_ctx": num_ctx,
                    },
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json().get("message", {}).get("content", "").strip() or None

        api_key = os.environ.get("IGA_LLM_API_KEY", "")
        if not api_key or not api_base:
            return None
        resp = requests.post(
            f"{api_base.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model or "qwen-plus", "messages": [{"role": "user", "content": prompt}]},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        return None
