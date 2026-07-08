"""统一 LLM 客户端：Ollama 本地小模型 / OpenAI 兼容 API。"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import requests


@dataclass
class LLMConfig:
    enabled: bool = False
    provider: str = "ollama"          # ollama | openai_compatible
    model: str = "qwen2.5:3b"
    api_base: str = "http://127.0.0.1:11434"
    api_key: str = ""
    timeout_sec: int = 90
    temperature: float = 0.80
    top_p: float = 0.92
    seed: int | None = None
    max_tokens: int = 512
    num_ctx: int = 4096
    num_gpu: int = -1
    max_variants_per_call: int = 4

    @classmethod
    def from_dict(cls, raw: dict | None) -> LLMConfig:
        if not raw:
            return cls()
        key_env = raw.get("api_key_env", "IGA_LLM_API_KEY")
        api_key = os.environ.get(key_env, "") or raw.get("api_key", "")
        base = raw.get("api_base") or os.environ.get("IGA_LLM_API_BASE", "")
        if not base and raw.get("provider", "ollama") == "ollama":
            base = "http://127.0.0.1:11434"
        return cls(
            enabled=bool(raw.get("enabled", False)),
            provider=raw.get("provider", "ollama"),
            model=os.environ.get("IGA_LLM_MODEL", raw.get("model", "qwen2.5:3b")),
            api_base=base,
            api_key=api_key,
            timeout_sec=int(raw.get("timeout_sec", 90)),
            temperature=float(raw.get("temperature", 0.80)),
            top_p=float(raw.get("top_p", 0.92)),
            seed=int(raw["seed"]) if raw.get("seed") is not None else None,
            max_tokens=int(raw.get("max_tokens", 512)),
            num_ctx=int(raw.get("num_ctx", 4096)),
            num_gpu=int(raw.get("num_gpu", -1)),
            max_variants_per_call=int(raw.get("max_variants_per_call", 4)),
        )

    def is_configured(self) -> bool:
        if not self.enabled:
            return False
        if self.provider == "ollama":
            return bool(self.api_base)
        return bool(self.api_base and self.api_key)


@dataclass
class LLMResponse:
    ok: bool
    content: str = ""
    model: str = ""
    provider: str = ""
    error: str = ""
    latency_ms: float = 0.0
    raw: dict = field(default_factory=dict)


class LLMClient:
    """轻量 chat 客户端，优先本地 Ollama 小模型。"""

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or LLMConfig()

    def status(self) -> dict[str, Any]:
        cfg = self.config
        out: dict[str, Any] = {
            "enabled": cfg.enabled,
            "configured": cfg.is_configured(),
            "provider": cfg.provider,
            "model": cfg.model,
            "api_base": cfg.api_base,
        }
        if cfg.provider == "ollama" and cfg.api_base:
            try:
                r = requests.get(f"{cfg.api_base.rstrip('/')}/api/tags", timeout=5)
                tags = r.json().get("models", []) if r.ok else []
                out["ollama_reachable"] = r.ok
                out["local_models"] = [m.get("name") for m in tags[:10]]
                out["model_available"] = any(
                    cfg.model in (m.get("name") or "") for m in tags
                )
            except Exception as exc:
                out["ollama_reachable"] = False
                out["error"] = str(exc)
        return out

    def _ollama_options(self, temperature: float | None) -> dict[str, Any]:
        cfg = self.config
        opts: dict[str, Any] = {
            "temperature": temperature if temperature is not None else cfg.temperature,
            "top_p": cfg.top_p,
            "num_predict": cfg.max_tokens,
            "num_ctx": cfg.num_ctx,
        }
        if cfg.num_gpu != 0:
            opts["num_gpu"] = cfg.num_gpu
        if cfg.seed is not None:
            opts["seed"] = int(cfg.seed)
        return opts

    def chat(
        self,
        user_prompt: str,
        *,
        system_prompt: str | None = None,
        temperature: float | None = None,
    ) -> LLMResponse:
        if not self.config.is_configured():
            return LLMResponse(ok=False, error="llm not configured")
        if self.config.provider == "ollama":
            return self._chat_ollama_native(user_prompt, system_prompt=system_prompt, temperature=temperature)
        return self._chat_openai_compatible(user_prompt, system_prompt=system_prompt, temperature=temperature)

    def _chat_ollama(
        self,
        user_prompt: str,
        *,
        system_prompt: str | None,
        temperature: float | None,
    ) -> LLMResponse:
        cfg = self.config
        import time
        t0 = time.perf_counter()
        # 优先 OpenAI 兼容端点（Ollama 0.3+）
        url = urljoin(cfg.api_base.rstrip("/") + "/", "v1/chat/completions")
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        headers = {"Content-Type": "application/json"}
        if cfg.api_key:
            headers["Authorization"] = f"Bearer {cfg.api_key}"
        body = {
            "model": cfg.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else cfg.temperature,
            "stream": False,
        }
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=cfg.timeout_sec)
            if resp.status_code == 404:
                return self._chat_ollama_native(user_prompt, system_prompt=system_prompt, temperature=temperature)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return LLMResponse(
                ok=True,
                content=content.strip(),
                model=cfg.model,
                provider="ollama",
                latency_ms=(time.perf_counter() - t0) * 1000,
                raw=data,
            )
        except Exception as exc:
            native = self._chat_ollama_native(user_prompt, system_prompt=system_prompt, temperature=temperature)
            if native.ok:
                return native
            return LLMResponse(ok=False, error=str(exc), provider="ollama")

    def _chat_ollama_native(
        self,
        user_prompt: str,
        *,
        system_prompt: str | None,
        temperature: float | None,
    ) -> LLMResponse:
        cfg = self.config
        import time
        t0 = time.perf_counter()
        url = urljoin(cfg.api_base.rstrip("/") + "/", "api/chat")
        body: dict[str, Any] = {
            "model": cfg.model,
            "messages": [{"role": "user", "content": user_prompt}],
            "stream": False,
            "options": self._ollama_options(temperature),
        }
        if system_prompt:
            body["messages"].insert(0, {"role": "system", "content": system_prompt})
        try:
            resp = requests.post(url, json=body, timeout=cfg.timeout_sec)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            return LLMResponse(
                ok=True,
                content=content.strip(),
                model=cfg.model,
                provider="ollama_native",
                latency_ms=(time.perf_counter() - t0) * 1000,
                raw=data,
            )
        except Exception as exc:
            return LLMResponse(ok=False, error=str(exc), provider="ollama_native")

    def _chat_openai_compatible(
        self,
        user_prompt: str,
        *,
        system_prompt: str | None,
        temperature: float | None,
    ) -> LLMResponse:
        cfg = self.config
        import time
        t0 = time.perf_counter()
        url = urljoin(cfg.api_base.rstrip("/") + "/", "v1/chat/completions")
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg.api_key}",
        }
        body = {
            "model": cfg.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else cfg.temperature,
            "max_tokens": cfg.max_tokens,
        }
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=cfg.timeout_sec)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return LLMResponse(
                ok=True,
                content=content.strip(),
                model=cfg.model,
                provider="openai_compatible",
                latency_ms=(time.perf_counter() - t0) * 1000,
                raw=data,
            )
        except Exception as exc:
            return LLMResponse(ok=False, error=str(exc), provider="openai_compatible")


def parse_variant_lines(text: str, *, max_lines: int = 10) -> list[str]:
    """从 LLM 输出解析载荷行（去编号、引号、markdown）。"""
    if not text:
        return []
    text = re.sub(r"```[\w]*", "", text).replace("```", "")
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^\d+[\.\)、]\s*", "", line)
        line = line.strip("\"'` ")
        if line.lower().startswith(("variant", "payload", "example")):
            parts = line.split(":", 1)
            if len(parts) == 2:
                line = parts[1].strip()
        if 3 <= len(line) <= 2048:
            out.append(line)
        if len(out) >= max_lines:
            break
    return out
