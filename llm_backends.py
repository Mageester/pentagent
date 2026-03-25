from __future__ import annotations

from dataclasses import dataclass
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Protocol

import requests


DEFAULT_OLLAMA_MODEL = "hf.co/mradermacher/Huihui-Qwen3-Coder-30B-A3B-Instruct-abliterated-i1-GGUF:Q4_K_M"


def _normalize_model_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").strip().lower())


def _tokenize_model_name(value: str) -> List[str]:
    return [token for token in re.split(r"[^a-z0-9]+", (value or "").lower()) if token]


def _ollama_installed_models() -> List[str]:
    if not shutil.which("ollama"):
        return []
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except Exception:
        return []
    if result.returncode != 0:
        return []
    models: List[str] = []
    for raw_line in (result.stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.upper().startswith("NAME "):
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[0].strip()
        if name and name.upper() != "NAME":
            models.append(name)
    return models


def resolve_ollama_model(requested: str) -> str:
    requested = (requested or "").strip()
    if not requested:
        return DEFAULT_OLLAMA_MODEL

    installed = _ollama_installed_models()
    if not installed:
        return requested

    requested_norm = _normalize_model_name(requested)
    installed_norm = {name: _normalize_model_name(name) for name in installed}

    for candidate, candidate_norm in installed_norm.items():
        if candidate == requested or candidate_norm == requested_norm:
            return candidate

    requested_tokens = _tokenize_model_name(requested)
    alias_tokens = {
        "qwen3coder30b": ["qwen3", "coder", "30b"],
        "qwen3coder": ["qwen3", "coder"],
    }.get(requested_norm)
    if alias_tokens:
        requested_tokens = alias_tokens

    if requested_tokens:
        scored: List[tuple[int, int, str]] = []
        for candidate, candidate_norm in installed_norm.items():
            token_score = sum(1 for token in requested_tokens if token in candidate_norm)
            if token_score == 0:
                continue
            exact_bonus = 20 if requested_norm and requested_norm in candidate_norm else 0
            family_bonus = 5 if any(token in candidate_norm for token in requested_tokens[:2]) else 0
            score = token_score * 10 + exact_bonus + family_bonus
            scored.append((score, len(candidate_norm), candidate))
        if scored:
            scored.sort(reverse=True)
            return scored[0][2]

    for candidate, candidate_norm in installed_norm.items():
        if requested_norm and requested_norm in candidate_norm:
            return candidate
        if candidate_norm and candidate_norm in requested_norm:
            return candidate

    return requested


@dataclass(frozen=True)
class BackendInfo:
    provider: str
    model: str
    base_url: str = ""
    api_key_env: str = ""
    api_key_present: bool = False


class ChatBackend(Protocol):
    info: BackendInfo

    def chat(self, messages: List[Dict[str, str]], *,
             think: bool = False, format: str | None = None,
             options: Optional[Dict[str, Any]] = None) -> Any:
        ...


class OllamaBackend:
    def __init__(self, model: str, host: str = "http://127.0.0.1:11434") -> None:
        import ollama  # type: ignore

        self._client = ollama.Client(host=host)
        self.info = BackendInfo(
            provider="ollama",
            model=model,
            base_url=host,
            api_key_env="",
            api_key_present=True,
        )

    def chat(self, messages: List[Dict[str, str]], *,
             think: bool = False, format: str | None = None,
             options: Optional[Dict[str, Any]] = None) -> Any:
        payload: Dict[str, Any] = {
            "model": self.info.model,
            "messages": messages,
        }
        if options:
            payload["options"] = options
        if format is not None:
            payload["format"] = format
        if think is not None:
            payload["think"] = think
        return self._client.chat(**payload)


class OpenAICompatibleBackend:
    def __init__(self, model: str, base_url: str,
                 api_key_env: str = "OPENAI_API_KEY",
                 api_key: str = "") -> None:
        base = (base_url or "").strip() or os.getenv("PENTAGENT_API_BASE", "").strip()
        if not base:
            base = "https://api.openai.com"
        self._base_url = base.rstrip("/")
        self._api_key_env = api_key_env or "OPENAI_API_KEY"
        self._api_key = api_key.strip() or os.getenv(self._api_key_env, "").strip()
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
        })
        if self._api_key:
            self._session.headers["Authorization"] = f"Bearer {self._api_key}"
        self.info = BackendInfo(
            provider="openai-compatible",
            model=model,
            base_url=self._base_url,
            api_key_env=self._api_key_env,
            api_key_present=bool(self._api_key),
        )

    def _endpoint(self) -> str:
        base = self._base_url.rstrip("/")
        if base.endswith("/v1"):
            return f"{base}/chat/completions"
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/v1/chat/completions"

    def chat(self, messages: List[Dict[str, str]], *,
             think: bool = False, format: str | None = None,
             options: Optional[Dict[str, Any]] = None) -> Any:
        payload: Dict[str, Any] = {
            "model": self.info.model,
            "messages": messages,
        }
        if options:
            if "num_predict" in options and "max_tokens" not in payload:
                payload["max_tokens"] = options["num_predict"]
            if "temperature" in options:
                payload["temperature"] = options["temperature"]
            for key in ("top_p", "frequency_penalty", "presence_penalty"):
                if key in options:
                    payload[key] = options[key]
        if format == "json":
            payload["response_format"] = {"type": "json_object"}
        if think is not None:
            # Kept for interface symmetry; OpenAI-compatible APIs ignore this.
            payload["stream"] = False

        resp = self._session.post(
            self._endpoint(),
            json=payload,
            timeout=300,
        )
        resp.raise_for_status()
        data = resp.json()
        content = ""
        choices = data.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            content = message.get("content", "") or ""
        return {"message": {"content": content}, "raw": data}


def build_backend(provider: str, model: str, *, api_base: str = "",
                  api_key_env: str = "OPENAI_API_KEY",
                  api_key: str = "") -> ChatBackend:
    normalized = (provider or "ollama").strip().lower()
    if normalized in {"local", "ollama"}:
        resolved_model = resolve_ollama_model(model)
        return OllamaBackend(model=resolved_model, host=api_base or "http://127.0.0.1:11434")
    if normalized in {"api", "openai", "openai-compatible"}:
        return OpenAICompatibleBackend(
            model=model,
            base_url=api_base,
            api_key_env=api_key_env,
            api_key=api_key,
        )
    raise ValueError(f"Unsupported LLM provider: {provider}")


def describe_backend(backend: ChatBackend | None) -> str:
    if backend is None:
        return "uninitialized"
    info = backend.info
    status = info.base_url or "local"
    if info.api_key_env:
        key_state = "key-set" if info.api_key_present else f"env:{info.api_key_env}"
        return f"{info.provider}:{info.model} @ {status} ({key_state})"
    return f"{info.provider}:{info.model} @ {status}"
