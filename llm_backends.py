from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Dict, List, Optional, Protocol

import requests


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
        return OllamaBackend(model=model, host=api_base or "http://127.0.0.1:11434")
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
