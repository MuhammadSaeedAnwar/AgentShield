"""Adapter for any OpenAI-compatible ``/v1/chat/completions`` endpoint."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence

from .base import Message, ModelAdapter, ModelResponse, ToolCall, ToolSpec


class ModelCallError(RuntimeError):
    """Raised when the provider cannot be reached or returns an unusable reply."""


class OpenAICompatibleAdapter(ModelAdapter):
    provider = "openai"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        *,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        api_key_env: str = "OPENAI_API_KEY",
        temperature: float = 0.0,
        max_tokens: int = 1024,
        timeout: float = 90.0,
        max_retries: int = 3,
        retry_backoff: float = 2.0,
        cache_dir: str | os.PathLike[str] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self._model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get(api_key_env, "")
        self.api_key_env = api_key_env
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.extra_headers = dict(extra_headers or {})
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.stats = {"requests": 0, "cache_hits": 0, "cache_misses": 0, "retries": 0}

    @property
    def model_name(self) -> str:
        return self._model

    def describe(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_name": self.model_name,
            "base_url": self.base_url,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "api_key_env": self.api_key_env,
            "api_key_present": bool(self.api_key),
            "cache_dir": str(self.cache_dir) if self.cache_dir else None,
            "stats": dict(self.stats),
        }

    def generate(
        self,
        messages: Sequence[Message],
        *,
        context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        payload = self._payload(messages, tools=None, **kwargs)
        return self._parse(self._post(payload))

    def generate_with_tools(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolSpec],
        *,
        context: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        payload = self._payload(messages, tools=list(tools), **kwargs)
        return self._parse(self._post(payload))

    def _payload(
        self,
        messages: Sequence[Message],
        tools: list[ToolSpec] | None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [m.to_provider_dict() for m in messages],
            "temperature": kwargs.pop("temperature", self.temperature),
            "max_tokens": kwargs.pop("max_tokens", self.max_tokens),
        }
        if tools:
            payload["tools"] = [t.to_provider_dict() for t in tools]
            payload["tool_choice"] = kwargs.pop("tool_choice", "auto")
        payload.update(kwargs)
        return payload

    def _cache_path(self, payload: Mapping[str, Any]) -> Path | None:
        if not self.cache_dir:
            return None
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return self.cache_dir / f"{hashlib.sha256(blob).hexdigest()}.json"

    def _post(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        cache_path = self._cache_path(payload)
        if cache_path and cache_path.exists():
            self.stats["cache_hits"] += 1
            return json.loads(cache_path.read_text("utf-8"))

        if not self.api_key and "localhost" not in self.base_url and "127.0.0.1" not in self.base_url:
            raise ModelCallError(
                f"No API key found. Set ${self.api_key_env} (or pass --api-key-env) "
                "before running with --model openai."
            )

        url = f"{self.base_url}/chat/completions"
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key or 'not-needed'}",
            "User-Agent": "AgentShield/0.1 (research benchmark)",
        }
        headers.update(self.extra_headers)

        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                request = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = json.loads(response.read().decode("utf-8"))
                self.stats["requests"] += 1
                self.stats["cache_misses"] += 1
                if cache_path:
                    cache_path.write_text(json.dumps(raw, ensure_ascii=False, indent=2), "utf-8")
                return raw
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:500]
                last_error = ModelCallError(f"HTTP {exc.code} from {url}: {detail}")
                if exc.code in (408, 409, 429) or 500 <= exc.code < 600:
                    self.stats["retries"] += 1
                    time.sleep(self.retry_backoff * (attempt + 1))
                    continue
                raise last_error from exc
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = ModelCallError(f"Request to {url} failed: {exc}")
                self.stats["retries"] += 1
                time.sleep(self.retry_backoff * (attempt + 1))
        raise last_error or ModelCallError("Unknown model call failure")

    @staticmethod
    def _parse(raw: Mapping[str, Any]) -> ModelResponse:
        try:
            choice = raw["choices"][0]
        except (KeyError, IndexError, TypeError) as exc:
            raise ModelCallError(f"Malformed provider response: {str(raw)[:300]}") from exc

        message = choice.get("message") or {}
        calls: list[ToolCall] = []
        for index, tc in enumerate(message.get("tool_calls") or []):
            fn = tc.get("function") or {}
            arguments = fn.get("arguments") or "{}"
            if isinstance(arguments, str):
                try:
                    parsed = json.loads(arguments)
                except json.JSONDecodeError:
                    parsed = {"__unparsed_arguments__": arguments}
            else:
                parsed = dict(arguments)
            if not isinstance(parsed, dict):
                parsed = {"__unparsed_arguments__": str(parsed)}
            calls.append(ToolCall(name=fn.get("name", "unknown"), arguments=parsed, id=tc.get("id", f"call_{index}")))

        return ModelResponse(
            text=message.get("content") or "",
            tool_calls=calls,
            finish_reason=choice.get("finish_reason", "stop"),
            usage=dict(raw.get("usage") or {}),
            raw=raw,
        )
