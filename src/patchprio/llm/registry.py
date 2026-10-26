"""Выбор провайдера языковой модели по конфигурации."""

from __future__ import annotations

from typing import Any

from .base import LLMMessage, LLMNotConfiguredError, LLMResponse


class NullProvider:
    """Провайдер-заглушка: любой вызов сообщает, что модель не настроена."""

    name = "none"

    def complete(
        self,
        messages: list[LLMMessage],
        *,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse:
        raise LLMNotConfiguredError(
            "языковая модель не подключена: задайте [llm].provider в config/experiment.toml"
        )


# Планируемые провайдеры:
#   "openai-compatible": любой сервер с OpenAI-совместимым API,
#                        в том числе локальный (vLLM, Ollama, llama.cpp)
#   "anthropic":         облачная модель через официальный SDK
PLANNED = {"openai-compatible", "anthropic"}


def get_provider(name: str = "none", **options: Any):
    if name == "none":
        return NullProvider()
    if name in PLANNED:
        raise NotImplementedError(
            f"провайдер '{name}' запланирован, но ещё не реализован"
        )
    raise ValueError(f"неизвестный провайдер языковой модели: '{name}'")
