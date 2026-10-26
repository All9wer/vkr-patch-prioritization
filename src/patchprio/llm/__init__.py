"""Интеллектуальный слой на основе языковых моделей.

Статус: заложен архитектурно, не реализован. Место применения
уточняется с научным руководителем.

Слой отделён от остальной системы двумя уровнями интерфейсов:

1. `LLMProvider`: доступ к конкретной модели. Позволяет подключить
   облачную модель или локальную через OpenAI-совместимый API,
   не меняя остальной код.
2. Интерфейсы задач (`ApplicabilityAssessor`, `ExploitationSignalExtractor`,
   `PriorityExplainer`, `ConsensusStrategy`): что именно система
   поручает модели. Ранжирование зависит только от них.

Пока провайдер не выбран, используются нейтральные реализации из
`fallback.py`: система работает полностью без языковой модели,
а интеллектуальный слой добавляется заменой реализации.
"""

from .base import (
    ApplicabilityAssessor,
    ApplicabilityVerdict,
    ConsensusStrategy,
    ExploitationSignalExtractor,
    ExploitationSignals,
    LLMMessage,
    LLMNotConfiguredError,
    LLMProvider,
    LLMResponse,
    PriorityExplainer,
)
from .registry import get_provider

__all__ = [
    "ApplicabilityAssessor",
    "ApplicabilityVerdict",
    "ConsensusStrategy",
    "ExploitationSignalExtractor",
    "ExploitationSignals",
    "LLMMessage",
    "LLMNotConfiguredError",
    "LLMProvider",
    "LLMResponse",
    "PriorityExplainer",
    "get_provider",
]
