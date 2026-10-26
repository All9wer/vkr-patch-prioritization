"""Интерфейсы интеллектуального слоя.

Три задачи, в которых языковая модель даёт результат, недостижимый
формальными правилами:

* применимость уязвимости к конкретной конфигурации актива;
* извлечение признаков эксплуатации из текстовых отчётов;
* формирование обоснования приоритета для специалиста.

Отдельно: согласование ответов нескольких независимых моделей
для снижения риска ошибочного вывода.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable


class LLMNotConfiguredError(RuntimeError):
    """Провайдер языковой модели не настроен."""


# ---------------------------------------------------------------------------
# Уровень 1: доступ к модели
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LLMMessage:
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str | None = None
    raw: Any = None


@runtime_checkable
class LLMProvider(Protocol):
    """Доступ к одной языковой модели.

    `json_schema` задаёт структуру ответа, если провайдер поддерживает
    структурированный вывод: задачам слоя нужны машиночитаемые ответы,
    а не свободный текст.
    """

    name: str

    def complete(
        self,
        messages: list[LLMMessage],
        *,
        json_schema: dict[str, Any] | None = None,
        temperature: float = 0.0,
    ) -> LLMResponse: ...


# ---------------------------------------------------------------------------
# Уровень 2: задачи
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApplicabilityVerdict:
    """Вывод о применимости уязвимости к активу.

    applicable=None означает "не удалось определить": такая уязвимость
    ранжируется так, как если бы вывода не было.
    """

    applicable: bool | None
    confidence: float = 0.0
    rationale: str = ""
    source: str = ""


@runtime_checkable
class ApplicabilityAssessor(Protocol):
    """Применима ли уязвимость к конкретной конфигурации.

    Совпадение по имени пакета и версии даёт ложные срабатывания:
    уязвимым может быть только определённый режим работы или сборка.
    Модель сопоставляет текст описания уязвимости с описанием
    конфигурации актива.
    """

    def assess(self, vulnerability: dict[str, Any], asset: dict[str, Any]) -> ApplicabilityVerdict: ...


@dataclass(frozen=True)
class ExploitationSignals:
    """Признаки эксплуатации, извлечённые из текста."""

    public_exploit: bool | None = None
    exploited_in_the_wild: bool | None = None
    threat_actors: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@runtime_checkable
class ExploitationSignalExtractor(Protocol):
    """Извлекает признаки эксплуатации из аналитических отчётов и бюллетеней."""

    def extract(self, cve_id: str, text: str) -> ExploitationSignals: ...


@runtime_checkable
class PriorityExplainer(Protocol):
    """Формирует понятное специалисту обоснование места в очереди."""

    def explain(self, vulnerability: dict[str, Any], features: dict[str, Any], rank: int) -> str: ...


@runtime_checkable
class ConsensusStrategy(Protocol):
    """Согласует выводы нескольких независимых моделей в один."""

    def combine(self, verdicts: list[ApplicabilityVerdict]) -> ApplicabilityVerdict: ...
