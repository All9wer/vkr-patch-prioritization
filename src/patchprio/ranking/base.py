"""Общий интерфейс ранжирования."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import pandas as pd


@runtime_checkable
class Ranker(Protocol):
    """Любой способ приоритизации.

    `score` возвращает оценку срочности для каждой строки: чем больше,
    тем раньше уязвимость нужно устранять. NaN означает "данных нет",
    такие уязвимости ставятся в конец очереди.

    Одинаковые оценки допустимы: при подсчёте метрик учитывается
    ожидаемый результат при случайном порядке внутри группы равных
    оценок (см. evaluation/metrics.py). Это важно для CVSS, где
    тысячи уязвимостей имеют одинаковый балл 9.8.
    """

    name: str

    def score(self, df: pd.DataFrame) -> pd.Series: ...

    @property
    def required_columns(self) -> tuple[str, ...]: ...
