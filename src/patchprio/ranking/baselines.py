"""Базовые линии для сравнения.

* RandomRanker: случайный порядок. Нижняя граница качества.
* CvssRanker: сортировка по баллу CVSS. Так приоритизируют на практике
  чаще всего, это основной конкурент.
* EpssRanker: сортировка по вероятности эксплуатации EPSS на дату
  среза. Более сильный конкурент: модель, которая уже учитывает
  внешние признаки эксплуатации, но не знает контекста инфраструктуры.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class RandomRanker:
    name: str = "Случайный порядок"

    @property
    def required_columns(self) -> tuple[str, ...]:
        return ()

    def score(self, df: pd.DataFrame) -> pd.Series:
        # Все оценки равны: метрики считаются как матожидание
        # по случайным перестановкам, без зависимости от seed.
        return pd.Series(0.0, index=df.index)


@dataclass(frozen=True)
class CvssRanker:
    name: str = "CVSS"

    @property
    def required_columns(self) -> tuple[str, ...]:
        return ("cvss_score",)

    def score(self, df: pd.DataFrame) -> pd.Series:
        return df["cvss_score"].astype(float)


@dataclass(frozen=True)
class EpssRanker:
    name: str = "EPSS"

    @property
    def required_columns(self) -> tuple[str, ...]:
        return ("epss",)

    def score(self, df: pd.DataFrame) -> pd.Series:
        return df["epss"].astype(float)
