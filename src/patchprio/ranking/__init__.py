"""Способы ранжирования уязвимостей.

Базовые линии (`baselines.py`) задают уровень, который разрабатываемая
модель обязана превзойти. Сама модель приоритизации с учётом контекста
инфраструктуры добавляется на этапе главы 2.
"""

from .base import Ranker
from .baselines import CvssRanker, EpssRanker, RandomRanker

__all__ = ["Ranker", "RandomRanker", "CvssRanker", "EpssRanker"]
