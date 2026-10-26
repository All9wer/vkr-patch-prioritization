"""Метрики качества приоритизации.

Постановка: у службы, устраняющей уязвимости, есть бюджет k (сколько
уязвимостей она успеет закрыть). Способ ранжирования хорош, если
в первые k позиций попадает как можно больше уязвимостей, которые
потом действительно начали эксплуатировать.

* покрытие (coverage, recall@k): доля эксплуатируемых уязвимостей,
  попавших в первые k;
* эффективность (efficiency, precision@k): доля эксплуатируемых
  среди первых k, то есть сколько из потраченных усилий было не зря;
* выигрыш (lift): во сколько раз эффективность выше случайного порядка.

Терминология coverage/efficiency совпадает с принятой в работах
по EPSS (Jacobs et al.), что упрощает сравнение с литературой.

Равные оценки. Если у нескольких уязвимостей одинаковый балл,
порядок внутри группы не определён. Вместо случайного разбиения
с фиксированным seed считается точное математическое ожидание:
из граничной группы в бюджет попадает доля (k - n_выше) / n_группы,
и столько же в среднем попадает её эксплуатируемых уязвимостей.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class TieGroups:
    """Группы равных оценок, упорядоченные по убыванию."""

    sizes: np.ndarray       # число уязвимостей в группе
    positives: np.ndarray   # число эксплуатируемых в группе

    @property
    def n(self) -> int:
        return int(self.sizes.sum())

    @property
    def n_pos(self) -> int:
        return int(self.positives.sum())


def tie_groups(scores: pd.Series, labels: pd.Series) -> TieGroups:
    s = pd.to_numeric(scores, errors="coerce").astype(float).fillna(-np.inf)
    y = pd.Series(labels.to_numpy(), index=s.index).astype(int)
    grouped = (
        pd.DataFrame({"s": s.to_numpy(), "y": y.to_numpy()})
        .groupby("s", sort=True)["y"]
        .agg(["size", "sum"])
        .iloc[::-1]
    )
    return TieGroups(
        sizes=grouped["size"].to_numpy(dtype=float),
        positives=grouped["sum"].to_numpy(dtype=float),
    )


def expected_hits_at_k(groups: TieGroups, k: int) -> float:
    """Ожидаемое число эксплуатируемых уязвимостей в первых k позициях."""
    k = max(0, min(int(k), groups.n))
    cum_n = np.cumsum(groups.sizes)
    cum_pos = np.cumsum(groups.positives)
    idx = int(np.searchsorted(cum_n, k, side="left"))
    if idx >= len(cum_n):
        return float(cum_pos[-1]) if len(cum_pos) else 0.0
    n_before = cum_n[idx - 1] if idx > 0 else 0.0
    pos_before = cum_pos[idx - 1] if idx > 0 else 0.0
    taken = k - n_before
    return float(pos_before + groups.positives[idx] * taken / groups.sizes[idx])


def effort_for_coverage(groups: TieGroups, target: float) -> int | None:
    """Минимальный бюджет k, при котором ожидаемое покрытие >= target."""
    if groups.n_pos == 0:
        return None
    need = target * groups.n_pos
    cum_n = 0.0
    cum_pos = 0.0
    for size, pos in zip(groups.sizes, groups.positives):
        if cum_pos + pos >= need - 1e-9:
            if pos == 0:
                return int(math.ceil(cum_n))
            extra = (need - cum_pos) / pos * size
            return int(math.ceil(cum_n + extra - 1e-9))
        cum_n += size
        cum_pos += pos
    return None


def coverage_curve(groups: TieGroups) -> tuple[np.ndarray, np.ndarray]:
    """Кривая "доля усилий -> покрытие".

    Точки на границах групп равных оценок. Между ними матожидание
    покрытия меняется линейно, поэтому линейная интерполяция точна.
    """
    if groups.n == 0 or groups.n_pos == 0:
        return np.array([0.0, 1.0]), np.array([0.0, 0.0])
    x = np.concatenate([[0.0], np.cumsum(groups.sizes) / groups.n])
    y = np.concatenate([[0.0], np.cumsum(groups.positives) / groups.n_pos])
    return x, y


def budget_metrics(groups: TieGroups, k: int) -> dict[str, float]:
    hits = expected_hits_at_k(groups, k)
    prevalence = groups.n_pos / groups.n if groups.n else 0.0
    efficiency = hits / k if k else 0.0
    return {
        "budget": int(k),
        "hits": hits,
        "coverage": hits / groups.n_pos if groups.n_pos else 0.0,
        "efficiency": efficiency,
        "lift": efficiency / prevalence if prevalence else float("nan"),
    }


def policy_metrics(mask: pd.Series, labels: pd.Series) -> dict[str, float]:
    """Метрики пороговой политики "закрываем всё, что отмечено mask"."""
    mask = mask.fillna(False).astype(bool).to_numpy()
    y = labels.astype(int).to_numpy()
    n, n_pos = len(y), int(y.sum())
    effort = int(mask.sum())
    hits = int(y[mask].sum())
    prevalence = n_pos / n if n else 0.0
    efficiency = hits / effort if effort else 0.0
    return {
        "effort": effort,
        "effort_share": effort / n if n else 0.0,
        "hits": hits,
        "coverage": hits / n_pos if n_pos else 0.0,
        "efficiency": efficiency,
        "lift": efficiency / prevalence if prevalence else float("nan"),
    }
