"""Ретроспективный эксперимент: базовые линии CVSS и EPSS.

Для каждой даты среза строится совокупность уязвимостей, каждый способ
ранжирования упорядочивает её, после чего считается, сколько реально
эксплуатируемых уязвимостей попало в начало очереди при разных
бюджетах устранения. Результаты сохраняются в experiments/results.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from ..collectors import epss as epss_src
from ..collectors import kev as kev_src
from ..collectors import nvd as nvd_src
from ..config import ExperimentConfig
from ..dataset import SnapshotSpec, build_snapshot
from ..ranking import CvssRanker, EpssRanker, RandomRanker, Ranker
from .metrics import (
    budget_metrics,
    coverage_curve,
    effort_for_coverage,
    policy_metrics,
    tie_groups,
)

log = logging.getLogger(__name__)


@dataclass
class ExperimentResult:
    snapshots: pd.DataFrame
    budgets: pd.DataFrame
    efforts: pd.DataFrame
    policies: pd.DataFrame
    curves: dict[str, list[tuple[np.ndarray, np.ndarray]]] = field(default_factory=dict)
    kev_version: str | None = None


def default_rankers() -> list[Ranker]:
    return [RandomRanker(), CvssRanker(), EpssRanker()]


def _ranker_applicable(ranker: Ranker, df: pd.DataFrame) -> bool:
    return all(col in df and df[col].notna().any() for col in ranker.required_columns)


def evaluate_snapshot(
    df: pd.DataFrame,
    rankers: list[Ranker],
    cfg: ExperimentConfig,
    result: ExperimentResult,
) -> None:
    snap = df.attrs["snapshot"]
    labels = df["exploited"]
    n = len(df)

    for ranker in rankers:
        if not _ranker_applicable(ranker, df):
            log.warning("срез %s: нет данных для способа %s, пропускаю", snap, ranker.name)
            continue
        groups = tie_groups(ranker.score(df), labels)

        for share in cfg.budgets:
            k = int(round(share * n))
            row = budget_metrics(groups, k)
            row.update({"snapshot": snap, "ranker": ranker.name, "budget_share": share})
            result.budgets = pd.concat([result.budgets, pd.DataFrame([row])], ignore_index=True)

        for target in cfg.coverage_targets:
            k = effort_for_coverage(groups, target)
            row = {
                "snapshot": snap,
                "ranker": ranker.name,
                "target": target,
                "effort": k,
                "effort_share": (k / n) if (k is not None and n) else np.nan,
            }
            result.efforts = pd.concat([result.efforts, pd.DataFrame([row])], ignore_index=True)

        result.curves.setdefault(ranker.name, []).append(coverage_curve(groups))

    for threshold in cfg.cvss_policies:
        row = policy_metrics(df["cvss_score"] >= threshold, labels)
        row.update({"snapshot": snap, "policy": f"CVSS >= {threshold:g}"})
        result.policies = pd.concat([result.policies, pd.DataFrame([row])], ignore_index=True)


def load_sources(cfg: ExperimentConfig) -> tuple[pd.DataFrame, pd.DataFrame]:
    raw = cfg.raw_dir
    kev = kev_src.load_kev(raw / kev_src.KEV_FILENAME)
    paths = [nvd_src.feed_path(raw, y) for y in cfg.nvd_years()]
    existing = [p for p in paths if p.exists()]
    missing = [p.name for p in paths if not p.exists()]
    if missing:
        log.warning("нет фидов NVD: %s (запустите `patchprio fetch`)", ", ".join(missing))
    if not existing:
        raise FileNotFoundError("фиды NVD не скачаны, запустите `patchprio fetch`")
    nvd = nvd_src.load_nvd(existing)
    return nvd, kev


def run_experiment(cfg: ExperimentConfig, rankers: list[Ranker] | None = None) -> ExperimentResult:
    rankers = rankers or default_rankers()
    nvd, kev = load_sources(cfg)
    log.info("загружено записей NVD: %d, записей KEV: %d", len(nvd), len(kev))

    result = ExperimentResult(
        snapshots=pd.DataFrame(),
        budgets=pd.DataFrame(),
        efforts=pd.DataFrame(),
        policies=pd.DataFrame(),
        kev_version=kev.attrs.get("catalog_version"),
    )

    for day in cfg.snapshots:
        spec = SnapshotSpec(day, cfg.window_days, cfg.horizon_days)
        epss_file = epss_src.epss_path(cfg.raw_dir, day)
        epss = epss_src.load_epss(epss_file) if epss_file.exists() else None
        if epss is None:
            log.warning("нет файла EPSS за %s, базовая линия EPSS для среза пропущена", day)

        df = build_snapshot(nvd, kev, spec, epss)
        result.snapshots = pd.concat([result.snapshots, pd.DataFrame([df.attrs])], ignore_index=True)
        log.info(
            "срез %s: %d CVE, эксплуатируемых %d",
            day, df.attrs["n_total"], df.attrs["n_exploited"],
        )
        evaluate_snapshot(df, rankers, cfg, result)

    return result
