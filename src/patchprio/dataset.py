"""Построение ретроспективного среза для эксперимента.

Срез на дату T отвечает на вопрос: какие уязвимости специалист
видел на дату T и какие из них потом действительно начали
эксплуатировать.

* совокупность: CVE, опубликованные в окне [T - window, T);
* из совокупности исключаются уязвимости, уже внесённые в KEV до T:
  их приоритет очевиден, задача прогноза в том, чтобы найти ещё
  неизвестные эксплуатируемые;
* признаки берутся на дату T (EPSS из файла за дату T);
* разметка: уязвимость внесена в KEV в интервале [T, T + horizon).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

import pandas as pd


@dataclass(frozen=True)
class SnapshotSpec:
    date: date
    window_days: int = 365
    horizon_days: int = 365

    @property
    def window_start(self) -> pd.Timestamp:
        return pd.Timestamp(self.date - timedelta(days=self.window_days))

    @property
    def t(self) -> pd.Timestamp:
        return pd.Timestamp(self.date)

    @property
    def horizon_end(self) -> pd.Timestamp:
        return pd.Timestamp(self.date + timedelta(days=self.horizon_days))


def build_snapshot(
    nvd: pd.DataFrame,
    kev: pd.DataFrame,
    spec: SnapshotSpec,
    epss: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """Возвращает таблицу среза с колонкой `exploited` (0/1).

    Служебная статистика среза сохраняется в `df.attrs`.
    """
    in_window = (nvd["published"] >= spec.window_start) & (nvd["published"] < spec.t)
    pop = nvd.loc[in_window].copy()

    kev_dates = kev.set_index("cve_id")["date_added"]
    pop["kev_date"] = pop["cve_id"].map(kev_dates)

    known_before = pop["kev_date"] < spec.t
    n_known_before = int(known_before.sum())
    pop = pop.loc[~known_before].copy()

    pop["exploited"] = (
        (pop["kev_date"] >= spec.t) & (pop["kev_date"] < spec.horizon_end)
    ).astype(int)
    pop["age_days"] = (spec.t - pop["published"]).dt.days

    if epss is not None:
        pop = pop.merge(epss[["cve_id", "epss"]], on="cve_id", how="left")
    else:
        pop["epss"] = float("nan")

    pop = pop.reset_index(drop=True)
    pop.attrs.update(
        {
            "snapshot": spec.date.isoformat(),
            "window_start": spec.window_start.date().isoformat(),
            "horizon_end": spec.horizon_end.date().isoformat(),
            "n_total": int(len(pop)),
            "n_exploited": int(pop["exploited"].sum()),
            "n_known_before_excluded": n_known_before,
            "share_missing_cvss": float(pop["cvss_score"].isna().mean()) if len(pop) else 0.0,
            "share_missing_epss": float(pop["epss"].isna().mean()) if len(pop) else 1.0,
            "epss_available": epss is not None,
            "epss_model_version": epss.attrs.get("model_version") if epss is not None else None,
        }
    )
    return pop
