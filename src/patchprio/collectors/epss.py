"""Exploit Prediction Scoring System (EPSS).

Ежедневные оценки вероятности эксплуатации уязвимости в течение
30 дней. Используются исторические файлы на дату среза, поэтому
в признаки не попадает информация из будущего.

Важно: модель EPSS менялась (v1 с 2021-04, v2 с 2022-02, v3 с 2023-03,
v4 с 2025-03). На каждую дату берётся та версия, которая была
опубликована в тот день, то есть ровно то, что видел бы специалист.
"""

from __future__ import annotations

import gzip
from datetime import date
from pathlib import Path

import pandas as pd

from .base import download_first

EPSS_URLS = [
    "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz",
    # Прежний адрес хранилища (до переезда в 2025 году)
    "https://epss.cyentia.com/epss_scores-{date}.csv.gz",
]


def epss_path(raw_dir: Path, day: date) -> Path:
    return Path(raw_dir) / "epss" / f"epss_scores-{day.isoformat()}.csv.gz"


def fetch_epss(raw_dir: Path, day: date, *, force: bool = False) -> Path:
    urls = [u.format(date=day.isoformat()) for u in EPSS_URLS]
    return download_first(urls, epss_path(raw_dir, day), force=force)


def load_epss(path: Path) -> pd.DataFrame:
    """Колонки: cve_id, epss, percentile (если есть в файле).

    Первая строка файла может быть комментарием вида
    `#model_version:v2023.03.01,score_date:...`, её сохраняем в attrs.
    """
    model_version = None
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        first = fh.readline()
    if first.startswith("#"):
        for part in first.lstrip("#").strip().split(","):
            key, _, value = part.partition(":")
            if key == "model_version":
                model_version = value

    df = pd.read_csv(path, comment="#", compression="gzip")
    df = df.rename(columns={"cve": "cve_id"})
    df["cve_id"] = df["cve_id"].str.strip().str.upper()
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    df.attrs["model_version"] = model_version
    return df
