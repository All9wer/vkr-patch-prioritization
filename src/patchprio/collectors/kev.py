"""Каталог CISA Known Exploited Vulnerabilities (KEV).

Перечень уязвимостей с подтверждённой эксплуатацией. У каждой записи
есть дата добавления в каталог: она используется как разметка
("уязвимость начали эксплуатировать") при ретроспективной проверке.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .base import download_first

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Официальное зеркало CISA на GitHub
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]

KEV_FILENAME = "kev.json"


def fetch_kev(raw_dir: Path, *, force: bool = False) -> Path:
    return download_first(KEV_URLS, Path(raw_dir) / KEV_FILENAME, force=force)


def load_kev(path: Path) -> pd.DataFrame:
    """Колонки: cve_id, date_added, ransomware."""
    with Path(path).open(encoding="utf-8") as fh:
        raw = json.load(fh)

    rows = [
        {
            "cve_id": v["cveID"].strip().upper(),
            "date_added": v["dateAdded"],
            "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
        }
        for v in raw["vulnerabilities"]
    ]
    df = pd.DataFrame(rows)
    df["date_added"] = pd.to_datetime(df["date_added"])
    df = df.sort_values("date_added").drop_duplicates("cve_id", keep="first")
    df.attrs["catalog_version"] = raw.get("catalogVersion")
    return df.reset_index(drop=True)
