"""Записи об уязвимостях NVD.

Используются годовые фиды в формате NVD API 2.0, которые ежедневно
собирает проект fkie-cad/nvd-json-data-feeds (GitHub). Это избавляет
от постраничной выгрузки через API NVD с его ограничениями частоты.

Ограничение: фид отражает текущее состояние записи. Оценка CVSS могла
быть выставлена или изменена позже даты среза (см. docs/methodology.md).
"""

from __future__ import annotations

import json
import lzma
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

from .base import download

FEED_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"

# Порядок предпочтения версий CVSS: для периода 2021-2023 основная версия 3.x
CVSS_PREFERENCE = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]


def feed_path(raw_dir: Path, year: int) -> Path:
    return Path(raw_dir) / "nvd" / f"CVE-{year}.json.xz"


def fetch_nvd_year(raw_dir: Path, year: int, *, force: bool = False) -> Path:
    return download(FEED_URL.format(year=year), feed_path(raw_dir, year), force=force)


def _pick_cvss(metrics: dict[str, Any]) -> dict[str, Any] | None:
    for key in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = [e for e in entries if e.get("type") == "Primary"]
        chosen = (primary or entries)[0]
        data = chosen.get("cvssData", {})
        return {
            "cvss_version": data.get("version"),
            "cvss_score": data.get("baseScore"),
            "cvss_severity": data.get("baseSeverity") or chosen.get("baseSeverity"),
            "cvss_vector": data.get("vectorString"),
            "attack_vector": data.get("attackVector") or data.get("accessVector"),
            "attack_complexity": data.get("attackComplexity") or data.get("accessComplexity"),
            "privileges_required": data.get("privilegesRequired") or data.get("authentication"),
            "user_interaction": data.get("userInteraction"),
        }
    return None


def _pick_cwe(item: dict[str, Any]) -> str | None:
    for weakness in item.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value")
            if value and value.startswith("CWE-"):
                return value
    return None


def _pick_description(item: dict[str, Any]) -> str | None:
    for desc in item.get("descriptions") or []:
        if desc.get("lang") == "en":
            return desc.get("value")
    return None


def parse_nvd_item(item: dict[str, Any]) -> dict[str, Any] | None:
    """Приводит запись NVD к плоскому словарю. Отозванные записи пропускает."""
    status = item.get("vulnStatus")
    if status == "Rejected":
        return None

    row: dict[str, Any] = {
        "cve_id": item["id"].strip().upper(),
        "published": item.get("published"),
        "vuln_status": status,
        "cwe": _pick_cwe(item),
        "description": _pick_description(item),
        "n_references": len(item.get("references") or []),
    }
    cvss = _pick_cvss(item.get("metrics") or {})
    if cvss:
        row.update(cvss)
    return row


def iter_feed(path: Path) -> Iterable[dict[str, Any]]:
    with lzma.open(path, "rt", encoding="utf-8") as fh:
        raw = json.load(fh)
    yield from raw.get("cve_items") or raw.get("vulnerabilities") or []


def load_nvd(paths: Iterable[Path]) -> pd.DataFrame:
    rows = []
    for path in paths:
        for item in iter_feed(path):
            parsed = parse_nvd_item(item)
            if parsed:
                rows.append(parsed)

    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"]).dt.tz_localize(None)
    df["cvss_score"] = pd.to_numeric(df.get("cvss_score"), errors="coerce")
    return df.drop_duplicates("cve_id", keep="last").reset_index(drop=True)
