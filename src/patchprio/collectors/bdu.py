"""Банк данных угроз безопасности информации ФСТЭК России (БДУ).

Выгрузка перечня уязвимостей: файл vullist.xlsx с сайта bdu.fstec.ru.
Сверху в файле есть строки-заголовки, названия колонок ниже: строка
с названиями ищется по ячейке «Идентификатор» в первой колонке.
Колонки находятся по ключевым словам в названии, поэтому небольшие
изменения формата выгрузки не ломают чтение.

Важно: выгрузка отражает текущее состояние. Отметка «Наличие эксплойта»
стоит сегодня, дата её появления неизвестна, поэтому в ретроспективных
срезах для сортировки она не используется (подглядывание в будущее).
Дата публикации записи в БДУ известна, поэтому можно определить,
была ли уязвимость описана в БДУ на дату среза.

Чтение Excel медленное, поэтому после первого чтения рядом сохраняется
копия в CSV (vullist.csv.gz) и дальше читается она.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pandas as pd

from .base import download

log = logging.getLogger(__name__)

BDU_URL = "https://bdu.fstec.ru/files/documents/vullist.xlsx"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# «...базовая оценка CVSS 3.0 составляет 9,8...»
SCORE_RE = re.compile(r"CVSS\s*(\d)\.\d\s*составляет\s*(\d+(?:[.,]\d+)?)", re.IGNORECASE)

# Колонка -> ключевые слова в названии (без учёта регистра)
COLUMNS = {
    "bdu_id": ["идентификатор"],
    "name": ["наименование уязвимости"],
    "vendor": ["вендор"],
    "product": ["название по"],
    "software_type": ["тип по"],
    "cvss2_vector": ["cvss 2"],
    "cvss3_vector": ["cvss 3"],
    "danger_level": ["уровень опасности"],
    "status": ["статус уязвимости"],
    "exploit": ["наличие эксплойта"],
    "other_ids": ["других систем"],
    "published": ["дата публикации"],
    "cwe": ["тип ошибки cwe"],
    # Появилась в выгрузке недавно, у старых записей пустая.
    # Пригодится для проверки таблицы CWE -> последствие по ФСТЭК.
    "consequence_bdu": ["последствия эксплуатации"],
}
REQUIRED = ("bdu_id", "other_ids", "exploit", "danger_level", "published")


def bdu_dir(raw_dir: Path) -> Path:
    return Path(raw_dir) / "bdu"


def xlsx_path(raw_dir: Path) -> Path:
    return bdu_dir(raw_dir) / "vullist.xlsx"


def cache_path(raw_dir: Path) -> Path:
    return bdu_dir(raw_dir) / "vullist.csv.gz"


def fetch_bdu(raw_dir: Path, *, force: bool = False) -> Path:
    """Пробует скачать выгрузку. Сайт ФСТЭК часто не пускает программы
    и иностранные адреса, тогда файл нужно скачать браузером вручную."""
    path = xlsx_path(raw_dir)
    try:
        return download(BDU_URL, path, force=force, timeout=600)
    except Exception as exc:
        raise RuntimeError(
            f"{exc}. Скачайте файл браузером с {BDU_URL} "
            f"и положите в {path}"
        ) from exc


def _match_columns(header: list[str]) -> dict[str, int]:
    found: dict[str, int] = {}
    for key, words in COLUMNS.items():
        for i, title in enumerate(header):
            t = title.lower()
            if key == "bdu_id":
                # «Идентификатор», но не «Идентификаторы других систем...»
                if t.strip() == "идентификатор":
                    found[key] = i
                    break
            elif any(w in t for w in words):
                found[key] = i
                break
    missing = [k for k in REQUIRED if k not in found]
    if missing:
        raise ValueError(
            f"в выгрузке БДУ не найдены колонки: {', '.join(missing)}. "
            f"Названия колонок в файле: {header}"
        )
    return found


def _parse_scores(text: str) -> tuple[float | None, float | None]:
    """Баллы CVSS 2.0 и 3.x из текста «Уровень опасности уязвимости»."""
    v2 = v3 = None
    for version, score in SCORE_RE.findall(text or ""):
        value = float(score.replace(",", "."))
        if version == "2":
            v2 = value
        elif version == "3":
            v3 = value
    return v2, v3


def _exploit_flag(text: str) -> int:
    """1, если эксплойт существует (в открытом доступе или нет)."""
    return int(str(text or "").strip().lower().startswith("существует"))


def parse_bdu(raw: pd.DataFrame) -> pd.DataFrame:
    """Таблица из выгрузки (без заголовка) -> одна строка на запись БДУ."""
    first_col = raw.iloc[:, 0].astype(str).str.strip().str.lower()
    header_rows = first_col.index[first_col == "идентификатор"]
    if len(header_rows) == 0:
        raise ValueError("в выгрузке БДУ не найдена строка с названиями колонок (ячейка «Идентификатор»)")
    h = header_rows[0]
    header = [str(v).strip() for v in raw.iloc[h].tolist()]
    cols = _match_columns(header)

    data = raw.iloc[h + 1:]
    data = data[data.iloc[:, cols["bdu_id"]].astype(str).str.startswith("BDU:")]
    df = pd.DataFrame({key: data.iloc[:, i].to_numpy() for key, i in cols.items()})

    df["cve_ids"] = df["other_ids"].fillna("").astype(str).map(
        lambda s: ";".join(dict.fromkeys(c.upper() for c in CVE_RE.findall(s))))
    scores = df["danger_level"].fillna("").astype(str).map(_parse_scores)
    df["cvss2_score"] = scores.map(lambda t: t[0])
    df["cvss3_score"] = scores.map(lambda t: t[1])
    df["has_exploit_now"] = df["exploit"].map(_exploit_flag)
    df["published"] = pd.to_datetime(df["published"], format="%d.%m.%Y", errors="coerce")
    df = df.drop(columns=["other_ids"])
    return df.reset_index(drop=True)


def load_bdu_records(raw_dir: Path) -> pd.DataFrame:
    """Все записи БДУ (одна строка на запись), с кэшем в CSV."""
    xlsx, cache = xlsx_path(raw_dir), cache_path(raw_dir)
    if cache.exists() and (not xlsx.exists() or cache.stat().st_mtime >= xlsx.stat().st_mtime):
        return pd.read_csv(cache, parse_dates=["published"], keep_default_na=True,
                           dtype={"cve_ids": str})
    log.info("читаю выгрузку БДУ (Excel, может занять несколько минут)")
    records = parse_bdu(pd.read_excel(xlsx, header=None, dtype=str))
    records.to_csv(cache, index=False)
    return records


def bdu_by_cve(records: pd.DataFrame) -> pd.DataFrame:
    """Сведения БДУ для каждой CVE.

    Колонки: cve_id, bdu_first_published (самая ранняя публикация в БДУ),
    bdu_exploit_now (хотя бы у одной записи сейчас отмечен эксплойт),
    bdu_cvss3 (наибольший балл CVSS 3.x среди записей).
    """
    df = records.assign(cve_id=records["cve_ids"].fillna("").str.split(";")).explode("cve_id")
    df = df[df["cve_id"].str.startswith("CVE-")]
    return (
        df.groupby("cve_id", as_index=False)
        .agg(bdu_first_published=("published", "min"),
             bdu_exploit_now=("has_exploit_now", "max"),
             bdu_cvss3=("cvss3_score", "max"))
    )
