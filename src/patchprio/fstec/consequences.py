"""Показатель последствий H из методики ФСТЭК (таблица 1, п. 17).

Методика задаёт 12 типов последствий со своими значениями H, но не
говорит, как определить тип автоматически: в примере он выбирается
«исходя из описания уязвимости». Здесь тип определяется так:

1. По типу слабости CWE, по таблице config/fstec_cwe_consequences.csv.
   Если у уязвимости несколько CWE, берётся наибольшее H (п. 17:
   «присваивается наибольшее из значений»).
2. Если ни один CWE не сопоставлен (CWE нет, он слишком общий или
   редкий), тип определяется по вектору CVSS: высокий ущерб
   конфиденциальности, целостности или доступности. Берётся наибольшее.
3. Если нет и CVSS, тип не определён.

В колонке consequence_source записывается, каким способом определён тип:
это нужно, чтобы оценить, насколько надёжен результат.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

# Таблица 1 методики: тип последствия -> H
FSTEC_H: dict[str, float] = {
    "Выполнение произвольного кода": 0.5,
    "Повышение привилегий": 0.5,
    "Обход механизмов безопасности": 0.4,
    "Внедрение кода": 0.34,
    "Получение конфиденциальной информации": 0.3,
    "Нарушение целостности данных": 0.3,
    "Отказ в обслуживании": 0.26,
    "Перезапись произвольных файлов": 0.22,
    "Запись локальных файлов": 0.2,
    "Чтение локальных файлов": 0.18,
    "Поддельный пользовательский интерфейс": 0.12,
    "Межсайтовый скриптинг": 0.1,
}

BY_CVSS = "по CVSS"

# Ущерб по вектору CVSS -> тип последствия.
# Порядок важен: при равном H выбирается тот, что раньше в списке.
CVSS_IMPACTS = [
    ("conf_impact", "Получение конфиденциальной информации"),
    ("integ_impact", "Нарушение целостности данных"),
    ("avail_impact", "Отказ в обслуживании"),
]
# Значения, которые считаются значимым ущербом (CVSS 3.x и 4.0 / CVSS 2.0)
SIGNIFICANT = {"HIGH", "COMPLETE"}
MINOR = {"LOW", "PARTIAL"}


def load_cwe_mapping(path: str | Path) -> dict[str, str]:
    """Читает таблицу CWE -> тип последствия.

    Строки с типом «по CVSS» в результат не попадают: для таких CWE
    тип определяется по вектору CVSS. Неизвестный тип последствия
    считается ошибкой в таблице.
    """
    table = pd.read_csv(path)
    mapping: dict[str, str] = {}
    for _, row in table.iterrows():
        consequence = str(row["consequence"]).strip()
        if consequence == BY_CVSS:
            continue
        if consequence not in FSTEC_H:
            raise ValueError(f"{path}: неизвестный тип последствия для {row['cwe']}: '{consequence}'")
        mapping[str(row["cwe"]).strip()] = consequence
    return mapping


def _by_cwe(cwes: str, mapping: dict[str, str]) -> str | None:
    candidates = [mapping[c] for c in str(cwes or "").split(";") if c in mapping]
    if not candidates:
        return None
    return max(candidates, key=lambda c: FSTEC_H[c])


def _by_cvss(row: pd.Series) -> str | None:
    for level in (SIGNIFICANT, MINOR):
        candidates = [c for col, c in CVSS_IMPACTS if str(row.get(col) or "").upper() in level]
        if candidates:
            # max с ключом H; при равенстве остаётся первый по порядку CVSS_IMPACTS
            return max(candidates, key=lambda c: FSTEC_H[c])
    return None


def assign_consequences(nvd: pd.DataFrame, mapping: dict[str, str]) -> pd.DataFrame:
    """Добавляет колонки consequence, fstec_h, consequence_source."""
    df = nvd.copy()
    cwes = df["cwes"] if "cwes" in df else df.get("cwe", pd.Series("", index=df.index))
    by_cwe = cwes.fillna("").map(lambda s: _by_cwe(s, mapping))

    consequence = by_cwe.copy()
    source = pd.Series("CWE", index=df.index).where(by_cwe.notna())

    missing = consequence.isna()
    if missing.any():
        by_cvss = df.loc[missing].apply(_by_cvss, axis=1)
        consequence.loc[missing] = by_cvss
        source.loc[missing] = by_cvss.notna().map({True: "CVSS", False: "не определён"})

    df["consequence"] = consequence
    df["fstec_h"] = consequence.map(FSTEC_H)
    df["consequence_source"] = source
    return df
