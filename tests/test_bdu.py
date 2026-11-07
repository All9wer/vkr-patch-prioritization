import openpyxl
import pandas as pd
import pytest

from patchprio.collectors.bdu import bdu_by_cve, load_bdu_records, parse_bdu

HEADER = [
    # Порядок и названия как в реальной выгрузке vullist.xlsx (ноябрь 2026)
    "Идентификатор", "Наименование уязвимости", "Описание уязвимости", "Вендор ПО",
    "Название ПО", "Версия ПО", "Тип ПО", "Наименование ОС и тип аппаратной платформы",
    "Класс уязвимости", "Дата выявления", "CVSS 2.0", "CVSS 3.0", "CVSS 4.0",
    "Уровень опасности уязвимости", "Возможные меры по устранению", "Статус уязвимости",
    "Наличие эксплойта", "Информация об устранении", "Ссылки на источники",
    "Идентификаторы других систем описаний уязвимости", "Прочая информация",
    "Связь с инцидентами ИБ", "Способ эксплуатации", "Способ устранения",
    "Дата публикации", "Дата последнего обновления", "Последствия эксплуатации уязвимости",
    "Состояние уязвимости", "Описание ошибки CWE", "Тип ошибки CWE",
    "Идентификатор", "Наименование",
]


def _row(bdu_id, vendor, level, exploit, ids, published, consequence=""):
    row = [""] * len(HEADER)
    row[0], row[3], row[13], row[16], row[19], row[24] = bdu_id, vendor, level, exploit, ids, published
    row[26] = consequence
    return row


ROWS = [
    _row("BDU:2014-00002", "D-Link Corp.",
         "Критический уровень опасности (базовая оценка CVSS 2.0 составляет 10)",
         "Существует", "CVE-2013-5946, OSVDB ID:100840, Bugtraq ID:64172", "07.07.2016"),
    _row("BDU:2021-05812", "Apache Software Foundation",
         "Критический уровень опасности (базовая оценка CVSS 2.0 составляет 9,3), "
         "критический уровень опасности (базовая оценка CVSS 3.0 составляет 10)",
         "Существует в открытом доступе", "CVE-2021-44228", "13.12.2021",
         "Выполнение произвольного кода"),
    # Вторая запись на ту же CVE: опубликована позже, эксплойт не отмечен
    _row("BDU:2022-00001", "Apache Software Foundation",
         "Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 8,1)",
         "Данные уточняются", "CVE-2021-44228", "10.01.2022"),
    # Российское ПО без CVE
    _row("BDU:2023-01234", "ООО «РусБИТех-Астра»",
         "Средний уровень опасности (базовая оценка CVSS 3.0 составляет 5,5)",
         "Данные уточняются", "", "01.03.2023"),
]


@pytest.fixture
def xlsx(tmp_path):
    raw_dir = tmp_path
    path = raw_dir / "bdu" / "vullist.xlsx"
    path.parent.mkdir()
    wb = openpyxl.Workbook()
    ws = wb.active
    # Две строки-заголовка сверху, как в реальной выгрузке
    ws.append(["Описание уязвимостей"])
    ws.append(["Общая информация"] + [None] * 27 + ["CWE", None, "Возможные меры по устранению"])
    ws.append(HEADER)
    for row in ROWS:
        ws.append(row)
    wb.save(path)
    return raw_dir


def test_parse_bdu(xlsx):
    df = load_bdu_records(xlsx).set_index("bdu_id")
    assert len(df) == 4
    assert df.loc["BDU:2014-00002", "cve_ids"] == "CVE-2013-5946"
    assert df.loc["BDU:2014-00002", "cvss2_score"] == 10.0
    assert df.loc["BDU:2021-05812", "cvss2_score"] == 9.3
    assert df.loc["BDU:2021-05812", "cvss3_score"] == 10.0
    assert df.loc["BDU:2021-05812", "has_exploit_now"] == 1
    assert df.loc["BDU:2022-00001", "has_exploit_now"] == 0
    assert pd.isna(df.loc["BDU:2023-01234", "cve_ids"]) or df.loc["BDU:2023-01234", "cve_ids"] == ""
    assert df.loc["BDU:2021-05812", "published"] == pd.Timestamp("2021-12-13")
    assert df.loc["BDU:2021-05812", "consequence_bdu"] == "Выполнение произвольного кода"


def test_cache_is_written_and_used(xlsx):
    first = load_bdu_records(xlsx)
    cache = xlsx / "bdu" / "vullist.csv.gz"
    assert cache.exists()
    (xlsx / "bdu" / "vullist.xlsx").unlink()  # теперь читается только кэш
    second = load_bdu_records(xlsx)
    assert list(second["bdu_id"]) == list(first["bdu_id"])


def test_bdu_by_cve_combines_records(xlsx):
    by_cve = bdu_by_cve(load_bdu_records(xlsx)).set_index("cve_id")
    assert set(by_cve.index) == {"CVE-2013-5946", "CVE-2021-44228"}
    log4j = by_cve.loc["CVE-2021-44228"]
    assert log4j["bdu_first_published"] == pd.Timestamp("2021-12-13")  # самая ранняя запись
    assert log4j["bdu_exploit_now"] == 1                              # хотя бы у одной записи
    assert log4j["bdu_cvss3"] == 10.0                                 # наибольший балл


def test_missing_columns_reported():
    raw = pd.DataFrame([["Идентификатор", "Что-то ещё"], ["BDU:2020-00001", "x"]])
    with pytest.raises(ValueError, match="не найдены колонки"):
        parse_bdu(raw)
