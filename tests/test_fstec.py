from pathlib import Path

import pandas as pd
import pytest

from patchprio.fstec import FSTEC_H, assign_consequences, load_cwe_mapping

MAPPING_CSV = """cwe,cwe_name,consequence,h,confidence,rationale
CWE-79,XSS,Межсайтовый скриптинг,0.1,высокая,x
CWE-78,Внедрение команд ОС,Выполнение произвольного кода,0.5,высокая,x
CWE-476,Нулевой указатель,Отказ в обслуживании,0.26,высокая,x
CWE-20,Проверка входных данных,по CVSS,,нет,x
"""


@pytest.fixture
def mapping(tmp_path):
    path = tmp_path / "map.csv"
    path.write_text(MAPPING_CSV, encoding="utf-8")
    return load_cwe_mapping(path)


def test_load_mapping_skips_by_cvss(mapping):
    assert mapping == {
        "CWE-79": "Межсайтовый скриптинг",
        "CWE-78": "Выполнение произвольного кода",
        "CWE-476": "Отказ в обслуживании",
    }


def test_load_mapping_rejects_unknown_type(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("cwe,consequence\nCWE-1,Что-то своё\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_cwe_mapping(path)


def test_real_mapping_file_is_valid():
    path = Path(__file__).resolve().parents[1] / "config" / "fstec_cwe_consequences.csv"
    mapping = load_cwe_mapping(path)
    table = pd.read_csv(path)
    assert table["cwe"].is_unique
    # Значение h в таблице совпадает с методикой
    for _, row in table[table["consequence"] != "по CVSS"].iterrows():
        assert FSTEC_H[row["consequence"]] == pytest.approx(row["h"])
    assert len(mapping) > 0


def test_assign_consequences(mapping):
    nvd = pd.DataFrame({
        "cve_id": ["A", "B", "C", "D", "E"],
        # B: два CWE, берётся наибольшее H
        # C: CWE «по CVSS», D: CWE нет, E: нет ни CWE, ни CVSS
        "cwes": ["CWE-79", "CWE-79;CWE-78", "CWE-20", "", ""],
        "conf_impact": [None, None, "LOW", "HIGH", None],
        "integ_impact": [None, None, "NONE", "HIGH", None],
        "avail_impact": [None, None, "HIGH", "NONE", None],
    })
    df = assign_consequences(nvd, mapping).set_index("cve_id")

    assert df.loc["A", "consequence"] == "Межсайтовый скриптинг"
    assert df.loc["B", "consequence"] == "Выполнение произвольного кода"
    assert df.loc["B", "fstec_h"] == 0.5
    # Значимый ущерб только доступности: отказ в обслуживании
    assert df.loc["C", "consequence"] == "Отказ в обслуживании"
    assert df.loc["C", "consequence_source"] == "CVSS"
    # Значимый ущерб конфиденциальности и целостности, H равны: первый по порядку
    assert df.loc["D", "consequence"] == "Получение конфиденциальной информации"
    assert pd.isna(df.loc["E", "consequence"])
    assert df.loc["E", "consequence_source"] == "не определён"
    assert df["consequence_source"].tolist() == ["CWE", "CWE", "CVSS", "CVSS", "не определён"]
