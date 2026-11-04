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


# --- Формула критичности ---------------------------------------------------

from patchprio.fstec import InfraProfile, criticality, fstec_scores, level  # noqa: E402


def test_methodology_example_1():
    # Пример 1 методики: межсетевой экран, 10-50% узлов, из интернета,
    # CVSS 8.8, эксплойта нет, повышение привилегий
    infra = InfraProfile(component="firewall", share="10-50", internet=True)
    assert infra.i_infr == pytest.approx(0.9)
    v = criticality(8.8, 0.1, 0.5, infra.i_infr)
    assert v == pytest.approx(4.752)
    assert level(v) == "Средний"


def test_methodology_example_2():
    # Пример 2: компоненты важных процессов, >70% узлов, из интернета,
    # CVSS 9.8, эксплуатируется в атаках, выполнение кода
    infra = InfraProfile(component="critical_process", share=">70", internet=True)
    assert infra.i_infr == pytest.approx(1.08)
    v = criticality(9.8, 0.6, 0.5, infra.i_infr)
    assert v == pytest.approx(11.6424)
    assert level(v) == "Критический"


def test_level_boundaries():
    assert level(8.01) == "Критический"
    assert level(8.0) == "Высокий"
    assert level(5.0) == "Высокий"
    assert level(4.99) == "Средний"
    assert level(2.0) == "Средний"
    assert level(1.99) == "Низкий"
    assert level(float("nan")) is None


def test_fstec_scores_uses_exploit_and_h():
    df = pd.DataFrame({
        "cvss_score": [9.8, 9.8, 5.0],
        "has_exploit": [1, 0, 0],
        "fstec_h": [0.5, 0.5, None],
    })
    v = fstec_scores(df).tolist()
    assert v[0] == pytest.approx(9.8 * (0.3 + 0.5))
    assert v[1] == pytest.approx(9.8 * (0.1 + 0.5))
    # Тип последствия не определён: H = 0
    assert v[2] == pytest.approx(5.0 * 0.1)


def test_fstec_scores_without_exploit_column():
    df = pd.DataFrame({"cvss_score": [7.0], "fstec_h": [0.3]})
    assert fstec_scores(df).iloc[0] == pytest.approx(7.0 * (0.1 + 0.3))
