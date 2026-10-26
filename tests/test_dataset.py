from datetime import date

import pandas as pd

from patchprio.dataset import SnapshotSpec, build_snapshot


def _nvd():
    return pd.DataFrame(
        {
            "cve_id": ["CVE-A", "CVE-B", "CVE-C", "CVE-D", "CVE-E"],
            "published": pd.to_datetime(
                ["2021-03-01", "2021-06-01", "2021-09-01", "2022-02-01", "2020-01-01"]
            ),
            "cvss_score": [9.8, 7.5, 5.0, 9.0, 8.0],
        }
    )


def _kev():
    return pd.DataFrame(
        {
            "cve_id": ["CVE-A", "CVE-B", "CVE-D"],
            "date_added": pd.to_datetime(["2021-11-03", "2022-03-01", "2022-03-01"]),
        }
    )


def test_population_and_labels():
    spec = SnapshotSpec(date(2022, 1, 1), window_days=365, horizon_days=365)
    df = build_snapshot(_nvd(), _kev(), spec)

    # CVE-D опубликована после среза, CVE-E вне окна
    # CVE-A уже была в KEV до среза: исключается
    assert set(df["cve_id"]) == {"CVE-B", "CVE-C"}
    assert df.set_index("cve_id")["exploited"].to_dict() == {"CVE-B": 1, "CVE-C": 0}
    assert df.attrs["n_known_before_excluded"] == 1
    assert df.attrs["n_exploited"] == 1


def test_horizon_limits_label():
    spec = SnapshotSpec(date(2022, 1, 1), window_days=365, horizon_days=30)
    df = build_snapshot(_nvd(), _kev(), spec)
    # CVE-B внесена в KEV через 59 дней: за пределами горизонта
    assert df["exploited"].sum() == 0


def test_epss_merge():
    spec = SnapshotSpec(date(2022, 1, 1))
    epss = pd.DataFrame({"cve_id": ["CVE-B"], "epss": [0.42]})
    df = build_snapshot(_nvd(), _kev(), spec, epss)
    scores = df.set_index("cve_id")["epss"]
    assert scores["CVE-B"] == 0.42
    assert pd.isna(scores["CVE-C"])
    assert df.attrs["epss_available"] is True
