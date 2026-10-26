import gzip
import json
import lzma

from patchprio.collectors.epss import load_epss
from patchprio.collectors.kev import load_kev
from patchprio.collectors.nvd import load_nvd, parse_nvd_item

NVD_ITEM = {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features ..."}],
    "references": [{"url": "a"}, {"url": "b"}],
    "weaknesses": [
        {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-917"}]}
    ],
    "metrics": {
        "cvssMetricV31": [
            {"source": "other", "type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 9.0}},
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "attackVector": "NETWORK",
                },
            },
        ],
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 9.3}}],
    },
}


def test_parse_nvd_prefers_primary_v31():
    row = parse_nvd_item(NVD_ITEM)
    assert row["cvss_score"] == 10.0
    assert row["cvss_version"] == "3.1"
    assert row["attack_vector"] == "NETWORK"
    assert row["cwe"] == "CWE-917"
    assert row["n_references"] == 2


def test_parse_nvd_skips_rejected():
    assert parse_nvd_item({"id": "CVE-X", "vulnStatus": "Rejected"}) is None


def test_load_nvd_feed(tmp_path):
    path = tmp_path / "CVE-2021.json.xz"
    payload = {"cve_items": [NVD_ITEM, {"id": "CVE-2021-0001", "vulnStatus": "Rejected"}]}
    with lzma.open(path, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh)
    df = load_nvd([path])
    assert list(df["cve_id"]) == ["CVE-2021-44228"]
    assert str(df["published"].dtype).startswith("datetime64")


def test_load_kev(tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(
        json.dumps(
            {
                "catalogVersion": "2026.01.01",
                "vulnerabilities": [
                    {"cveID": "cve-2021-44228", "dateAdded": "2021-12-10",
                     "knownRansomwareCampaignUse": "Known"},
                    {"cveID": "CVE-2022-0001", "dateAdded": "2022-01-05"},
                ],
            }
        ),
        encoding="utf-8",
    )
    df = load_kev(path)
    assert df.loc[0, "cve_id"] == "CVE-2021-44228"
    assert bool(df.loc[0, "ransomware"]) is True
    assert df.attrs["catalog_version"] == "2026.01.01"


def test_load_epss_with_comment_line(tmp_path):
    path = tmp_path / "epss.csv.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("#model_version:v2023.03.01,score_date:2023-07-01T00:00:00+0000\n")
        fh.write("cve,epss,percentile\nCVE-2021-44228,0.97565,0.99996\ncve-2022-0001,0.0004,0.1\n")
    df = load_epss(path)
    assert df.attrs["model_version"] == "v2023.03.01"
    assert set(df["cve_id"]) == {"CVE-2021-44228", "CVE-2022-0001"}
    assert df["epss"].max() > 0.97
