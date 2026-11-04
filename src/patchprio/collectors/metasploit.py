"""Metasploit Framework: модули атак, привязанные к CVE.

Список модулей берётся из файла db/modules_metadata_base.json в
репозитории rapid7/metasploit-framework. В нём есть ссылки на CVE,
но нет даты появления модуля: поле disclosure_date означает дату
раскрытия самой уязвимости, а не дату, когда написали модуль.

Поэтому дата появления модуля берётся из истории репозитория: момент,
когда файл модуля попал в основную ветку master. Для этого делается
облегчённый клон (только история, без содержимого файлов, ~100 МБ),
из него извлекаются даты, после чего клон удаляется.

Если модуль когда-то переносили в другую папку, датой считается
дата переноса, то есть более поздняя. Это осторожная оценка: она
может занизить число эксплойтов, но не подсмотрит в будущее.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

import pandas as pd

from .base import download

log = logging.getLogger(__name__)

REPO_URL = "https://github.com/rapid7/metasploit-framework.git"
METADATA_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
)


def msf_dir(raw_dir: Path) -> Path:
    return Path(raw_dir) / "metasploit"


def metadata_path(raw_dir: Path) -> Path:
    return msf_dir(raw_dir) / "modules_metadata_base.json"


def dates_path(raw_dir: Path) -> Path:
    return msf_dir(raw_dir) / "module_dates.csv"


def _git(*args: str) -> str:
    result = subprocess.run(["git", *args], check=True, capture_output=True, text=True)
    return result.stdout


def parse_added_log(text: str) -> pd.DataFrame:
    """Разбирает вывод git log: строки '@<дата>' и под ними пути файлов.

    Колонки: path, added. Если файл добавляли несколько раз (удалили и
    вернули), берётся самая ранняя дата.
    """
    rows = []
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("@"):
            current = line[1:]
        elif current is not None:
            rows.append((line, current))
    df = pd.DataFrame(rows, columns=["path", "added"])
    df["added"] = pd.to_datetime(df["added"], utc=True).dt.tz_convert(None)
    return df.groupby("path", as_index=False)["added"].min()


def fetch_metasploit(raw_dir: Path, *, force: bool = False) -> Path:
    out_dir = msf_dir(raw_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    download(METADATA_URL, metadata_path(raw_dir), force=force)

    dates = dates_path(raw_dir)
    if dates.exists() and not force:
        log.info("уже скачано: %s", dates)
        return dates

    repo = out_dir / "repo.git"
    if repo.exists():
        shutil.rmtree(repo)
    log.info("клонирую историю Metasploit (около 100 МБ)")
    _git("clone", "--quiet", "--bare", "--filter=blob:none", "--single-branch",
         "--branch", "master", REPO_URL, str(repo))
    try:
        # --first-parent -m: дата слияния в master, а не дата коммита в ветке автора
        text = _git("-C", str(repo), "log", "--first-parent", "-m", "--diff-filter=A",
                    "--no-renames", "--format=@%cI", "--name-only", "--", "modules/")
        parse_added_log(text).to_csv(dates, index=False)
    finally:
        shutil.rmtree(repo, ignore_errors=True)
    return dates


def load_metasploit(raw_dir: Path) -> pd.DataFrame:
    """Первая дата появления модуля Metasploit для каждой CVE.

    Колонки: cve_id, exploit_date.
    """
    with metadata_path(raw_dir).open(encoding="utf-8") as fh:
        modules = json.load(fh)
    dates = pd.read_csv(dates_path(raw_dir), parse_dates=["added"])

    rows = [
        {"path": m["path"].lstrip("/"), "cve_id": ref.upper()}
        for m in modules.values()
        for ref in m.get("references") or []
        if ref.upper().startswith("CVE-")
    ]
    df = pd.DataFrame(rows, columns=["path", "cve_id"]).merge(dates, on="path", how="inner")
    first = df.groupby("cve_id", as_index=False)["added"].min()
    return first.rename(columns={"added": "exploit_date"}).reset_index(drop=True)
