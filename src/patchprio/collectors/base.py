"""Общие функции скачивания с кэшированием."""

from __future__ import annotations

import logging
import shutil
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

USER_AGENT = "patchprio/0.1 (research; vulnerability prioritization thesis)"


def download(url: str, dest: Path, *, force: bool = False, timeout: int = 120) -> Path:
    """Скачивает файл по URL в dest.

    Если файл уже существует и force=False, повторно не скачивает.
    Запись идёт во временный файл, который переименовывается только
    после успешного завершения, чтобы не оставлять обрезанных файлов.
    """
    dest = Path(dest)
    if dest.exists() and not force:
        log.info("уже скачано: %s", dest)
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")

    log.info("скачиваю %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp, tmp.open("wb") as out:
        shutil.copyfileobj(resp, out)

    tmp.replace(dest)
    return dest


def download_first(urls: list[str], dest: Path, *, force: bool = False) -> Path:
    """Пробует несколько адресов по очереди (основной источник и зеркала)."""
    errors: list[str] = []
    for url in urls:
        try:
            return download(url, dest, force=force)
        except Exception as exc:  # noqa: BLE001 - пробуем следующий адрес
            log.warning("не удалось скачать %s: %s", url, exc)
            errors.append(f"{url}: {exc}")
    raise RuntimeError("все источники недоступны:\n" + "\n".join(errors))
