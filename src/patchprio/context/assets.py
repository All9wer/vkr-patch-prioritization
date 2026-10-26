"""Сведения об активе, которые не учитывают CVSS и EPSS.

Это внутренний контекст из постановки задачи: одна и та же уязвимость
на сервере, доступном из интернета, и на изолированном тестовом стенде
имеет разный приоритет.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Exposure(str, Enum):
    INTERNET = "internet"       # доступен из интернета
    INTERNAL = "internal"       # доступен из внутренней сети
    ISOLATED = "isolated"       # изолированный сегмент


class Criticality(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AssetContext:
    asset_id: str
    exposure: Exposure = Exposure.INTERNAL
    criticality: Criticality = Criticality.MEDIUM
    # Компенсирующие меры: WAF, сегментация, отключённый уязвимый модуль и т.п.
    compensating_controls: list[str] = field(default_factory=list)
    # Трудоёмкость устранения: требуется ли перезапуск, есть ли окно обслуживания
    requires_restart: bool = False
    has_maintenance_window: bool = True
    # Установленное ПО: используется для сопоставления с уязвимостями
    software: list[dict[str, str]] = field(default_factory=list)
