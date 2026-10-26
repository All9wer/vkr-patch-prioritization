"""Контекст инфраструктуры: модель актива.

Статус: модель данных. Источник сведений об активах (стенд, данные
сканера, CMDB) определяется на этапе главы 2 и 3.
"""

from .assets import AssetContext, Criticality, Exposure

__all__ = ["AssetContext", "Criticality", "Exposure"]
