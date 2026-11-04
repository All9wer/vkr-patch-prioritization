"""Уровень критичности уязвимости по методике ФСТЭК (30.06.2025).

    V = Icvss × Iinfr × (Iat + Iimp)                     (п. 12)
    Iinfr = k·K + l·L + p·P,  k = 0,5; l = 0,2; p = 0,3   (п. 14)
    Iat = e·E,  e = 1,0                                   (п. 16)
    Iimp = h·H, h = 1,0                                   (п. 17)

Ниже в таблицах сразу хранятся взвешенные значения k·K, l·L и p·P,
так же, как они приводятся в примерах расчёта методики.

В ретроспективном эксперименте инфраструктура неизвестна. Iinfr
одинаков для всех уязвимостей среза, поэтому на порядок в очереди
не влияет. Для уровней критичности используется типовой профиль
инфраструктуры, заданный в config/experiment.toml.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

# Тип компонента, k·K (таблица 1).
# В тексте методики для «других компонентов» итог напечатан как 0,5,
# хотя 0,5 × 0,1 = 0,05: здесь используется 0,05.
COMPONENT = {
    "critical_process": 0.55,   # компоненты, обеспечивающие важные процессы
    "firewall": 0.45,           # межсетевые экраны
    "network": 0.45,            # сетевые устройства и шлюзы
    "telecom": 0.40,            # телекоммуникационное оборудование, СУ сетью
    "server": 0.35,             # серверы
    "workstation": 0.25,        # пользовательские устройства (АРМ)
    "storage": 0.20,            # системы хранения данных
    "other": 0.05,              # другие компоненты
}

# Доля уязвимых компонентов, l·L
SHARE = {
    ">70": 0.20,
    "50-70": 0.16,
    "10-50": 0.12,
    "<10": 0.10,
}

# Влияние на периметр, p·P
PERIMETER = {
    True: 0.33,    # доступен из интернета
    False: 0.18,   # не доступен из интернета
}

# Эксплуатация, E (e = 1,0)
E_IN_THE_WILD = 0.6     # эксплуатируется в реальных атаках
E_EXPLOIT = 0.3         # есть сведения о наличии эксплойта
E_NONE = 0.1            # сведений нет

# Уровни критичности (таблица 2) и рекомендуемые сроки устранения (п. 21)
LEVEL_ORDER = ["Критический", "Высокий", "Средний", "Низкий"]
DEADLINES = {
    "Критический": "до 24 часов",   # V > 8,0
    "Высокий": "до 7 дней",          # 5,0 <= V <= 8,0
    "Средний": "до 4 недель",        # 2,0 <= V < 5,0
    "Низкий": "до 4 месяцев",        # V < 2,0
}


@dataclass(frozen=True)
class InfraProfile:
    """Описание инфраструктуры для показателя Iinfr."""

    component: str = "server"
    share: str = "10-50"
    internet: bool = True

    @property
    def i_infr(self) -> float:
        return COMPONENT[self.component] + SHARE[self.share] + PERIMETER[self.internet]

    def describe(self) -> str:
        names = {
            "critical_process": "компоненты важных процессов", "firewall": "межсетевой экран",
            "network": "сетевое устройство", "telecom": "телекоммуникационное оборудование",
            "server": "сервер", "workstation": "АРМ", "storage": "СХД", "other": "другой компонент",
        }
        where = "доступен из интернета" if self.internet else "не доступен из интернета"
        return f"{names[self.component]}, уязвимо {self.share}% узлов, {where} (Iinfr = {self.i_infr:.2f})"


def exploitation_factor(df: pd.DataFrame) -> pd.Series:
    """E по данным среза.

    Эксплойт на дату среза (колонка has_exploit) даёт 0,3, иначе 0,1.
    Вариант 0,6 («эксплуатируется в реальных атаках») в срезе не
    встречается: такие уязвимости уже есть в KEV и из среза исключены.
    """
    if "has_exploit" not in df:
        return pd.Series(E_NONE, index=df.index)
    return df["has_exploit"].fillna(0).astype(int).map({1: E_EXPLOIT, 0: E_NONE})


def criticality(icvss, iat, iimp, i_infr: float = 1.0):
    """V = Icvss × Iinfr × (Iat + Iimp). Работает и с числами, и с колонками."""
    return icvss * i_infr * (iat + iimp)


def level(v: float) -> str | None:
    """Уровень критичности по значению V (таблица 2)."""
    if v is None or np.isnan(v):
        return None
    if v > 8.0:
        return "Критический"
    if v >= 5.0:
        return "Высокий"
    if v >= 2.0:
        return "Средний"
    return "Низкий"


def fstec_scores(df: pd.DataFrame, i_infr: float = 1.0) -> pd.Series:
    """V для каждой уязвимости среза.

    Если тип последствия не определён, H = 0 (вклад только эксплуатации).
    """
    h = df["fstec_h"].fillna(0.0) if "fstec_h" in df else pd.Series(0.0, index=df.index)
    return criticality(df["cvss_score"].astype(float), exploitation_factor(df), h, i_infr)
