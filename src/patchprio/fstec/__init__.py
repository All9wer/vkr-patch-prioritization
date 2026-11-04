"""Методика ФСТЭК России оценки уровня критичности уязвимостей (30.06.2025).

consequences.py: показатель последствий H, тип последствия по CWE или CVSS.
criticality.py:  формула V, показатель инфраструктуры, уровни критичности.
"""

from .consequences import FSTEC_H, assign_consequences, load_cwe_mapping
from .criticality import InfraProfile, criticality, fstec_scores, level

__all__ = [
    "FSTEC_H",
    "InfraProfile",
    "assign_consequences",
    "criticality",
    "fstec_scores",
    "level",
    "load_cwe_mapping",
]
