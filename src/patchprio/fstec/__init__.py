"""Методика ФСТЭК России оценки уровня критичности уязвимостей (30.06.2025).

consequences.py: показатель последствий H, тип последствия по CWE или CVSS.
"""

from .consequences import FSTEC_H, assign_consequences, load_cwe_mapping

__all__ = ["FSTEC_H", "assign_consequences", "load_cwe_mapping"]
