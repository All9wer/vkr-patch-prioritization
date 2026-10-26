"""Нейтральные реализации задач без языковой модели.

Используются, пока провайдер не подключён. Они не влияют на
ранжирование: система работает как без интеллектуального слоя.
"""

from __future__ import annotations

from typing import Any

from .base import ApplicabilityVerdict, ExploitationSignals


class NeutralApplicabilityAssessor:
    def assess(self, vulnerability: dict[str, Any], asset: dict[str, Any]) -> ApplicabilityVerdict:
        return ApplicabilityVerdict(applicable=None, source="fallback")


class EmptySignalExtractor:
    def extract(self, cve_id: str, text: str) -> ExploitationSignals:
        return ExploitationSignals()


class TemplateExplainer:
    """Обоснование по шаблону из числовых признаков, без модели."""

    def explain(self, vulnerability: dict[str, Any], features: dict[str, Any], rank: int) -> str:
        parts = [f"{vulnerability.get('cve_id', '?')}: позиция {rank} в очереди."]
        if features.get("cvss_score") is not None:
            parts.append(f"CVSS {features['cvss_score']}.")
        if features.get("epss") is not None:
            parts.append(f"Вероятность эксплуатации по EPSS {features['epss']:.1%}.")
        return " ".join(parts)
