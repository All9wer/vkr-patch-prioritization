"""Загрузка конфигурации эксперимента из TOML."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path


@dataclass(frozen=True)
class ExperimentConfig:
    raw_dir: Path
    results_dir: Path
    snapshots: list[date]
    window_days: int = 365
    horizon_days: int = 365
    budgets: list[float] = field(default_factory=lambda: [0.01, 0.05, 0.10, 0.20])
    coverage_targets: list[float] = field(default_factory=lambda: [0.5, 0.8])
    cvss_policies: list[float] = field(default_factory=lambda: [7.0, 9.0])
    llm_provider: str = "none"

    def nvd_years(self) -> list[int]:
        """Годы фидов NVD, которые нужны для всех срезов.

        Идентификатор CVE может быть зарезервирован заранее и опубликован
        позже, поэтому берём запас в два года назад от начала окна.
        """
        earliest = min(self.snapshots)
        start_year = earliest.year - (self.window_days // 365) - 2
        end_year = max(self.snapshots).year
        return list(range(start_year, end_year + 1))


def load_config(path: str | Path) -> ExperimentConfig:
    path = Path(path)
    with path.open("rb") as fh:
        raw = tomllib.load(fh)

    exp = raw.get("experiment", {})
    data = raw.get("data", {})
    llm = raw.get("llm", {})

    return ExperimentConfig(
        raw_dir=Path(data.get("raw_dir", "data/raw")),
        results_dir=Path(exp.get("results_dir", "experiments/results")),
        snapshots=[date.fromisoformat(s) for s in exp["snapshots"]],
        window_days=int(exp.get("window_days", 365)),
        horizon_days=int(exp.get("horizon_days", 365)),
        budgets=[float(b) for b in exp.get("budgets", [0.01, 0.05, 0.10, 0.20])],
        coverage_targets=[float(t) for t in exp.get("coverage_targets", [0.5, 0.8])],
        cvss_policies=[float(t) for t in exp.get("cvss_policies", [7.0, 9.0])],
        llm_provider=str(llm.get("provider", "none")),
    )
