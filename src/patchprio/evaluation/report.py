"""Формирование отчёта по эксперименту: таблицы CSV, график, Markdown."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from .experiment import ExperimentResult  # noqa: E402

# Цвет закреплён за способом ранжирования, а не за порядком на графике,
# чтобы на всех графиках работы один способ был одного цвета.
COLORS = {
    "Случайный порядок": "#8a8a85",
    "CVSS": "#2a78d6",
    "EPSS": "#eb6834",
    "Разрабатываемая модель": "#1baf7a",
}
SURFACE = "#fcfcfb"
TEXT = "#2b2b29"
MUTED = "#6b6b66"
GRID = "#e6e5e0"


def _pct(x: float) -> str:
    return "н/д" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x * 100:.1f}%"


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def plot_coverage(result: ExperimentResult, path: Path, x_max: float = 0.6) -> None:
    grid = np.linspace(0, x_max, 201)
    fig, ax = plt.subplots(figsize=(8, 5), dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    for name, curves in result.curves.items():
        mean = np.mean([np.interp(grid, x, y) for x, y in curves], axis=0)
        style = "--" if name == "Случайный порядок" else "-"
        color = COLORS.get(name, TEXT)
        ax.plot(grid * 100, mean * 100, style, color=color, linewidth=2, label=name)
        ax.annotate(
            name, (grid[-1] * 100, mean[-1] * 100), xytext=(6, 0),
            textcoords="offset points", va="center", color=TEXT, fontsize=9,
        )

    if not result.policies.empty:
        pol = result.policies.groupby("policy")[["effort_share", "coverage"]].mean()
        for policy, row in pol.iterrows():
            if row["effort_share"] > x_max:
                continue
            ax.plot(row["effort_share"] * 100, row["coverage"] * 100, "o",
                    markersize=8, color=COLORS["CVSS"], markeredgecolor=SURFACE,
                    markeredgewidth=2, zorder=5)
            ax.annotate(policy, (row["effort_share"] * 100, row["coverage"] * 100),
                        xytext=(-10, 8), textcoords="offset points", ha="right",
                        color=MUTED, fontsize=8)

    ax.set_xlim(0, x_max * 100)
    ax.set_ylim(0, 100)
    ax.set_xlabel("Доля уязвимостей, которые служба успевает устранить, %", color=TEXT)
    ax.set_ylabel("Покрытие эксплуатируемых уязвимостей, %", color=TEXT)
    ax.set_title("Покрытие при заданном объёме работ (среднее по срезам)",
                 color=TEXT, loc="left", fontsize=11)
    ax.grid(True, color=GRID, linewidth=0.8)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=MUTED)
    ax.legend(frameon=False, loc="lower right", labelcolor=TEXT)
    fig.tight_layout()
    fig.subplots_adjust(right=0.82)
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


def write_report(result: ExperimentResult, results_dir: Path) -> Path:
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    result.snapshots.to_csv(results_dir / "snapshots.csv", index=False)
    result.budgets.to_csv(results_dir / "budget_metrics.csv", index=False)
    result.efforts.to_csv(results_dir / "effort_metrics.csv", index=False)
    result.policies.to_csv(results_dir / "policy_metrics.csv", index=False)
    plot_coverage(result, results_dir / "coverage_curve.png")

    snaps = result.snapshots
    rankers = list(result.curves.keys())
    lines: list[str] = []
    lines.append("# Базовые линии приоритизации\n")
    lines.append(
        f"Сформировано: {datetime.now():%Y-%m-%d %H:%M}. "
        f"Версия каталога CISA KEV: {result.kev_version or 'н/д'}.\n"
    )
    lines.append(
        "Отчёт формируется командой `patchprio baseline`. Методика: "
        "[docs/methodology.md](../../docs/methodology.md).\n"
    )

    if not snaps["epss_available"].any():
        lines.append(
            "> **EPSS не загружен.** Базовая линия EPSS отсутствует в этом прогоне. "
            "Для её расчёта выполните `patchprio fetch --sources epss` и повторите "
            "`patchprio baseline`.\n"
        )

    lines.append("## Срезы\n")
    rows = []
    for _, s in snaps.iterrows():
        prevalence = s["n_exploited"] / s["n_total"] if s["n_total"] else 0.0
        version = s.get("epss_model_version")
        if not s["epss_available"]:
            epss_info = "нет"
        elif isinstance(version, str) and version:
            epss_info = version
        else:
            epss_info = "есть"
        rows.append([
            s["snapshot"], f"{s['window_start']} .. {s['snapshot']}",
            f"{s['n_total']:,}".replace(",", " "), str(s["n_exploited"]), _pct(prevalence),
            str(s["n_known_before_excluded"]), _pct(s["share_missing_cvss"]), str(epss_info),
        ])
    lines.append(_md_table(
        ["Срез", "Окно публикации", "CVE", "Эксплуатируемых", "Доля",
         "Исключено (уже в KEV)", "Без CVSS", "EPSS"], rows))
    lines.append("")

    b = result.budgets.groupby(["ranker", "budget_share"])[["coverage", "efficiency", "lift"]].mean()
    shares = sorted(result.budgets["budget_share"].unique())

    lines.append("## Покрытие при фиксированном бюджете\n")
    lines.append(
        "Какая доля реально эксплуатируемых уязвимостей окажется устранена, "
        "если служба успевает закрыть указанную долю всех уязвимостей. "
        "Среднее по срезам.\n"
    )
    lines.append(_md_table(
        ["Способ"] + [f"Бюджет {s * 100:g}%" for s in shares],
        [[r] + [_pct(b.loc[(r, s), "coverage"]) for s in shares] for r in rankers],
    ))
    lines.append("")

    lines.append("## Эффективность при фиксированном бюджете\n")
    lines.append("Доля эксплуатируемых среди устранённых: сколько усилий потрачено не зря.\n")
    lines.append(_md_table(
        ["Способ"] + [f"Бюджет {s * 100:g}%" for s in shares],
        [[r] + [_pct(b.loc[(r, s), "efficiency"]) for s in shares] for r in rankers],
    ))
    lines.append("")

    e = result.efforts.groupby(["ranker", "target"])["effort_share"].mean()
    targets = sorted(result.efforts["target"].unique())
    lines.append("## Объём работ для заданного покрытия\n")
    lines.append(
        "Какую долю всех уязвимостей нужно устранить, чтобы закрыть указанную "
        "долю эксплуатируемых. Меньше значит лучше.\n"
    )
    lines.append(_md_table(
        ["Способ"] + [f"Покрытие {t * 100:g}%" for t in targets],
        [[r] + [_pct(e.loc[(r, t)]) for t in targets] for r in rankers],
    ))
    lines.append("")

    if not result.policies.empty:
        p = result.policies.groupby("policy")[["effort_share", "coverage", "efficiency"]].mean()
        lines.append("## Пороговые политики CVSS\n")
        lines.append("Типовая практика \"устраняем всё выше порога\".\n")
        lines.append(_md_table(
            ["Политика", "Доля устраняемых", "Покрытие", "Эффективность"],
            [[pol, _pct(r["effort_share"]), _pct(r["coverage"]), _pct(r["efficiency"])]
             for pol, r in p.iterrows()],
        ))
        lines.append("")

    lines.append("## Кривая покрытия\n")
    lines.append("![Кривая покрытия](coverage_curve.png)\n")

    lines.append("## Как читать результат\n")
    lines.append(
        "Чем выше и левее кривая, тем лучше способ: при меньшем объёме работ "
        "он закрывает больше реально эксплуатируемых уязвимостей. Разрабатываемая "
        "модель должна превзойти обе базовые линии: CVSS как распространённую "
        "практику и EPSS как наиболее сильный открытый аналог.\n"
    )
    lines.append("## Ограничения\n")
    lines.append(
        "* Разметка по CISA KEV включает только подтверждённые случаи "
        "эксплуатации и ориентирована на ПО, используемое в США.\n"
        "* Балл CVSS взят из текущего состояния записи NVD и мог быть "
        "выставлен позже даты среза.\n"
        "* Подробнее: [docs/methodology.md](../../docs/methodology.md).\n"
    )

    report = results_dir / "baseline_report.md"
    report.write_text("\n".join(lines), encoding="utf-8")
    return report
