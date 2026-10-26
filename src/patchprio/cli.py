"""Командная строка.

    patchprio fetch      скачать данные из открытых источников
    patchprio baseline   рассчитать базовые линии и сформировать отчёт
"""

from __future__ import annotations

import argparse
import logging
import sys

from .collectors import epss as epss_src
from .collectors import kev as kev_src
from .collectors import nvd as nvd_src
from .config import load_config

SOURCES = ("kev", "nvd", "epss")


def cmd_fetch(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    sources = args.sources.split(",") if args.sources else list(SOURCES)
    failed: list[str] = []

    if "kev" in sources:
        try:
            kev_src.fetch_kev(cfg.raw_dir, force=args.force)
        except Exception as exc:  # noqa: BLE001
            logging.error("KEV: %s", exc)
            failed.append("kev")

    if "nvd" in sources:
        for year in cfg.nvd_years():
            try:
                nvd_src.fetch_nvd_year(cfg.raw_dir, year, force=args.force)
            except Exception as exc:  # noqa: BLE001
                logging.error("NVD %d: %s", year, exc)
                failed.append(f"nvd-{year}")

    if "epss" in sources:
        for day in cfg.snapshots:
            try:
                epss_src.fetch_epss(cfg.raw_dir, day, force=args.force)
            except Exception as exc:  # noqa: BLE001
                logging.error("EPSS %s: %s", day, exc)
                failed.append(f"epss-{day}")

    if failed:
        logging.error("не скачано: %s", ", ".join(failed))
        return 1
    logging.info("готово, данные в %s", cfg.raw_dir)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    from .evaluation.experiment import run_experiment
    from .evaluation.report import write_report

    cfg = load_config(args.config)
    result = run_experiment(cfg)
    report = write_report(result, cfg.results_dir)
    logging.info("отчёт: %s", report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="patchprio", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="config/experiment.toml",
                        help="путь к конфигурации (по умолчанию config/experiment.toml)")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_fetch = sub.add_parser("fetch", help="скачать данные")
    p_fetch.add_argument("--sources", help=f"через запятую из: {', '.join(SOURCES)}")
    p_fetch.add_argument("--force", action="store_true", help="скачать заново")
    p_fetch.set_defaults(func=cmd_fetch)

    p_base = sub.add_parser("baseline", help="рассчитать базовые линии CVSS и EPSS")
    p_base.set_defaults(func=cmd_baseline)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
