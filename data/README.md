# Данные

Каталог для скачанных данных. Содержимое `raw/` и `processed/` не хранится в git.

```bash
patchprio fetch                  # все источники
patchprio fetch --sources epss   # только один источник
patchprio fetch --force          # скачать заново
```

После загрузки:

```
data/raw/
  kev.json
  nvd/CVE-2019.json.xz ... CVE-2023.json.xz
  epss/epss_scores-2022-01-01.csv.gz ...
```

Откуда берутся данные: [docs/methodology.md](../docs/methodology.md).
