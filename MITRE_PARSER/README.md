# MITRE Parser 2.0

Полнофункциональный генератор русскоязычных баз знаний по кибербезопасности
для учебного полигона. Скачивает официальные источники, парсит расширенный
набор полей, связывает объекты между собой, переводит всё на русский и
собирает две специализированные базы — атакующих инструментов и средств
защиты — на основе MITRE ATT&CK и курируемого каталога.

## Источники

| База      | Источник                                                                    | Формат      |
| --------- | --------------------------------------------------------------------------- | ----------- |
| ATT&CK    | enterprise-attack STIX 2.1 (mitre-attack/attack-stix-data)                  | JSON (STIX) |
| CAPEC     | capec.mitre.org/data/xml/capec_latest.xml                                   | XML         |
| CWE       | cwe.mitre.org/data/xml/cwec_latest.xml.zip                                  | XML/ZIP     |
| CVE       | nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz                 | JSON.gz     |

Все четыре источника скачиваются параллельно. Содержимое кэшируется в
`output/_cache/` и переиспользуется при сетевых сбоях.

## Что генерирует

В каталоге `databases/` (рядом с парсером, по умолчанию `../databases/`):

```
databases/
├── capec_database.json     # CAPEC: + execution_flow, consequences, skills, taxonomy_mappings, ...
├── cwe_database.json       # CWE:   + extended_description, common_consequences, modes_of_introduction, ...
├── cve_database.json       # CVE:   + cvss_v2/v3 раздельно, references_categorized, exploit_available
├── mitre_attack.json       # ATT&CK: + tactics, software_used, groups_using, mitigations_detailed
├── tools_database.json     # Расширен: ваши TOOL-NNN + 30 курируемых TOOL-SEED-NNN + MITRE S-коды
└── defense_database.json   # Расширен: ваши DEF-NNN + 30 курируемых DEF-SEED-NNN + MITRE M-коды
```

Все текстовые поля переведены на русский (Google через `deep_translator`,
с резервом — прямой HTTP к `translate.googleapis.com`, тот же бэкенд, что у
встроенного переводчика Chrome). Кеш переводов лежит в
`output/translate_cache.json` и переживает прогоны.

Дополнительно в `output/`:
- `mitre_software.json` — каталог ПО (S-коды), как извлечён из ATT&CK
- `mitre_mitigations.json` — каталог защит (M-коды)
- `mitre_groups.json` — каталог APT-групп (G-коды)
- `_cache/` — кэш сырых HTTP-ответов
- `translate_cache.json` — кэш переводов

## Связывание объектов

Парсер делает **двунаправленное** многопроходное связывание:

```
            CWE.observed_examples
CVE ─────────────────────────────► CWE
 │                                   │
 │ related_cwe                       │ related_capec
 ▼                                   ▼
CVE.related_capec ◄── CWE ── CAPEC ◄──► ATT&CK
 │                                   │
 │                                   │ software_used
 ▼                                   ▼
CVE.related_mitre               Tools (S-коды)
                                Defense (M-коды)
```

После прохода у каждого объекта максимально полные `related_*`-списки,
а CVE дополнительно получают:
- `related_tools` — список S-кодов, реализующих эту атаку;
- `related_defense` — список M-кодов, рекомендуемых для защиты.

## Установка и запуск

```bash
cd MITRE_PARSER
python -m venv .venv
.venv\Scripts\activate           # Windows
pip install -r requirements.txt

# Полный прогон с переводом (десятки минут)
python src/cli.py

# Быстрый прогон без перевода (для теста структуры)
python src/cli.py --skip-translate

# Сгенерировать только tools/defense базы (нужны techniques+software)
python src/cli.py --only attack tools defense
```

## Конфигурация

`src/config.py` читает переменные окружения `MP_*`:

| Переменная             | По умолчанию | Описание                                       |
| ---------------------- | ------------ | ---------------------------------------------- |
| `MP_ENABLE_TRANSLATION`| `1`          | Включить русский перевод                       |
| `MP_TRANSLATE_TO`      | `ru`         | Целевой язык                                   |
| `MP_TRANSLATION_WORKERS`| `4`         | Параллельность сетевых батчей перевода         |
| `MP_TRANSLATION_DELAY` | `0.6`        | Глобальный rate-limit (секунд между запросами) |
| `MP_MAX_CAPEC_RECORDS` | `600`        | Лимит CAPEC                                    |
| `MP_MAX_CWE_RECORDS`   | `1500`       | Лимит CWE                                      |
| `MP_MAX_CVE_RECORDS`   | `800`        | Лимит CVE                                      |
| `MP_MAX_ATTACK_RECORDS`| `600`        | Лимит ATT&CK техник                            |
| `MP_MAX_MITRE_SOFTWARE`| `250`        | Сколько S-кодов вытащить                       |
| `MP_MAX_MITRE_MITIGATIONS`| `60`      | Сколько M-кодов вытащить                       |
| `MP_DATABASES_DIR`     | `../databases`| Куда писать готовые БД                        |
| `MP_OUTPUT_DIR`        | `output`     | Рабочая папка кэшей                            |

## Архитектура исходного кода

```
MITRE_PARSER/
├── src/
│   ├── config.py
│   ├── pipeline.py         # Главный оркестратор (7 этапов)
│   ├── cli.py              # python src/cli.py
│   ├── db_writer.py        # Атомарная запись + .backup_<ts>
│   ├── sources/
│   │   └── http_loader.py
│   ├── parsers/
│   │   ├── base.py
│   │   ├── attack_parser.py    # techniques + software + mitigations + groups
│   │   ├── capec_parser.py
│   │   ├── cwe_parser.py
│   │   └── cve_parser.py
│   ├── enrichment/
│   │   ├── cross_linker.py     # Многопроходное связывание ВСЕХ объектов
│   │   ├── attack_db_builder.py
│   │   └── defense_db_builder.py
│   ├── translation/
│   │   ├── translator.py       # deep_translator + HTTP fallback
│   │   ├── glossary.py         # ~150 терминов кибербеза EN→RU
│   │   └── cache.py            # потокобезопасный JSON-кэш
│   └── catalog/                # курируемые каталоги (на русском)
│       ├── attack_tools_seed.json   # 30 наступательных инструментов
│       ├── defense_tools_seed.json  # 30 защитных инструментов
│       └── attack_type_to_tools.json
├── output/
├── _legacy/                # старая версия парсера (для сравнения)
├── README.md
└── requirements.txt
```

## Совместимость с приложением

Схемы `databases/tools_database.json` и `databases/defense_database.json`
**только расширяются** — все поля, которые читает `server/attack_toolkit.py`
(`id, name, type, applicable_cve, applicable_attack_types, commands{}, phases,
skill_level, os` для тулов и `id, attack_type, cve_ids, name, description,
tools[].name, tools[].description, tools[].commands, priority, effort,
effectiveness` для защит), сохранены. Существующие ручные записи
(`TOOL-001..020`, `DEF-001..009`) **не перезаписываются** — они объединяются
с новыми. Перед каждой записью создаётся резервная копия `*.backup_<ts>`.
