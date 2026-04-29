# MITRE PARSER

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

**MITRE PARSER** — это мощный и гибкий инструмент для автоматического сбора, парсинга, обогащения и перевода данных из ключевых баз знаний в области кибербезопасности:
- [MITRE ATT&CK®](https://attack.mitre.org/) (техники атак)
- [CAPEC™](https://capec.mitre.org/) (шаблоны атак)
- [CWE™](https://cwe.mitre.org/) (слабые места ПО)
- [CVE®](https://nvd.nist.gov/) (публичные уязвимости)

Проект разделён на **три независимых этапа**, что даёт полный контроль над процессом и позволяет гибко настраивать обработку данных. Поддерживается как консольное меню, так и графический интерфейс (GUI) для максимального удобства.

Результатом работы являются **взаимосвязанные JSON-файлы** с заполненными перекрёстными ссылками и рекомендациями по устранению уязвимостей (`mitigations`), готовые для использования в аналитических системах, SIEM, SOAR, Threat Intelligence платформах или собственных исследованиях.

---

## ✨ Возможности

- 🔄 **Автоматическая загрузка** последних версий баз с официальных источников.
- 🧩 **Глубокий парсинг** исходных форматов (XML, STIX 2.1, JSON).
- 🔗 **Трёхэтапная архитектура**:
  1. **Парсинг** — получение чистых данных из источников.
  2. **Связывание** — заполнение перекрёстных ссылок и распространение мер защиты.
  3. **Перевод** — выборочный перевод полей через интернет.
- 🛡️ **Интеллектуальное связывание данных**:
  - `CAPEC ↔ ATT&CK`
  - `CVE → CWE → CAPEC → ATT&CK`
  - Обратное распространение связей и мер защиты.
- 🌐 **Опциональный перевод** выбранных полей (названия, описания, меры защиты) на русский язык через Google Translate с кэшированием.
- 🖥️ **Два режима управления**:
  - Консольное меню для быстрого доступа.
  - GUI на Tkinter с логом выполнения и настройками.
- ⚙️ **Гибкая настройка** через конфигурационный файл или переменные окружения (лимиты записей, режим перевода, пути).
- 📦 **Чистый и структурированный JSON** на выходе, готовый к импорту в БД или аналитику.

---

## Структура проекта

```
MITRE_PARSER_V3/
├── src/
│ ├── parsers/ # Парсеры для каждого источника
│ │ ├── base.py
│ │ ├── attack_parser.py
│ │ ├── capec_parser.py
│ │ ├── cwe_parser.py
│ │ └── cve_parser.py
│ ├── config.py # Настройки (поддержка переменных окружения)
│ ├── loader.py # Загрузка файлов с повторными попытками
│ ├── cross_linker.py # Логика связывания и обогащения данных
│ ├── normalizer.py # Очистка и нормализация JSON
│ ├── translator.py # Онлайн-переводчик (Google Translate) с кэшированием
│ ├── step1_parse.py # Этап 1: Скачивание и парсинг
│ ├── step2_link.py # Этап 2: Связывание данных
│ ├── translate_fields.py # Этап 3: Выборочный перевод полей
│ ├── menu.py # Консольное меню
│ └── gui_app.py # Графический интерфейс (Tkinter)
├── output/ # Результаты работы (создаётся автоматически)
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Установка и запуск

### 1. Клонирование репозитория

```bash
git clone https://github.com/yourusername/MITRE_PARSER.git
cd MITRE_PARSER
```

### 2. Создание виртуального окружения (рекомендуется)

```bash
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
```

### 3. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 4. Настройка (опционально)

Создайте копию .env.example как .env или отредактируйте src/config.py:

- Включить/выключить перевод (`ENABLE_TRANSLATION`)
- Параметры перевода (`ENABLE_TRANSLATION`, `TRANSLATE_TO`, задержки и размер батча)
- Ограничить количество обрабатываемых записей (`MAX_..._RECORDS`)
- Изменить выходную директорию (`OUTPUT_DIR`)

### 5. Запуск

```bash
python src/menu.py # Через консольное меню

# Поэтапно (вручную)
# Этап 1: скачивание и парсинг (без перевода)
python src/step1_parse.py

# Этап 2: связывание данных
python src/step2_link.py

# Этап 3: перевод полей
python src/translate_fields.py
```

После завершения работы в папке `output/` появятся файлы:

- `capec_database.json`
- `cwe_database.json`
- `cve_database.json`
- `mitre_attack.json`
- + `translate_cache.json` #Кэш перевода

---

## Конфигурация (`config.py`)

```python
class Config:
	MAX_CAPEC_RECORDS	Лимит записей CAPEC (0 = все)	0
	
	MAX_CWE_RECORDS	Лимит записей CWE	0
	
	MAX_CVE_RECORDS	Лимит записей CVE	1500
	
	MAX_ATTACK_RECORDS	Лимит записей ATT&CK	0
	
	ENABLE_TRANSLATION	Включить перевод (для этапа 3)	False
	
	TRANSLATE_TO	Код языка перевода	"ru"
	
	TRANSLATION_BATCH_SIZE	Строк в одном запросе к Google	50
	
	TRANSLATION_DELAY	Задержка между запросами (сек)	1.0
	
	TRANSLATION_MAX_RETRIES	Число повторных попыток	3
	
	OUTPUT_DIR	Папка для результатов	output/
```

---

## 📄 Формат выходных данных

### `mitre_attack.json`

```json
{
  "id": "T1055.011",
  "name": "Extra Window Memory Injection",
  "tactic": "Defense Evasion",
  "description": "...",
  "platforms": ["Windows"],
  "related_cwe": [],
  "related_capec": [],
  "requires_service": ["api_service", "windows_os"],
  "detection": "",
  "mitigations": ["Behavior Prevention on Endpoint ..."]
}
```

### `capec_database.json`

```json
{
  "id": "CAPEC-1",
  "name": "Accessing Functionality Not Properly Constrained by ACLs",
  "description": "...",
  "severity": "HIGH",
  "related_cwe": ["CWE-276", "CWE-285"],
  "related_mitre": [],
  "prerequisites": ["..."],
  "mitigations": ["In a J2EE setting, administrators can associate a role ..."]
}
```

### `cwe_database.json`

```json
{
  "id": "CWE-1021",
  "name": "Improper Restriction of Rendered UI Layers or Frames",
  "description": "...",
  "category": "unknown",
  "related_capec": ["CAPEC-103", "CAPEC-181"],
  "mitigation": "Implementation The use of X-Frame-Options ...",
  "requires_technology": [],
  "detection_methods": ["automated_static_analysis..."]
}
```

### `cve_database.json`

```json
{
  "id": "CVE-2005-3817",
  "description": "Multiple SQL injection vulnerabilities ...",
  "severity": "UNKNOWN",
  "cvss_score": 7.5,
  "affected_software": ["softbizscripts web_hosting_directory_script"],
  "attack_type": "sql_injection",
  "related_cwe": ["CWE-89"],
  "related_capec": [],
  "related_mitre": [],
  "requires_service": [],
  "requires_port": [],
  "prerequisites": [],
  "mitigations": [
    "Architecture and Design Libraries or Frameworks Use a vetted library ..."
  ]
}
```

---

## Примечания

- Поля могут оставаться пустыми, если соответствующие связи отсутствуют в исходных базах MITRE/NVD.
- Для включения перевода на русский язык установите `ENABLE_TRANSLATION = True` в `config.py`. Будет использоваться библиотека `googletrans` (требуется интернет-соединение).
- При первом запуске рекомендуется установить лимиты записей для тестирования (например, `MAX_CVE_RECORDS = 100`).

---
