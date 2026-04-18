# Обновление баз данных системы безопасности

## Описание

Скрипт `update_databases.py` предназначен для автоматического обновления баз данных CVE, CWE, CAPEC и MITRE ATT&CK реальными данными из официальных источников.

## Возможности

1. **Автоматическое получение данных CVE** из NVD (National Vulnerability Database)
2. **Обновление описаний и метрик** (CVSS, severity)
3. **Перевод на русский язык** ключевых терминов
4. **Заполнение пустых полей** значениями по умолчанию
5. **Создание резервных копий** перед изменениями

## Использование

### Базовое использование

```powershell
cd c:\BOS
python update_databases.py
```

### Что делает скрипт

1. Создает резервные копии всех баз данных
2. Обновляет первые 10 записей CVE из официального API NVD
3. Обновляет первые 20 записей CWE с переводом
4. Заполняет пустые поля значениями по умолчанию

## Ограничения текущей версии

### API NVD
- **Лимит**: 5 запросов в 30 секунд (без API ключа)
- **Решение**: Получите бесплатный API ключ на https://nvd.nist.gov/developers/request-an-api-key

### Перевод
- Текущая версия использует **простой словарь** терминов
- Для качественного перевода рекомендуется:
  - Google Translate API
  - DeepL API
  - Yandex Translate API

## Улучшение качества перевода

### Вариант 1: Google Translate API

```python
# Установка
pip install googletrans==4.0.0rc1

# Использование
from googletrans import Translator

translator = Translator()
result = translator.translate(text, src='en', dest='ru')
translated_text = result.text
```

### Вариант 2: DeepL API (рекомендуется)

```python
# Установка
pip install deepl

# Использование
import deepl

translator = deepl.Translator("YOUR_API_KEY")
result = translator.translate_text(text, target_lang="RU")
translated_text = result.text
```

### Вариант 3: Yandex Translate API

```python
# Установка
pip install yandex-translate

# Использование
from yandex_translate import YandexTranslate

translate = YandexTranslate('YOUR_API_KEY')
result = translate.translate(text, 'ru')
translated_text = result['text'][0]
```

## Настройка для полного обновления

Откройте `update_databases.py` и измените лимиты:

```python
# Строка 150
updater.update_cve_database(limit=100)  # Вместо 10

# Строка 153
# В методе update_cwe_database измените:
for i, entry in enumerate(cwe_data[:100]):  # Вместо 20
```

## Получение API ключа NVD

1. Перейдите на https://nvd.nist.gov/developers/request-an-api-key
2. Заполните форму регистрации
3. Получите API ключ на email
4. Добавьте в скрипт:

```python
headers = {
    'User-Agent': 'Mozilla/5.0',
    'apiKey': 'YOUR_NVD_API_KEY'
}
```

С API ключом лимит увеличивается до **50 запросов в 30 секунд**.

## Структура обновленных данных

### CVE запись после обновления

```json
{
  "id": "CVE-2022-1234",
  "description": "Original English description...",
  "description_ru": "Русское описание...",
  "severity": "HIGH",
  "severity_ru": "ВЫСОКИЙ",
  "cvss_score": 7.5,
  "attack_type": "sql_injection",
  "attack_type_ru": "SQL-инъекция",
  "mitigations": ["Мера защиты 1", "Мера защиты 2"],
  "related_cwe": ["CWE-89"],
  "related_capec": ["CAPEC-66"]
}
```

## Резервные копии

Скрипт автоматически создает резервные копии:

```
databases/
├── cve_database.json
├── cve_database.json.backup_20240115_143022
├── cwe_database.json
└── cwe_database.json.backup_20240115_143022
```

## Восстановление из резервной копии

```powershell
# Если что-то пошло не так
cd c:\BOS\databases
copy cve_database.json.backup_20240115_143022 cve_database.json
```

## Рекомендации

1. **Начните с малого**: Сначала обновите 10-20 записей для проверки
2. **Проверьте результат**: Откройте обновленные JSON файлы
3. **Используйте API ключи**: Для ускорения процесса
4. **Качественный перевод**: Интегрируйте профессиональный API переводчика
5. **Регулярное обновление**: Запускайте скрипт раз в месяц

## Альтернативный подход: Ручное обновление

Если автоматическое обновление не подходит, можно:

1. Скачать официальные базы:
   - CVE: https://nvd.nist.gov/vuln/data-feeds
   - CWE: https://cwe.mitre.org/data/downloads.html
   - CAPEC: https://capec.mitre.org/data/downloads.html
   - MITRE ATT&CK: https://attack.mitre.org/resources/

2. Конвертировать в нужный формат
3. Перевести через профессиональный сервис

## Поддержка

При возникновении проблем:

1. Проверьте подключение к интернету
2. Убедитесь, что API доступны
3. Проверьте лимиты запросов
4. Посмотрите логи ошибок в консоли

## Лицензия

Данные из официальных источников:
- NVD/CVE: Public Domain
- CWE/CAPEC/MITRE: © The MITRE Corporation
