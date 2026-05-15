#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для выборочного перевода полей в JSON-файлах MITRE Parser.
Использует онлайн-переводчик (Google Translate) для быстрой работы.
Запускать после генерации английских JSON.
"""
import json
import re
from pathlib import Path
from config import Config
from translator import Translator

# Поля, которые нужно перевести в каждом типе файла
FIELDS_TO_TRANSLATE = {
    "capec_database.json": ["name", "description", "severity", "prerequisites", "mitigations"],
    "cwe_database.json": ["name", "description", "mitigation", "category", "detection_methods"],
    "cve_database.json": ["description", "severity", "mitigations", "mitigation", "affected_software", "attack_type", "requires_service"],
    "mitre_attack.json": ["name", "description", "requires_service", "mitigations", "detection", "tactic"]
}

def translate_field(value, translator: Translator):
    """Рекурсивно переводит строки в значении (строка или список)"""
    if isinstance(value, str):
        return translator.translate(value)
    elif isinstance(value, list):
        return [translate_field(item, translator) for item in value]
    else:
        return value

def translate_file(filepath: Path, fields: list, translator: Translator):
    print(f"📄 Обработка {filepath.name}...")
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    total_items = len(data)
    updated = 0
    for idx, item in enumerate(data):
        item_updated = False
        for field in fields:
            if field in item:
                original = item[field]
                translated = translate_field(original, translator)
                if translated != original:
                    item[field] = translated
                    item_updated = True
        if item_updated:
            updated += 1
        if (idx + 1) % 100 == 0:
            print(f"  🔄 Прогресс: {idx+1}/{total_items}")
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"✅ {filepath.name}: переведено элементов — {updated} из {total_items}")

def main():
    print("🎯 Выборочный перевод полей JSON-файлов (онлайн-режим)")
    translator = Translator(force_enable=True)   # принудительное включение перевода
    if not translator.enabled:
        print("❌ Не удалось включить переводчик")
        return
    
    output_dir = Config.OUTPUT_DIR
    for filename, fields in FIELDS_TO_TRANSLATE.items():
        filepath = output_dir / filename
        if filepath.exists():
            translate_file(filepath, fields, translator)
        else:
            print(f"⚠️ Файл {filename} не найден, пропущен")
    
    translator._save_cache()
    print("🎉 Готово! Все указанные поля переведены.")

if __name__ == "__main__":
    main()