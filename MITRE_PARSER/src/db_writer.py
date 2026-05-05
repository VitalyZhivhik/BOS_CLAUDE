"""
Атомарная запись JSON-баз с резервной копией, валидацией и append-режимом.

Поддерживает:
  - Создание бэкапа перед перезаписью
  - Atomic write через .tmp
  - Append mode: дозапись только уникальных записей (по id)
  - Валидация обязательных полей
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(path)


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_suffix(path.suffix + f".backup_{ts}")
    try:
        shutil.copy2(path, backup)
        return backup
    except OSError as e:
        print(f"  [Writer] Не удалось создать бэкап {path.name}: {e}")
        return None


def _validate_records(records: list, required: list[str]) -> tuple[int, list[str]]:
    bad: list[str] = []
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            bad.append(f"#{i}: не объект")
            continue
        for f in required:
            if f not in rec:
                bad.append(f"#{i} (id={rec.get('id', '?')}): нет поля '{f}'")
                break
    return len(records) - len(bad), bad[:5]


def _load_existing(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _merge_records(existing: list[dict], new_records: list[dict]) -> tuple[list[dict], int]:
    """Merge new records into existing, skipping duplicates by id.
    Returns (merged_list, count_of_new_added)."""
    existing_ids: set[str] = set()
    for rec in existing:
        if isinstance(rec, dict) and rec.get("id"):
            existing_ids.add(rec["id"])

    added = 0
    merged = list(existing)
    for rec in new_records:
        if not isinstance(rec, dict):
            continue
        rec_id = rec.get("id")
        if rec_id and rec_id not in existing_ids:
            merged.append(rec)
            existing_ids.add(rec_id)
            added += 1

    return merged, added


def write_database(
    target: Path,
    records: list,
    *,
    required_fields: list[str] | None = None,
    name: str = "",
    append: bool = False,
) -> bool:
    """Write JSON database. Returns True on success.
    
    If append=True, merges new records with existing file (unique by id).
    """
    target = Path(target)

    if required_fields:
        ok_count, sample_errors = _validate_records(records, required_fields)
        if sample_errors:
            print(f"  [Writer] {name or target.name}: предупреждения по схеме:")
            for e in sample_errors:
                print(f"    - {e}")

    final_records = records
    if append:
        existing = _load_existing(target)
        if existing:
            final_records, added = _merge_records(existing, records)
            print(f"  [Writer] {name}: append +{added} новых "
                  f"(было {len(existing)}, стало {len(final_records)})")
        else:
            print(f"  [Writer] {name}: файл пуст, записываем {len(records)} записей")

    backup = _backup(target)
    if backup:
        print(f"  [Writer] Резервная копия: {backup.name}")

    try:
        _atomic_write(target, final_records)
        print(f"  [Writer] Записано {len(final_records)} записей в {target}")
        return True
    except OSError as e:
        print(f"  [Writer] Ошибка записи {target}: {e}")
        return False


__all__ = ["write_database"]
