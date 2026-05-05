"""
Простой потокобезопасный JSON-кэш переводов на диске.
Ключ — оригинальная строка; значение — переведённая строка.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path


class TranslationCache:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, str] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._data = {str(k): str(v) for k, v in data.items()}
                print(f"  [Cache] Загружено {len(self._data)} переводов из {self.path.name}")
            except (OSError, json.JSONDecodeError) as e:
                print(f"  [Cache] Не удалось прочитать кэш: {e}")
                self._data = {}

    def get(self, key: str) -> str | None:
        with self._lock:
            return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            if self._data.get(key) != value:
                self._data[key] = value
                self._dirty = True

    def update(self, items: dict[str, str]) -> None:
        with self._lock:
            for k, v in items.items():
                if self._data.get(k) != v:
                    self._data[k] = v
                    self._dirty = True

    def flush(self, force: bool = False) -> None:
        with self._lock:
            if not (self._dirty or force):
                return
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(self.path.suffix + ".tmp")
                with tmp.open("w", encoding="utf-8") as f:
                    json.dump(self._data, f, ensure_ascii=False, indent=2)
                tmp.replace(self.path)
                self._dirty = False
            except OSError as e:
                print(f"  [Cache] Не удалось сохранить кэш: {e}")

    def size(self) -> int:
        with self._lock:
            return len(self._data)


__all__ = ["TranslationCache"]
