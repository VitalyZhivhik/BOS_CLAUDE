"""
HTTP-загрузчик с повторными попытками, поддержкой .gz/.zip и локальным
кэшем сырых файлов на диске. Если сервер не вернул свежую версию (304/ошибка),
используется ранее закэшированная копия.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import time
import zipfile
from pathlib import Path
from typing import Any

import requests

from config import Config


class HttpLoader:
    """Скачивает файлы с retry и кеширует «сырые» байты на диск."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir or Config.CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.USER_AGENT})

    # ── Внутреннее ─────────────────────────────────────────
    def _cache_path(self, url: str) -> Path:
        digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
        suffix = url.split("/")[-1] or "data"
        return self.cache_dir / f"{digest}_{suffix}"

    def _read_cache(self, url: str) -> bytes | None:
        path = self._cache_path(url)
        if path.exists():
            try:
                return path.read_bytes()
            except OSError:
                return None
        return None

    def _write_cache(self, url: str, content: bytes) -> None:
        try:
            self._cache_path(url).write_bytes(content)
        except OSError:
            pass

    # ── Публичные методы ──────────────────────────────────
    def fetch(self, url: str, *, use_cache: bool = True) -> bytes | None:
        """Скачивает обычный файл. При неудаче возвращает кэш (если есть)."""
        last_err: Exception | None = None
        for attempt in range(1, Config.RETRY_ATTEMPTS + 1):
            try:
                print(f"  [HTTP] GET {url} (попытка {attempt})")
                resp = self.session.get(url, timeout=Config.REQUEST_TIMEOUT)
                resp.raise_for_status()
                content = resp.content
                if use_cache:
                    self._write_cache(url, content)
                return content
            except requests.RequestException as e:
                last_err = e
                print(f"  [HTTP] Ошибка: {e}")
                if attempt < Config.RETRY_ATTEMPTS:
                    time.sleep(Config.RETRY_DELAY * attempt)

        if use_cache:
            cached = self._read_cache(url)
            if cached:
                print(f"  [HTTP] Использую кэш для {url} (последняя ошибка: {last_err})")
                return cached
        print(f"  [HTTP] Не удалось получить {url}")
        return None

    def fetch_zip_member(
        self, url: str, target_extension: str = ".xml"
    ) -> bytes | None:
        """Скачивает ZIP-архив и возвращает первый файл с нужным расширением."""
        raw = self.fetch(url)
        if not raw:
            return None
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                members = [n for n in zf.namelist() if n.endswith(target_extension)]
                if not members:
                    print(f"  [ZIP] Не найдено *{target_extension} в {url}")
                    return None
                return zf.read(members[0])
        except zipfile.BadZipFile as e:
            print(f"  [ZIP] Битый архив: {e}")
            return None

    def fetch_gz_json(self, url: str) -> dict[str, Any] | None:
        """Скачивает .json.gz, распаковывает и парсит."""
        raw = self.fetch(url)
        if not raw:
            return None
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                payload = gz.read()
            return json.loads(payload)
        except (OSError, json.JSONDecodeError) as e:
            print(f"  [GZ] Не удалось распаковать/распарсить: {e}")
            return None


__all__ = ["HttpLoader"]
