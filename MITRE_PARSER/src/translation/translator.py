"""
Multi-provider переводчик с двунаправленным переводом.

Поддерживает:
  - Google Translate (бесплатный, с rate-limit)
  - Groq (llama-3.3-70b, быстрый, бесплатный tier)
  - Mistral (mistral-small, бесплатный tier)

Если выбрано 2+ провайдера, один переводит с начала, другой с конца — 
результаты мержатся. Circuit breaker отключает упавший провайдер.
"""
from __future__ import annotations

import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future
from pathlib import Path
from typing import Callable, Iterable

from config import Config
from translation.cache import TranslationCache
from translation.glossary import (
    PROTECTED_TOKENS,
    apply_glossary,
    is_protected,
    split_for_translation,
)
from translation.providers.base import BaseProvider, ProviderStatus


PROTECTED_TOKENS_UPPER: set[str] = {t.upper() for t in PROTECTED_TOKENS}

_RU_RE = re.compile(r"[А-Яа-яЁё]")
_LATIN_WORD_RE = re.compile(r"[A-Za-z]{4,}")


def is_russian(text: str) -> bool:
    """Text is considered Russian if Cyrillic dominates and no stray Latin words remain."""
    if not text:
        return False
    letters = sum(1 for c in text if c.isalpha())
    if not letters:
        return False
    cyr = len(_RU_RE.findall(text))
    if cyr / letters < 0.6:
        return False
    for m in _LATIN_WORD_RE.finditer(text):
        word = m.group(0)
        if word.upper() in PROTECTED_TOKENS_UPPER:
            continue
        return False
    return True


class Translator:
    """Multi-provider translator with cache, bidirectional mode, and circuit breaker."""

    def __init__(
        self,
        providers: list[BaseProvider] | None = None,
        target_lang: str | None = None,
        cache_path: Path | None = None,
        force_enable: bool = False,
        batch_size: int | None = None,
        max_len: int | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> None:
        self.enabled: bool = force_enable or Config.ENABLE_TRANSLATION
        self.target_lang: str = target_lang or Config.TRANSLATE_TO
        self.batch_size: int = batch_size or max(1, Config.TRANSLATION_BATCH_SIZE)
        self.max_len: int = max_len or max(500, Config.TRANSLATION_MAX_LEN)
        self.progress_callback = progress_callback

        self.cache = TranslationCache(
            cache_path or (Config.OUTPUT_DIR / "translate_cache.json")
        )
        self._purge_hybrid_cache_entries()

        self._providers: list[BaseProvider] = providers or []
        self._provider_healthy: list[bool] = [True] * len(self._providers)
        self._provider_fails: list[int] = [0] * len(self._providers)
        self._cb_threshold = max(2, Config.TRANSLATION_CB_TRIP_THRESHOLD)
        self._lock = threading.Lock()

        self._stats = {"glossary": 0, "cache": 0, "translated": 0, "fail": 0}

        if not self._providers and self.enabled:
            print("  [Translator] Нет провайдеров — перевод будет из кэша/глоссария")
        elif self._providers:
            names = [p.name for p in self._providers]
            print(f"  [Translator] Провайдеры: {', '.join(names)}")

        if not self.enabled:
            print("  [Translator] Перевод ОТКЛЮЧЁН (быстрый режим)")

    @property
    def network_available(self) -> bool:
        return any(self._provider_healthy)

    def get_healthy_providers(self) -> list[BaseProvider]:
        return [p for p, h in zip(self._providers, self._provider_healthy) if h]

    # ── Public API ────────────────────────────────────────

    def translate(self, text: str) -> str:
        """Translate a single string. Safe for any input."""
        if not isinstance(text, str) or not text.strip():
            return text
        if not self.enabled:
            return text

        text = text.strip()
        if is_protected(text):
            return text
        if is_russian(text):
            return text

        cached = self.cache.get(text)
        if cached:
            self._stats["cache"] += 1
            return cached

        glossed = apply_glossary(text)
        if glossed != text and is_russian(glossed):
            self._stats["glossary"] += 1
            self.cache.set(text, glossed)
            return glossed

        result = self._translate_remote(text)
        if result:
            self.cache.set(text, result)
            self._stats["translated"] += 1
            return result

        self._stats["fail"] += 1
        return text

    def translate_list(self, items: Iterable[str]) -> list[str]:
        """Translate a list of strings with batching."""
        items = list(items)
        if not items or not self.enabled:
            return list(items)

        result: list[str] = list(items)
        net_indices: list[int] = []
        net_payload: list[str] = []

        for i, raw in enumerate(items):
            if not isinstance(raw, str) or not raw.strip():
                continue
            text = raw.strip()
            if is_protected(text) or is_russian(text):
                result[i] = text
                continue
            cached = self.cache.get(text)
            if cached:
                result[i] = cached
                self._stats["cache"] += 1
                continue
            glossed = apply_glossary(text)
            if glossed != text and is_russian(glossed):
                result[i] = glossed
                self.cache.set(text, glossed)
                self._stats["glossary"] += 1
                continue
            net_indices.append(i)
            net_payload.append(text[:self.max_len])

        if not net_payload:
            return result

        translated = self._translate_batch_remote(net_payload)
        for idx, src, tr in zip(net_indices, net_payload, translated):
            final = tr.strip() if tr else None
            if final:
                result[idx] = final
                self.cache.set(items[idx].strip(), final)
                self._stats["translated"] += 1
            else:
                result[idx] = items[idx]
                self._stats["fail"] += 1

        return result

    def translate_keep_original(self, text: str) -> str:
        """Translate and append original in parentheses for short terms.
        
        E.g. "Buffer Overflow" -> "Переполнение буфера (Buffer Overflow)"
        Useful for taxonomy names, entry_names, etc.
        """
        if not isinstance(text, str) or not text.strip():
            return text
        if not self.enabled:
            return text
        text = text.strip()
        if is_protected(text):
            return text
        if is_russian(text):
            return text

        translated = self.translate(text)
        if translated == text:
            return text
        if is_russian(translated) and translated != text:
            return f"{translated} ({text})"
        return translated

    def translate_dict(self, obj: dict, fields: Iterable[str]) -> dict:
        """Translate specified text fields in a dict (in-place)."""
        for field in fields:
            if field in obj:
                value = obj[field]
                if isinstance(value, str):
                    obj[field] = self.translate(value)
                elif isinstance(value, list):
                    obj[field] = self.translate_list(value)
        return obj

    def translate_dict_keep_original(self, obj: dict, fields: Iterable[str]) -> dict:
        """Translate fields keeping original in parentheses (for short terms)."""
        for field in fields:
            if field in obj:
                value = obj[field]
                if isinstance(value, str) and value.strip():
                    obj[field] = self.translate_keep_original(value)
        return obj

    def translate_records_parallel(
        self,
        records: list[dict],
        translate_fn: Callable[[dict], None],
        label: str = "",
        checkpoint_fn: Callable[[int], None] | None = None,
    ) -> None:
        """Translate records splitting work across all healthy providers.
        
        If N providers are healthy, splits records into N equal segments
        and translates each segment in parallel using a dedicated provider.
        """
        total = len(records)
        if total == 0:
            return

        healthy = self.get_healthy_providers()
        n_workers = len(healthy)
        if n_workers >= 2:
            self._translate_n_way(records, translate_fn, label, checkpoint_fn, n_workers)
        else:
            self._translate_sequential(records, translate_fn, label, checkpoint_fn)

    # Keep old name as alias for backward compatibility
    translate_records_bidirectional = translate_records_parallel

    def flush(self) -> None:
        self.cache.flush(force=True)

    def stats(self) -> dict:
        s = dict(self._stats)
        s["cache_size"] = self.cache.size()
        s["providers_healthy"] = sum(self._provider_healthy)
        s["providers_total"] = len(self._providers)
        return s

    # ── N-way parallel translation ──────────────────────────

    def _translate_n_way(
        self,
        records: list[dict],
        translate_fn: Callable[[dict], None],
        label: str,
        checkpoint_fn: Callable[[int], None] | None,
        n_workers: int,
    ) -> None:
        """Split records into n_workers segments, translate in parallel."""
        total = len(records)
        segment_size = total // n_workers
        segments: list[tuple[int, int]] = []

        for w in range(n_workers):
            start = w * segment_size
            end = start + segment_size if w < n_workers - 1 else total
            segments.append((start, end))

        progress_counter = {"done": 0}
        progress_lock = threading.Lock()

        def _work_segment(seg_start: int, seg_end: int) -> None:
            for i in range(seg_start, seg_end):
                translate_fn(records[i])
                with progress_lock:
                    progress_counter["done"] += 1
                    done = progress_counter["done"]
                if self.progress_callback and done % 3 == 0:
                    self.progress_callback(done, total, label)
                if checkpoint_fn and done % 20 == 0:
                    checkpoint_fn(done)

        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [
                pool.submit(_work_segment, s, e)
                for s, e in segments
            ]
            for f in futures:
                f.result()

        self.flush()
        if self.progress_callback:
            self.progress_callback(total, total, label)

    def _translate_sequential(
        self,
        records: list[dict],
        translate_fn: Callable[[dict], None],
        label: str,
        checkpoint_fn: Callable[[int], None] | None,
    ) -> None:
        total = len(records)
        for i, rec in enumerate(records):
            translate_fn(rec)
            if self.progress_callback and (i % 5 == 0 or i == total - 1):
                self.progress_callback(i + 1, total, label)
            if checkpoint_fn and (i + 1) % 20 == 0:
                checkpoint_fn(i + 1)
        self.flush()

    # ── Remote translation ────────────────────────────────

    def _get_active_provider(self) -> BaseProvider | None:
        for p, healthy in zip(self._providers, self._provider_healthy):
            if healthy:
                return p
        return None

    def _record_provider_failure(self, provider: BaseProvider) -> None:
        with self._lock:
            try:
                idx = self._providers.index(provider)
            except ValueError:
                return
            self._provider_fails[idx] += 1
            if self._provider_fails[idx] >= self._cb_threshold:
                self._provider_healthy[idx] = False
                print(
                    f"  [Translator] Провайдер «{provider.name}» отключён "
                    f"({self._cb_threshold} ошибок подряд)"
                )

    def _record_provider_success(self, provider: BaseProvider) -> None:
        with self._lock:
            try:
                idx = self._providers.index(provider)
            except ValueError:
                return
            self._provider_fails[idx] = 0

    def _translate_remote(self, text: str) -> str | None:
        """Try each healthy provider in order."""
        for i, provider in enumerate(self._providers):
            if not self._provider_healthy[i]:
                continue
            try:
                result = provider.translate_text(text[:self.max_len])
                if result:
                    self._record_provider_success(provider)
                    return result
            except Exception:
                pass
            self._record_provider_failure(provider)
        return None

    def _translate_batch_remote(self, texts: list[str]) -> list[str | None]:
        """Batch translate using healthy providers."""
        results: list[str | None] = [None] * len(texts)

        for start in range(0, len(texts), self.batch_size):
            batch = texts[start:start + self.batch_size]
            batch_results = self._translate_single_batch(batch)
            for i, val in enumerate(batch_results):
                results[start + i] = val

        self.cache.flush()
        return results

    def _translate_single_batch(self, batch: list[str]) -> list[str | None]:
        for i, provider in enumerate(self._providers):
            if not self._provider_healthy[i]:
                continue
            if provider.supports_batch:
                try:
                    result = provider.translate_batch(batch)
                    if result and len(result) == len(batch):
                        valid_count = sum(1 for r in result if r)
                        if valid_count > 0:
                            self._record_provider_success(provider)
                            return result
                except Exception:
                    pass
                self._record_provider_failure(provider)
            else:
                out = []
                for text in batch:
                    try:
                        r = provider.translate_text(text)
                        out.append(r)
                        if r:
                            self._record_provider_success(provider)
                    except Exception:
                        out.append(None)
                        self._record_provider_failure(provider)
                        if not self._provider_healthy[i]:
                            out.extend([None] * (len(batch) - len(out)))
                            break
                if any(out):
                    return out

        return [None] * len(batch)

    # ── Cache maintenance ─────────────────────────────────

    def _purge_hybrid_cache_entries(self) -> None:
        """Remove hybrid entries (Russian + long English words) from cache."""
        bad_keys: list[str] = []
        for k, v in list(self.cache._data.items()):  # noqa: SLF001
            if not isinstance(v, str):
                bad_keys.append(k)
                continue
            cyr = len(_RU_RE.findall(v))
            if cyr == 0:
                continue
            for m in _LATIN_WORD_RE.finditer(v):
                if m.group(0).upper() not in PROTECTED_TOKENS_UPPER:
                    bad_keys.append(k)
                    break
        if bad_keys:
            for k in bad_keys:
                self.cache._data.pop(k, None)  # noqa: SLF001
            self.cache._dirty = True  # noqa: SLF001
            self.cache.flush(force=True)
            print(f"  [Translator] Очищено {len(bad_keys)} «гибридных» переводов из кеша")


__all__ = ["Translator", "is_russian"]
