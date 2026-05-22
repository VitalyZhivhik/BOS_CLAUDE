# src/translator.py
import re
import time
import json
import ssl
from pathlib import Path
from deep_translator import GoogleTranslator
from config import Config

# Создаём безопасный SSL-контекст для обхода ошибок SSL EOF
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

class Translator:
    """Онлайн-переводчик через Google Translate с пакетной обработкой, кэшированием и разбиением длинных текстов"""

    MAX_TEXT_LENGTH = 4500  # безопасный лимит для Google Translate

    def __init__(self, target_lang: str = None, force_enable: bool = False):
        self.enabled = force_enable or Config.ENABLE_TRANSLATION
        self.target_lang = target_lang or Config.TRANSLATE_TO
        self.batch_size = getattr(Config, 'TRANSLATION_BATCH_SIZE', 25)
        self.delay = getattr(Config, 'TRANSLATION_DELAY', 1.5)
        self.max_retries = getattr(Config, 'TRANSLATION_MAX_RETRIES', 5)

        if self.enabled:
            try:
                self.translator = GoogleTranslator(source='auto', target=self.target_lang)
                print(f"🌐 Онлайн-переводчик готов (Google Translate → {self.target_lang})")
            except Exception as e:
                print(f"⚠️ Ошибка инициализации переводчика: {e}")
                self.enabled = False
        else:
            self.translator = None
            print("⚡ Перевод отключён в настройках")

        self._cache = {}
        self._cache_file = Config.OUTPUT_DIR / "translate_cache.json"
        self._load_cache()
        self._request_count = 0

    def _load_cache(self):
        if self._cache_file.exists():
            try:
                with open(self._cache_file, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
                print(f"📦 Загружено {len(self._cache)} переводов из кэша")
            except:
                pass

    def _save_cache(self):
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False, indent=2)
        except:
            pass

    def _split_long_text(self, text: str) -> list:
        """Разбивает длинный текст на части по предложениям или абзацам, не превышая MAX_TEXT_LENGTH"""
        if len(text) <= self.MAX_TEXT_LENGTH:
            return [text]

        parts = text.split('\n\n')
        result = []
        for part in parts:
            if len(part) <= self.MAX_TEXT_LENGTH:
                result.append(part)
            else:
                subparts = re.split(r'(?<=[.!?])\s+', part)
                current = ""
                for sub in subparts:
                    if len(current) + len(sub) + 1 <= self.MAX_TEXT_LENGTH:
                        current = (current + " " + sub).strip() if current else sub
                    else:
                        if current:
                            result.append(current)
                        current = sub
                if current:
                    result.append(current)
        return result

    def translate(self, text: str, use_cache: bool = True) -> str:
        if not self.enabled:
            return text
        if not text or not isinstance(text, str):
            return text
        text = text.strip()
        if not text:
            return text
        if re.match(r'^(CAPEC|CWE|CVE|T\d{4}(\.\d{3})?|[A-Z]{2,}-\d+)$', text):
            return text
        if self._is_russian(text):
            return text
        if use_cache and text in self._cache:
            return self._cache[text]

        # === АВТОЗАМЕНА ПОДЧЁРКИВАНИЙ ПЕРЕД ПЕРЕВОДОМ ===
        original_text = text
        if '_' in text:
            cleaned = text.replace('_', ' ').strip()
            if cleaned != text:
                print(f"    🔄 Замена подчёркиваний для '{text[:50]}...'")
                text = cleaned
        # =================================================

        parts = self._split_long_text(text)
        translated_parts = []
        for part in parts:
            for attempt in range(self.max_retries):
                try:
                    if self.delay > 0 and self._request_count > 0:
                        time.sleep(self.delay)
                    result = self.translator.translate(part)
                    translated_parts.append(result)
                    self._request_count += 1
                    break
                except Exception as e:
                    print(f"⚠️ Попытка {attempt+1}/{self.max_retries} для '{part[:40]}...' провалена: {e}")
                    time.sleep(2 * (attempt + 1))
            else:
                translated_parts.append(part)

        full_translation = " ".join(translated_parts)
        self._cache[original_text] = full_translation
        if self._request_count % 20 == 0:
            self._save_cache()
        return full_translation

    def translate_batch(self, texts: list) -> list:
        if not self.enabled:
            return texts
        if not texts:
            return []

        to_translate = []
        indices = []
        for i, text in enumerate(texts):
            if not text or not isinstance(text, str):
                continue
            text = text.strip()
            if not text:
                continue
            if re.match(r'^(CAPEC|CWE|CVE|T\d{4}(\.\d{3})?|[A-Z]{2,}-\d+)$', text):
                continue
            if self._is_russian(text):
                continue
            if text in self._cache:
                continue

            if '_' in text:
                cleaned = text.replace('_', ' ').strip()
                if cleaned != text:
                    text = cleaned

            parts = self._split_long_text(text)
            for part in parts:
                to_translate.append(part)
                indices.append(i)

        if not to_translate:
            return texts[:]

        results = texts[:]
        for start in range(0, len(to_translate), self.batch_size):
            batch = to_translate[start:start+self.batch_size]
            batch_indices = indices[start:start+self.batch_size]

            for attempt in range(self.max_retries):
                try:
                    if self.delay > 0 and self._request_count > 0:
                        time.sleep(self.delay)
                    translated_batch = self.translator.translate_batch(batch)
                    self._request_count += 1
                    temp_results = {}
                    for idx, trans in zip(batch_indices, translated_batch):
                        if idx not in temp_results:
                            temp_results[idx] = []
                        temp_results[idx].append(trans)
                    for idx, trans_parts in temp_results.items():
                        full_trans = " ".join(trans_parts)
                        self._cache[texts[idx]] = full_trans
                        results[idx] = full_trans
                    self._save_cache()
                    print(f"    📦 Батч {start//self.batch_size + 1}: переведено {len(batch)} частей")
                    break
                except Exception as e:
                    print(f"⚠️ Попытка {attempt+1}/{self.max_retries} для батча провалена: {e}")
                    time.sleep(2 * (attempt + 1))
            else:
                for idx in set(batch_indices):
                    results[idx] = texts[idx]
        return results

    def translate_list(self, items: list) -> list:
        if not self.enabled:
            return items
        if not items:
            return []
        return self.translate_batch(items)

    def _is_russian(self, text: str) -> bool:
        return bool(re.search(r'[а-яА-ЯёЁ]', text))

    def __del__(self):
        if hasattr(self, '_cache'):
            self._save_cache()