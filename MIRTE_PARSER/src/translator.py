# src/translator.py
import re
import time
import json
from pathlib import Path
from deep_translator import GoogleTranslator
from config import Config


class Translator:
    def __init__(self, target_lang: str = None, force_enable: bool = False):
        # Если force_enable=True, включаем перевод независимо от конфига
        self.enabled = force_enable or Config.ENABLE_TRANSLATION
        self.target_lang = target_lang or Config.TRANSLATE_TO
        self.batch_size = getattr(Config, 'TRANSLATION_BATCH_SIZE', 50)
        self.delay = getattr(Config, 'TRANSLATION_DELAY', 1.0)
        self.max_retries = getattr(Config, 'TRANSLATION_MAX_RETRIES', 3)
        
        if self.enabled:
            try:
                from deep_translator import GoogleTranslator
                self.translator = GoogleTranslator(source='auto', target=self.target_lang)
                print(f"🌐 Онлайн-переводчик готов (Google Translate → {self.target_lang})")
            except Exception as e:
                print(f"⚠️ Ошибка инициализации переводчика: {e}")
                self.enabled = False
        else:
            self.translator = None
            print("⚡ Перевод отключён (force_enable=False и ENABLE_TRANSLATION=False)")
        
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
    
    def translate(self, text: str, use_cache: bool = True) -> str:
        if not self.enabled:
            return text
        if not text or not isinstance(text, str):
            return text
        text = text.strip()
        if not text:
            return text
        # Пропускаем технические идентификаторы
        if re.match(r'^(CAPEC|CWE|CVE|T\d{4}(\.\d{3})?|[A-Z]{2,}-\d+)$', text):
            return text
        # Проверяем, не на русском ли уже
        if self._is_russian(text):
            return text
        if use_cache and text in self._cache:
            return self._cache[text]
        
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0 and self._request_count > 0:
                    time.sleep(self.delay)
                result = self.translator.translate(text)
                self._cache[text] = result
                self._request_count += 1
                if self._request_count % 20 == 0:
                    self._save_cache()
                return result
            except Exception as e:
                print(f"⚠️ Попытка {attempt+1}/{self.max_retries} для '{text[:40]}...' провалена: {e}")
                time.sleep(2 * (attempt + 1))  # увеличиваем задержку с каждой попыткой
        # Если все попытки исчерпаны, возвращаем оригинал
        return text
    
    def translate_batch(self, texts: list) -> list:
        """Переводит список строк одним пакетным запросом (если переводчик включён)"""
        if not self.enabled:
            return texts
        if not texts:
            return []
        
        # Фильтруем: оставляем только строки, требующие перевода
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
            to_translate.append(text)
            indices.append(i)
        
        if not to_translate:
            return texts[:]
        
        results = texts[:]
        # Разбиваем на батчи
        for start in range(0, len(to_translate), self.batch_size):
            batch = to_translate[start:start+self.batch_size]
            batch_indices = indices[start:start+self.batch_size]
            
            for attempt in range(self.max_retries):
                try:
                    if self.delay > 0 and self._request_count > 0:
                        time.sleep(self.delay)
                    translated_batch = self.translator.translate_batch(batch)
                    self._request_count += 1
                    for idx, orig, trans in zip(batch_indices, batch, translated_batch):
                        self._cache[orig] = trans
                        results[idx] = trans
                    self._save_cache()
                    print(f"    📦 Батч {start//self.batch_size + 1}: переведено {len(batch)} строк")
                    break  # успех – выходим из цикла попыток
                except Exception as e:
                    print(f"⚠️ Попытка {attempt+1}/{self.max_retries} для батча провалена: {e}")
                    time.sleep(2 * (attempt + 1))
            else:
                # все попытки исчерпаны – оставляем оригиналы
                for idx in batch_indices:
                    results[idx] = texts[idx]
        return results
    
    def translate_list(self, items: list) -> list:
        """Переводит список строк, используя пакетный режим"""
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