"""Google Translate provider (free endpoints)."""
from __future__ import annotations

import time
import urllib.parse

import requests

from translation.providers.base import BaseProvider


class GoogleProvider(BaseProvider):
    """Uses deep_translator + free googleapis endpoint as fallback."""

    name = "Google Translate"
    supports_batch = True

    GOOGLE_FREE_URL = "https://translate.googleapis.com/translate_a/single"

    def __init__(
        self,
        target_lang: str = "ru",
        timeout: int = 15,
        delay: float = 0.3,
        max_retries: int = 2,
        **kwargs,
    ) -> None:
        super().__init__(target_lang, **kwargs)
        self.timeout = timeout
        self.delay = delay
        self.max_retries = max_retries

        self._deep = None
        try:
            from deep_translator import GoogleTranslator
            self._deep = GoogleTranslator(source="auto", target=self.target_lang)
        except Exception:
            pass

        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; BOS-MITRE-Parser/2.0)"
        })

    def translate_text(self, text: str) -> str | None:
        if not text or not text.strip():
            return text

        if self._deep is not None:
            for attempt in range(1, self.max_retries + 1):
                try:
                    out = self._deep.translate(text)
                    if out and isinstance(out, str):
                        self.stats.translated += 1
                        return out
                except Exception:
                    if attempt < self.max_retries:
                        time.sleep(self.delay * attempt)

        return self._http_translate(text)

    def translate_batch(self, texts: list[str]) -> list[str | None]:
        if self._deep is not None:
            try:
                results = self._deep.translate_batch(texts)
                if results and len(results) == len(texts):
                    self.stats.translated += len(texts)
                    return [r if isinstance(r, str) and r else None for r in results]
            except Exception:
                pass

        return [self.translate_text(t) for t in texts]

    def _http_translate(self, text: str) -> str | None:
        params = {
            "client": "gtx",
            "sl": "auto",
            "tl": self.target_lang,
            "dt": "t",
            "q": text[:4500],
        }
        url = f"{self.GOOGLE_FREE_URL}?{urllib.parse.urlencode(params)}"
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.get(url, timeout=self.timeout)
                if resp.status_code == 429:
                    time.sleep(2 * attempt)
                    continue
                resp.raise_for_status()
                data = resp.json()
                segments = data[0] if isinstance(data, list) and data else []
                translated = "".join(
                    seg[0] for seg in segments
                    if isinstance(seg, list) and seg and seg[0]
                )
                if translated:
                    self.stats.translated += 1
                    return translated
            except Exception:
                if attempt < self.max_retries:
                    time.sleep(self.delay * attempt)
        self.stats.failed += 1
        return None
