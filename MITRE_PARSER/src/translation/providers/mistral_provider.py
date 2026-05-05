"""Mistral AI translation provider."""
from __future__ import annotations

import json
import time

import requests

from translation.providers.base import BaseProvider


_SYSTEM_PROMPT = (
    "You are a professional translator. Translate the following text to Russian. "
    "Keep technical terms (CVE, CWE, SQL, XSS, CAPEC, MITRE, etc.) untranslated. "
    "Return ONLY the translated text, no explanations."
)

_BATCH_SYSTEM_PROMPT = (
    "You are a professional translator. Translate each line to Russian. "
    "Keep technical terms (CVE, CWE, SQL, XSS, CAPEC, MITRE, ATT&CK, etc.) untranslated. "
    "Return a JSON array of translated strings, same order and count as input. "
    "Return ONLY the JSON array, nothing else."
)


class MistralProvider(BaseProvider):
    """Mistral AI API provider."""

    name = "Mistral"
    supports_batch = True

    API_URL = "https://api.mistral.ai/v1/chat/completions"
    MODEL = "mistral-small-latest"

    def __init__(
        self,
        api_key: str,
        target_lang: str = "ru",
        timeout: int = 30,
        max_retries: int = 2,
        **kwargs,
    ) -> None:
        super().__init__(target_lang, **kwargs)
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def translate_text(self, text: str) -> str | None:
        if not text or not text.strip():
            return text

        payload = {
            "model": self.MODEL,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            "temperature": 0.1,
            "max_tokens": min(len(text) * 3, 8000),
        }

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.post(
                    self.API_URL, json=payload, timeout=self.timeout
                )
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("retry-after", 2 * attempt))
                    time.sleep(retry_after)
                    continue
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"].strip()
                if content:
                    self.stats.translated += 1
                    return content
            except Exception:
                if attempt < self.max_retries:
                    time.sleep(1.5 * attempt)

        self.stats.failed += 1
        return None

    def translate_batch(self, texts: list[str]) -> list[str | None]:
        if not texts:
            return []
        if len(texts) == 1:
            return [self.translate_text(texts[0])]

        numbered = "\n".join(f"{i+1}. {t}" for i, t in enumerate(texts))
        payload = {
            "model": self.MODEL,
            "messages": [
                {"role": "system", "content": _BATCH_SYSTEM_PROMPT},
                {"role": "user", "content": numbered},
            ],
            "temperature": 0.1,
            "max_tokens": sum(len(t) * 3 for t in texts) + 500,
        }

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.post(
                    self.API_URL, json=payload, timeout=self.timeout * 2
                )
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("retry-after", 3 * attempt))
                    time.sleep(retry_after)
                    continue
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"].strip()
                parsed = self._parse_batch_response(content, len(texts))
                if parsed and len(parsed) == len(texts):
                    self.stats.translated += len(texts)
                    return parsed
            except Exception:
                if attempt < self.max_retries:
                    time.sleep(2 * attempt)

        return [self.translate_text(t) for t in texts]

    @staticmethod
    def _parse_batch_response(content: str, expected: int) -> list[str] | None:
        content = content.strip()
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            arr = json.loads(content)
            if isinstance(arr, list) and len(arr) == expected:
                return [str(x) if x else "" for x in arr]
        except (json.JSONDecodeError, ValueError):
            pass

        lines = [l.strip() for l in content.split("\n") if l.strip()]
        cleaned = []
        for line in lines:
            if line and line[0].isdigit() and ". " in line:
                line = line.split(". ", 1)[1]
            cleaned.append(line)
        if len(cleaned) == expected:
            return cleaned
        return None
