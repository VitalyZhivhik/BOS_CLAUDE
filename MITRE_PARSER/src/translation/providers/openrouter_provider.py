"""OpenRouter API translation provider.

OpenRouter provides access to many free models via a unified API.
Free models (no credit card required):
  - meta-llama/llama-3.3-70b-instruct:free
  - google/gemma-2-9b-it:free
  - mistralai/mistral-7b-instruct:free
  - qwen/qwen-2.5-72b-instruct:free
"""
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

FREE_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "google/gemma-2-9b-it:free",
    "mistralai/mistral-7b-instruct:free",
]


class OpenRouterProvider(BaseProvider):
    """OpenRouter unified API — supports many free models."""

    name = "OpenRouter"
    supports_batch = True

    API_URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(
        self,
        api_key: str,
        model: str = "",
        target_lang: str = "ru",
        timeout: int = 30,
        max_retries: int = 2,
        label: str = "",
        **kwargs,
    ) -> None:
        super().__init__(target_lang, **kwargs)
        self.api_key = api_key
        self.model = model or FREE_MODELS[0]
        self.timeout = timeout
        self.max_retries = max_retries
        if label:
            self.name = f"OpenRouter ({label})"
        else:
            short_model = self.model.split("/")[-1].split(":")[0]
            self.name = f"OpenRouter ({short_model})"

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/BOS-MITRE-Parser",
            "X-Title": "BOS MITRE Parser",
        })

    def translate_text(self, text: str) -> str | None:
        if not text or not text.strip():
            return text

        payload = {
            "model": self.model,
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
            "model": self.model,
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
