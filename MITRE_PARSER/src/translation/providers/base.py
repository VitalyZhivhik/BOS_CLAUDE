"""Abstract base class for translation providers."""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProviderStatus:
    name: str
    available: bool
    latency_ms: float = 0.0
    error: str = ""


@dataclass
class ProviderStats:
    translated: int = 0
    failed: int = 0
    total_time: float = 0.0


class BaseProvider(ABC):
    """Base class for all translation providers."""

    name: str = "base"
    supports_batch: bool = False

    def __init__(self, target_lang: str = "ru", **kwargs: Any) -> None:
        self.target_lang = target_lang
        self.stats = ProviderStats()

    @abstractmethod
    def translate_text(self, text: str) -> str | None:
        """Translate a single text string. Returns None on failure."""

    def translate_batch(self, texts: list[str]) -> list[str | None]:
        """Translate a batch of texts. Default: sequential calls."""
        return [self.translate_text(t) for t in texts]

    def check_availability(self) -> ProviderStatus:
        """Check if this provider is reachable."""
        t0 = time.monotonic()
        try:
            result = self.translate_text("Hello")
            if result and len(result) > 0:
                return ProviderStatus(
                    name=self.name,
                    available=True,
                    latency_ms=(time.monotonic() - t0) * 1000,
                )
            return ProviderStatus(name=self.name, available=False, error="Empty response")
        except Exception as e:
            return ProviderStatus(
                name=self.name,
                available=False,
                latency_ms=(time.monotonic() - t0) * 1000,
                error=str(e)[:200],
            )


__all__ = ["BaseProvider", "ProviderStatus", "ProviderStats"]
