"""Базовые утилиты, общие для всех парсеров."""
from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def clean_html(text: str | None) -> str:
    """Удаляет HTML-теги и нормализует пробелы."""
    if not text:
        return ""
    no_tags = _TAG_RE.sub(" ", text)
    no_ws = _WS_RE.sub(" ", no_tags)
    return html.unescape(no_ws).strip()


def text_of(elem: ET.Element | None) -> str:
    """Извлекает весь текст из XML-элемента (с учётом вложенных тегов)."""
    if elem is None:
        return ""
    parts: list[str] = []
    if elem.text and elem.text.strip():
        parts.append(elem.text.strip())
    for child in elem:
        parts.append(text_of(child))
        if child.tail and child.tail.strip():
            parts.append(child.tail.strip())
    return _WS_RE.sub(" ", " ".join(p for p in parts if p)).strip()


def find_all(parent: ET.Element | None, ns: str, tag: str) -> list[ET.Element]:
    if parent is None:
        return []
    return parent.findall(f".//{{{ns}}}{tag}")


def find_one(parent: ET.Element | None, ns: str, tag: str) -> ET.Element | None:
    if parent is None:
        return None
    return parent.find(f".//{{{ns}}}{tag}")


def trunc(text: str, n: int = 600) -> str:
    text = text or ""
    if len(text) <= n:
        return text
    return text[: n - 1].rsplit(" ", 1)[0] + "…"


__all__ = ["clean_html", "text_of", "find_all", "find_one", "trunc"]
