"""
Единая конфигурация парсера баз кибербезопасности.

Все настройки можно переопределить переменными окружения с префиксом MP_,
например: MP_ENABLE_TRANSLATION=0, MP_MAX_CVE_RECORDS=2000.
"""
from __future__ import annotations

import os
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


class Config:
    # ── Пути ────────────────────────────────────────────────
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    OUTPUT_DIR: Path = Path(os.getenv("MP_OUTPUT_DIR", str(BASE_DIR / "output")))
    CACHE_DIR: Path = OUTPUT_DIR / "_cache"
    PROJECT_DATABASES_DIR: Path = Path(
        os.getenv("MP_DATABASES_DIR", str(BASE_DIR.parent / "databases"))
    )
    CATALOG_DIR: Path = BASE_DIR / "src" / "catalog"

    # ── Перевод (по умолчанию ВКЛЮЧЁН) ──────────────────────
    ENABLE_TRANSLATION: bool = _env_bool("MP_ENABLE_TRANSLATION", True)
    TRANSLATE_TO: str = os.getenv("MP_TRANSLATE_TO", "ru")
    TRANSLATION_BATCH_SIZE: int = _env_int("MP_TRANSLATION_BATCH_SIZE", 15)
    TRANSLATION_DELAY: float = _env_float("MP_TRANSLATION_DELAY", 0.3)
    TRANSLATION_MAX_RETRIES: int = _env_int("MP_TRANSLATION_MAX_RETRIES", 2)
    TRANSLATION_WORKERS: int = _env_int("MP_TRANSLATION_WORKERS", 4)
    TRANSLATION_MAX_LEN: int = _env_int("MP_TRANSLATION_MAX_LEN", 4500)
    TRANSLATION_CB_TRIP_THRESHOLD: int = _env_int("MP_TRANSLATION_CB_TRIP", 3)
    TRANSLATION_TIMEOUT: int = _env_int("MP_TRANSLATION_TIMEOUT", 15)

    # ── API ключи ──────────────────────────────────────────
    GROQ_API_KEYS: list[str] = [
        k.strip() for k in
        os.getenv("MP_GROQ_API_KEYS", "").split(",") if k.strip()
    ]
    MISTRAL_API_KEY: str = os.getenv("MP_MISTRAL_API_KEY", "")

    # ── HTTP ────────────────────────────────────────────────
    REQUEST_TIMEOUT: int = _env_int("MP_REQUEST_TIMEOUT", 60)
    RETRY_ATTEMPTS: int = _env_int("MP_RETRY_ATTEMPTS", 3)
    RETRY_DELAY: int = _env_int("MP_RETRY_DELAY", 5)
    USER_AGENT: str = os.getenv(
        "MP_USER_AGENT",
        "Mozilla/5.0 (compatible; BOS-MITRE-Parser/2.0; +https://example.local)",
    )

    # ── Лимиты записей (0 = все) ─────────────────────────────
    MAX_CAPEC_RECORDS: int = _env_int("MP_MAX_CAPEC_RECORDS", 600)
    MAX_CWE_RECORDS: int = _env_int("MP_MAX_CWE_RECORDS", 1500)
    MAX_CVE_RECORDS: int = _env_int("MP_MAX_CVE_RECORDS", 800)
    MAX_ATTACK_RECORDS: int = _env_int("MP_MAX_ATTACK_RECORDS", 600)
    MAX_MITRE_SOFTWARE: int = _env_int("MP_MAX_MITRE_SOFTWARE", 250)
    MAX_MITRE_MITIGATIONS: int = _env_int("MP_MAX_MITRE_MITIGATIONS", 60)

    # ── Checkpoint ──────────────────────────────────────────
    CHECKPOINT_INTERVAL: int = _env_int("MP_CHECKPOINT_INTERVAL", 20)

    # ── Источники данных ────────────────────────────────────
    SOURCES = {
        "capec": "https://capec.mitre.org/data/xml/capec_latest.xml",
        "cwe": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "cve_latest": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
        "cve_recent": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz",
        "attack_stix": (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json"
        ),
    }

    # ── Файлы вывода (имена соответствуют databases/) ───────
    DB_FILES = {
        "capec": "capec_database.json",
        "cwe": "cwe_database.json",
        "cve": "cve_database.json",
        "attack": "mitre_attack.json",
        "tools": "tools_database.json",
        "defense": "defense_database.json",
    }

    # ── Логирование ────────────────────────────────────────
    VERBOSE: bool = _env_bool("MP_VERBOSE", True)


__all__ = ["Config"]
