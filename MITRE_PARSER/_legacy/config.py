from pathlib import Path

class Config:
    BASE_DIR = Path(__file__).parent.parent
    OUTPUT_DIR = BASE_DIR / "output"
    
    # 🔹 НАСТРОЙКА ПЕРЕВОДА 🔹
    ENABLE_TRANSLATION = False
    TRANSLATE_TO = "ru" # <- Код языка для Русского
    TRANSLATION_DELAY = 1.5     # Задержка между запросами к переводчику (сек)
    TRANSLATION_BATCH_SIZE = 20 # Сколько строк отправлять за раз (Google позволяет до ~100)
    TRANSLATION_MAX_RETRIES = 4     # Число повторных попыток при ошибке
    
    # Настройки загрузки
    REQUEST_TIMEOUT = 30
    RETRY_ATTEMPTS = 3
    RETRY_DELAY = 5

    # 🔹 Ограничение записей (0 или None = все) 🔹
    MAX_CAPEC_RECORDS = 330
    MAX_CWE_RECORDS = 500
    MAX_CVE_RECORDS = 2000
    MAX_ATTACK_RECORDS = 300
    
    # Источники данных
    SOURCES = {
        "capec": "https://capec.mitre.org/data/xml/capec_latest.xml",
        "cwe": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "cve_latest": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
        "attack_stix": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    }
    
    # Маппинг полей (без пробелов в концах ключей!)
    FIELD_MAPPING = {
        "capec": {"id": "id", "name": "name", "description": "description", "severity": "severity", "related_cwe": "related_cwe", "related_mitre": "related_mitre", "prerequisites": "prerequisites", "mitigations": "mitigations"},
        "cve": {"id": "id", "description": "description", "severity": "severity", "cvss_score": "cvss_score", "affected_software": "affected_software", "attack_type": "attack_type", "related_cwe": "related_cwe", "related_capec": "related_capec", "related_mitre": "related_mitre", "requires_service": "requires_service", "requires_port": "requires_port", "prerequisites": "prerequisites"},
        "mitre_attack": {"id": "id", "name": "name", "tactic": "tactic", "description": "description", "platforms": "platforms", "related_cwe": "related_cwe", "related_capec": "related_capec", "requires_service": "requires_service", "detection": "detection", "mitigations": "mitigations"},
        "cwe": {"id": "id", "name": "name", "description": "description", "category": "category", "related_capec": "related_capec", "mitigation": "mitigation", "requires_technology": "requires_technology", "detection_methods": "detection_methods"}
        }