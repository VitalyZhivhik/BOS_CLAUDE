"""
Сопоставление векторов атак с CVE для локальной базы.

Полное «100%» попадание для любого паттерна невозможно (CVE привязаны к продуктам
и версиям), но здесь используется каскад источников, чтобы почти всегда получить
осмысленный набор CVE/CWE для анализа: текст вектора, тип атаки, CWE, записи БД
и курируемые примеры по классу сервиса.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from common.models import AttackVector
    from server.vulnerability_db import VulnerabilityDatabase

# NVD формат: CVE-YYYY-NNNN+
CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Тип атаки вектора → поле attack_type в cve_database.json
AV_ATTACK_TO_DB_ATTACK: dict[str, str] = {
    "sql_injection": "sql_injection",
    "cross_site_scripting": "cross_site_scripting",
    "path_traversal": "remote_code_execution",
    "remote_code_execution": "remote_code_execution",
    "csrf": "cross_site_scripting",
    "ssrf": "remote_code_execution",
    "deserialization_attack": "deserialization_attack",
    "privilege_escalation": "privilege_escalation",
    "denial_of_service": "denial_of_service",
    "protocol_attack": "remote_code_execution",
    "credential_theft": "remote_code_execution",
    "authentication_bypass": "remote_code_execution",
    "man_in_the_middle": "remote_code_execution",
    "misconfiguration": "remote_code_execution",
    "known_vulnerability": "remote_code_execution",
    "brute_force": "denial_of_service",
    "information_disclosure": "remote_code_execution",
    "abuse": "remote_code_execution",
    "network_reconnaissance": "remote_code_execution",
    "dns_attack": "denial_of_service",
}

# Тип атаки вектора → CWE для поиска в related_cwe
AV_ATTACK_TO_CWES: dict[str, list[str]] = {
    "sql_injection": ["CWE-89"],
    "cross_site_scripting": ["CWE-79"],
    "path_traversal": ["CWE-22"],
    "csrf": ["CWE-352"],
    "ssrf": ["CWE-918"],
    "deserialization_attack": ["CWE-502"],
    "privilege_escalation": ["CWE-269"],
}

# Классы сервисов вектора → ключи курируемого списка (см. CURATED_PRODUCT_CVES)
SERVICE_CLASS_TO_PRODUCTS: dict[str, list[str]] = {
    "HTTP": ["Apache", "nginx", "Microsoft-IIS"],
    "HTTPS": ["OpenSSL", "nginx", "Apache"],
    "HTTP-Proxy": ["Apache", "nginx"],
    "FTP": ["FTP", "ProFTPD", "vsftpd"],
    "SSH": ["OpenSSH"],
    "SMB": ["SMB"],
    "RDP": ["Microsoft-RDP"],
    "MySQL": ["MySQL"],
    "PostgreSQL": ["PostgreSQL"],
    "Redis": ["Redis"],
    "MongoDB": [],
    "MSSQL": ["MySQL"],
    "DNS": ["DNS"],
    "SMTP": ["Exim"],
    "IMAP": ["Dovecot"],
    "POP3": ["Dovecot"],
    "VNC": ["Microsoft-RDP"],
    "Telnet": ["OpenSSH"],
    "RPC": ["SMB"],
    "NetBIOS": ["SMB"],
    "VMware": ["VMware"],
    "Windows": ["SMB"],
    "Windows SMB": ["SMB"],
    "Windows AD": ["SMB"],
    "Linux": [],
    "banner_detected": [],
    "generic": [],
}

# Курируемые CVE (id, severity, краткое описание) — синхронно с типовыми угрозами по продукту
CURATED_PRODUCT_CVES: dict[str, list[tuple[str, str, str]]] = {
    "Apache": [
        ("CVE-2021-41773", "CRITICAL", "Apache 2.4.49 — Path Traversal/RCE"),
        ("CVE-2021-42013", "CRITICAL", "Apache 2.4.50 — Path Traversal/RCE"),
        ("CVE-2022-22720", "HIGH", "Apache 2.4.52 — mod_sed"),
    ],
    "nginx": [
        ("CVE-2021-23017", "HIGH", "Nginx — DNS resolver"),
        ("CVE-2023-44487", "HIGH", "HTTP/2 rapid reset"),
    ],
    "Microsoft-IIS": [
        ("CVE-2021-31166", "CRITICAL", "IIS — HTTP Protocol Stack RCE"),
        ("CVE-2022-21907", "CRITICAL", "IIS — HTTP Protocol Stack RCE"),
    ],
    "OpenSSL": [
        ("CVE-2014-0160", "CRITICAL", "Heartbleed"),
        ("CVE-2014-3566", "MEDIUM", "POODLE SSL 3.0"),
        ("CVE-2017-13099", "HIGH", "ROBOT"),
    ],
    "OpenSSH": [
        ("CVE-2020-15778", "MEDIUM", "scp command injection"),
        ("CVE-2023-38408", "HIGH", "OpenSSH PKCS#11"),
    ],
    "ProFTPD": [
        ("CVE-2019-12815", "CRITICAL", "ProFTPD mod_copy"),
        ("CVE-2020-9273", "HIGH", "ProFTPD mod_copy injection"),
    ],
    "vsftpd": [
        ("CVE-2011-2523", "CRITICAL", "vsftpd backdoor 2.3.4"),
    ],
    "MySQL": [
        ("CVE-2012-2122", "HIGH", "MySQL auth bypass"),
        ("CVE-2022-21890", "CRITICAL", "MySQL RCE (пример из класса)"),
    ],
    "PostgreSQL": [
        ("CVE-2019-10164", "HIGH", "PostgreSQL buffer overrun"),
        ("CVE-2021-32027", "CRITICAL", "PostgreSQL memory corruption"),
    ],
    "SMB": [
        ("CVE-2017-0144", "CRITICAL", "EternalBlue SMB"),
        ("CVE-2020-0796", "CRITICAL", "SMBGhost"),
    ],
    "Microsoft-RDP": [
        ("CVE-2019-0708", "CRITICAL", "BlueKeep"),
        ("CVE-2020-16898", "CRITICAL", "Bad Neighbor"),
    ],
    "Redis": [
        ("CVE-2022-0543", "CRITICAL", "Redis Lua sandbox"),
    ],
    "DNS": [
        ("CVE-2020-1350", "CRITICAL", "Windows DNS SIGRed"),
    ],
    "Exim": [
        ("CVE-2019-10149", "CRITICAL", "Exim RCE"),
    ],
    "Dovecot": [
        ("CVE-2019-11500", "HIGH", "Dovecot IMAP literal"),
    ],
    "VMware": [
        ("CVE-2021-21972", "CRITICAL", "vSphere Client RCE"),
    ],
    "FTP": [
        ("CVE-2020-9273", "HIGH", "ProFTPD mod_copy"),
    ],
}

SEVERITY_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0}


def _synthetic_cve(cve_id: str, severity: str, description: str) -> dict[str, Any]:
    return {
        "id": cve_id.upper(),
        "description": description,
        "description_ru": description,
        "severity": severity,
        "severity_ru": severity,
        "cvss_score": SEVERITY_SCORE.get(severity.upper(), 5.0),
        "affected_software": [],
        "attack_type": "unknown",
        "attack_type_ru": "Каталог/справочник",
        "related_cwe": [],
        "related_capec": [],
        "related_mitre": [],
        "mitigations": [
            "Сверьте детали на https://nvd.nist.gov/ (официальное описание CVE).",
            "Сопоставьте с установленными версиями ПО и данными сканеров (Trivy и т.д.).",
        ],
        "requires_service": [],
        "requires_port": [],
        "prerequisites": [],
        "_synthetic": True,
    }


def _merge_curated_for_service(service: str, max_per_product: int = 3) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    products = SERVICE_CLASS_TO_PRODUCTS.get(service, [])
    for prod in products:
        rows = CURATED_PRODUCT_CVES.get(prod, [])
        for cve_id, sev, desc in rows[:max_per_product]:
            out.append(_synthetic_cve(cve_id, sev, desc))
    return out


def _dedupe_cves(entries: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result: list[dict] = []
    for e in entries:
        cid = e.get("id", "")
        if not cid or cid in seen:
            continue
        seen.add(cid)
        result.append(e)
    return result


def resolve_cves_for_attack_vector(av: AttackVector, vuln_db: VulnerabilityDatabase) -> list[dict]:
    """
    Возвращает упорядоченный список записей CVE (из БД или синтетических справочных).
    """
    collected: list[dict] = []

    # 1) Явный список от клиента/генератора
    for rid in getattr(av, "representative_cve_ids", None) or []:
        if not rid:
            continue
        rid_s = str(rid).strip().upper()
        row = vuln_db.get_cve_by_id(rid_s)
        if row:
            collected.append(row)
        else:
            collected.append(_synthetic_cve(rid_s, "MEDIUM", f"CVE {rid_s} (вне локальной БД; требуется сверка с NVD)."))

    # 2) CVE в названии/описании/инструментах
    blob = f"{av.name} {av.description} {av.tools_used}"
    for m in CVE_IN_TEXT.findall(blob):
        rid = m.upper()
        row = vuln_db.get_cve_by_id(rid)
        if row:
            collected.append(row)
        else:
            collected.append(_synthetic_cve(rid, "MEDIUM", f"CVE {rid} упомянут во векторе; нет строки в локальной БД."))

    # 3) Тип атаки → поле attack_type в JSON
    db_at = AV_ATTACK_TO_DB_ATTACK.get(av.attack_type or "")
    if db_at:
        collected.extend(vuln_db.find_cves_by_attack_type(db_at, limit=16))

    # 4) CWE по типу атаки
    cwes = AV_ATTACK_TO_CWES.get(av.attack_type or "", [])
    if cwes:
        collected.extend(vuln_db.find_cves_by_cwe_ids(cwes, limit=12))

    # 5) Сервис/порт — штатные поиски (requires_service в БД)
    if av.target_service:
        collected.extend(vuln_db.find_cves_by_service(av.target_service))
        collected.extend(vuln_db.find_cves_by_software(av.target_service))
    if av.target_port is not None:
        collected.extend(vuln_db.find_cves_by_port(int(av.target_port)))

    # 6) Курируемые примеры по классу сервиса (закрывает случаи «brute_force» и т.д.)
    if av.target_service:
        collected.extend(_merge_curated_for_service(av.target_service))

    merged = _dedupe_cves(collected)

    # Ограничение размера: приоритет — реальные записи БД, затем синтетика
    def sort_key(c: dict) -> tuple[int, float]:
        syn = 1 if c.get("_synthetic") else 0
        return (syn, -vuln_db._cvss_value(c))

    merged.sort(key=sort_key)
    cap = 28
    return merged[:cap]
