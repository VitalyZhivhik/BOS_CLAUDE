#!/usr/bin/env python3
"""
Улучшенный резолвер CVE с мощной логикой определения уязвимостей.
Интеграция всех доступных баз данных (CVE, CWE, MITRE ATT&CK, CAPEC)
и реализация продвинутого анализа векторов атаки.

Основные улучшения:
1. Интеграция MITRE ATT&CK техник и тактик
2. Комбинированный анализ нескольких параметров одновременно
3. Кросс-референсы между CVE, CWE, MITRE ATT&CK и CAPEC
4. Улучшенное ранжирование и приоритизация результатов
5. Контекстно-зависимый анализ векторов атаки
"""

from __future__ import annotations

import re
import json
import os
from typing import TYPE_CHECKING, Any, List, Dict, Set, Tuple, Optional

if TYPE_CHECKING:
    from common.models import AttackVector
    from server.vulnerability_db import VulnerabilityDatabase

# NVD формат: CVE-YYYY-NNNN+
CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Расширенное сопоставление типов атак
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

# Расширенное сопоставление типов атак с CWE
AV_ATTACK_TO_CWES: dict[str, list[str]] = {
    "sql_injection": ["CWE-89"],
    "cross_site_scripting": ["CWE-79"],
    "path_traversal": ["CWE-22"],
    "csrf": ["CWE-352"],
    "ssrf": ["CWE-918"],
    "deserialization_attack": ["CWE-502"],
    "privilege_escalation": ["CWE-269"],
    "denial_of_service": ["CWE-400"],
    "remote_code_execution": ["CWE-94", "CWE-78", "CWE-88"],
    "information_disclosure": ["CWE-200"],
    "authentication_bypass": ["CWE-287", "CWE-306"],
    "brute_force": ["CWE-307"],
    "misconfiguration": ["CWE-16", "CWE-2"],
}

# Сопоставление тактик MITRE ATT&CK с типами атак
MITRE_TACTIC_TO_ATTACK_TYPES: dict[str, list[str]] = {
    "Initial Access": ["remote_code_execution", "sql_injection", "cross_site_scripting"],
    "Execution": ["remote_code_execution", "deserialization_attack"],
    "Persistence": ["privilege_escalation", "misconfiguration"],
    "Privilege Escalation": ["privilege_escalation", "authentication_bypass"],
    "Defense Evasion": ["misconfiguration", "information_disclosure"],
    "Credential Access": ["credential_theft", "authentication_bypass"],
    "Discovery": ["network_reconnaissance", "information_disclosure"],
    "Lateral Movement": ["remote_code_execution", "protocol_attack"],
    "Collection": ["information_disclosure"],
    "Command and Control": ["remote_code_execution"],
    "Exfiltration": ["information_disclosure"],
    "Impact": ["denial_of_service", "remote_code_execution"],
}

# Сопоставление сервисов с продуктами
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

# Курируемые CVE (id, severity, краткое описание)
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

def _load_mitre_attack_database() -> list[dict]:
    """Загрузка базы данных MITRE ATT&CK."""
    try:
        mitre_path = os.path.join(os.path.dirname(__file__), "..", "databases", "mitre_attack.json")
        with open(mitre_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Ошибка загрузки MITRE ATT&CK базы: {e}")
        return []

def _load_cwe_database() -> list[dict]:
    """Загрузка базы данных CWE."""
    try:
        cwe_path = os.path.join(os.path.dirname(__file__), "..", "databases", "cwe_database.json")
        with open(cwe_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Ошибка загрузки CWE базы: {e}")
        return []

def _find_mitre_techniques_by_cwe(cwe_id: str, mitre_db: list[dict]) -> list[str]:
    """Поиск техник MITRE ATT&CK по CWE."""
    techniques = []
    for technique in mitre_db:
        if cwe_id in technique.get("related_cwe", []):
            techniques.append(technique["id"])
    return techniques

def _find_mitre_techniques_by_attack_type(attack_type: str, mitre_db: list[dict]) -> list[str]:
    """Поиск техник MITRE ATT&CK по типу атаки."""
    techniques = []
    for technique in mitre_db:
        if attack_type in MITRE_TACTIC_TO_ATTACK_TYPES.get(technique.get("tactic", ""), []):
            techniques.append(technique["id"])
    return techniques

def _find_cwe_by_mitre_technique(technique_id: str, mitre_db: list[dict]) -> list[str]:
    """Поиск CWE по технике MITRE ATT&CK."""
    for technique in mitre_db:
        if technique["id"] == technique_id:
            return technique.get("related_cwe", [])
    return []

def _analyze_attack_vector_context(av: AttackVector) -> dict:
    """Анализ контекста вектора атаки для выявления дополнительных параметров."""
    context = {
        "services": set(),
        "ports": set(),
        "technologies": set(),
        "attack_patterns": set()
    }

    # Анализ названия и описания
    text = f"{av.name} {av.description}".lower()

    # Поиск сервисов
    service_patterns = {
        r"ssh": "SSH", r"http": "HTTP", r"https": "HTTPS", r"ftp": "FTP",
        r"smb": "SMB", r"rdp": "RDP", r"mysql": "MySQL", r"postgresql": "PostgreSQL",
        r"redis": "Redis", r"mongodb": "MongoDB", r"mssql": "MSSQL",
        r"dns": "DNS", r"smtp": "SMTP", r"imap": "IMAP", r"pop3": "POP3",
        r"vnc": "VNC", r"telnet": "Telnet", r"rpc": "RPC", r"netbios": "NetBIOS",
        r"vmware": "VMware", r"apache": "Apache", r"nginx": "nginx",
        r"iis": "Microsoft-IIS", r"openssl": "OpenSSL", r"openssh": "OpenSSH"
    }

    for pattern, service in service_patterns.items():
        if re.search(pattern, text):
            context["services"].add(service)

    # Поиск портов
    port_matches = re.findall(r"\bport\s+(\d+)\b|\b(\d+)\s+port\b", text)
    for match in port_matches:
        for port_str in match:
            if port_str:
                context["ports"].add(int(port_str))

    # Поиск технологий
    tech_patterns = {
        r"apache": "Apache", r"nginx": "nginx", r"microsoft.*iis": "Microsoft-IIS",
        r"openssl": "OpenSSL", r"openssh": "OpenSSH", r"vmware": "VMware",
        r"mysql": "MySQL", r"postgresql": "PostgreSQL", r"redis": "Redis",
        r"mongodb": "MongoDB", r"windows": "Windows", r"linux": "Linux"
    }

    for pattern, tech in tech_patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            context["technologies"].add(tech)

    # Анализ шаблонов атак
    attack_patterns = {
        r"sql.*inject": "sql_injection", r"xss": "cross_site_scripting",
        r"path.*trav": "path_traversal", r"rce": "remote_code_execution",
        r"csrf": "csrf", r"ssrf": "ssrf", r"deserial": "deserialization_attack",
        r"priv.*escal": "privilege_escalation", r"dos": "denial_of_service",
        r"brute.*force": "brute_force", r"info.*disc": "information_disclosure",
        r"auth.*bypass": "authentication_bypass", r"mitm": "man_in_the_middle"
    }

    for pattern, attack_type in attack_patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            context["attack_patterns"].add(attack_type)

    return context

def _get_combined_score(cve: dict, context_matches: int, mitre_matches: int) -> float:
    """Вычисление комбинированного скора для ранжирования CVE."""
    base_score = cve.get("cvss_score", 5.0)
    severity_score = SEVERITY_SCORE.get(cve.get("severity", "MEDIUM").upper(), 5.0)

    # Учитываем контекстные совпадения
    context_boost = context_matches * 0.5
    mitre_boost = mitre_matches * 0.3

    # Бонус за наличие связанных CWE, CAPEC, MITRE
    related_bonus = 0
    if cve.get("related_cwe"):
        related_bonus += 0.2
    if cve.get("related_capec"):
        related_bonus += 0.2
    if cve.get("related_mitre"):
        related_bonus += 0.3

    return base_score + context_boost + mitre_boost + related_bonus

def resolve_cves_for_attack_vector(av: AttackVector, vuln_db: VulnerabilityDatabase) -> list[dict]:
    """
    Улучшенный резолвер CVE с мощной логикой определения уязвимостей.
    Использует все доступные источники данных и контекстный анализ.
    """
    collected: list[dict] = []
    mitre_db = _load_mitre_attack_database()
    cwe_db = _load_cwe_database()

    # 1. Явный список CVE от клиента/генератора
    for rid in getattr(av, "representative_cve_ids", None) or []:
        if not rid:
            continue
        rid_s = str(rid).strip().upper()
        row = vuln_db.get_cve_by_id(rid_s)
        if row:
            collected.append(row)
        else:
            collected.append(_synthetic_cve(rid_s, "MEDIUM", f"CVE {rid_s} (вне локальной БД; требуется сверка с NVD)."))

    # 2. CVE в названии/описании/инструментах
    blob = f"{av.name} {av.description} {av.tools_used}"
    for m in CVE_IN_TEXT.findall(blob):
        rid = m.upper()
        row = vuln_db.get_cve_by_id(rid)
        if row:
            collected.append(row)
        else:
            collected.append(_synthetic_cve(rid, "MEDIUM", f"CVE {rid} упомянут во векторе; нет строки в локальной БД."))

    # 3. Тип атаки → поле attack_type в JSON
    db_at = AV_ATTACK_TO_DB_ATTACK.get(av.attack_type or "")
    if db_at:
        collected.extend(vuln_db.find_cves_by_attack_type(db_at, limit=20))

    # 4. CWE по типу атаки
    cwes = AV_ATTACK_TO_CWES.get(av.attack_type or "", [])
    if cwes:
        collected.extend(vuln_db.find_cves_by_cwe_ids(cwes, limit=15))

    # 5. Сервис/порт — штатные поиски
    if av.target_service:
        collected.extend(vuln_db.find_cves_by_service(av.target_service))
        collected.extend(vuln_db.find_cves_by_software(av.target_service))
    if av.target_port is not None:
        collected.extend(vuln_db.find_cves_by_port(int(av.target_port)))

    # 6. Курируемые примеры по классу сервиса
    if av.target_service:
        collected.extend(_merge_curated_for_service(av.target_service))

    # 7. Контекстный анализ вектора атаки
    context_analysis = _analyze_attack_vector_context(av)

    # Добавляем CVE для найденных сервисов
    for service in context_analysis["services"]:
        collected.extend(vuln_db.find_cves_by_service(service))
        collected.extend(vuln_db.find_cves_by_software(service))
        collected.extend(_merge_curated_for_service(service))

    # Добавляем CVE для найденных портов
    for port in context_analysis["ports"]:
        collected.extend(vuln_db.find_cves_by_port(port))

    # 8. Интеграция MITRE ATT&CK
    # Поиск техник по типу атаки
    mitre_techniques = _find_mitre_techniques_by_attack_type(av.attack_type or "", mitre_db)
    for technique_id in mitre_techniques:
        # Поиск CWE по технике MITRE
        technique_cwes = _find_cwe_by_mitre_technique(technique_id, mitre_db)
        if technique_cwes:
            collected.extend(vuln_db.find_cves_by_cwe_ids(technique_cwes, limit=10))

    # 9. Кросс-референсы: поиск CVE через связанные CWE, CAPEC, MITRE
    # Анализ уже найденных CVE для поиска связанных уязвимостей
    related_cwes = set()
    related_capecs = set()
    related_mitres = set()

    for cve in collected:
        related_cwes.update(cve.get("related_cwe", []))
        related_capecs.update(cve.get("related_capec", []))
        related_mitres.update(cve.get("related_mitre", []))

    # Поиск CVE по связанным CWE
    if related_cwes:
        collected.extend(vuln_db.find_cves_by_cwe_ids(list(related_cwes), limit=15))

    # Поиск CVE по связанным CAPEC (через CWE)
    if related_capecs and cwe_db:
        for capec_id in related_capecs:
            for cwe_item in cwe_db:
                if capec_id in cwe_item.get("related_capec", []):
                    related_cwes.add(cwe_item["id"])

        if related_cwes:
            collected.extend(vuln_db.find_cves_by_cwe_ids(list(related_cwes), limit=10))

    # Поиск CVE по связанным MITRE техникам
    if related_mitres and mitre_db:
        for mitre_id in related_mitres:
            technique_cwes = _find_cwe_by_mitre_technique(mitre_id, mitre_db)
            if technique_cwes:
                collected.extend(vuln_db.find_cves_by_cwe_ids(technique_cwes, limit=10))

    # Удаление дубликатов
    merged = _dedupe_cves(collected)

    # 10. Улучшенное ранжирование с учетом контекста
    # Анализ релевантности каждого CVE к вектору атаки
    ranked_cves = []
    for cve in merged:
        context_matches = 0
        mitre_matches = 0

        # Проверка соответствия контексту
        cve_software = [s.lower() for s in cve.get("affected_software", [])]
        cve_services = [s.lower() for s in cve.get("requires_service", [])]
        cve_ports = cve.get("requires_port", [])

        # Совпадение по сервису
        if av.target_service and av.target_service.lower() in cve_software + cve_services:
            context_matches += 2

        # Совпадение по порту
        if av.target_port and av.target_port in cve_ports:
            context_matches += 2

        # Совпадение по типу атаки
        if cve.get("attack_type") == AV_ATTACK_TO_DB_ATTACK.get(av.attack_type or ""):
            context_matches += 3

        # Совпадение по связанным MITRE техникам
        cve_mitre = cve.get("related_mitre", [])
        for mitre_id in cve_mitre:
            if mitre_id in related_mitres:
                mitre_matches += 1

        # Вычисление комбинированного скора
        score = _get_combined_score(cve, context_matches, mitre_matches)
        ranked_cves.append((score, cve))

    # Сортировка по комбинированному скору
    ranked_cves.sort(key=lambda x: (-x[0], x[1].get("severity", "MEDIUM") != "CRITICAL"))

    # Ограничение размера результата
    final_cves = [cve for score, cve in ranked_cves[:35]]

    return final_cves

def get_mitre_attack_context(cve_list: list[dict]) -> dict:
    """
    Получение контекста MITRE ATT&CK для списка CVE.
    Возвращает информацию о связанных техниках, тактиках и рекомендациях.
    """
    mitre_db = _load_mitre_attack_database()
    context = {
        "techniques": set(),
        "tactics": set(),
        "recommendations": set()
    }

    # Анализ CVE для поиска связанных MITRE техник
    for cve in cve_list:
        mitre_ids = cve.get("related_mitre", [])
        if mitre_ids:
            for mitre_id in mitre_ids:
                for technique in mitre_db:
                    if technique["id"] == mitre_id:
                        context["techniques"].add(mitre_id)
                        context["tactics"].add(technique.get("tactic", "Unknown"))
                        context["recommendations"].update(technique.get("mitigations", []))

    return {
        "techniques": list(context["techniques"]),
        "tactics": list(context["tactics"]),
        "recommendations": list(context["recommendations"]),
        "technique_count": len(context["techniques"]),
        "tactic_count": len(context["tactics"])
    }

def get_cve_statistics(cve_list: list[dict]) -> dict:
    """
    Получение статистики по списку CVE.
    """
    stats = {
        "total": len(cve_list),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "with_cwe": 0,
        "with_capec": 0,
        "with_mitre": 0,
        "with_software_info": 0,
        "with_port_info": 0
    }

    for cve in cve_list:
        severity = cve.get("severity", "MEDIUM").upper()
        if severity == "CRITICAL":
            stats["critical"] += 1
        elif severity == "HIGH":
            stats["high"] += 1
        elif severity == "MEDIUM":
            stats["medium"] += 1
        elif severity == "LOW":
            stats["low"] += 1

        if cve.get("related_cwe"):
            stats["with_cwe"] += 1
        if cve.get("related_capec"):
            stats["with_capec"] += 1
        if cve.get("related_mitre"):
            stats["with_mitre"] += 1
        if cve.get("affected_software") or cve.get("requires_service"):
            stats["with_software_info"] += 1
        if cve.get("requires_port"):
            stats["with_port_info"] += 1

    return stats
