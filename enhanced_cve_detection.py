#!/usr/bin/env python3
"""
Улучшенная система определения CVE для векторов атак.
Интеграция с внешними инструментами для более точного определения уязвимостей.
"""

import subprocess
import json
import requests
import re
import time
from typing import List, Dict, Tuple, Optional
import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

from common.logger import get_server_logger

logger = get_server_logger()


class EnhancedCVEDetector:
    """Улучшенный детектор CVE с интеграцией внешних инструментов."""
    
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cve_search_base = "https://cve.circl.lu/api"
        # Простой кэш, чтобы не долбить внешние API при повторных вызовах
        self._cache: dict[tuple, tuple[float, list]] = {}
        self._cache_ttl_sec = 6 * 60 * 60  # 6 часов
        
    def detect_cves_for_service(self, service: str, version: str = "", port: int = 0) -> List[Dict]:
        """
        Определение CVE для сервиса с использованием нескольких источников.
        
        Args:
            service: Название сервиса (SSH, HTTP, SMB и т.д.)
            version: Версия сервиса (если известна)
            port: Номер порта
            
        Returns:
            Список найденных CVE
        """
        key = (service or "").strip().lower(), (version or "").strip().lower(), int(port or 0)
        now = time.time()
        cached = self._cache.get(key)
        if cached and (now - cached[0]) < self._cache_ttl_sec:
            return cached[1]

        cves: list[dict] = []
        
        # 1. Поиск по локальной базе (быстро)
        local_cves = self._search_local_cve_database(service, version, port)
        cves.extend(local_cves)
        
        # 2. Поиск по NVD API (если версия известна)
        if version:
            nvd_cves = self._search_nvd_by_version(service, version)
            cves.extend(nvd_cves)

        # 2.1 Доп. источник: CIRCL cve-search (быстрый, но не гарантирован)
        # Включаем только если есть версия или узнаваемый продукт в баннере
        if version:
            cves.extend(self._search_circl_by_keyword(service, version))
        
        # 3. Поиск по порту (универсальный)
        if port:
            port_cves = self._search_cves_by_port(port, service)
            cves.extend(port_cves)
        
        # 4. Поиск по баннеру (если есть)
        if version:
            banner_cves = self._search_cves_by_banner(version)
            cves.extend(banner_cves)
        
        # Удаляем дубликаты
        unique_cves = []
        seen = set()
        for cve in cves:
            cve_id = cve.get('id', '')
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                unique_cves.append(cve)
        
        self._cache[key] = (now, unique_cves)
        return unique_cves
    
    def _search_local_cve_database(self, service: str, version: str, port: int) -> List[Dict]:
        """Поиск CVE в локальной базе данных."""
        local_cves = []
        
        # Локальная база CVE для основных сервисов
        local_db = {
            "SSH": [
                {"id": "CVE-2020-15778", "severity": "MEDIUM", "description": "OpenSSH < 8.0 — command injection via scp"},
                {"id": "CVE-2023-38408", "severity": "HIGH", "description": "OpenSSH < 8.8 — PKCS#11 vulnerability"},
                {"id": "CVE-2018-15473", "severity": "MEDIUM", "description": "OpenSSH username enumeration vulnerability"},
            ],
            "SMB": [
                {"id": "CVE-2017-0144", "severity": "CRITICAL", "description": "EternalBlue — SMB RCE"},
                {"id": "CVE-2020-0796", "severity": "CRITICAL", "description": "SMBv3 vulnerability (SMBGhost)"},
                {"id": "CVE-2019-0708", "severity": "CRITICAL", "description": "BlueKeep — RDP vulnerability"},
            ],
            "RPC": [
                {"id": "CVE-2021-34527", "severity": "CRITICAL", "description": "PrintNightmare — Print Spooler vulnerability"},
                {"id": "CVE-2020-1472", "severity": "CRITICAL", "description": "Zerologon — Netlogon vulnerability"},
            ],
            "VMware": [
                {"id": "CVE-2021-21972", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
                {"id": "CVE-2021-21985", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
                {"id": "CVE-2020-3992", "severity": "HIGH", "description": "VMware ESXi OpenSLP stack overflow"},
            ],
            "HTTP": [
                {"id": "CVE-2021-41773", "severity": "CRITICAL", "description": "Apache 2.4.49 — Path Traversal/RCE"},
                {"id": "CVE-2021-42013", "severity": "CRITICAL", "description": "Apache 2.4.50 — Path Traversal/RCE"},
                {"id": "CVE-2021-23017", "severity": "HIGH", "description": "Nginx < 1.18 — DNS resolver vulnerability"},
            ],
            "HTTPS": [
                {"id": "CVE-2014-0160", "severity": "CRITICAL", "description": "Heartbleed — OpenSSL buffer over-read"},
                {"id": "CVE-2014-3566", "severity": "MEDIUM", "description": "POODLE — SSL 3.0 vulnerability"},
                {"id": "CVE-2017-13099", "severity": "HIGH", "description": "ROBOT — RSA vulnerability"},
            ],
        }
        
        # Поиск по сервису
        if service in local_db:
            local_cves.extend(local_db[service])
        
        # Поиск по порту
        port_mapping = {
            22: "SSH",
            23: "Telnet", 
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            902: "VMware",
            912: "VMware",
            27017: "MongoDB",
        }
        
        if port in port_mapping:
            port_service = port_mapping[port]
            if port_service in local_db:
                local_cves.extend(local_db[port_service])
        
        return local_cves
    
    def _search_nvd_by_version(self, service: str, version: str) -> List[Dict]:
        """Поиск CVE по версии в NVD."""
        cves = []
        try:
            # Формируем запрос к NVD API
            # Пример: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OpenSSH+8.2
            search_term = f"{service} {version}".replace(" ", "+")
            url = f"{self.nvd_api_base}?keywordSearch={search_term}"
            
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for cve_item in data.get("vulnerabilities", []):
                    cve = cve_item.get("cve", {})
                    cve_id = cve.get("id", "")
                    description = cve.get("descriptions", [{}])[0].get("value", "")
                    severity = self._extract_severity_from_nvd(cve)
                    
                    if cve_id and "CVE-" in cve_id:
                        cves.append({
                            "id": cve_id,
                            "severity": severity,
                            "description": description[:200]
                        })
        except Exception as e:
            logger.warning(f"NVD API search failed: {e}")
        
        return cves
    
    def _search_cves_by_port(self, port: int, service: str) -> List[Dict]:
        """Поиск CVE по порту."""
        cves = []
        
        # CVE для конкретных портов
        port_cves = {
            22: [
                {"id": "CVE-2020-15778", "severity": "MEDIUM", "description": "OpenSSH command injection"},
                {"id": "CVE-2018-15473", "severity": "MEDIUM", "description": "OpenSSH username enumeration"},
            ],
            135: [
                {"id": "CVE-2021-34527", "severity": "CRITICAL", "description": "PrintNightmare"},
                {"id": "CVE-2020-1472", "severity": "CRITICAL", "description": "Zerologon"},
            ],
            445: [
                {"id": "CVE-2017-0144", "severity": "CRITICAL", "description": "EternalBlue"},
                {"id": "CVE-2020-0796", "severity": "CRITICAL", "description": "SMBGhost"},
            ],
            902: [
                {"id": "CVE-2021-21972", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
                {"id": "CVE-2021-21985", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
            ],
            912: [
                {"id": "CVE-2021-21972", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
                {"id": "CVE-2021-21985", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
            ],
        }
        
        if port in port_cves:
            cves.extend(port_cves[port])
        
        return cves
    
    def _search_cves_by_banner(self, banner: str) -> List[Dict]:
        """Поиск CVE по баннеру."""
        cves = []
        
        # Регулярные выражения для определения CVE по баннеру.
        # Покрываем несколько форматов: "Apache/2.4.49", "Server: Apache/2.4.49", "SSH-2.0-OpenSSH_7.4p1", и т.д.
        banner_patterns = {
            # OpenSSH
            r"OpenSSH[_/-]([0-9]+\.[0-9]+)(?:p[0-9]+)?": [
                {"id": "CVE-2020-15778", "severity": "MEDIUM", "description": "OpenSSH < 8.0 — command injection via scp (сверьте версию)"},
                {"id": "CVE-2023-38408", "severity": "HIGH", "description": "OpenSSH < 8.8 — PKCS#11 vulnerability (сверьте версию)"},
            ],
            # Apache
            r"(?:Apache|Server:\\s*Apache)[/ ]2\\.4\\.49\\b": [
                {"id": "CVE-2021-41773", "severity": "CRITICAL", "description": "Apache 2.4.49 — Path Traversal/RCE"},
            ],
            r"(?:Apache|Server:\\s*Apache)[/ ]2\\.4\\.50\\b": [
                {"id": "CVE-2021-42013", "severity": "CRITICAL", "description": "Apache 2.4.50 — Path Traversal/RCE"},
            ],
            # nginx
            r"(?:nginx|Server:\\s*nginx)/1\\.(?:[0-9]|1[0-7])\\.[0-9]+": [
                {"id": "CVE-2021-23017", "severity": "HIGH", "description": "Nginx < 1.18 — DNS resolver vulnerability"},
            ],
            # IIS
            r"(?:Microsoft-IIS|Server:\\s*Microsoft-IIS)/([7-9]|10)\\.0": [
                {"id": "CVE-2021-31166", "severity": "CRITICAL", "description": "IIS — HTTP Protocol Stack RCE"},
            ],
            # OpenSSL
            r"OpenSSL\\s*1\\.0\\.1[a-z]?\\b": [
                {"id": "CVE-2014-0160", "severity": "CRITICAL", "description": "Heartbleed — OpenSSL buffer over-read (зависит от сборки)"},
            ],
            # VMware
            r"VMware.*Authentication.*Daemon": [
                {"id": "CVE-2021-21972", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
                {"id": "CVE-2021-21985", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
            ],
        }
        
        for pattern, pattern_cves in banner_patterns.items():
            if re.search(pattern, banner, re.IGNORECASE):
                cves.extend(pattern_cves)
        
        return cves

    def _search_circl_by_keyword(self, service: str, version: str) -> List[Dict]:
        """
        Дополнительный источник: CIRCL cve-search (keyword search).
        ВНИМАНИЕ: это best-effort, может быть нестабильно/ограничено.
        """
        out: list[dict] = []
        try:
            q = f\"{service} {version}\".strip().replace(\" \", \"%20\")
            url = f\"{self.cve_search_base}/search/{q}\"
            r = requests.get(url, timeout=8)
            if r.status_code != 200:
                return []
            data = r.json()
            # Формат может отличаться; пытаемся извлечь CVE-id
            if isinstance(data, dict):
                items = data.get(\"results\") or data.get(\"data\") or []
            else:
                items = data
            for it in items[:25]:
                cid = it.get(\"id\") or it.get(\"cve\") or it.get(\"CVE\") or \"\"
                if cid and str(cid).startswith(\"CVE-\"):
                    out.append({\"id\": str(cid), \"severity\": \"UNKNOWN\", \"description\": (it.get(\"summary\") or it.get(\"description\") or \"\")[:200]})
        except Exception as e:
            logger.warning(f\"CIRCL search failed: {e}\")
        return out
    
    def _extract_severity_from_nvd(self, cve_data: Dict) -> str:
        """Извлечение уровня критичности из данных NVD."""
        try:
            metrics = cve_data.get("metrics", {})
            
            # Проверяем CVSS v3.1
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    return severity
            
            # Проверяем CVSS v3.0
            cvss_v30 = metrics.get("cvssMetricV30", [])
            if cvss_v30:
                severity = cvss_v30[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    return severity
            
            # Проверяем CVSS v2
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                base_score = cvss_v2[0].get("cvssData", {}).get("baseScore", 0)
                if base_score >= 7.0:
                    return "HIGH"
                elif base_score >= 4.0:
                    return "MEDIUM"
                elif base_score >= 1.0:
                    return "LOW"
                else:
                    return "LOW"
            
        except Exception:
            pass
        
        return "UNKNOWN"
    
    def integrate_with_nmap(self, target: str, port: int) -> List[Dict]:
        """
        Интеграция с Nmap для получения более точной информации о сервисах.
        
        Args:
            target: IP-адрес цели
            port: Порт для сканирования
            
        Returns:
            Список найденных CVE
        """
        cves = []
        
        try:
            # Запускаем Nmap с скриптами для определения версий и уязвимостей
            cmd = [
                "nmap", "-sV", "-sC", "--script", "vuln", 
                "-p", str(port), target, "-oX", "-"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Парсим XML-вывод Nmap
                xml_output = result.stdout
                nmap_cves = self._parse_nmap_vuln_output(xml_output)
                cves.extend(nmap_cves)
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Nmap scan timeout for {target}:{port}")
        except Exception as e:
            logger.warning(f"Nmap integration failed: {e}")
        
        return cves
    
    def _parse_nmap_vuln_output(self, xml_output: str) -> List[Dict]:
        """Парсинг XML-вывода Nmap для извлечения CVE."""
        cves = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            
            # Ищем элементы с CVE
            for elem in root.iter():
                if elem.tag == "elem" and elem.get("key") == "CVE":
                    cve_id = elem.text
                    if cve_id and cve_id.startswith("CVE-"):
                        cves.append({
                            "id": cve_id,
                            "severity": "UNKNOWN",
                            "description": "Found by Nmap vulnerability scan"
                        })
                        
        except Exception as e:
            logger.warning(f"Failed to parse Nmap XML: {e}")
        
        return cves


def test_enhanced_cve_detection():
    """Тестирование улучшенной системы определения CVE."""
    print("=== ТЕСТ УЛУЧШЕННОЙ СИСТЕМЫ ОПРЕДЕЛЕНИЯ CVE ===")
    
    detector = EnhancedCVEDetector()
    
    # Тестовые сервисы из логов
    test_services = [
        ("RPC", "", 135),
        ("SMB", "", 445),
        ("VMware", "VMware Authentication Daemon Version 1.10", 902),
        ("VMware", "VMware Authentication Daemon Version 1.0", 912),
        ("SSH", "OpenSSH_8.2p1", 22),
        ("HTTP", "Apache/2.4.49", 80),
    ]
    
    for service, version, port in test_services:
        print(f"\n--- {service} (порт {port}) ---")
        cves = detector.detect_cves_for_service(service, version, port)
        
        print(f"Найдено CVE: {len(cves)}")
        for cve in cves[:3]:  # Показываем первые 3
            print(f"  {cve['id']} ({cve['severity']}): {cve['description'][:80]}")


if __name__ == "__main__":
    test_enhanced_cve_detection()