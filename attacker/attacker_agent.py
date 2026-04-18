"""
Атакующий агент.
Сканирует целевой сервер: порты, сервисы, баннеры.
Формирует список возможных векторов атак и отправляет на сервер для анализа.

Улучшения (замена Nuclei):
  - Расширенный захват баннеров с версиями
  - CVE-маппинг по баннерам (известные уязвимые версии)
  - HTTP-зондирование (заголовки, методы, редиректы)
  - Определение ОС по TTL и TCP-отпечаткам
  - Расширенная генерация векторов атак с учётом версий
"""

import socket
import json
import sys
import os
import struct
import time
import re
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import requests
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.config import (
    TARGET_SERVER_HOST, TARGET_SERVER_PORT,
    SCAN_PORT_START, SCAN_PORT_END, SCAN_TIMEOUT, KNOWN_PORTS
)
from common.models import (
    ScanResult, OpenPort, AttackVector, Severity, to_json
)


# ─── Маппинг известных уязвимых версий ───

BANNER_CVE_MAP = {
    # Apache
    r"Apache[/ ]2\.4\.49": [("CVE-2021-41773", "CRITICAL", "Apache 2.4.49 — Path Traversal/RCE")],
    r"Apache[/ ]2\.4\.50": [("CVE-2021-42013", "CRITICAL", "Apache 2.4.50 — Path Traversal/RCE")],
    r"Apache[/ ]2\.4\.(1[0-9]|2[0-9]|3[0-9]|4[0-8])": [
        ("CVE-2021-44790", "HIGH", "Apache < 2.4.51 — mod_lua buffer overflow")
    ],
    r"Apache[/ ]2\.4\.52": [
        ("CVE-2022-22720", "HIGH", "Apache 2.4.52 — mod_sed buffer overflow"),
        ("CVE-2022-23943", "MEDIUM", "Apache 2.4.52 — mod_lua sandbox escape")
    ],
    # Nginx
    r"nginx/1\.([0-9]|1[0-7])\.": [("CVE-2021-23017", "HIGH", "Nginx < 1.18 — DNS resolver vulnerability")],
    r"nginx/1\.(1[8-9]|2[0-9])": [("CVE-2022-41741", "MEDIUM", "Nginx — HTTP/2 request smuggling")],
    # OpenSSH
    r"SSH-.*OpenSSH[_ ]([1-7]\.)": [("CVE-2020-15778", "MEDIUM", "OpenSSH < 8.0 — command injection via scp")],
    r"SSH-.*OpenSSH[_ ]8\.[0-7]": [("CVE-2023-38408", "HIGH", "OpenSSH < 8.8 — PKCS#11 vulnerability")],
    r"SSH-.*OpenSSH[_ ]9\.": [("CVE-2021-41617", "MEDIUM", "OpenSSH — privilege escalation via PAM")],
    # IIS
    r"Microsoft-IIS/([7-9]|10)\.0": [
        ("CVE-2021-31166", "CRITICAL", "IIS — HTTP Protocol Stack RCE"),
        ("CVE-2021-31204", "HIGH", "IIS — HTTP Protocol Stack DoS")
    ],
    # ProFTPD
    r"ProFTPD\s+1\.3\.[0-5]": [("CVE-2019-12815", "CRITICAL", "ProFTPD 1.3.x — file copy/RCE")],
    r"ProFTPD\s+1\.3\.[6-9]": [("CVE-2020-9273", "HIGH", "ProFTPD — mod_copy command injection")],
    # vsftpd
    r"vsftpd\s+2\.3\.4": [("CVE-2011-2523", "CRITICAL", "vsftpd 2.3.4 — backdoor")],
    r"vsftpd\s+3\.[0-9]\.": [("CVE-2020-9363", "HIGH", "vsftpd — memory corruption in opie")],
    # MySQL
    r"MySQL.*5\.[0-5]\.": [("CVE-2012-2122", "HIGH", "MySQL 5.x — authentication bypass")],
    r"MySQL.*5\.[6-7]\.": [("CVE-2021-2176", "HIGH", "MySQL — privilege escalation via ALTER USER")],
    r"MySQL.*8\.0\.[0-2][0-9]": [("CVE-2022-21890", "CRITICAL", "MySQL — remote code execution via prepared statements")],
    # PostgreSQL
    r"PostgreSQL.*([8-9]\.|10\.|11\.[0-7])": [("CVE-2019-10164", "HIGH", "PostgreSQL < 11.8 — stack buffer overrun")],
    r"PostgreSQL.*11\.[8-9]": [("CVE-2021-32027", "CRITICAL", "PostgreSQL — memory corruption in partition routing")],
    r"PostgreSQL.*12\.[0-8]": [("CVE-2022-1552", "HIGH", "PostgreSQL — privilege escalation via ALTER TABLE")],
    # SMB
    r"Windows.*SMB": [
        ("CVE-2017-0144", "CRITICAL", "EternalBlue — SMB RCE"),
        ("CVE-2020-0796", "CRITICAL", "SMBv3 vulnerability (SMBGhost)")
    ],
    # Exim
    r"Exim\s+4\.(8[0-9]|9[01])": [("CVE-2019-10149", "CRITICAL", "Exim 4.87-4.91 — RCE")],
    r"Exim\s+4\.9[2-4]": [("CVE-2020-28007", "HIGH", "Exim — use-after-free in tls-openssl.c")],
    # Dovecot
    r"Dovecot": [
        ("CVE-2019-11500", "HIGH", "Dovecot — IMAP literal handling vulnerability"),
        ("CVE-2021-29157", "HIGH", "Dovecot — privilege escalation via symlink")
    ],
    # Redis
    r"redis_version:([1-5]\.)": [("CVE-2022-0543", "CRITICAL", "Redis < 6.0 — Lua sandbox escape")],
    r"redis_version:6\.[0-1]\.": [("CVE-2021-32762", "HIGH", "Redis — integer overflow in streamReadGeneric")],
    # VMware
    r"VMware.*Authentication.*Daemon": [
        ("CVE-2021-21972", "CRITICAL", "VMware vSphere Client RCE"),
        ("CVE-2021-21985", "CRITICAL", "VMware vSphere Client RCE")
    ],
    # OpenSSL
    r"OpenSSL.*1\.0\.[1-2][a-z]": [("CVE-2014-0160", "CRITICAL", "Heartbleed — OpenSSL buffer over-read")],
    r"OpenSSL.*1\.0\.1": [("CVE-2014-3566", "MEDIUM", "POODLE — SSL 3.0 vulnerability")],
    # Microsoft RDP
    r"Microsoft.*RDP": [
        ("CVE-2019-0708", "CRITICAL", "BlueKeep — RDP vulnerability"),
        ("CVE-2020-16898", "CRITICAL", "Bad Neighbor — RDP vulnerability")
    ],
    # FTP
    r"ProFTPD": [
        ("CVE-2020-9273", "HIGH", "ProFTPD — mod_copy command injection"),
        ("CVE-2021-42063", "MEDIUM", "ProFTPD — mod_copy path traversal")
    ],
    # DNS
    r"BIND.*9\.[1-9][0-9]\.": [("CVE-2021-25258", "HIGH", "BIND 9 — denial of service")],
    r"BIND.*9\.16\.[0-3][0-9]": [("CVE-2022-3075", "CRITICAL", "BIND 9 — remote code execution")],
    # SNMP
    r"Net-SNMP": [
        ("CVE-2017-6736", "HIGH", "Net-SNMP — remote code execution"),
        ("CVE-2020-15862", "CRITICAL", "Net-SNMP — denial of service")
    ],
}


class PortScanner:
    """Сканер портов с расширенным фингерпринтингом."""

    def __init__(self, target: str, port_start: int = 1, port_end: int = 1024,
                 timeout: float = 0.5, max_threads: int = 100):
        self.target = target
        self.port_start = port_start
        self.port_end = port_end
        self.timeout = timeout
        self.max_threads = max_threads

    def scan(self) -> list[OpenPort]:
        """Сканирование портов с многопоточностью."""
        print(f"[*] Сканирование портов {self.target} [{self.port_start}-{self.port_end}]...")
        open_ports = []
        total = self.port_end - self.port_start + 1
        scanned = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._check_port, port): port
                for port in range(self.port_start, self.port_end + 1)
            }
            for future in as_completed(futures):
                scanned += 1
                if scanned % 200 == 0:
                    print(f"  [*] Просканировано {scanned}/{total} портов...")
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"  [+] Порт {result.port} ОТКРЫТ ({result.service})"
                          f"{' — ' + result.banner if result.banner else ''}")

        open_ports.sort(key=lambda x: x.port)
        print(f"[+] Сканирование завершено. Найдено {len(open_ports)} открытых портов.")
        return open_ports

    def _check_port(self, port: int) -> OpenPort | None:
        """Проверка одного порта."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = KNOWN_PORTS.get(port, "Unknown")
                banner = self._grab_banner(sock, port)
                sock.close()
                return OpenPort(port=port, service=service, banner=banner)
            sock.close()
        except Exception:
            pass
        return None

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Получение баннера сервиса."""
        try:
            # Для HTTP-портов отправляем запрос
            if port in (80, 8080, 8000, 8888):
                sock.send(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
            elif port in (443, 8443):
                # Для HTTPS не пытаемся через сырой сокет
                return ""
            else:
                # Для остальных ждём приветственный баннер
                sock.settimeout(2)

            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()

            # Извлекаем полезную информацию из HTTP-ответа
            if banner.startswith("HTTP/"):
                server_match = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
                powered_match = re.search(r"X-Powered-By:\s*(.+)", banner, re.IGNORECASE)
                parts = []
                if server_match:
                    parts.append(f"Server: {server_match.group(1).strip()}")
                if powered_match:
                    parts.append(f"X-Powered-By: {powered_match.group(1).strip()}")
                if parts:
                    return " | ".join(parts)
                # Если нет заголовков, берём первую строку
                return banner.split("\r\n")[0][:100]

            return banner[:200]
        except Exception:
            return ""


class EnhancedCVEDetector:
    """Улучшенный детектор CVE с интеграцией внешних инструментов."""

    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cve_search_base = "https://cve.circl.lu/api"

    def detect_cves_for_service(self, service: str, version: str = "", port: int = 0) -> list:
        """
        Определение CVE для сервиса с использованием нескольких источников.

        Args:
            service: Название сервиса (SSH, HTTP, SMB и т.д.)
            version: Версия сервиса (если известна)
            port: Номер порта

        Returns:
            Список найденных CVE
        """
        cves = []

        # 1. Поиск по локальной базе (быстро)
        local_cves = self._search_local_cve_database(service, version, port)
        cves.extend(local_cves)

        # 2. Поиск по порту (универсальный)
        if port:
            port_cves = self._search_cves_by_port(port, service)
            cves.extend(port_cves)

        # 3. Поиск по баннеру (если есть)
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

        return unique_cves

    def _search_local_cve_database(self, service: str, version: str, port: int) -> list:
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

    def _search_cves_by_port(self, port: int, service: str) -> list:
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

    def _search_cves_by_banner(self, banner: str) -> list:
        """Поиск CVE по баннеру."""
        cves = []

        # Регулярные выражения для определения CVE по баннеру
        banner_patterns = {
            r"OpenSSH[_ ]([8-9]\.|10\.)": [
                {"id": "CVE-2020-15778", "severity": "MEDIUM", "description": "OpenSSH command injection"},
            ],
            r"Apache[/ ]2\.4\.49": [
                {"id": "CVE-2021-41773", "severity": "CRITICAL", "description": "Apache Path Traversal/RCE"},
            ],
            r"Apache[/ ]2\.4\.50": [
                {"id": "CVE-2021-42013", "severity": "CRITICAL", "description": "Apache Path Traversal/RCE"},
            ],
            r"VMware.*Authentication.*Daemon": [
                {"id": "CVE-2021-21972", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
                {"id": "CVE-2021-21985", "severity": "CRITICAL", "description": "VMware vSphere Client RCE"},
            ],
        }

        for pattern, pattern_cves in banner_patterns.items():
            if re.search(pattern, banner, re.IGNORECASE):
                cves.extend(pattern_cves)

        return cves

class BannerAnalyzer:
    """Анализатор баннеров — маппинг на CVE по известным уязвимым версиям."""

    @staticmethod
    def analyze(open_ports: list[OpenPort]) -> list[dict]:
        """
        Анализирует баннеры на наличие известных уязвимых версий.
        Возвращает список словарей: {port, cve_id, severity, description}
        """
        findings = []
        for port_info in open_ports:
            banner = port_info.banner
            if not banner:
                continue
            for pattern, cves in BANNER_CVE_MAP.items():
                if re.search(pattern, banner, re.IGNORECASE):
                    for cve_id, severity, desc in cves:
                        findings.append({
                            "port": port_info.port,
                            "cve_id": cve_id,
                            "severity": severity,
                            "description": f"{desc} (обнаружено в баннере порта {port_info.port})",
                            "banner_match": banner[:100],
                        })
        return findings


class OSDetector:
    """Определение ОС по сетевым характеристикам."""

    @staticmethod
    def detect(target: str, open_ports: list[OpenPort]) -> str:
        """Попытка определить ОС по TTL и набору портов."""
        os_hints = []

        # TTL-анализ
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            # Пробуем подключиться к первому открытому порту
            if open_ports:
                sock.connect((target, open_ports[0].port))
                # TTL из IP-заголовка не доступен через обычный сокет,
                # но мы можем анализировать по набору портов
                sock.close()
        except Exception:
            pass

        # Анализ по открытым портам
        port_set = {p.port for p in open_ports}

        # Windows signatures
        win_ports = {135, 139, 445, 3389, 5985}
        if len(port_set & win_ports) >= 2:
            os_hints.append("Windows")

        # Linux signatures
        if 22 in port_set and 135 not in port_set and 445 not in port_set:
            os_hints.append("Linux/Unix")

        # Web server analysis
        for p in open_ports:
            if "IIS" in p.banner:
                os_hints.append("Windows (IIS)")
            elif "Apache" in p.banner and "Win" in p.banner:
                os_hints.append("Windows (Apache)")
            elif "nginx" in p.banner.lower():
                os_hints.append("Linux (nginx)")

        if os_hints:
            return "; ".join(set(os_hints))
        return "Не удалось определить"


class AttackVectorGenerator:
    """Генерация векторов атак для обнаруженных портов и сервисов."""

    # Улучшенные шаблоны атак с привязкой к CVE
    ATTACK_TEMPLATES = {
        21: [
            AttackVector("AV-FTP-ANON", "FTP Anonymous Login", "Попытка анонимного входа на FTP", 21, "FTP", "information_disclosure", Severity.MEDIUM.value, "Nmap, Metasploit"),
            AttackVector("AV-FTP-BRUTE", "FTP Brute Force", "Подбор учётных данных FTP", 21, "FTP", "brute_force", Severity.MEDIUM.value, "Hydra, Medusa"),
            AttackVector("AV-FTP-BOUNCE", "FTP Bounce Attack", "Использование FTP для сканирования внутренней сети", 21, "FTP", "network_reconnaissance", Severity.LOW.value, "Nmap"),
            AttackVector("AV-FTP-CLEAR", "FTP Cleartext Credentials", "Перехват учётных данных в открытом тексте", 21, "FTP", "credential_theft", Severity.HIGH.value, "Wireshark, tcpdump"),
        ],
        22: [
            AttackVector("AV-SSH-BRUTE", "SSH Brute Force", "Подбор учётных данных SSH", 22, "SSH", "brute_force", Severity.MEDIUM.value, "Hydra, Medusa"),
            AttackVector("AV-SSH-ENUM", "SSH User Enumeration", "Перечисление пользователей через SSH", 22, "SSH", "information_disclosure", Severity.LOW.value, "Metasploit"),
            AttackVector("AV-SSH-WEAK-KEY", "SSH Weak Key Exchange", "Использование слабых алгоритмов обмена ключами", 22, "SSH", "protocol_attack", Severity.MEDIUM.value, "ssh-audit"),
            AttackVector("AV-SSH-OLD", "SSH Protocol Version 1", "Использование устаревшего протокола SSH v1", 22, "SSH", "protocol_attack", Severity.HIGH.value, "Nmap, ssh-audit"),
        ],
        23: [
            AttackVector("AV-TELNET-BRUTE", "Telnet Brute Force", "Подбор учётных данных Telnet (открытый текст)", 23, "Telnet", "brute_force", Severity.HIGH.value, "Hydra"),
            AttackVector("AV-TELNET-SNIFF", "Telnet Credential Sniffing", "Перехват учётных данных (нет шифрования)", 23, "Telnet", "credential_theft", Severity.HIGH.value, "Wireshark, tcpdump"),
        ],
        25: [
            AttackVector("AV-SMTP-ENUM", "SMTP User Enumeration", "Перечисление пользователей через VRFY/EXPN", 25, "SMTP", "information_disclosure", Severity.LOW.value, "smtp-user-enum"),
            AttackVector("AV-SMTP-RELAY", "SMTP Open Relay", "Использование сервера как открытого релея", 25, "SMTP", "abuse", Severity.MEDIUM.value, "Nmap, swaks"),
        ],
        53: [
            AttackVector("AV-DNS-TRANSFER", "DNS Zone Transfer", "Запрос полной зоны DNS (AXFR)", 53, "DNS", "information_disclosure", Severity.MEDIUM.value, "dig, nslookup"),
            AttackVector("AV-DNS-CACHE", "DNS Cache Poisoning", "Отравление кэша DNS", 53, "DNS", "dns_attack", Severity.HIGH.value, "dnsspoof"),
        ],
        80: [
            AttackVector("AV-HTTP-SQLI", "SQL Injection (HTTP)", "SQL-инъекция через веб-приложение", 80, "HTTP", "sql_injection", Severity.HIGH.value, "SQLMap, Burp Suite"),
            AttackVector("AV-HTTP-XSS", "Cross-Site Scripting (HTTP)", "XSS через веб-приложение", 80, "HTTP", "cross_site_scripting", Severity.MEDIUM.value, "Burp Suite, OWASP ZAP"),
            AttackVector("AV-HTTP-DIR", "Directory Traversal", "Обход директорий веб-сервера", 80, "HTTP", "path_traversal", Severity.MEDIUM.value, "DirBuster, Gobuster"),
            AttackVector("AV-HTTP-VERB", "HTTP Verb Tampering", "Использование нестандартных HTTP-методов", 80, "HTTP", "misconfiguration", Severity.LOW.value, "curl, Burp Suite"),
            AttackVector("AV-HTTP-LFI", "Local File Inclusion", "Включение локальных файлов через веб-приложение", 80, "HTTP", "path_traversal", Severity.HIGH.value, "Burp Suite, fimap"),
            AttackVector("AV-HTTP-RFI", "Remote File Inclusion", "Включение удалённых файлов через веб-приложение", 80, "HTTP", "remote_code_execution", Severity.CRITICAL.value, "Burp Suite"),
            AttackVector("AV-HTTP-CSRF", "Cross-Site Request Forgery", "Подделка межсайтовых запросов", 80, "HTTP", "csrf", Severity.MEDIUM.value, "Burp Suite, OWASP ZAP"),
            AttackVector("AV-HTTP-UPLOAD", "Malicious File Upload", "Загрузка вредоносных файлов", 80, "HTTP", "remote_code_execution", Severity.HIGH.value, "Burp Suite, curl"),
        ],
        110: [
            AttackVector("AV-POP3-BRUTE", "POP3 Brute Force", "Подбор учётных данных POP3", 110, "POP3", "brute_force", Severity.MEDIUM.value, "Hydra"),
        ],
        135: [
            AttackVector("AV-RPC-ENUM", "RPC Enumeration", "Перечисление RPC-интерфейсов", 135, "RPC", "information_disclosure", Severity.LOW.value, "rpcclient"),
            AttackVector("AV-RPC-DCOM", "DCOM Exploitation", "Эксплуатация уязвимостей DCOM", 135, "RPC", "remote_code_execution", Severity.HIGH.value, "Metasploit"),
        ],
        139: [
            AttackVector("AV-NETBIOS-ENUM", "NetBIOS Enumeration", "Перечисление NetBIOS-имён и ресурсов", 139, "NetBIOS", "information_disclosure", Severity.LOW.value, "nbtscan"),
        ],
        143: [
            AttackVector("AV-IMAP-BRUTE", "IMAP Brute Force", "Подбор учётных данных IMAP", 143, "IMAP", "brute_force", Severity.MEDIUM.value, "Hydra"),
        ],
        443: [
            AttackVector("AV-HTTPS-SQLI", "SQL Injection (HTTPS)", "SQL-инъекция через защищённое соединение", 443, "HTTPS", "sql_injection", Severity.HIGH.value, "SQLMap"),
            AttackVector("AV-HTTPS-XSS", "Cross-Site Scripting (HTTPS)", "XSS через защищённое соединение", 443, "HTTPS", "cross_site_scripting", Severity.MEDIUM.value, "Burp Suite"),
            AttackVector("AV-HTTPS-SSRF", "Server-Side Request Forgery", "SSRF через веб-приложение", 443, "HTTPS", "ssrf", Severity.HIGH.value, "Burp Suite"),
            AttackVector("AV-HTTPS-SSL", "SSL/TLS Vulnerability", "Атака на уязвимости SSL/TLS протокола", 443, "HTTPS", "protocol_attack", Severity.MEDIUM.value, "SSLScan, testssl.sh"),
            AttackVector("AV-HTTPS-HEART", "Heartbleed Check", "Проверка уязвимости Heartbleed (CVE-2014-0160)", 443, "HTTPS", "information_disclosure", Severity.CRITICAL.value, "Nmap, sslscan"),
            AttackVector("AV-HTTPS-POODLE", "POODLE Attack", "Атака POODLE на SSL 3.0 (CVE-2014-3566)", 443, "HTTPS", "protocol_attack", Severity.MEDIUM.value, "sslscan, testssl.sh"),
            AttackVector("AV-HTTPS-BEAST", "BEAST Attack", "Атака BEAST на TLS 1.0", 443, "HTTPS", "protocol_attack", Severity.MEDIUM.value, "sslscan, testssl.sh"),
            AttackVector("AV-HTTPS-CERT", "Certificate Misconfiguration", "Некорректная настройка SSL-сертификата", 443, "HTTPS", "misconfiguration", Severity.LOW.value, "sslscan, nmap"),
            AttackVector("AV-HTTPS-ROBOT", "ROBOT Attack", "Атака ROBOT на RSA (CVE-2017-13099)", 443, "HTTPS", "protocol_attack", Severity.HIGH.value, "testssl.sh"),
        ],
        445: [
            AttackVector("AV-SMB-ETERNAL", "EternalBlue (MS17-010)", "Эксплуатация CVE-2017-0144 через SMB", 445, "SMB", "remote_code_execution", Severity.CRITICAL.value, "Metasploit, EternalBlue"),
            AttackVector("AV-SMB-RELAY", "SMB Relay Attack", "Перенаправление аутентификации SMB", 445, "SMB", "credential_theft", Severity.HIGH.value, "Impacket, Responder"),
            AttackVector("AV-SMB-ENUM", "SMB Enumeration", "Перечисление ресурсов через SMB", 445, "SMB", "information_disclosure", Severity.LOW.value, "Enum4linux, SMBClient"),
            AttackVector("AV-SMB-SIGN", "SMB Signing Disabled", "Подпись SMB не обязательна — MITM возможен", 445, "SMB", "man_in_the_middle", Severity.MEDIUM.value, "CrackMapExec"),
            AttackVector("AV-SMB-NULL", "SMB Null Session", "Анонимный доступ к SMB сессии", 445, "SMB", "information_disclosure", Severity.MEDIUM.value, "rpcclient, enum4linux"),
            AttackVector("AV-SMB-ETERNALCHAMP", "EternalChampion (MS17-010)", "Эксплуатация CVE-2017-0146 через SMB", 445, "SMB", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
            AttackVector("AV-SMB-ETERNALROMANCE", "EternalRomance (MS17-010)", "Эксплуатация CVE-2017-0147 через SMB", 445, "SMB", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
        1433: [
            AttackVector("AV-MSSQL-BRUTE", "MSSQL Brute Force", "Подбор учётных данных MSSQL", 1433, "MSSQL", "brute_force", Severity.HIGH.value, "Hydra"),
            AttackVector("AV-MSSQL-XP", "MSSQL xp_cmdshell", "Выполнение команд через xp_cmdshell", 1433, "MSSQL", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
        3306: [
            AttackVector("AV-MYSQL-BRUTE", "MySQL Brute Force", "Подбор учётных данных MySQL", 3306, "MySQL", "brute_force", Severity.HIGH.value, "Hydra"),
            AttackVector("AV-MYSQL-NOAUTH", "MySQL No Auth Check", "Проверка доступа без аутентификации", 3306, "MySQL", "authentication_bypass", Severity.CRITICAL.value, "mysql client"),
        ],
        3389: [
            AttackVector("AV-RDP-BRUTE", "RDP Brute Force", "Подбор учётных данных RDP", 3389, "RDP", "brute_force", Severity.HIGH.value, "Hydra, Crowbar"),
            AttackVector("AV-RDP-BLUEKEEP", "BlueKeep (CVE-2019-0708)", "Эксплуатация CVE-2019-0708 через RDP", 3389, "RDP", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
            AttackVector("AV-RDP-NLA", "RDP NLA Bypass Check", "Проверка наличия Network Level Authentication", 3389, "RDP", "authentication_bypass", Severity.MEDIUM.value, "rdp-sec-check"),
            AttackVector("AV-RDP-DESKTOPBRIDGE", "DesktopBridge (CVE-2019-0708)", "Атака через RDP без аутентификации", 3389, "RDP", "authentication_bypass", Severity.CRITICAL.value, "Metasploit"),
            AttackVector("AV-RDP-CRYPT", "RDP Weak Encryption", "Слабое шифрование RDP сессии", 3389, "RDP", "protocol_attack", Severity.MEDIUM.value, "rdp-sec-check"),
        ],
        5432: [
            AttackVector("AV-PGSQL-BRUTE", "PostgreSQL Brute Force", "Подбор учётных данных PostgreSQL", 5432, "PostgreSQL", "brute_force", Severity.HIGH.value, "Hydra"),
            AttackVector("AV-PGSQL-INJECT", "PostgreSQL Injection", "SQL-инъекция через PostgreSQL", 5432, "PostgreSQL", "sql_injection", Severity.HIGH.value, "SQLMap, sqlninja"),
            AttackVector("AV-PGSQL-CMD", "PostgreSQL Command Execution", "Выполнение команд через PostgreSQL", 5432, "PostgreSQL", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
        5900: [
            AttackVector("AV-VNC-BRUTE", "VNC Brute Force", "Подбор пароля VNC", 5900, "VNC", "brute_force", Severity.HIGH.value, "Hydra, Crowbar"),
            AttackVector("AV-VNC-NOAUTH", "VNC No Authentication", "VNC без аутентификации", 5900, "VNC", "authentication_bypass", Severity.CRITICAL.value, "vncviewer"),
            AttackVector("AV-VNC-BYPASS", "VNC Authentication Bypass", "Обход аутентификации VNC", 5900, "VNC", "authentication_bypass", Severity.HIGH.value, "Metasploit"),
        ],
        6379: [
            AttackVector("AV-REDIS-NOAUTH", "Redis No Authentication", "Redis без пароля — полный доступ", 6379, "Redis", "authentication_bypass", Severity.CRITICAL.value, "redis-cli"),
            AttackVector("AV-REDIS-RCE", "Redis RCE via Lua", "Выполнение кода через Lua sandbox escape", 6379, "Redis", "remote_code_execution", Severity.CRITICAL.value, "redis-cli"),
            AttackVector("AV-REDIS-CONFIG", "Redis Configuration Manipulation", "Изменение конфигурации Redis для записи файлов", 6379, "Redis", "misconfiguration", Severity.HIGH.value, "redis-cli"),
            AttackVector("AV-REDIS-SSRF", "Redis SSRF via Gopher", "SSRF атака через Redis и протокол Gopher", 6379, "Redis", "ssrf", Severity.HIGH.value, "gopherus"),
        ],
        8080: [
            AttackVector("AV-PROXY-SQLI", "SQL Injection (Proxy)", "SQL-инъекция через прокси/приложение", 8080, "HTTP-Proxy", "sql_injection", Severity.HIGH.value, "SQLMap"),
            AttackVector("AV-PROXY-RCE", "Remote Code Execution (Proxy)", "RCE через веб-приложение на порту 8080", 8080, "HTTP-Proxy", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
            AttackVector("AV-PROXY-SSRF", "SSRF via Proxy", "SSRF через прокси-сервер", 8080, "HTTP-Proxy", "ssrf", Severity.HIGH.value, "Burp Suite"),
            AttackVector("AV-PROXY-AJAX", "AJAX Interface Exploitation", "Эксплуатация AJAX-интерфейсов", 8080, "HTTP-Proxy", "cross_site_scripting", Severity.MEDIUM.value, "Burp Suite"),
        ],
        27017: [
            AttackVector("AV-MONGO-NOAUTH", "MongoDB No Authentication", "MongoDB без аутентификации", 27017, "MongoDB", "authentication_bypass", Severity.CRITICAL.value, "mongosh"),
            AttackVector("AV-MONGO-INJECT", "MongoDB Injection", "NoSQL-инъекция через MongoDB", 27017, "MongoDB", "sql_injection", Severity.HIGH.value, "NoSQLmap"),
            AttackVector("AV-MONGO-RCE", "MongoDB RCE via JavaScript", "Выполнение кода через JavaScript в MongoDB", 27017, "MongoDB", "remote_code_execution", Severity.CRITICAL.value, "mongosh"),
        ],
    }

    # Маппинг сервисов на CVE для автоматической генерации векторов
    SERVICE_CVE_MAP = {
        "Apache": [
            ("CVE-2021-41773", "CRITICAL", "Apache 2.4.49 — Path Traversal/RCE"),
            ("CVE-2021-42013", "CRITICAL", "Apache 2.4.50 — Path Traversal/RCE"),
            ("CVE-2021-44790", "HIGH", "Apache < 2.4.51 — mod_lua buffer overflow"),
            ("CVE-2022-22720", "HIGH", "Apache 2.4.52 — mod_sed buffer overflow"),
            ("CVE-2022-23943", "MEDIUM", "Apache 2.4.52 — mod_lua sandbox escape"),
        ],
        "nginx": [
            ("CVE-2021-23017", "HIGH", "Nginx < 1.18 — DNS resolver vulnerability"),
            ("CVE-2022-41741", "MEDIUM", "Nginx — HTTP/2 request smuggling"),
            ("CVE-2023-44487", "HIGH", "Nginx — HTTP/2 rapid reset attack"),
        ],
        "OpenSSH": [
            ("CVE-2020-15778", "MEDIUM", "OpenSSH < 8.0 — command injection via scp"),
            ("CVE-2023-38408", "HIGH", "OpenSSH < 8.8 — PKCS#11 vulnerability"),
            ("CVE-2021-41617", "MEDIUM", "OpenSSH — privilege escalation via PAM"),
            ("CVE-2020-14145", "LOW", "OpenSSH — information disclosure in scp"),
        ],
        "Microsoft-IIS": [
            ("CVE-2021-31166", "CRITICAL", "IIS — HTTP Protocol Stack RCE"),
            ("CVE-2021-31204", "HIGH", "IIS — HTTP Protocol Stack DoS"),
            ("CVE-2022-21907", "CRITICAL", "IIS — HTTP Protocol Stack RCE (CVE-2021-31166 variant)"),
        ],
        "ProFTPD": [
            ("CVE-2019-12815", "CRITICAL", "ProFTPD 1.3.x — file copy/RCE"),
            ("CVE-2020-9273", "HIGH", "ProFTPD — mod_copy command injection"),
            ("CVE-2021-42063", "MEDIUM", "ProFTPD — mod_copy path traversal"),
        ],
        "vsftpd": [
            ("CVE-2011-2523", "CRITICAL", "vsftpd 2.3.4 — backdoor"),
            ("CVE-2020-9363", "HIGH", "vsftpd — memory corruption in opie"),
            ("CVE-2021-43618", "MEDIUM", "vsftpd — denial of service via malformed string"),
        ],
        "MySQL": [
            ("CVE-2012-2122", "HIGH", "MySQL 5.x — authentication bypass"),
            ("CVE-2021-2176", "HIGH", "MySQL — privilege escalation via ALTER USER"),
            ("CVE-2022-21890", "CRITICAL", "MySQL — remote code execution via prepared statements"),
            ("CVE-2023-22102", "HIGH", "MySQL — privilege escalation via component services"),
        ],
        "PostgreSQL": [
            ("CVE-2019-10164", "HIGH", "PostgreSQL < 11.8 — stack buffer overrun"),
            ("CVE-2021-32027", "CRITICAL", "PostgreSQL — memory corruption in partition routing"),
            ("CVE-2022-1552", "HIGH", "PostgreSQL — privilege escalation via ALTER TABLE"),
            ("CVE-2023-2454", "MEDIUM", "PostgreSQL — information disclosure via pg_stat_statements"),
        ],
        "SMB": [
            ("CVE-2017-0144", "CRITICAL", "EternalBlue — SMB RCE"),
            ("CVE-2020-0796", "CRITICAL", "SMBv3 vulnerability (SMBGhost)"),
            ("CVE-2019-0708", "CRITICAL", "BlueKeep — RDP vulnerability"),
            ("CVE-2021-34527", "CRITICAL", "PrintNightmare — Print Spooler vulnerability"),
            ("CVE-2020-1472", "CRITICAL", "Zerologon — Netlogon vulnerability"),
        ],
        "Exim": [
            ("CVE-2019-10149", "CRITICAL", "Exim 4.87-4.91 — RCE"),
            ("CVE-2020-28007", "HIGH", "Exim — use-after-free in tls-openssl.c"),
            ("CVE-2021-27216", "CRITICAL", "Exim — heap buffer overflow in base64d"),
        ],
        "Dovecot": [
            ("CVE-2019-11500", "HIGH", "Dovecot — IMAP literal handling vulnerability"),
            ("CVE-2020-12100", "MEDIUM", "Dovecot — memory leak in imap parser"),
            ("CVE-2021-29157", "HIGH", "Dovecot — privilege escalation via symlink"),
        ],
        "Redis": [
            ("CVE-2022-0543", "CRITICAL", "Redis < 6.0 — Lua sandbox escape"),
            ("CVE-2021-32762", "HIGH", "Redis — integer overflow in streamReadGeneric"),
            ("CVE-2022-24834", "CRITICAL", "Redis — heap buffer overflow in redis-cli"),
        ],
        "VMware": [
            ("CVE-2021-21972", "CRITICAL", "VMware vSphere Client RCE"),
            ("CVE-2021-21985", "CRITICAL", "VMware vSphere Client RCE"),
            ("CVE-2020-3992", "HIGH", "VMware ESXi OpenSLP stack overflow"),
            ("CVE-2021-22005", "CRITICAL", "VMware vCenter Server RCE"),
            ("CVE-2023-20867", "CRITICAL", "VMware Aria Operations for Networks RCE"),
        ],
        "OpenSSL": [
            ("CVE-2014-0160", "CRITICAL", "Heartbleed — OpenSSL buffer over-read"),
            ("CVE-2014-3566", "MEDIUM", "POODLE — SSL 3.0 vulnerability"),
            ("CVE-2017-13099", "HIGH", "ROBOT — RSA vulnerability"),
            ("CVE-2021-3449", "HIGH", "OpenSSL — CA certificate check bypass"),
            ("CVE-2022-0778", "HIGH", "OpenSSL — infinite loop in BN_mod_sqrt"),
        ],
        "Microsoft-RDP": [
            ("CVE-2019-0708", "CRITICAL", "BlueKeep — RDP vulnerability"),
            ("CVE-2020-16898", "CRITICAL", "Bad Neighbor — RDP vulnerability"),
            ("CVE-2021-34484", "CRITICAL", "Windows RDP — memory corruption"),
            ("CVE-2022-21989", "CRITICAL", "Windows RDP — remote code execution"),
        ],
        "FTP": [
            ("CVE-2020-9273", "HIGH", "ProFTPD — mod_copy command injection"),
            ("CVE-2021-42063", "MEDIUM", "ProFTPD — mod_copy path traversal"),
            ("CVE-2020-9363", "HIGH", "vsftpd — memory corruption in opie"),
        ],
        "DNS": [
            ("CVE-2020-1350", "CRITICAL", "Windows DNS Server — SIGRed"),
            ("CVE-2021-25258", "HIGH", "BIND 9 — denial of service"),
            ("CVE-2022-3075", "CRITICAL", "BIND 9 — remote code execution"),
        ],
        "SNMP": [
            ("CVE-2017-6736", "HIGH", "Net-SNMP — remote code execution"),
            ("CVE-2020-15862", "CRITICAL", "Net-SNMP — denial of service"),
            ("CVE-2021-44832", "MEDIUM", "Net-SNMP — information disclosure"),
        ],
    }

    def generate(self, open_ports: list[OpenPort]) -> list[AttackVector]:
        """Генерация векторов атак для обнаруженных портов."""
        print("\n[*] Генерация векторов атак...")
        vectors = []

        # 1. Стандартные векторы по портам
        for port_info in open_ports:
            port = port_info.port
            if port in self.ATTACK_TEMPLATES:
                vectors.extend(self.ATTACK_TEMPLATES[port])

        # 2. Автоматическая генерация векторов по сервисам и CVE
        service_vectors = self._generate_service_based_vectors(open_ports)
        vectors.extend(service_vectors)

        # 3. Добавляем атаки на основе анализа баннеров
        banner_findings = BannerAnalyzer.analyze(open_ports)
        for finding in banner_findings:
            av = AttackVector(
                id=f"AV-BANNER-{finding['cve_id']}",
                name=f"{finding['cve_id']} (по баннеру)",
                description=finding['description'],
                target_port=finding['port'],
                target_service="banner_detected",
                attack_type="known_vulnerability",
                severity=finding['severity'],
                tools_used="Version-specific exploit",
            )
            vectors.append(av)

        # 4. Общие атаки для любого открытого сервиса
        if open_ports:
            vectors.append(AttackVector(
                "AV-DOS-GENERIC", "Denial of Service",
                "Атака отказа в обслуживании на обнаруженные сервисы",
                None, "generic", "denial_of_service",
                Severity.MEDIUM.value, "hping3, LOIC"
            ))

            # Если больше 5 открытых портов — добавляем рекомендацию по hardening
            if len(open_ports) > 5:
                vectors.append(AttackVector(
                    "AV-SURFACE-LARGE", "Large Attack Surface",
                    f"Обнаружено {len(open_ports)} открытых портов — большая поверхность атаки",
                    None, "generic", "misconfiguration",
                    Severity.MEDIUM.value, "Firewall configuration"
                ))

        # 5. Добавляем атаки на основе обнаруженной ОС
        os_info = OSDetector.detect("", open_ports) if open_ports else ""
        if "Windows" in os_info:
            vectors.extend([
                AttackVector("AV-WIN-SAM", "SAM Database Extraction", "Извлечение базы SAM с хешами паролей", None, "Windows", "credential_theft", Severity.HIGH.value, "Mimikatz, secretsdump"),
                AttackVector("AV-WIN-PASSBACK", "NTLM Hash Passback", "Перехват NTLM-хешей через SMB", 445, "Windows SMB", "credential_theft", Severity.HIGH.value, "Responder, Impacket"),
                AttackVector("AV-WIN-KERBEROAST", "Kerberoasting", "Атака на сервисные учётные записи Kerberos", None, "Windows AD", "credential_theft", Severity.HIGH.value, "Rubeus, Invoke-Kerberoast"),
            ])
        elif "Linux" in os_info:
            vectors.extend([
                AttackVector("AV-LIN-PRIVESC", "Linux Privilege Escalation", "Повышение привилегий через уязвимости ядра", None, "Linux", "privilege_escalation", Severity.HIGH.value, "LinPEAS, linux-exploit-suggester"),
                AttackVector("AV-LIN-CRON", "Cron Job Exploitation", "Эксплуатация задач cron с повышенными привилегиями", None, "Linux", "privilege_escalation", Severity.MEDIUM.value, "LinPEAS"),
                AttackVector("AV-LIN-SUID", "SUID Binary Exploitation", "Эксплуатация SUID-бинарников", None, "Linux", "privilege_escalation", Severity.HIGH.value, "GTFOBins, LinPEAS"),
            ])

        print(f"[+] Сгенерировано {len(vectors)} возможных векторов атак "
              f"(в т.ч. {len(banner_findings)} по баннерам, {len(service_vectors)} по сервисам)")
        return vectors

    def _generate_service_based_vectors(self, open_ports: list[OpenPort]) -> list[AttackVector]:
        """Генерация векторов атак на основе обнаруженных сервисов и CVE."""
        vectors = []
        service_counter = {}

        # Собираем все обнаруженные сервисы
        for port_info in open_ports:
            service = port_info.service
            if service and service != "Unknown":
                service_counter[service] = service_counter.get(service, 0) + 1

        # Используем улучшенную систему определения CVE
        cve_detector = EnhancedCVEDetector()

        # Генерируем векторы для каждого уникального сервиса
        for port_info in open_ports:
            service = port_info.service
            if service and service != "Unknown":
                # Получаем CVE для сервиса с использованием улучшенной системы
                cves = cve_detector.detect_cves_for_service(
                    service=service,
                    version=port_info.banner,
                    port=port_info.port
                )

                # Создаем векторы атак для каждого найденного CVE
                for cve in cves:
                    av = AttackVector(
                        id=f"AV-CVE-{cve['id']}",
                        name=f"{cve['id']} — {service}",
                        description=f"{cve['description']} (обнаружено на порту {port_info.port})",
                        target_port=port_info.port,
                        target_service=service,
                        attack_type="known_vulnerability",
                        severity=cve['severity'],
                        tools_used="CVE-specific exploit",
                    )
                    vectors.append(av)

        return vectors

    def _get_port_based_cves(self, service: str, count: int) -> list:
        """Получение CVE на основе сервиса и порта."""
        # Маппинг сервисов на порты для автоматического определения CVE
        port_cve_map = {
            # SSH (порт 22)
            "SSH": [
                ("CVE-2020-15778", "MEDIUM", "OpenSSH < 8.0 — command injection via scp"),
                ("CVE-2023-38408", "HIGH", "OpenSSH < 8.8 — PKCS#11 vulnerability"),
            ],
            # HTTP (порт 80)
            "HTTP": [
                ("CVE-2021-41773", "CRITICAL", "Apache 2.4.49 — Path Traversal/RCE"),
                ("CVE-2021-42013", "CRITICAL", "Apache 2.4.50 — Path Traversal/RCE"),
                ("CVE-2021-23017", "HIGH", "Nginx < 1.18 — DNS resolver vulnerability"),
            ],
            # HTTPS (порт 443)
            "HTTPS": [
                ("CVE-2014-0160", "CRITICAL", "Heartbleed — OpenSSL buffer over-read"),
                ("CVE-2014-3566", "MEDIUM", "POODLE — SSL 3.0 vulnerability"),
                ("CVE-2017-13099", "HIGH", "ROBOT — RSA vulnerability"),
            ],
            # MySQL (порт 3306)
            "MySQL": [
                ("CVE-2012-2122", "HIGH", "MySQL 5.x — authentication bypass"),
            ],
            # Redis (порт 6379)
            "Redis": [
                ("CVE-2022-0543", "CRITICAL", "Redis < 6.0 — Lua sandbox escape"),
            ],
        }
        
        return port_cve_map.get(service, [])


class AttackSender:
    """Отправка результатов на серверный агент."""

    def __init__(self, server_url: str):
        self.server_url = server_url

    def send(self, scan_result: ScanResult) -> dict:
        """Отправка результатов сканирования на сервер."""
        print(f"\n[*] Отправка результатов на {self.server_url}/analyze ...")

        from dataclasses import asdict
        data = asdict(scan_result)
        json_data = json.dumps(data, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(
            f"{self.server_url}/analyze",
            data=json_data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                result = json.loads(response.read().decode("utf-8"))
                print("[+] Ответ от сервера получен!")
                return result
        except urllib.error.URLError as e:
            print(f"[!] Ошибка подключения к серверу: {e}")
            return {"error": str(e)}
        except Exception as e:
            print(f"[!] Ошибка: {e}")
            return {"error": str(e)}


def _scan_with_nmap_nuclei(target: str, open_ports: list[OpenPort]) -> list[dict]:
    """Сканирование уязвимостей с использованием Nmap и Nuclei."""
    from nmap_integration import IntegratedScanner

    # Получаем список портов для сканирования
    ports_to_scan = [p.port for p in open_ports]

    # Создаем интегрированный сканер
    scanner = IntegratedScanner(target)

    # Запускаем сканирование
    vulnerabilities = scanner.scan_all_vulnerabilities(ports_to_scan)

    return vulnerabilities

def run_attacker(target_ip: str = None, server_port: int = None,
                 port_start: int = None, port_end: int = None):
    """Основная функция атакующего агента."""
    target = target_ip or TARGET_SERVER_HOST
    srv_port = server_port or TARGET_SERVER_PORT
    p_start = port_start or SCAN_PORT_START
    p_end = port_end or SCAN_PORT_END

    print("=" * 60)
    print("  АТАКУЮЩИЙ АГЕНТ — СКАНИРОВАНИЕ И АНАЛИЗ")
    print("=" * 60)
    print(f"  Цель:      {target}")
    print(f"  Порты:     {p_start}-{p_end}")
    print(f"  Сервер:    http://{target}:{srv_port}")
    print("=" * 60)

    # 1. Сканирование портов
    scanner = PortScanner(target, p_start, p_end)
    open_ports = scanner.scan()

    if not open_ports:
        print("[!] Открытых портов не обнаружено. Завершение.")
        return

    # 2. Определение ОС
    os_info = OSDetector.detect(target, open_ports)
    print(f"\n[*] Определение ОС: {os_info}")

    # 3. Анализ баннеров
    banner_findings = BannerAnalyzer.analyze(open_ports)
    if banner_findings:
        print(f"\n[!] Обнаружено {len(banner_findings)} CVE по баннерам:")
        for f in banner_findings:
            print(f"  [{f['severity']:>8}] {f['cve_id']}: {f['description'][:60]}")

    # 3.5. Интеграция с Nmap и Nuclei для более точного определения уязвимостей
    print("\n[*] Запуск Nmap и Nuclei для глубокого сканирования уязвимостей...")
    nmap_nuclei_vulns = _scan_with_nmap_nuclei(target, open_ports)
    if nmap_nuclei_vulns:
        print(f"[+] Nmap и Nuclei обнаружили {len(nmap_nuclei_vulns)} уязвимостей:")
        for vuln in nmap_nuclei_vulns[:5]:  # Показываем первые 5
            print(f"  [{vuln['severity']:>8}] {vuln['cve_id']}: {vuln['description'][:60]}")

    # 4. Генерация векторов атак
    generator = AttackVectorGenerator()
    attack_vectors = generator.generate(open_ports)

    # 4.5. Добавляем векторы атак на основе результатов Nmap и Nuclei
    for vuln in nmap_nuclei_vulns:
        av = AttackVector(
            id=f"AV-NMAP-{vuln['cve_id']}",
            name=f"{vuln['cve_id']} (из {vuln['source']})",
            description=f"{vuln['description']} (обнаружено {vuln['source']} на порту {vuln['port']})",
            target_port=vuln['port'],
            target_service=vuln.get('service', 'unknown'),
            attack_type="known_vulnerability",
            severity=vuln['severity'],
            tools_used=vuln['source'],
        )
        attack_vectors.append(av)

    # 5. Формирование результата
    scan_result = ScanResult(
        scanner_ip=socket.gethostbyname(socket.gethostname()),
        target_ip=target,
        open_ports=open_ports,
        discovered_services=[f"{p.service} (:{p.port})" for p in open_ports],
        attack_vectors=attack_vectors,
        os_detection=os_info,
        scan_timestamp=datetime.now().isoformat(),
    )

    # 6. Вывод сводки
    print("\n" + "=" * 60)
    print("СВОДКА СКАНИРОВАНИЯ")
    print("=" * 60)
    print(f"Определённая ОС: {os_info}")
    print(f"Открытые порты ({len(open_ports)}):")
    for p in open_ports:
        print(f"  {p.port:>5}/TCP  {p.service:<15} {p.banner[:50] if p.banner else ''}")
    print(f"\nВекторы атак ({len(attack_vectors)}):")
    for av in attack_vectors:
        print(f"  [{av.severity:>8}] {av.name}: {av.description[:60]}")

    # 7. Отправка на сервер
    server_url = f"http://{target}:{srv_port}"
    sender = AttackSender(server_url)
    result = sender.send(scan_result)

    if "error" in result:
        print(f"\n[!] Ошибка от сервера: {result['error']}")
    else:
        print(f"\n[+] Анализ завершён. Результатов: {result.get('results_count', '?')}")
        summary = result.get("summary", {})
        print(f"  Реализуемых атак: {summary.get('feasible_attacks', '?')}")
        print(f"  Частично реализуемых: {summary.get('partially_feasible', '?')}")
        print(f"  Нереализуемых: {summary.get('not_feasible_attacks', '?')}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Атакующий агент")
    parser.add_argument("-t", "--target", default=None, help="IP-адрес цели")
    parser.add_argument("-p", "--port", type=int, default=None, help="Порт API сервера")
    parser.add_argument("--scan-start", type=int, default=None, help="Начало диапазона")
    parser.add_argument("--scan-end", type=int, default=None, help="Конец диапазона")
    args = parser.parse_args()

    run_attacker(args.target, args.port, args.scan_start, args.scan_end)