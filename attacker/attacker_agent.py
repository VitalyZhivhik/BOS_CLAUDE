"""
Атакующий агент.
Сканирует целевой сервер: порты, сервисы, баннеры.
Формирует список возможных векторов атак и отправляет на сервер для анализа.
"""

import socket
import json
import sys
import os
import struct
import time
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.config import (
    TARGET_SERVER_HOST, TARGET_SERVER_PORT,
    SCAN_PORT_START, SCAN_PORT_END, SCAN_TIMEOUT, KNOWN_PORTS
)
from common.models import (
    ScanResult, OpenPort, AttackVector, Severity, to_json
)


class PortScanner:
    """Сканер портов."""

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
            # Для HTTP-портов отправляем GET запрос
            if port in (80, 443, 8080, 8443):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            else:
                sock.sendall(b"\r\n")
            sock.settimeout(1.0)
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            return banner[:200]  # обрезаем длинные баннеры
        except Exception:
            return ""


class AttackVectorGenerator:
    """Генерация возможных векторов атак на основе обнаруженных портов и сервисов."""

    # Шаблоны атак для различных сервисов
    ATTACK_TEMPLATES = {
        21: [
            AttackVector("AV-FTP-BRUTE", "FTP Brute Force", "Подбор учётных данных FTP", 21, "FTP", "brute_force", Severity.MEDIUM.value, "Hydra, Medusa"),
            AttackVector("AV-FTP-ANON", "FTP Anonymous Access", "Попытка анонимного доступа к FTP", 21, "FTP", "unauthorized_access", Severity.MEDIUM.value, "FTP Client"),
        ],
        22: [
            AttackVector("AV-SSH-BRUTE", "SSH Brute Force", "Подбор учётных данных SSH", 22, "SSH", "brute_force", Severity.MEDIUM.value, "Hydra, Medusa"),
            AttackVector("AV-SSH-KEY", "SSH Key Exploitation", "Попытка использования украденных SSH-ключей", 22, "SSH", "credential_theft", Severity.HIGH.value, "SSH Client"),
        ],
        80: [
            AttackVector("AV-HTTP-SQLI", "SQL Injection (HTTP)", "SQL-инъекция через веб-приложение", 80, "HTTP", "sql_injection", Severity.HIGH.value, "SQLMap"),
            AttackVector("AV-HTTP-XSS", "Cross-Site Scripting (HTTP)", "Межсайтовый скриптинг через веб-приложение", 80, "HTTP", "cross_site_scripting", Severity.MEDIUM.value, "XSSer, Burp Suite"),
            AttackVector("AV-HTTP-DIRB", "Directory Bruteforcing", "Перебор каталогов и файлов веб-сервера", 80, "HTTP", "information_disclosure", Severity.LOW.value, "DirBuster, Gobuster"),
            AttackVector("AV-HTTP-RCE", "Remote Code Execution (HTTP)", "Удалённое выполнение кода через веб-приложение", 80, "HTTP", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
        443: [
            AttackVector("AV-HTTPS-SQLI", "SQL Injection (HTTPS)", "SQL-инъекция через защищённое веб-приложение", 443, "HTTPS", "sql_injection", Severity.HIGH.value, "SQLMap"),
            AttackVector("AV-HTTPS-XSS", "Cross-Site Scripting (HTTPS)", "XSS через защищённое соединение", 443, "HTTPS", "cross_site_scripting", Severity.MEDIUM.value, "Burp Suite"),
            AttackVector("AV-HTTPS-SSRF", "Server-Side Request Forgery", "SSRF через веб-приложение", 443, "HTTPS", "ssrf", Severity.HIGH.value, "Burp Suite"),
            AttackVector("AV-HTTPS-SSL", "SSL/TLS Vulnerability", "Атака на уязвимости SSL/TLS протокола", 443, "HTTPS", "protocol_attack", Severity.MEDIUM.value, "SSLScan, testssl.sh"),
        ],
        445: [
            AttackVector("AV-SMB-ETERNAL", "EternalBlue (MS17-010)", "Эксплуатация CVE-2017-0144 через SMB", 445, "SMB", "remote_code_execution", Severity.CRITICAL.value, "Metasploit, EternalBlue"),
            AttackVector("AV-SMB-RELAY", "SMB Relay Attack", "Перенаправление аутентификации SMB", 445, "SMB", "credential_theft", Severity.HIGH.value, "Impacket, Responder"),
            AttackVector("AV-SMB-ENUM", "SMB Enumeration", "Перечисление ресурсов через SMB", 445, "SMB", "information_disclosure", Severity.LOW.value, "Enum4linux, SMBClient"),
        ],
        135: [
            AttackVector("AV-RPC-ENUM", "RPC Enumeration", "Перечисление RPC-интерфейсов", 135, "RPC", "information_disclosure", Severity.LOW.value, "rpcclient"),
            AttackVector("AV-RPC-DCOM", "DCOM Exploitation", "Эксплуатация уязвимостей DCOM", 135, "RPC", "remote_code_execution", Severity.HIGH.value, "Metasploit"),
        ],
        139: [
            AttackVector("AV-NETBIOS-ENUM", "NetBIOS Enumeration", "Перечисление NetBIOS-имён и ресурсов", 139, "NetBIOS", "information_disclosure", Severity.LOW.value, "nbtscan"),
        ],
        1433: [
            AttackVector("AV-MSSQL-BRUTE", "MSSQL Brute Force", "Подбор учётных данных MSSQL", 1433, "MSSQL", "brute_force", Severity.HIGH.value, "Hydra"),
            AttackVector("AV-MSSQL-XP", "MSSQL xp_cmdshell", "Выполнение команд через xp_cmdshell", 1433, "MSSQL", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
        3306: [
            AttackVector("AV-MYSQL-BRUTE", "MySQL Brute Force", "Подбор учётных данных MySQL", 3306, "MySQL", "brute_force", Severity.HIGH.value, "Hydra"),
        ],
        3389: [
            AttackVector("AV-RDP-BRUTE", "RDP Brute Force", "Подбор учётных данных RDP", 3389, "RDP", "brute_force", Severity.HIGH.value, "Hydra, Crowbar"),
            AttackVector("AV-RDP-BLUEKEEP", "BlueKeep (CVE-2019-0708)", "Эксплуатация CVE-2019-0708 через RDP", 3389, "RDP", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
        5432: [
            AttackVector("AV-PGSQL-BRUTE", "PostgreSQL Brute Force", "Подбор учётных данных PostgreSQL", 5432, "PostgreSQL", "brute_force", Severity.HIGH.value, "Hydra"),
        ],
        8080: [
            AttackVector("AV-PROXY-SQLI", "SQL Injection (Proxy)", "SQL-инъекция через прокси/приложение", 8080, "HTTP-Proxy", "sql_injection", Severity.HIGH.value, "SQLMap"),
            AttackVector("AV-PROXY-RCE", "Remote Code Execution (Proxy)", "RCE через веб-приложение на порту 8080", 8080, "HTTP-Proxy", "remote_code_execution", Severity.CRITICAL.value, "Metasploit"),
        ],
    }

    def generate(self, open_ports: list[OpenPort]) -> list[AttackVector]:
        """Генерация векторов атак для обнаруженных портов."""
        print("\n[*] Генерация векторов атак...")
        vectors = []

        for port_info in open_ports:
            port = port_info.port
            if port in self.ATTACK_TEMPLATES:
                vectors.extend(self.ATTACK_TEMPLATES[port])

        # Общие атаки для любого открытого сервиса
        if open_ports:
            vectors.append(AttackVector(
                "AV-DOS-GENERIC", "Denial of Service",
                "Атака отказа в обслуживании на обнаруженные сервисы",
                None, "generic", "denial_of_service",
                Severity.MEDIUM.value, "hping3, LOIC"
            ))

        print(f"[+] Сгенерировано {len(vectors)} возможных векторов атак")
        return vectors


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

    # 2. Генерация векторов атак
    generator = AttackVectorGenerator()
    attack_vectors = generator.generate(open_ports)

    # 3. Формирование результата
    scan_result = ScanResult(
        scanner_ip=socket.gethostbyname(socket.gethostname()),
        target_ip=target,
        open_ports=open_ports,
        discovered_services=[f"{p.service} (:{p.port})" for p in open_ports],
        attack_vectors=attack_vectors,
        os_detection="Windows (based on port fingerprint)",
        scan_timestamp=datetime.now().isoformat(),
    )

    # 4. Вывод локальной сводки
    print("\n" + "=" * 60)
    print("СВОДКА СКАНИРОВАНИЯ")
    print("=" * 60)
    print(f"Открытые порты ({len(open_ports)}):")
    for p in open_ports:
        print(f"  {p.port:>5}/TCP  {p.service:<15} {p.banner[:50] if p.banner else ''}")
    print(f"\nВекторы атак ({len(attack_vectors)}):")
    for av in attack_vectors:
        print(f"  [{av.severity:>8}] {av.name}: {av.description[:60]}")

    # 5. Отправка на сервер
    server_url = f"http://{target}:{srv_port}"
    sender = AttackSender(server_url)
    response = sender.send(scan_result)

    # 6. Обработка ответа
    if "error" in response:
        print(f"\n[!] Ошибка от сервера: {response['error']}")
        # Сохраняем результаты локально
        local_path = f"scan_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(local_path, "w", encoding="utf-8") as f:
            from dataclasses import asdict
            json.dump(asdict(scan_result), f, ensure_ascii=False, indent=2)
        print(f"[+] Результаты сканирования сохранены локально: {local_path}")
    else:
        print("\n" + "=" * 60)
        print("РЕЗУЛЬТАТЫ АНАЛИЗА (от сервера)")
        print("=" * 60)
        summary = response.get("summary", {})
        print(f"  Всего проанализировано:   {summary.get('total_vulnerabilities_analyzed', 0)}")
        print(f"  Реализуемые атаки:        {summary.get('feasible_attacks', 0)}")
        print(f"  Частично реализуемые:     {summary.get('partially_feasible', 0)}")
        print(f"  Нереализуемые:            {summary.get('not_feasible_attacks', 0)}")
        print(f"  Требуют анализа:          {summary.get('requires_analysis', 0)}")
        print(f"\n  HTML-отчёт: {response.get('html_report', 'N/A')}")
        print(f"  JSON-отчёт: {response.get('json_report', 'N/A')}")

        # Вывод деталей
        details = response.get("details", [])
        if details:
            print(f"\nДетали ({len(details)}):")
            for d in details:
                status_icon = {
                    "РЕАЛИЗУЕМА": "❌",
                    "НЕ РЕАЛИЗУЕМА": "✅",
                    "ЧАСТИЧНО РЕАЛИЗУЕМА": "⚠️",
                    "ТРЕБУЕТ АНАЛИЗА": "❓",
                }.get(d["feasibility"], "•")
                print(f"  {status_icon} [{d['severity']:>8}] {d['cve_id']}: {d['feasibility']}")
                print(f"     {d['reason'][:80]}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Атакующий агент — сканер безопасности")
    parser.add_argument("--target", "-t", default=TARGET_SERVER_HOST, help="IP-адрес целевого сервера")
    parser.add_argument("--port", "-p", type=int, default=TARGET_SERVER_PORT, help="Порт API сервера")
    parser.add_argument("--scan-start", type=int, default=SCAN_PORT_START, help="Начальный порт сканирования")
    parser.add_argument("--scan-end", type=int, default=SCAN_PORT_END, help="Конечный порт сканирования")
    args = parser.parse_args()

    run_attacker(args.target, args.port, args.scan_start, args.scan_end)
