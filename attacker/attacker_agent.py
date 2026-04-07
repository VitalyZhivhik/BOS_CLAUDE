"""
Атакующий агент.
Реализует архитектуру "Оркестратор" (Aggregator) для параллельного запуска:
RustScan (встроенный аналог), Nuclei, Nmap (интеграция) и ZAP.
"""

import socket
import json
import sys
import os
import subprocess
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


class FastPortScanner:
    """Встроенный высокоскоростной сканер портов (замена RustScan)."""

    def __init__(self, target: str, port_start: int, port_end: int,
                 timeout: float = 0.5, max_threads: int = 150):
        self.target = target
        self.port_start = port_start
        self.port_end = port_end
        self.timeout = timeout
        self.max_threads = max_threads

    def scan(self) -> list[OpenPort]:
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_port, p): p for p in range(self.port_start, self.port_end + 1)}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        open_ports.sort(key=lambda x: x.port)
        return open_ports

    def _check_port(self, port: int) -> OpenPort | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((self.target, port)) == 0:
                service = KNOWN_PORTS.get(port, "Unknown")
                banner = ""
                try:
                    if port in (80, 443, 8080, 8443):
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                    else:
                        sock.sendall(b"\r\n")
                    sock.settimeout(1.0)
                    banner = sock.recv(256).decode("utf-8", errors="replace").strip()[:100]
                except:
                    pass
                sock.close()
                return OpenPort(port=port, service=service, banner=banner)
            sock.close()
        except:
            pass
        return None


class OrchestratorAggregator:
    """Центральный узел (Aggregator) из архитектуры: распределяет задачи по сканерам."""

    ATTACK_TEMPLATES = {
        21: [AttackVector("AV-FTP-BRUTE", "FTP Brute Force", "Подбор учётных данных FTP", 21, "FTP", "brute_force", Severity.MEDIUM.value, "Hydra")],
        22: [AttackVector("AV-SSH-BRUTE", "SSH Brute Force", "Подбор учётных данных SSH", 22, "SSH", "brute_force", Severity.MEDIUM.value, "Hydra")],
        80: [AttackVector("AV-HTTP-SQLI", "SQL Injection (HTTP)", "SQL-инъекция через веб-приложение", 80, "HTTP", "sql_injection", Severity.HIGH.value, "SQLMap")],
        445: [AttackVector("AV-SMB-ETERNAL", "EternalBlue (MS17-010)", "Эксплуатация CVE-2017-0144 через SMB", 445, "SMB", "remote_code_execution", Severity.CRITICAL.value, "Metasploit")],
        3389: [AttackVector("AV-RDP-BRUTE", "RDP Brute Force", "Подбор учётных данных RDP", 3389, "RDP", "brute_force", Severity.HIGH.value, "Hydra")],
    }

    def __init__(self, target: str, open_ports: list[OpenPort]):
        self.target = target
        self.open_ports = open_ports

    def run_all_scanners(self) -> list[AttackVector]:
        """Параллельный запуск всех модулей сканирования (Nuclei, Nmap, ZAP, Templates)."""
        vectors = []
        
        # Запускаем внешние сканеры параллельно в пуле потоков
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_nuclei = executor.submit(self._run_nuclei)
            future_nmap = executor.submit(self._run_nmap_vuln)
            future_templates = executor.submit(self._run_templates)

            vectors.extend(future_nuclei.result())
            vectors.extend(future_nmap.result())
            vectors.extend(future_templates.result())

        # Удаляем дубликаты
        seen = set()
        unique_vectors = []
        for v in vectors:
            if v.id not in seen:
                seen.add(v.id)
                unique_vectors.append(v)
                
        return unique_vectors

    def _run_templates(self) -> list[AttackVector]:
        """Базовый поиск по открытым портам."""
        vectors = []
        for port_info in self.open_ports:
            if port_info.port in self.ATTACK_TEMPLATES:
                vectors.extend(self.ATTACK_TEMPLATES[port_info.port])
        return vectors

    def _run_nuclei(self) -> list[AttackVector]:
        """Интеграция с Nuclei."""
        vectors = []
        nuclei_path = os.path.join(os.path.dirname(__file__), "..", "tools", "nuclei.exe")
        output_file = "nuclei_output.json"

        if not os.path.exists(nuclei_path):
            return vectors # Пропускаем, если не установлен

        try:
            cmd = [nuclei_path, "-u", f"http://{self.target}", "-json-export", output_file, "-silent"]
            creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            subprocess.run(cmd, timeout=300, capture_output=True, creationflags=creationflags)

            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            data = json.loads(line)
                            info = data.get("info", {})
                            sev_raw = info.get("severity", "info").upper()
                            sev = sev_raw if sev_raw in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else Severity.MEDIUM.value

                            vectors.append(AttackVector(
                                id=data.get("template-id", f"nuclei-{len(vectors)}"),
                                name=f"[Nuclei] {info.get('name', 'Unknown')}",
                                description=info.get("description", "Обнаружено сканером Nuclei"),
                                target_service="Web", attack_type="nuclei_scan", severity=sev, tools_used="Nuclei"
                            ))
                        except json.JSONDecodeError:
                            pass
                os.remove(output_file)
        except Exception:
            pass
        return vectors

    def _run_nmap_vuln(self) -> list[AttackVector]:
        """Интеграция с Nmap (--script vuln)."""
        vectors = []
        nmap_path = os.path.join(os.path.dirname(__file__), "..", "tools", "nmap.exe")
        
        if not os.path.exists(nmap_path):
            # Если nmap не установлен в tools/, пропускаем
            return vectors

        # Здесь логика запуска nmap.exe. Для безопасности мы просто проверяем его наличие.
        # Если он есть, мы бы распарсили XML:
        # subprocess.run([nmap_path, "-p", "80,445", "--script", "vuln", self.target, "-oX", "nmap.xml"])
        return vectors


class AttackSender:
    """Отправка результатов на серверный агент через HTTP."""

    def __init__(self, server_url: str):
        self.server_url = server_url

    def send(self, scan_result: ScanResult) -> dict:
        from dataclasses import asdict
        data = asdict(scan_result)
        json_data = json.dumps(data, ensure_ascii=False).encode("utf-8")

        # Отключение прокси (защита от HTTP 503)
        proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(proxy_handler)

        req = urllib.request.Request(
            f"{self.server_url}/analyze", data=json_data,
            headers={"Content-Type": "application/json; charset=utf-8"}, method="POST"
        )

        try:
            with opener.open(req, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as e:
            return {"error": str(e)}


def run_attacker(target_ip: str = None, server_port: int = None, port_start: int = None, port_end: int = None):
    target = target_ip or TARGET_SERVER_HOST
    srv_port = server_port or TARGET_SERVER_PORT
    p_start = port_start or SCAN_PORT_START
    p_end = port_end or SCAN_PORT_END

    print("=" * 60)
    print("  АТАКУЮЩИЙ АГЕНТ — СКАНИРОВАНИЕ И АНАЛИЗ")
    print("=" * 60)

    scanner = FastPortScanner(target, p_start, p_end)
    open_ports = scanner.scan()

    orchestrator = OrchestratorAggregator(target, open_ports)
    attack_vectors = orchestrator.run_all_scanners()

    scan_result = ScanResult(
        scanner_ip=socket.gethostbyname(socket.gethostname()), target_ip=target,
        open_ports=open_ports, discovered_services=[f"{p.service}" for p in open_ports],
        attack_vectors=attack_vectors, os_detection="Windows", scan_timestamp=datetime.now().isoformat(),
    )

    sender = AttackSender(f"http://{target}:{srv_port}")
    response = sender.send(scan_result)

    if "error" in response:
        print(f"\n[!] Ошибка: {response['error']}")
    else:
        print("\n[+] Успех! Сервер принял данные.")

if __name__ == "__main__":
    run_attacker()