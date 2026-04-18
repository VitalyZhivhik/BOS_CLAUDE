#!/usr/bin/env python3
"""
Интеграция с Nmap и Nuclei для более точного определения уязвимостей.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import re
from typing import List, Dict, Optional
import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

from common.logger import get_server_logger

logger = get_server_logger()

class NmapScanner:
    """Интеграция с Nmap для сканирования уязвимостей."""

    def __init__(self, target: str):
        self.target = target
        self.nmap_path = "nmap"

    def scan_vulnerabilities(self, ports: List[int] = None) -> List[Dict]:
        """
        Сканирование уязвимостей с использованием Nmap.

        Args:
            ports: Список портов для сканирования

        Returns:
            Список найденных уязвимостей
        """
        vulnerabilities = []

        if not ports:
            return vulnerabilities

        # Формируем команду Nmap
        port_list = ",".join(map(str, ports))
        cmd = [
            self.nmap_path,
            "-sV", "-sC", "--script", "vuln",
            "-p", port_list,
            self.target,
            "-oX", "-"
        ]

        try:
            logger.info(f"Запуск Nmap для сканирования уязвимостей: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                vulnerabilities = self._parse_nmap_xml(result.stdout)
                logger.info(f"Nmap нашел {len(vulnerabilities)} уязвимостей")
            else:
                logger.warning(f"Nmap завершился с ошибкой: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.warning("Nmap сканирование превысило лимит времени")
        except Exception as e:
            logger.error(f"Ошибка при выполнении Nmap: {e}")

        return vulnerabilities

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict]:
        """Парсинг XML-вывода Nmap."""
        vulnerabilities = []

        try:
            root = ET.fromstring(xml_output)

            # Ищем хосты
            for host in root.findall("host"):
                # Получаем IP-адрес
                address = host.find("address")
                if address is None or address.get("addrtype") != "ipv4":
                    continue

                ip_address = address.get("addr", "unknown")

                # Ищем порты с уязвимостями
                for port in host.findall("ports/port"):
                    port_id = port.get("portid", "0")
                    protocol = port.get("protocol", "tcp")

                    # Ищем скрипты с уязвимостями
                    for script in port.findall("script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")

                        # Ищем CVE в выводе скрипта
                        cve_matches = re.findall(r"CVE-(\d{4}-\d+)", script_output)
                        for cve_id in cve_matches:
                            vulnerabilities.append({
                                "cve_id": f"CVE-{cve_id}",
                                "port": int(port_id),
                                "protocol": protocol,
                                "service": self._get_service_from_port(port),
                                "severity": self._determine_severity(script_id),
                                "description": script_output[:200],
                                "source": "Nmap",
                                "script": script_id
                            })

        except Exception as e:
            logger.error(f"Ошибка при парсинге XML Nmap: {e}")

        return vulnerabilities

    def _get_service_from_port(self, port_element) -> str:
        """Получение названия сервиса из элемента порта."""
        service = port_element.find("service")
        if service is not None:
            return service.get("name", "unknown")
        return "unknown"

    def _determine_severity(self, script_id: str) -> str:
        """Определение уровня критичности по ID скрипта."""
        # Скрипты с известными критическими уязвимостями
        critical_scripts = [
            "vuln", "smb-vuln-ms17-010", "http-vuln-cve2017-5638",
            "ssl-heartbleed", "http-shellshock", "smb-vuln-ms08-067"
        ]

        # Скрипты с высоким уровнем критичности
        high_scripts = [
            "http-slowloris-check", "http-sql-injection", "smb-vuln-cve2009-3103",
            "ssl-poodle", "http-vuln-cve2013-0156"
        ]

        if any(cs in script_id for cs in critical_scripts):
            return "CRITICAL"
        elif any(hs in script_id for hs in high_scripts):
            return "HIGH"
        else:
            return "MEDIUM"

class NucleiScanner:
    """Интеграция с Nuclei для сканирования уязвимостей."""

    def __init__(self, target: str):
        self.target = target
        self.nuclei_path = "nuclei"

    def scan_vulnerabilities(self, ports: List[int] = None) -> List[Dict]:
        """
        Сканирование уязвимостей с использованием Nuclei.

        Args:
            ports: Список портов для сканирования

        Returns:
            Список найденных уязвимостей
        """
        vulnerabilities = []

        if not ports:
            return vulnerabilities

        # Формируем команду Nuclei
        target_url = f"http://{self.target}" if any(p in [80, 443, 8080, 8443] for p in ports) else self.target
        cmd = [
            self.nuclei_path,
            "-u", target_url,
            "-t", "cves/",
            "-json",
            "-silent"
        ]

        try:
            logger.info(f"Запуск Nuclei для сканирования уязвимостей: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            if result.returncode == 0 and result.stdout:
                vulnerabilities = self._parse_nuclei_json(result.stdout)
                logger.info(f"Nuclei нашел {len(vulnerabilities)} уязвимостей")
            else:
                logger.warning(f"Nuclei завершился с ошибкой: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.warning("Nuclei сканирование превысило лимит времени")
        except Exception as e:
            logger.error(f"Ошибка при выполнении Nuclei: {e}")

        return vulnerabilities

    def _parse_nuclei_json(self, json_output: str) -> List[Dict]:
        """Парсинг JSON-вывода Nuclei."""
        vulnerabilities = []

        try:
            # Парсим JSON построчно (Nuclei выводит по одному JSON объекту на строку)
            for line in json_output.strip().split("\n"):
                if not line:
                    continue

                try:
                    result = json.loads(line)

                    # Извлекаем информацию об уязвимости
                    vulnerability = {
                        "cve_id": result.get("info", {}).get("classification", {}).get("cve-id", [""])[0],
                        "port": result.get("host", "0").split(":")[-1],
                        "protocol": "tcp",
                        "service": result.get("service", {}).get("name", "unknown"),
                        "severity": result.get("info", {}).get("severity", "medium").upper(),
                        "description": result.get("info", {}).get("name", "Unknown vulnerability"),
                        "source": "Nuclei",
                        "template": result.get("template-id", "")
                    }

                    # Проверяем, что CVE-ID валиден
                    if vulnerability["cve_id"] and vulnerability["cve_id"].startswith("CVE-"):
                        vulnerabilities.append(vulnerability)

                except json.JSONDecodeError:
                    continue

        except Exception as e:
            logger.error(f"Ошибка при парсинге JSON Nuclei: {e}")

        return vulnerabilities

class IntegratedScanner:
    """Интегрированный сканер уязвимостей (Nmap + Nuclei)."""

    def __init__(self, target: str):
        self.target = target
        self.nmap_scanner = NmapScanner(target)
        self.nuclei_scanner = NucleiScanner(target)

    def scan_all_vulnerabilities(self, ports: List[int]) -> List[Dict]:
        """
        Полное сканирование уязвимостей с использованием Nmap и Nuclei.

        Args:
            ports: Список портов для сканирования

        Returns:
            Объединённый список уязвимостей
        """
        # Сканируем с помощью Nmap
        nmap_vulns = self.nmap_scanner.scan_vulnerabilities(ports)

        # Сканируем с помощью Nuclei
        nuclei_vulns = self.nuclei_scanner.scan_vulnerabilities(ports)

        # Объединяем результаты и удаляем дубликаты
        all_vulns = nmap_vulns + nuclei_vulns

        # Удаляем дубликаты по CVE-ID и порту
        unique_vulns = []
        seen = set()

        for vuln in all_vulns:
            key = (vuln["cve_id"], vuln["port"])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        logger.info(f"Всего найдено уникальных уязвимостей: {len(unique_vulns)}")
        return unique_vulns

def test_integration():
    """Тестирование интеграции с Nmap и Nuclei."""
    print("=== ТЕСТ ИНТЕГРАЦИИ С Nmap и Nuclei ===")

    # Создаем интегрированный сканер
    scanner = IntegratedScanner("127.0.0.1")

    # Тестовые порты
    test_ports = [135, 445, 902, 912]

    print(f"\nСканирование портов: {test_ports}...")
    vulnerabilities = scanner.scan_all_vulnerabilities(test_ports)

    print(f"\nНайдено уязвимостей: {len(vulnerabilities)}")
    for vuln in vulnerabilities:
        print(f"  [{vuln['severity']:>8}] {vuln['cve_id']}: {vuln['description'][:60]}")
        print(f"    Порт: {vuln['port']}, Сервис: {vuln['service']}, Источник: {vuln['source']}")

if __name__ == "__main__":
    test_integration()