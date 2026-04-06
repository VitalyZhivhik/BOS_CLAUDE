"""
Модуль анализа системы сервера.
Собирает информацию об установленном ПО, сервисах, средствах защиты.
Работает на Windows 10.
"""

import subprocess
import socket
import json
import platform
import os
import re
from datetime import datetime

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.models import SystemInfo, InstalledSoftware, SecurityMeasure, OpenPort
from common.config import KNOWN_PORTS
from common.logger import get_server_logger

logger = get_server_logger()


class SystemAnalyzer:
    """Анализатор серверной системы Windows."""

    def __init__(self):
        self.system_info = SystemInfo()

    def analyze(self) -> SystemInfo:
        """Полный анализ системы."""
        logger.info("=" * 50)
        logger.info("НАЧАЛО АНАЛИЗА СЕРВЕРНОЙ СИСТЕМЫ")
        logger.info("=" * 50)
        self._collect_os_info()
        self._collect_installed_software()
        self._collect_running_services()
        self._collect_open_ports()
        self._collect_security_measures()
        self._detect_databases()
        self._detect_web_servers()
        self._detect_remote_access()
        logger.info("АНАЛИЗ СИСТЕМЫ ЗАВЕРШЁН")
        return self.system_info

    def _collect_os_info(self):
        logger.info("Сбор информации об ОС...")
        self.system_info.os_name = platform.system()
        self.system_info.os_version = platform.version()
        self.system_info.hostname = socket.gethostname()
        try:
            self.system_info.ip_addresses = list(set(
                addr[4][0]
                for addr in socket.getaddrinfo(socket.gethostname(), None)
                if addr[0] == socket.AF_INET
            ))
        except Exception as e:
            logger.warning(f"Ошибка получения IP: {e}")
            self.system_info.ip_addresses = ["127.0.0.1"]
        logger.info(f"  ОС: {self.system_info.os_name} {self.system_info.os_version}")
        logger.info(f"  Имя: {self.system_info.hostname}")
        logger.info(f"  IP: {', '.join(self.system_info.ip_addresses)}")

    def _collect_installed_software(self):
        logger.info("Сбор списка установленного ПО...")
        software_list = []
        registry_paths = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ]
        for reg_path in registry_paths:
            try:
                result = subprocess.run(
                    ["reg", "query", reg_path, "/s"],
                    capture_output=True, text=True, timeout=30,
                    encoding="cp866", errors="replace"
                )
                if result.returncode == 0:
                    current = {}
                    for line in result.stdout.split("\n"):
                        line = line.strip()
                        if line.startswith("HKEY_"):
                            if current.get("name"):
                                software_list.append(InstalledSoftware(
                                    name=current.get("name", ""),
                                    version=current.get("version", ""),
                                    publisher=current.get("publisher", ""),
                                    install_date=current.get("date", ""),
                                ))
                            current = {}
                        elif "DisplayName" in line and "REG_SZ" in line:
                            current["name"] = line.split("REG_SZ")[-1].strip()
                        elif "DisplayVersion" in line and "REG_SZ" in line:
                            current["version"] = line.split("REG_SZ")[-1].strip()
                        elif "Publisher" in line and "REG_SZ" in line:
                            current["publisher"] = line.split("REG_SZ")[-1].strip()
                        elif "InstallDate" in line and "REG_SZ" in line:
                            current["date"] = line.split("REG_SZ")[-1].strip()
                    if current.get("name"):
                        software_list.append(InstalledSoftware(
                            name=current["name"],
                            version=current.get("version", ""),
                            publisher=current.get("publisher", ""),
                            install_date=current.get("date", ""),
                        ))
            except Exception as e:
                logger.error(f"Ошибка чтения реестра {reg_path}: {e}")

        seen = set()
        unique = []
        for sw in software_list:
            key = sw.name.lower()
            if key not in seen and sw.name:
                seen.add(key)
                unique.append(sw)
        self.system_info.installed_software = unique
        logger.info(f"  Найдено {len(unique)} программ")

    def _collect_running_services(self):
        """Сбор запущенных сервисов — 3 метода с fallback."""
        logger.info("Сбор информации о запущенных сервисах...")
        services = []

        # Метод 1: PowerShell Get-Service (самый надёжный)
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
                 "Select-Object -ExpandProperty Name"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    svc = line.strip()
                    if svc:
                        services.append(svc)
                if services:
                    logger.info(f"  Найдено {len(services)} работающих сервисов (PowerShell)")
                    self.system_info.running_services = services
                    return
        except Exception as e:
            logger.warning(f"PowerShell Get-Service не удался: {e}")

        # Метод 2: sc query
        try:
            result = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "active"],
                capture_output=True, text=True, timeout=30,
                encoding="cp866", errors="replace"
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line.upper().startswith("SERVICE_NAME:") or "ИМЯ_СЛУЖБЫ:" in line:
                        svc_name = line.split(":", 1)[1].strip()
                        if svc_name:
                            services.append(svc_name)
                if services:
                    logger.info(f"  Найдено {len(services)} работающих сервисов (sc query)")
                    self.system_info.running_services = services
                    return
        except Exception as e:
            logger.warning(f"sc query не удался: {e}")

        # Метод 3: net start
        try:
            result = subprocess.run(
                ["net", "start"], capture_output=True, text=True, timeout=30,
                encoding="cp866", errors="replace"
            )
            if result.returncode == 0:
                started = False
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line.startswith("---"):
                        started = True
                        continue
                    if started and line and not line.startswith("Команда"):
                        services.append(line)
                logger.info(f"  Найдено {len(services)} работающих сервисов (net start)")
        except Exception as e:
            logger.error(f"net start не удался: {e}")

        self.system_info.running_services = services
        if not services:
            logger.warning("  Не удалось получить список сервисов ни одним методом!")

    def _collect_open_ports(self):
        logger.info("Сбор информации об открытых портах...")
        open_ports = []
        try:
            result = subprocess.run(
                ["netstat", "-an"], capture_output=True, text=True, timeout=30,
                encoding="cp866", errors="replace"
            )
            if result.returncode == 0:
                seen_ports = set()
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if "LISTENING" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            local_addr = parts[1]
                            if ":" in local_addr:
                                port_str = local_addr.rsplit(":", 1)[-1]
                                try:
                                    port = int(port_str)
                                    if port not in seen_ports:
                                        seen_ports.add(port)
                                        service = KNOWN_PORTS.get(port, "Unknown")
                                        protocol = "TCP" if "TCP" in parts[0] else "UDP"
                                        open_ports.append(OpenPort(port=port, service=service, protocol=protocol))
                                except ValueError:
                                    pass
        except Exception as e:
            logger.error(f"Ошибка получения портов: {e}")

        self.system_info.open_ports = open_ports
        logger.info(f"  Найдено {len(open_ports)} открытых портов (LISTENING)")
        known = [p for p in open_ports if p.service != "Unknown"]
        if known:
            logger.info(f"  Известные: {', '.join(f'{p.port}/{p.service}' for p in known)}")

    def _collect_security_measures(self):
        logger.info("Анализ средств обеспечения безопасности...")
        measures = []
        fw = self._check_firewall(); measures.append(fw)
        self.system_info.firewall_active = (fw.status == "active")
        av = self._check_antivirus(); measures.append(av)
        self.system_info.antivirus_active = (av.status == "active")
        measures.append(self._check_updates())
        measures.append(self._check_uac())
        measures.append(self._check_bitlocker())
        measures.append(self._check_exploit_guard())
        self.system_info.security_measures = measures
        for m in measures:
            logger.info(f"  {m.name}: {m.status} — {m.details}")

    def _check_firewall(self) -> SecurityMeasure:
        try:
            r = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"],
                               capture_output=True, text=True, timeout=15, encoding="cp866", errors="replace")
            if r.returncode == 0 and "ON" in r.stdout.upper():
                return SecurityMeasure("Брандмауэр Windows", "firewall", "active", "Включён")
        except Exception as e:
            logger.debug(f"Ошибка проверки firewall: {e}")
        return SecurityMeasure("Брандмауэр Windows", "firewall", "inactive", "Выключен или недоступен")

    def _check_antivirus(self) -> SecurityMeasure:
        try:
            r = subprocess.run(["powershell", "-Command",
                                "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | Format-List"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and "True" in r.stdout:
                return SecurityMeasure("Windows Defender", "antivirus", "active", "Активен, защита в реальном времени")
        except Exception as e:
            logger.debug(f"Ошибка проверки антивируса: {e}")
        return SecurityMeasure("Windows Defender", "antivirus", "unknown", "Не удалось определить")

    def _check_updates(self) -> SecurityMeasure:
        try:
            r = subprocess.run(["powershell", "-Command",
                                "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                return SecurityMeasure("Windows Update", "patch_management", "active",
                                       f"Последнее обновление: {r.stdout.strip()}")
        except Exception as e:
            logger.debug(f"Ошибка проверки обновлений: {e}")
        return SecurityMeasure("Windows Update", "patch_management", "unknown", "Не удалось определить")

    def _check_uac(self) -> SecurityMeasure:
        try:
            r = subprocess.run(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                                "/v", "EnableLUA"],
                               capture_output=True, text=True, timeout=10, encoding="cp866", errors="replace")
            if r.returncode == 0 and "0x1" in r.stdout:
                return SecurityMeasure("UAC", "access_control", "active", "Включён")
        except Exception as e:
            logger.debug(f"Ошибка проверки UAC: {e}")
        return SecurityMeasure("UAC", "access_control", "inactive", "Выключен или недоступен")

    def _check_bitlocker(self) -> SecurityMeasure:
        try:
            r = subprocess.run(["powershell", "-Command",
                                "Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and "On" in r.stdout:
                return SecurityMeasure("BitLocker", "encryption", "active", "Шифрование включено")
        except Exception as e:
            logger.debug(f"Ошибка проверки BitLocker: {e}")
        return SecurityMeasure("BitLocker", "encryption", "inactive", "Не включён")

    def _check_exploit_guard(self) -> SecurityMeasure:
        try:
            r = subprocess.run(["powershell", "-Command", "Get-ProcessMitigation -System | Format-List"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and r.stdout.strip():
                return SecurityMeasure("Exploit Guard", "exploit_protection", "active", "Настроен")
        except Exception as e:
            logger.debug(f"Ошибка Exploit Guard: {e}")
        return SecurityMeasure("Exploit Guard", "exploit_protection", "unknown", "Не удалось проверить")

    def _detect_databases(self):
        logger.info("Поиск установленных баз данных...")
        db_keywords = {"mysql": "MySQL", "mariadb": "MariaDB", "postgresql": "PostgreSQL",
                       "mssql": "MSSQL", "sql server": "MSSQL", "oracle": "Oracle",
                       "mongodb": "MongoDB", "redis": "Redis", "sqlite": "SQLite"}
        db_ports = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                    1521: "Oracle", 27017: "MongoDB", 6379: "Redis"}
        db_services_map = {"mysql": "MySQL", "mariadb": "MariaDB", "postgresql": "PostgreSQL",
                           "mssqlserver": "MSSQL", "sqlserver": "MSSQL", "mssql": "MSSQL",
                           "oracleservice": "Oracle", "mongodb": "MongoDB", "redis": "Redis"}
        found_dbs = set()

        for sw in self.system_info.installed_software:
            nl = sw.name.lower()
            for kw, name in db_keywords.items():
                if kw in nl:
                    found_dbs.add(name)

        for svc in self.system_info.running_services:
            sl = svc.lower()
            for kw, name in db_services_map.items():
                if kw in sl:
                    found_dbs.add(name)

        for op in self.system_info.open_ports:
            if op.port in db_ports:
                found_dbs.add(db_ports[op.port])

        self.system_info.has_database = len(found_dbs) > 0
        self.system_info.database_types = list(found_dbs)
        logger.info(f"  СУБД: {', '.join(found_dbs) if found_dbs else 'не обнаружены'}")

    def _detect_web_servers(self):
        logger.info("Поиск веб-серверов...")
        ws_keywords = {"apache": "Apache", "nginx": "Nginx", "iis": "IIS",
                       "tomcat": "Tomcat", "jenkins": "Jenkins"}
        found_ws = set()

        for sw in self.system_info.installed_software:
            nl = sw.name.lower()
            for kw, name in ws_keywords.items():
                if kw in nl:
                    found_ws.add(name)

        for svc in self.system_info.running_services:
            sl = svc.lower()
            if "w3svc" in sl: found_ws.add("IIS")
            for kw, name in ws_keywords.items():
                if kw in sl:
                    found_ws.add(name)

        self.system_info.has_web_server = len(found_ws) > 0
        self.system_info.web_server_types = list(found_ws)
        logger.info(f"  Веб-серверы: {', '.join(found_ws) if found_ws else 'не обнаружены'}")

    def _detect_remote_access(self):
        logger.info("Проверка средств удалённого доступа...")
        try:
            r = subprocess.run(["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                                "/v", "fDenyTSConnections"],
                               capture_output=True, text=True, timeout=10, encoding="cp866", errors="replace")
            if r.returncode == 0 and "0x0" in r.stdout:
                self.system_info.has_rdp_enabled = True
                logger.info("  RDP: ВКЛЮЧЁН")
            else:
                logger.info("  RDP: выключен")
        except Exception as e:
            logger.warning(f"  Не удалось проверить RDP: {e}")

        for op in self.system_info.open_ports:
            if op.port == 445:
                self.system_info.has_smb_enabled = True
                logger.info("  SMB: порт 445 открыт")
                break
        else:
            logger.info("  SMB: не обнаружен")

        for op in self.system_info.open_ports:
            if op.port == 21:
                self.system_info.has_ftp_enabled = True
                logger.info("  FTP: порт 21 открыт")
                break

    def get_summary(self) -> dict:
        return {
            "os": f"{self.system_info.os_name} {self.system_info.os_version}",
            "hostname": self.system_info.hostname,
            "ip_addresses": self.system_info.ip_addresses,
            "installed_software_count": len(self.system_info.installed_software),
            "running_services_count": len(self.system_info.running_services),
            "open_ports_count": len(self.system_info.open_ports),
            "has_database": self.system_info.has_database,
            "database_types": self.system_info.database_types,
            "has_web_server": self.system_info.has_web_server,
            "web_server_types": self.system_info.web_server_types,
            "has_rdp": self.system_info.has_rdp_enabled,
            "has_smb": self.system_info.has_smb_enabled,
            "has_ftp": self.system_info.has_ftp_enabled,
            "firewall": self.system_info.firewall_active,
            "antivirus": self.system_info.antivirus_active,
            "security_measures": [
                {"name": m.name, "status": m.status, "details": m.details}
                for m in self.system_info.security_measures
            ]
        }
