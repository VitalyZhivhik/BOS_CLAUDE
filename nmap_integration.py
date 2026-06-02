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
import shutil

# Добавляем путь к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

from common.logger import get_server_logger
from common.bundle_paths import bundle_resources_root, tools_dir

logger = get_server_logger()

def _expand_candidate_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths or []:
        s = str(p or "").strip()
        if not s:
            continue
        s = os.path.expandvars(os.path.expanduser(s))
        out.append(s)
    return out

def _windows_tool_candidates(tool: str) -> list[str]:
    if os.name != "nt":
        return []
    pf = os.environ.get("ProgramFiles", "")
    pf86 = os.environ.get("ProgramFiles(x86)", "")
    local = os.environ.get("LOCALAPPDATA", "")
    user = os.environ.get("USERPROFILE", "")
    choco = os.environ.get("ChocolateyInstall", "")
    programdata = os.environ.get("ProgramData", r"C:\ProgramData")

    t = str(tool or "").strip().lower()
    exe = f"{t}.exe" if not t.endswith(".exe") else t

    candidates: list[str] = []

    if t in ("nmap", "nmap.exe"):
        candidates.extend([
            os.path.join(pf, "Nmap", "nmap.exe"),
            os.path.join(pf86, "Nmap", "nmap.exe"),
            os.path.join(local, "Programs", "Nmap", "nmap.exe"),
        ])
    elif t in ("nuclei", "nuclei.exe"):
        candidates.extend([
            os.path.join(pf, "nuclei", "nuclei.exe"),
            os.path.join(pf86, "nuclei", "nuclei.exe"),
            os.path.join(local, "Programs", "nuclei", "nuclei.exe"),
            os.path.join(local, "Programs", "Nuclei", "nuclei.exe"),
        ])

    candidates.extend([
        os.path.join(choco, "bin", exe) if choco else "",
        os.path.join(programdata, "chocolatey", "bin", exe),
        os.path.join(user, "scoop", "shims", exe),
        os.path.join(user, "scoop", "apps", t.replace(".exe", ""), "current", exe),
    ])

    return _expand_candidate_paths(candidates)

def _normalize_location(value: object) -> str:
    s = str(value or "").strip().lower()
    if s in ("server", "srv", "local", "localhost", "сервер"):
        return "server"
    if s in ("attacker", "client", "atk", "att", "атакующий", "клиент"):
        return "attacker"
    return s or "unknown"

def _location_label(norm_location: str) -> str:
    if norm_location == "server":
        return "Сервер"
    if norm_location == "attacker":
        return "Атакующий"
    return norm_location

def _resolve_nuclei_templates_dir() -> str:
    env_keys = (
        "BOS_NUCLEI_TEMPLATES_DIR",
        "NUCLEI_TEMPLATES_DIR",
    )
    env_candidates: list[str] = []
    for k in env_keys:
        v = str(os.environ.get(k, "") or "").strip()
        if v:
            env_candidates.append(v)

    base_dir = bundle_resources_root()
    tr = tools_dir()
    user = os.environ.get("USERPROFILE", "")
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")

    candidates = _expand_candidate_paths([
        *env_candidates,
        os.path.join(tr, "nuclei-templates"),
        os.path.join(tr, "nuclei-templates", "nuclei-templates"),
        os.path.join(tr, "nuclei_templates"),
        os.path.join(tr, "templates"),
        os.path.join(tr, "nuclei", "nuclei-templates"),
        os.path.join(tr, "nuclei", "templates"),
        os.path.join(base_dir, "nuclei-templates"),
        os.path.join(base_dir, "templates"),
        os.path.join(user, "nuclei-templates"),
        os.path.join(user, ".nuclei", "templates"),
        os.path.join(local, "nuclei-templates"),
        os.path.join(local, "nuclei-templates", "nuclei-templates"),
        os.path.join(local, "nuclei", "templates"),
        os.path.join(roaming, "nuclei-templates"),
        os.path.join(roaming, "nuclei", "templates"),
        os.path.join(local, "nuclei-templates", "nuclei-templates"),
    ])

    for root in candidates:
        if not root or not os.path.isdir(root):
            continue
        cves_dir = os.path.join(root, "cves")
        http_dir = os.path.join(root, "http")
        network_dir = os.path.join(root, "network")
        if os.path.isdir(cves_dir):
            return cves_dir
        if os.path.isdir(http_dir) or os.path.isdir(network_dir):
            return root
        try:
            for f in os.listdir(root):
                if f.endswith((".yaml", ".yml")):
                    return root
        except Exception:
            continue
    return ""


def _try_update_nuclei_templates(nuclei_path: str, install_dir: str, timeout_sec: int = 240) -> bool:
    p = str(nuclei_path or "").strip()
    if not p:
        return False
    install_dir = os.path.abspath(os.path.expandvars(os.path.expanduser(str(install_dir or "").strip())))
    if not install_dir:
        return False
    try:
        os.makedirs(install_dir, exist_ok=True)
    except Exception:
        return False

    cmd = [p, "-v", "-ut", "-ud", install_dir]
    try:
        logger.info(f"[NUCLEI] Шаблоны не найдены. Пробуем установить/обновить nuclei-templates в: {install_dir}")
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30, int(timeout_sec)),
            cwd=os.path.dirname(os.path.abspath(p)) if os.path.isfile(p) else None,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        if out:
            logger.debug(f"[NUCLEI] update stdout: {out[:4000]}")
        if err:
            logger.debug(f"[NUCLEI] update stderr: {err[:4000]}")

        resolved_after = _resolve_nuclei_templates_dir()
        if resolved_after:
            logger.info(f"[NUCLEI] ✅ nuclei-templates доступны: {resolved_after}")
            return True

        if r.returncode != 0:
            logger.warning(f"[NUCLEI] ❌ Не удалось обновить nuclei-templates (код {r.returncode})")
        else:
            logger.warning("[NUCLEI] ❌ Обновление завершилось, но шаблоны так и не появились (возможно нет доступа к сети)")
        return False
    except Exception as e:
        logger.warning(f"[NUCLEI] ❌ Ошибка обновления nuclei-templates: {e}")
        return False


def _resolve_nmap_datadir(nmap_exe_path: str) -> str:
    if not isinstance(nmap_exe_path, str) or not nmap_exe_path:
        return ""
    base = os.path.dirname(os.path.abspath(nmap_exe_path)) if os.path.isfile(nmap_exe_path) else ""
    candidates = [base]
    if base:
        candidates.extend([
            os.path.join(base, "share", "nmap"),
            os.path.join(base, "..", "share", "nmap"),
            os.path.join(base, "..", "..", "share", "nmap"),
        ])
    for root in candidates:
        if not root or not os.path.isdir(root):
            continue
        scripts_dir = os.path.join(root, "scripts")
        probes = os.path.join(root, "nmap-service-probes")
        if os.path.isdir(scripts_dir) and os.path.isfile(probes):
            return os.path.abspath(root)
    return ""


class NmapScanner:
    """Интеграция с Nmap для сканирования уязвимостей."""

    def __init__(self, target: str, settings: Optional[Dict] = None, scanner_location: str = "unknown"):
        self.target = target
        self.settings = settings or {}
        self.scanner_location = _normalize_location(scanner_location)
        self.nmap_path = self._find_nmap()
    
    def _find_nmap(self) -> str:
        """Поиск исполняемого файла Nmap."""
        base_dir = bundle_resources_root()
        tools_root = tools_dir()

        possible_paths = [
            os.path.join(tools_root, "nmap.exe"),
            os.path.join(tools_root, "nmap", "nmap.exe"),
            *_windows_tool_candidates("nmap"),
            "nmap",
        ]
        
        logger.info(f"[NMAP] Базовая директория: {base_dir}")
        logger.info(f"[NMAP] Поиск Nmap в {len(possible_paths)} локациях...")
        
        for path in possible_paths:
            logger.debug(f"[NMAP] Проверка: {path}")
            if os.path.isfile(path):
                logger.info(f"[NMAP] ✅ Найден по пути: {path}")
                return path
            if path in ("nmap", "nmap.exe"):
                resolved = shutil.which(path) or ""
                if resolved and os.path.isfile(resolved):
                    logger.info(f"[NMAP] ✅ В PATH: {resolved}")
                    return resolved
                try:
                    r = subprocess.run(
                        [path, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    )
                    if r.returncode == 0:
                        logger.info(f"[NMAP] ✅ В PATH: {path}")
                        return path
                except Exception:
                    pass
        
        logger.warning(f"[NMAP] ❌ Исполняемый файл Nmap не найден. Проверенные пути: {possible_paths}")
        return "nmap"  # Fallback на PATH

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
            f"-{self.settings.get('timing', 'T4')}",
            "--min-rate", str(self.settings.get("min_rate", 250)),
            "--min-parallelism", str(self.settings.get("threads", 10)),
            "--max-retries", str(self.settings.get("max_retries", 2)),
            "--script-timeout", f"{self.settings.get('script_timeout', 120)}s",
            "-p", port_list,
            self.target,
            "-oX", "-"
        ]

        try:
            logger.info(f"Запуск Nmap для сканирования уязвимостей: {' '.join(cmd)}")
            env = os.environ.copy()
            datadir = _resolve_nmap_datadir(self.nmap_path)
            if datadir:
                env["NMAPDIR"] = datadir
            cwd = os.path.dirname(os.path.abspath(self.nmap_path)) if os.path.isfile(self.nmap_path) else None
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(self.settings.get("process_timeout", 240)),
                cwd=cwd,
                env=env,
            )

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
                                "cwe_id": "",
                                "port": int(port_id),
                                "protocol": protocol,
                                "service": self._get_service_from_port(port),
                                "severity": self._determine_severity(script_id),
                                "description": script_output[:200],
                                "source": "Nmap",
                                "script": script_id,
                                "scanner_location": self.scanner_location,
                                "scanner_label": _location_label(self.scanner_location),
                                "target": ip_address,
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

    def __init__(self, target: str, settings: Optional[Dict] = None, scanner_location: str = "unknown"):
        self.target = target
        self.settings = settings or {}
        self.scanner_location = _normalize_location(scanner_location)
        self.nuclei_path = self._find_nuclei()
    
    def _find_nuclei(self) -> str:
        """Поиск исполняемого файла Nuclei."""
        base_dir = bundle_resources_root()
        tools_root = tools_dir()

        possible_paths = [
            os.path.join(tools_root, "nuclei.exe"),
            os.path.join(tools_root, "nuclei", "nuclei.exe"),
            *_windows_tool_candidates("nuclei"),
            "nuclei",
        ]
        
        logger.info(f"[NUCLEI] Базовая директория: {base_dir}")
        logger.info(f"[NUCLEI] Поиск Nuclei в {len(possible_paths)} локациях...")
        
        for path in possible_paths:
            logger.debug(f"[NUCLEI] Проверка: {path}")
            if os.path.isfile(path):
                logger.info(f"[NUCLEI] ✅ Найден по пути: {path}")
                return path
            if path in ("nuclei", "nuclei.exe"):
                resolved = shutil.which(path) or ""
                if resolved and os.path.isfile(resolved):
                    logger.info(f"[NUCLEI] ✅ В PATH: {resolved}")
                    return resolved
                try:
                    r = subprocess.run(
                        [path, "-version"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    )
                    if r.returncode == 0:
                        logger.info(f"[NUCLEI] ✅ В PATH: {path}")
                        return path
                except Exception:
                    pass
        
        logger.warning(f"[NUCLEI] ❌ Исполняемый файл Nuclei не найден. Проверенные пути: {possible_paths}")
        return "nuclei"  # Fallback на PATH

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
        templates_dir = _resolve_nuclei_templates_dir()
        
        # Если шаблоны не найдены, пробуем использовать пути по умолчанию или пропускаем сканирование
        if not templates_dir:
            install_dir = os.path.join(tools_dir(), "nuclei-templates")
            if _try_update_nuclei_templates(self.nuclei_path, install_dir):
                templates_dir = _resolve_nuclei_templates_dir()
            if not templates_dir:
                logger.warning(
                    "[NUCLEI] Директория с шаблонами не найдена или пуста. Сканирование отменено. "
                    "Укажите путь через BOS_NUCLEI_TEMPLATES_DIR или установите шаблоны в tools/nuclei-templates."
                )
                return vulnerabilities
        
        cmd = [
            self.nuclei_path,
            "-u", target_url,
            "-json",
            "-duc",  # Disable update checks
            "-ni",   # Disable nuclei-ignore file
            "-c", str(self.settings.get("concurrency", 40)),
            "-timeout", str(self.settings.get("timeout", 4)),
            "-retries", str(self.settings.get("retries", 1)),
            "-mhe", str(self.settings.get("max_host_errors", 100000)),
            "-t", templates_dir,
        ]

        try:
            logger.info(f"Запуск Nuclei для сканирования уязвимостей: {' '.join(cmd)}")
            cwd = os.path.dirname(os.path.abspath(self.nuclei_path)) if os.path.isfile(self.nuclei_path) else None
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(self.settings.get("process_timeout", 300)),
                cwd=cwd,
            )

            if result.returncode == 0 and result.stdout:
                vulnerabilities = self._parse_nuclei_json(result.stdout)
                logger.info(f"Nuclei нашел {len(vulnerabilities)} уязвимостей")
            elif result.returncode != 0:
                logger.warning(f"Nuclei завершился с кодом {result.returncode}. stderr: {result.stderr}")
            else:
                logger.info("Nuclei завершил работу без результатов (уязвимости не найдены)")

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

                    info = result.get("info") or {}
                    if isinstance(info, list) and info:
                        info = info[0] if isinstance(info[0], dict) else {}
                    if not isinstance(info, dict):
                        info = {}

                    classification = info.get("classification") or {}
                    if not isinstance(classification, dict):
                        classification = {}

                    cve_raw = classification.get("cve-id", "")
                    if isinstance(cve_raw, list):
                        cve_id = str((cve_raw[0] if cve_raw else "") or "").strip()
                    else:
                        cve_id = str(cve_raw or "").strip()

                    cwe_raw = classification.get("cwe-id", "")
                    cwe_id = ""
                    if isinstance(cwe_raw, list):
                        cwe_id = str((cwe_raw[0] if cwe_raw else "") or "").strip()
                    else:
                        cwe_id = str(cwe_raw or "").strip()

                    port = None
                    port_raw = result.get("port", None)
                    if isinstance(port_raw, int):
                        port = port_raw
                    else:
                        try:
                            if port_raw is not None and str(port_raw).isdigit():
                                port = int(str(port_raw))
                        except Exception:
                            port = None
                    if port is None:
                        host = str(result.get("host", "") or "")
                        if ":" in host:
                            tail = host.rsplit(":", 1)[-1]
                            if tail.isdigit():
                                port = int(tail)

                    # Извлекаем информацию об уязвимости
                    vulnerability = {
                        "cve_id": cve_id,
                        "cwe_id": cwe_id,
                        "port": port if port is not None else 0,
                        "protocol": "tcp",
                        "service": result.get("service", {}).get("name", "unknown"),
                        "severity": str(info.get("severity", "medium")).upper(),
                        "description": str(info.get("name", "Unknown vulnerability")),
                        "source": "Nuclei",
                        "template": result.get("template-id", ""),
                        "scanner_location": self.scanner_location,
                        "scanner_label": _location_label(self.scanner_location),
                        "target": str(result.get("host", "") or self.target),
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

    def __init__(self, target: str, settings: Optional[Dict] = None, scanner_location: str = "unknown"):
        self.target = target
        settings = settings or {}
        self.scanner_location = _normalize_location(scanner_location)
        self.nmap_scanner = NmapScanner(target, settings=settings.get("nmap"), scanner_location=self.scanner_location)
        self.nuclei_scanner = NucleiScanner(target, settings=settings.get("nuclei"), scanner_location=self.scanner_location)

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
