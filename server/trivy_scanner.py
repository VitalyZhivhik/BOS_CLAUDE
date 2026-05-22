"""
Модуль для работы с Trivy (от Aqua Security).
Сканирует установленное ПО на сервере и находит CVE, CWE, CAPEC.
Используется для улучшения корреляции атак.
"""

import os
import sys
import glob
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.logger import get_server_logger
from common.bundle_paths import application_base_dir, bundle_resources_root

logger = get_server_logger()


@dataclass
class TrivyVulnerability:
    """Представляет одну уязвимость из Trivy."""
    vuln_id: str  # CVE-ID или BDU-ID
    pkg_name: str  # Название пакета/ПО
    installed_version: str  # Установленная версия
    fixed_version: str  # Версия с исправлением (если есть)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    title: str  # Заголовок уязвимости
    description: str  # Описание
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    vendor_severity: str = ""  # vendor-specific severity
    status: str = ""  # статус уязвимости


@dataclass
class TrivyScanResult:
    """Результат сканирования Trivy."""
    timestamp: str
    hostname: str
    os_name: str
    os_version: str
    total_vulns: int
    vulnerabilities: List[TrivyVulnerability] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    raw_output: str = ""  # Сырой JSON от Trivy
    error: str = ""  # Ошибка если была


class TrivyScanner:
    """Сканер уязвимостей на основе Trivy."""

    def __init__(self, trivy_path: str = "", progress_callback=None):
        self.trivy_path = trivy_path or self._find_trivy()
        self.progress_callback = progress_callback or (lambda percent, text: None)
        self.last_result: Optional[TrivyScanResult] = None

    def _find_trivy(self) -> str:
        """Поиск исполняемого файла Trivy."""
        base_dir = bundle_resources_root()
        tools_root = os.path.join(base_dir, "tools")

        possible_paths = [
            os.path.join(tools_root, "trivy_0.69.3_windows-64bit", "trivy.exe"),
            os.path.join(tools_root, "trivy.exe"),
            os.path.join(tools_root, "trivy", "trivy.exe"),
        ]

        logger.info(f"[TRIVY] Базовая директория ресурсов: {base_dir}")
        logger.info(f"[TRIVY] Поиск Trivy в {len(possible_paths)}+ локациях...")

        for path in possible_paths:
            logger.debug(f"[TRIVY] Проверка: {path}")
            if os.path.isfile(path):
                logger.info(f"[TRIVY] ✅ Найден по пути: {path}")
                return path

        if os.path.isdir(tools_root):
            for path in sorted(glob.glob(os.path.join(tools_root, "**", "trivy.exe"), recursive=True)):
                if os.path.isfile(path):
                    logger.info(f"[TRIVY] ✅ Найден (glob): {path}")
                    return path

        for path in ("trivy.exe", "trivy"):
            logger.debug(f"[TRIVY] Проверка PATH: {path}")
            try:
                r = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                if r.returncode == 0:
                    logger.info(f"[TRIVY] ✅ В PATH: {path}")
                    return path
            except Exception:
                continue

        logger.warning(
            f"[TRIVY] ❌ Исполняемый файл Trivy не найден. Проверенные пути: {possible_paths}"
        )
        return ""

    def is_available(self) -> bool:
        """Проверяет, доступен ли Trivy."""
        if not self.trivy_path:
            return False
        
        # Проверяем версию
        trivy_home = (
            os.path.dirname(os.path.abspath(self.trivy_path))
            if os.path.isfile(self.trivy_path)
            else ""
        )
        env = os.environ.copy()
        if trivy_home:
            env["PATH"] = trivy_home + os.pathsep + env.get("PATH", "")
        try:
            result = subprocess.run(
                [self.trivy_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=trivy_home or None,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            if result.returncode == 0:
                logger.info(f"[TRIVY] Версия: {result.stdout.strip()}")
                return True
            else:
                logger.warning(f"[TRIVY] Ошибка проверки версии: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"[TRIVY] Ошибка проверки доступности: {e}")
            return False

    def scan_local_system(self, security_checks: bool = True, scan_options: Dict[str, Any] = None) -> TrivyScanResult:
        """
        Анализирует установленное ПО и сопоставляет с CVE/CWE/CAPEC.
        НЕ ищет уязвимости, только собирает информацию об ПО.
        
        Args:
            security_checks: Не используется (для обратной совместимости)
            
        Returns:
            TrivyScanResult с информацией об ПО и сопоставлением с CVE/CWE/CAPEC
        """
        start_time = datetime.now()
        self.progress_callback(5, "Инициализация Trivy...")
        
        scan_options = scan_options or {}
        timeout_minutes = max(1, min(int(scan_options.get("timeout_minutes", 15)), 120))
        scan_threads = max(1, min(int(scan_options.get("threads", 10)), 32))
        result = TrivyScanResult(
            timestamp=datetime.now().isoformat(),
            hostname="",
            os_name="",
            os_version="",
            total_vulns=0,
        )

        if not self.trivy_path or not os.path.exists(self.trivy_path):
            error_msg = f"Trivy не найден по пути: {self.trivy_path}"
            logger.error(f"[TRIVY] {error_msg}")
            result.error = error_msg
            return result

        logger.info("=" * 60)
        logger.info(" TRIVY: АНАЛИЗ УСТАНОВЛЕННОГО ПО И СОПОСТАВЛЕНИЕ С CVE/CWE/CAPEC")
        logger.info("=" * 60)
        logger.info(f"  Путь к Trivy: {self.trivy_path}")
        logger.info(f"  Режим: Анализ ПО (без поиска уязвимостей)")

        try:
            # Создаём временный файл для JSON-вывода
            fd, output_path = tempfile.mkstemp(suffix=".json")
            os.close(fd)

            self.progress_callback(10, "Запуск анализа ПО через Trivy...")
            logger.info(f"  Вывод результатов в: {output_path}")

            target_path = scan_options.get("target_path", "")
            if not isinstance(target_path, str) or not target_path.strip():
                target_path = r"C:\\"
            target_path = os.path.abspath(target_path)

            cache_dir = scan_options.get("cache_dir", "")
            if not isinstance(cache_dir, str) or not cache_dir.strip():
                cache_dir = os.path.join(tempfile.gettempdir(), "trivy_cache")
            cache_dir = os.path.abspath(cache_dir)

            cmd = [
                self.trivy_path,
                "fs",  # Filesystem scan
                target_path,
                "--format", "json",
                "--output", output_path,
                "--scanners", "vuln",
                "--exit-code", "0",
                "--timeout", f"{timeout_minutes}m",
                "--parallel", str(scan_threads),
                "--cache-dir", cache_dir,
                "--pkg-types", "os,library",
            ]

            logger.info(f"  Цель сканирования: {target_path}")
            logger.info(f"  Cache dir: {cache_dir}")
            logger.info(f"  Команда: {' '.join(cmd)}")
            self.progress_callback(15, "Trivy анализирует установленное ПО...")

            # Запускаем процесс
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            trivy_home = (
                os.path.dirname(os.path.abspath(self.trivy_path))
                if self.trivy_path and os.path.isfile(self.trivy_path)
                else ""
            )
            env = os.environ.copy()
            if trivy_home:
                env["PATH"] = trivy_home + os.pathsep + env.get("PATH", "")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                cwd=trivy_home or None,
                env=env,
            )

            # Читаем вывод для логирования прогресса
            output_lines = []
            import re
            last_progress_update = 0
            
            for line in process.stdout:
                line = line.strip()
                if line:
                    output_lines.append(line)
                    logger.debug(f"[TRIVY-OUT] {line}")
                    
                    # Обновляем прогресс на основе ключевых слов
                    current_time = datetime.now().timestamp()
                    if "Detected OS" in line and current_time - last_progress_update > 2:
                        self.progress_callback(25, f"Trivy обнаружил ОС")
                        last_progress_update = current_time
                    elif "Detecting library vulnerabilities" in line and current_time - last_progress_update > 2:
                        self.progress_callback(40, "Trivy сопоставляет ПО с CVE/CWE/CAPEC...")
                        last_progress_update = current_time
                    elif "Vulnerability scanning" in line and current_time - last_progress_update > 2:
                        self.progress_callback(60, "Trivy анализирует CVE...")
                        last_progress_update = current_time
                    elif "Processed" in line and "files" in line and current_time - last_progress_update > 2:
                        self.progress_callback(75, "Обработка файлов...")
                        last_progress_update = current_time

            process.wait()
            return_code = process.returncode
            
            elapsed_wait = (datetime.now() - start_time).total_seconds()
            logger.info(f"  [TRIVY] Процесс завершилось через {elapsed_wait:.2f} сек (код: {return_code})")

            self.progress_callback(85, "Trivy завершил сканирование, обработка результатов...")
            logger.info(f"  Код возврата: {return_code}")
            logger.info(f"  Вывод Trivy ({len(output_lines)} строк)")

            # Если результат не сформирован (часто из-за заблокированных файлов на Windows),
            # повторяем скан с динамическим исключением проблемного файла.
            if (return_code != 0) and (not (os.path.exists(output_path) and os.path.getsize(output_path) > 0)):
                excluded_files: list[str] = []
                max_attempts = 5
                for attempt in range(1, max_attempts + 1):
                    locked_file = self._extract_locked_file_path(output_lines)
                    if not locked_file or locked_file in excluded_files:
                        break
                    excluded_files.append(locked_file)
                    logger.warning(f"[TRIVY] Обнаружен заблокированный файл: {locked_file}. Повторяем скан с исключением. (попытка {attempt}/{max_attempts})")

                    retry_cmd = list(cmd)
                    for excluded in excluded_files:
                        retry_cmd.extend(["--skip-files", excluded])

                    process = subprocess.Popen(
                        retry_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                        universal_newlines=True,
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                        cwd=trivy_home or None,
                        env=env,
                    )
                    output_lines = []
                    last_progress_update = 0
                    for raw in process.stdout:
                        line = (raw or "").strip()
                        if not line:
                            continue
                        output_lines.append(line)
                        logger.debug(f"[TRIVY-RETRY] {line}")
                        current_time = datetime.now().timestamp()
                        if "Detected OS" in line and current_time - last_progress_update > 2:
                            self.progress_callback(25, "Trivy обнаружил ОС")
                            last_progress_update = current_time
                        elif "Detecting library vulnerabilities" in line and current_time - last_progress_update > 2:
                            self.progress_callback(40, "Trivy сопоставляет ПО с CVE/CWE/CAPEC...")
                            last_progress_update = current_time
                        elif "Vulnerability scanning" in line and current_time - last_progress_update > 2:
                            self.progress_callback(60, "Trivy анализирует CVE...")
                            last_progress_update = current_time
                        elif "Processed" in line and "files" in line and current_time - last_progress_update > 2:
                            self.progress_callback(75, "Обработка файлов...")
                            last_progress_update = current_time
                    process.wait()
                    return_code = process.returncode
                    logger.info(f"[TRIVY] Повтор завершён с кодом: {return_code}")

                    if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                        break

                if not (os.path.exists(output_path) and os.path.getsize(output_path) > 0):
                    out = "\n".join(output_lines).lower() if output_lines else ""
                    if (
                        "failed to download" in out
                        or "unable to download" in out
                        or "db error" in out
                        or "no such host" in out
                        or "connection refused" in out
                    ):
                        logger.warning("[TRIVY] Похоже, недоступно обновление базы. Повторяем запуск с --skip-db-update (если DB уже кэширована).")
                        retry_cmd = list(cmd)
                        if "--skip-db-update" not in retry_cmd:
                            retry_cmd.append("--skip-db-update")
                        process = subprocess.Popen(
                            retry_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            bufsize=1,
                            universal_newlines=True,
                            startupinfo=startupinfo,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                            cwd=trivy_home or None,
                            env=env,
                        )
                        output_lines = []
                        for raw in process.stdout:
                            line = (raw or "").strip()
                            if line:
                                output_lines.append(line)
                                logger.debug(f"[TRIVY-RETRY] {line}")
                        process.wait()
                        return_code = process.returncode
                        logger.info(f"[TRIVY] Повтор (skip DB update) завершён с кодом: {return_code}")

            # Читаем JSON результат
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path, 'r', encoding='utf-8') as f:
                    raw_json = json.load(f)
                    result.raw_output = json.dumps(raw_json, ensure_ascii=False, indent=2)
                    
                    # Парсим результаты
                    self._parse_trivy_output(raw_json, result)
            else:
                logger.warning("[TRIVY] Файл результатов пуст или не создан")
                reason = self._extract_failure_reason(output_lines, return_code)
                result.error = reason

            # Удаляем временный файл
            try:
                os.remove(output_path)
            except:
                pass

            # Считаем время
            elapsed = (datetime.now() - start_time).total_seconds()
            result.scan_duration_seconds = elapsed

            self.progress_callback(90, f"Обработка завершена. Найдено {result.total_vulns} уязвимостей")
            logger.info(f"  Сканирование завершено за {elapsed:.2f} сек")
            logger.info(f"  Найдено уязвимостей: {result.total_vulns}")
            logger.info(f"  Критических: {sum(1 for v in result.vulnerabilities if v.severity == 'CRITICAL')}")
            logger.info(f"  Высоких: {sum(1 for v in result.vulnerabilities if v.severity == 'HIGH')}")

            self.progress_callback(100, f"Trivy сканирование завершено! Найдено {result.total_vulns} уязвимостей")

        except subprocess.TimeoutExpired:
            error_msg = "Trivy превысил таймаут выполнения (10 минут)"
            logger.error(f"[TRIVY] {error_msg}")
            result.error = error_msg
            self.progress_callback(100, "Ошибка: таймаут Trivy")
        except Exception as e:
            error_msg = f"Ошибка при сканировании Trivy: {e}"
            logger.error(f"[TRIVY] {error_msg}", exc_info=True)
            result.error = error_msg
            self.progress_callback(100, f"Ошибка: {str(e)}")

        self.last_result = result
        return result

    def _extract_failure_reason(self, output_lines: List[str], return_code: int) -> str:
        """Возвращает человекочитаемую причину сбоя Trivy."""
        if return_code != 0:
            tail = " | ".join(output_lines[-3:]) if output_lines else "нет вывода процесса"
            return f"Trivy завершился с кодом {return_code}. Детали: {tail}"

        if output_lines:
            tail = " | ".join(output_lines[-3:])
            return f"Trivy не сформировал JSON-отчёт. Последние сообщения: {tail}"

        return "Trivy не сформировал JSON-отчёт (пустой вывод процесса)"

    def _extract_locked_file_path(self, output_lines: List[str]) -> str:
        """Возвращает путь к файлу, который Trivy не смог открыть (если есть)."""
        patterns = [
            r"unable to open\s+([A-Za-z]:\\.+)$",
            r"file_path=\"([A-Za-z]:\\[^\"]+)\"",
            r"open\s+([A-Za-z]:\\.+?)(?::\s+|$)",
            r"cannot access the file\s+\"([A-Za-z]:\\.+?)\"",
        ]
        for line in reversed(output_lines):
            low = line.lower()
            if (
                "cannot access the file" not in low
                and "unable to open" not in low
                and "access is denied" not in low
                and "permission denied" not in low
            ):
                continue
            for pattern in patterns:
                m = re.search(pattern, line, re.IGNORECASE)
                if m:
                    return m.group(1).strip().rstrip(".")
        return ""

    def _parse_trivy_output(self, raw_json: Dict[str, Any], result: TrivyScanResult):
        """Парсит JSON-вывод Trivy в структурированные данные."""
        try:
            # Общая информация
            metadata = raw_json.get("Metadata", {})
            result.os_name = metadata.get("OS", {}).get("Family", "Unknown")
            result.os_version = metadata.get("OS", {}).get("Name", "Unknown")
            result.hostname = raw_json.get("Results", [{}])[0].get("Target", "Unknown")

            vulnerabilities = []
            results_list = raw_json.get("Results", [])

            for res in results_list:
                target = res.get("Target", "")
                vulnerabilities_list = res.get("Vulnerabilities", [])

                if not vulnerabilities_list:
                    continue

                logger.debug(f"[TRIVY-PARSE] Цель: {target}, уязвимостей: {len(vulnerabilities_list)}")

                for vuln in vulnerabilities_list:
                    trivy_vuln = TrivyVulnerability(
                        vuln_id=vuln.get("VulnerabilityID", ""),
                        pkg_name=vuln.get("PkgName", ""),
                        installed_version=vuln.get("InstalledVersion", ""),
                        fixed_version=vuln.get("FixedVersion", ""),
                        severity=vuln.get("Severity", "UNKNOWN"),
                        title=vuln.get("Title", ""),
                        description=vuln.get("Description", ""),
                        references=vuln.get("References", []),
                        cwe_ids=vuln.get("CweIDs", []),
                        capec_ids=vuln.get("CapecIDs", []),
                        vendor_severity=vuln.get("VendorSeverity", ""),
                        status=vuln.get("Status", ""),
                    )

                    vulnerabilities.append(trivy_vuln)

            result.vulnerabilities = vulnerabilities
            result.total_vulns = len(vulnerabilities)

            logger.info(f"[TRIVY-PARSE] Обработано {result.total_vulns} уязвимостей")

        except Exception as e:
            logger.error(f"[TRIVY-PARSE] Ошибка парсинга: {e}", exc_info=True)

    def get_vulnerabilities_by_package(self) -> Dict[str, List[TrivyVulnerability]]:
        """Группирует уязвимости по пакетам/ПО."""
        if not self.last_result:
            return {}

        grouped = {}
        for vuln in self.last_result.vulnerabilities:
            pkg = vuln.pkg_name
            if pkg not in grouped:
                grouped[pkg] = []
            grouped[pkg].append(vuln)

        return grouped

    def get_vulnerabilities_by_severity(self) -> Dict[str, List[TrivyVulnerability]]:
        """Группирует уязвимости по серьёзности."""
        if not self.last_result:
            return {}

        grouped = {}
        for vuln in self.last_result.vulnerabilities:
            sev = vuln.severity
            if sev not in grouped:
                grouped[sev] = []
            grouped[sev].append(vuln)

        return grouped

    def get_summary(self) -> Dict[str, Any]:
        """Возвращает краткую сводку по результатам."""
        if not self.last_result:
            return {"error": "Сканирование ещё не выполнено"}

        by_severity = self.get_vulnerabilities_by_severity()
        by_package = self.get_vulnerabilities_by_package()

        return {
            "timestamp": self.last_result.timestamp,
            "hostname": self.last_result.hostname,
            "os": f"{self.last_result.os_name} {self.last_result.os_version}",
            "total_vulns": self.last_result.total_vulns,
            "critical": len(by_severity.get("CRITICAL", [])),
            "high": len(by_severity.get("HIGH", [])),
            "medium": len(by_severity.get("MEDIUM", [])),
            "low": len(by_severity.get("LOW", [])),
            "unknown": len(by_severity.get("UNKNOWN", [])),
            "affected_packages": len(by_package),
            "scan_duration": f"{self.last_result.scan_duration_seconds:.2f} сек",
            "error": self.last_result.error if self.last_result.error else None,
        }

    def export_to_json(self, output_path: str) -> bool:
        """Экспортирует результаты в JSON файл."""
        if not self.last_result:
            logger.warning("[TRIVY] Нет результатов для экспорта")
            return False

        try:
            output_data = {
                "scan_info": {
                    "timestamp": self.last_result.timestamp,
                    "scanner": f"Trivy ({self.trivy_path})",
                    "hostname": self.last_result.hostname,
                    "os": f"{self.last_result.os_name} {self.last_result.os_version}",
                    "duration": self.last_result.scan_duration_seconds,
                },
                "summary": self.get_summary(),
                "vulnerabilities": [
                    {
                        "vuln_id": v.vuln_id,
                        "pkg_name": v.pkg_name,
                        "installed_version": v.installed_version,
                        "fixed_version": v.fixed_version,
                        "severity": v.severity,
                        "title": v.title,
                        "description": v.description[:500],  # Обрезаем длинные описания
                        "cwe_ids": v.cwe_ids,
                        "capec_ids": v.capec_ids,
                        "references": v.references[:5],  # Первые 5 ссылок
                    }
                    for v in self.last_result.vulnerabilities
                ]
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2)

            logger.info(f"[TRIVY] Результаты экспортированы в: {output_path}")
            return True

        except Exception as e:
            logger.error(f"[TRIVY] Ошибка экспорта: {e}", exc_info=True)
            return False
