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

    def _exclusions_file_path(self) -> str:
        data_dir = os.path.join(application_base_dir(), "data")
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, "trivy_exclusions.json")

    def _load_exclusions(self) -> Dict[str, Any]:
        path = self._exclusions_file_path()
        data: Dict[str, Any] = {"version": 1, "skip_files_error": [], "skip_files_large": [], "updated_at": ""}
        if not os.path.exists(path):
            return data
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                data.update(raw)
        except Exception:
            return data
        for k in ("skip_files_error", "skip_files_large"):
            v = data.get(k)
            if not isinstance(v, list):
                data[k] = []
            else:
                data[k] = [str(x) for x in v if x]
        if not isinstance(data.get("updated_at"), str):
            data["updated_at"] = ""
        if not isinstance(data.get("version"), int):
            data["version"] = 1
        return data

    def _save_exclusions(self, data: Dict[str, Any]) -> None:
        path = self._exclusions_file_path()
        data = dict(data or {})
        data["version"] = int(data.get("version", 1) or 1)
        data["updated_at"] = datetime.now().isoformat()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _normalize_path_for_exclusion(self, path: str, target_root: str = "") -> str:
        p = (path or "").strip().strip('"').strip("'")
        if not p:
            return ""
        p = p.replace("/", "\\")
        if re.match(r"^[A-Za-z]:\\", p) or p.startswith("\\\\"):
            return os.path.normpath(p)
        if target_root:
            return os.path.normpath(os.path.join(target_root, p))
        return p

    def _merge_exclusions(self, existing: List[str], new_items: List[str], limit: int = 2000) -> List[str]:
        merged = list(existing or [])
        merged.extend(new_items or [])
        merged = [x for x in (self._normalize_path_for_exclusion(p) for p in merged) if x]
        merged = list(dict.fromkeys(merged))
        if len(merged) > limit:
            merged = merged[-limit:]
        return merged

    def _extract_secret_large_file_path(self, line: str, target_root: str = "") -> str:
        if "The size of the scanned file is too large" not in (line or ""):
            return ""
        m = re.search(r'file_path="([^"]+)"', line)
        if not m:
            return ""
        return self._normalize_path_for_exclusion(m.group(1), target_root=target_root)

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
        use_saved_exclusions = bool(scan_options.get("use_saved_exclusions", True))
        use_saved_large_exclusions = bool(scan_options.get("use_saved_large_exclusions", False))
        persist_exclusions = bool(scan_options.get("persist_exclusions", True))
        persist_large_exclusions = bool(scan_options.get("persist_large_exclusions", True))
        timeout_minutes = max(0, min(int(scan_options.get("timeout_minutes", 15)), 720))
        scan_threads = max(1, min(int(scan_options.get("threads", 5)), 128))
        severities = scan_options.get("severities", ["MEDIUM", "HIGH", "CRITICAL"])
        if isinstance(severities, str):
            severities = [x.strip().upper() for x in severities.split(",") if x.strip()]
        scanners = scan_options.get("scanners", ["vuln"])
        if isinstance(scanners, str):
            scanners = [x.strip() for x in scanners.split(",") if x.strip()]
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

            # Используем fs для сканирования установленного ПО
            # --security-checks vuln отключён - только анализ ПО
            # Исключаем шумные/проблемные системные пути.
            # Для не-системных дисков (например D:\) не добавляем пути с C:\, чтобы не плодить предупреждения Trivy.
            skip_dirs: List[str] = []
            skip_files: List[str] = []
            for custom_dir in scan_options.get("skip_dirs", []) if isinstance(scan_options.get("skip_dirs"), list) else []:
                if custom_dir and custom_dir not in skip_dirs:
                    skip_dirs.append(str(custom_dir))
            for custom_file in scan_options.get("skip_files", []) if isinstance(scan_options.get("skip_files"), list) else []:
                if custom_file and custom_file not in skip_files:
                    skip_files.append(str(custom_file))

            target_path = scan_options.get("target_path", "")
            if not isinstance(target_path, str) or not target_path.strip():
                candidates = [
                    os.environ.get("ProgramFiles", ""),
                    os.environ.get("ProgramFiles(x86)", ""),
                    r"C:\Program Files",
                    r"C:\Program Files (x86)",
                    r"C:\\",
                ]
                target_path = next((p for p in candidates if p and os.path.isdir(p)), r"C:\\")
            target_path = os.path.abspath(target_path)
            target_drive, _ = os.path.splitdrive(target_path)
            target_drive = target_drive or "C:"
            skip_dirs.extend([
                os.path.join(target_drive + "\\", "$Recycle.Bin"),
                os.path.join(target_drive + "\\", "System Volume Information"),
            ])
            if target_drive.upper() == "C:":
                skip_dirs.append(os.path.join(target_drive + "\\", "Windows", "Temp"))
                skip_files.extend([
                    os.path.join(target_drive + "\\", "DumpStack.log.tmp"),
                    os.path.join(target_drive + "\\", "pagefile.sys"),
                    os.path.join(target_drive + "\\", "swapfile.sys"),
                    os.path.join(target_drive + "\\", "hiberfil.sys"),
                ])

            skip_dir_globs = scan_options.get("skip_dir_globs", None)
            if isinstance(skip_dir_globs, str):
                skip_dir_globs = [p.strip() for p in skip_dir_globs.split(";") if p.strip()]
            if not isinstance(skip_dir_globs, list):
                skip_dir_globs = [r"Qt\**\Src"]

            resolved = []
            for g in skip_dir_globs:
                if not g:
                    continue
                g = str(g).strip().strip('"').strip("'")
                if not g:
                    continue
                if re.match(r"^[A-Za-z]:\\", g) or g.startswith("\\\\"):
                    pattern_path = g
                else:
                    pattern_path = os.path.join(target_path, g)
                try:
                    for m in glob.glob(pattern_path, recursive=True):
                        if m and os.path.isdir(m):
                            resolved.append(os.path.abspath(m))
                except Exception:
                    continue
            if resolved:
                resolved = sorted(set(resolved))
                if len(resolved) > 200:
                    resolved = resolved[:200]
                for d in resolved:
                    if d not in skip_dirs:
                        skip_dirs.append(d)

            cache_dir = scan_options.get("cache_dir", "")
            if not isinstance(cache_dir, str) or not cache_dir.strip():
                data_cache_dir = os.path.join(application_base_dir(), "data", "trivy_cache")
                tools_cache_dir = os.path.join(bundle_resources_root(), "tools", "trivy_cache")
                data_has_db = os.path.isfile(os.path.join(data_cache_dir, "db", "trivy.db"))
                tools_has_db = os.path.isfile(os.path.join(tools_cache_dir, "db", "trivy.db"))
                if data_has_db:
                    cache_dir = data_cache_dir
                elif tools_has_db:
                    cache_dir = tools_cache_dir
                elif os.path.isdir(data_cache_dir):
                    cache_dir = data_cache_dir
                elif os.path.isdir(tools_cache_dir):
                    cache_dir = tools_cache_dir
                else:
                    cache_dir = data_cache_dir
            cache_dir = os.path.abspath(cache_dir)
            os.makedirs(cache_dir, exist_ok=True)

            skip_db_update = scan_options.get("skip_db_update", None)
            if not isinstance(skip_db_update, bool):
                skip_db_update = True

            db_repos = scan_options.get("db_repositories", None)
            if not isinstance(db_repos, list) or not db_repos:
                db_repos = [
                    "ghcr.io/aquasecurity/trivy-db",
                    "public.ecr.aws/aquasecurity/trivy-db",
                    "mirror.gcr.io/aquasec/trivy-db",
                ]

            cmd = [
                self.trivy_path,
                "fs",  # Filesystem scan
                target_path,
                "--format", "json",
                "--output", output_path,
                "--scanners", ",".join(scanners) if scanners else "vuln",
                "--severity", ",".join(severities) if severities else "MEDIUM,HIGH,CRITICAL",
                "--exit-code", "0",
                "--parallel", str(scan_threads),
                "--cache-dir", cache_dir,
            ]
            if timeout_minutes > 0:
                cmd.extend(["--timeout", f"{timeout_minutes}m"])
            for repo in db_repos:
                if repo:
                    cmd.extend(["--db-repository", str(repo)])
            if skip_db_update:
                cmd.append("--skip-db-update")

            exclusions = self._load_exclusions() if use_saved_exclusions else {"skip_files_error": [], "skip_files_large": []}
            if use_saved_exclusions:
                saved_error_files = exclusions.get("skip_files_error", [])
                if isinstance(saved_error_files, list):
                    skip_files.extend(saved_error_files)
                if use_saved_large_exclusions:
                    saved_large_files = exclusions.get("skip_files_large", [])
                    if isinstance(saved_large_files, list):
                        skip_files.extend(saved_large_files)
            skip_files = list(dict.fromkeys([p for p in (self._normalize_path_for_exclusion(x, target_root=target_path) for x in skip_files) if p]))

            for skip_dir in skip_dirs:
                cmd.extend(["--skip-dirs", skip_dir])
            for skip_file in skip_files:
                cmd.extend(["--skip-files", skip_file])

            logger.info(f"  Цель сканирования: {target_path}")
            logger.info(f"  Cache dir: {cache_dir}")
            logger.info(f"  skip_db_update: {skip_db_update}")
            logger.info(f"  Команда: {' '.join(cmd)}")
            self.progress_callback(15, "Trivy анализирует установленное ПО...")

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

            output_lines = []
            last_progress_update = 0
            last_elapsed_update = 0
            current_percent = 15
            error_files_found = set()
            large_files_found = set()
            
            for line in process.stdout:
                line = line.strip()
                if line:
                    output_lines.append(line)
                    logger.debug(f"[TRIVY-OUT] {line}")
                    
                    current_time = datetime.now().timestamp()
                    large_path = self._extract_secret_large_file_path(line, target_root=target_path)
                    if large_path:
                        large_files_found.add(large_path)
                    if current_time - last_elapsed_update > 30:
                        elapsed_s = int((datetime.now() - start_time).total_seconds())
                        mins, secs = divmod(elapsed_s, 60)
                        self.progress_callback(current_percent, f"Trivy работает: {mins}м {secs}с")
                        last_elapsed_update = current_time
                    if "Detected OS" in line and current_time - last_progress_update > 2:
                        current_percent = 25
                        self.progress_callback(current_percent, "Trivy обнаружил ОС")
                        last_progress_update = current_time
                    elif "Detecting library vulnerabilities" in line and current_time - last_progress_update > 2:
                        current_percent = 40
                        self.progress_callback(current_percent, "Trivy сопоставляет ПО с CVE/CWE/CAPEC...")
                        last_progress_update = current_time
                    elif "Vulnerability scanning" in line and current_time - last_progress_update > 2:
                        current_percent = 60
                        self.progress_callback(current_percent, "Trivy анализирует CVE...")
                        last_progress_update = current_time
                    elif "Processed" in line and "files" in line and current_time - last_progress_update > 2:
                        current_percent = 75
                        self.progress_callback(current_percent, "Обработка файлов...")
                        last_progress_update = current_time

            process.wait()
            return_code = process.returncode
            
            elapsed_wait = (datetime.now() - start_time).total_seconds()
            logger.info(f"  [TRIVY] Процесс завершилось через {elapsed_wait:.2f} сек (код: {return_code})")

            self.progress_callback(85, "Trivy завершил сканирование, обработка результатов...")
            logger.info(f"  Код возврата: {return_code}")
            logger.info(f"  Вывод Trivy ({len(output_lines)} строк)")

            # Если упали на заблокированном файле - пробуем 1 повтор с динамическим skip-files.
            if return_code != 0:
                extra_skip_files: List[str] = []

                def _cmd_with_extra_skips(base_cmd: List[str]) -> List[str]:
                    merged = list(base_cmd)
                    for p in extra_skip_files:
                        merged.extend(["--skip-files", p])
                    return merged

                for _ in range(3):
                    problem_file = self._extract_problem_file_path(output_lines, target_path)
                    if not problem_file or problem_file in extra_skip_files:
                        break
                    extra_skip_files.append(problem_file)
                    error_files_found.add(problem_file)
                    logger.warning(
                        f"[TRIVY] Файл не удалось прочитать: {problem_file}. Повторяем скан с исключением."
                    )
                    retry_cmd = _cmd_with_extra_skips(cmd)
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
                    for line in process.stdout:
                        line = line.strip()
                        if line:
                            output_lines.append(line)
                            logger.debug(f"[TRIVY-RETRY] {line}")
                    process.wait()
                    return_code = process.returncode
                    logger.info(f"[TRIVY] Повтор завершён с кодом: {return_code}")
                    if return_code == 0:
                        break

                if return_code != 0:
                    out = "\n".join(output_lines[-80:]) if output_lines else ""
                    out_low = out.lower()
                    if "context deadline exceeded" in out_low:
                        timeout_hint = f"Trivy превысил таймаут сканирования. Увеличьте таймаут или сузьте путь сканирования (сейчас: {target_path})."
                        logger.warning(f"[TRIVY] {timeout_hint}")
                        result.error = timeout_hint
                    db_problem = any(
                        s in out_low
                        for s in (
                            "db error",
                            "failed to download vulnerability db",
                            "failed to download artifact",
                            "oci artifact error",
                            "need to update db",
                            "vulndb",
                            "no such host",
                            "dial tcp",
                        )
                    )

                    if skip_db_update and db_problem:
                        logger.warning("[TRIVY] Похоже, локальная DB отсутствует или повреждена. Пробуем обновить DB.")
                        retry_cmd = _cmd_with_extra_skips([x for x in cmd if x != "--skip-db-update"])
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
                        for line in process.stdout:
                            line = line.strip()
                            if line:
                                output_lines.append(line)
                                logger.debug(f"[TRIVY-RETRY] {line}")
                        process.wait()
                        return_code = process.returncode
                        logger.info(f"[TRIVY] Повтор (DB update) завершён с кодом: {return_code}")
                    elif (not skip_db_update) and db_problem:
                        logger.warning("[TRIVY] Ошибка загрузки DB. Пробуем без обновления DB (если cache уже есть).")
                        retry_cmd = _cmd_with_extra_skips(cmd + ["--skip-db-update"])
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
                        for line in process.stdout:
                            line = line.strip()
                            if line:
                                output_lines.append(line)
                                logger.debug(f"[TRIVY-RETRY] {line}")
                        process.wait()
                        return_code = process.returncode
                        logger.info(f"[TRIVY] Повтор (skip DB update) завершён с кодом: {return_code}")

            if persist_exclusions:
                try:
                    current = self._load_exclusions()
                    err_list = list(error_files_found)
                    large_list = list(large_files_found) if persist_large_exclusions else []
                    current["skip_files_error"] = self._merge_exclusions(current.get("skip_files_error", []), err_list)
                    current["skip_files_large"] = self._merge_exclusions(current.get("skip_files_large", []), large_list)
                    self._save_exclusions(current)
                except Exception:
                    pass

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

    def _extract_problem_file_path(self, output_lines: List[str], target_root: str = "") -> str:
        """Возвращает путь к файлу, который Trivy не смог обработать (если есть)."""
        patterns = [
            r"unknown error with\s+([A-Za-z]:\\[^:]+):",
            r"open\s+([A-Za-z]:\\[^:]+):\s+Operation did not complete successfully because the file contains a virus",
            r"open\s+([A-Za-z]:\\[^:]+):\s+Access is denied",
            r"open\s+([A-Za-z]:\\[^:]+):\s+The process cannot access the file",
            r"unable to open\s+([A-Za-z]:\\[^:]+):",
            r"unable to open\s+([A-Za-z]:\\[^:]+)$",
            r"file_path=\"([^\"]+)\"",
        ]
        for line in reversed(output_lines):
            low = line.lower()
            if (
                "cannot access the file" not in low
                and "unable to open" not in low
                and "access is denied" not in low
                and "contains a virus" not in low
                and "potentially unwanted" not in low
                and "unknown error with" not in low
                and "context deadline exceeded" not in low
            ):
                continue
            for pattern in patterns:
                m = re.search(pattern, line, re.IGNORECASE)
                if m:
                    p = (m.group(1) or "").strip().strip('"')
                    if not p:
                        continue
                    p = p.replace("/", "\\")
                    if re.match(r"^[A-Za-z]:\\", p):
                        return p
                    if target_root:
                        return os.path.abspath(os.path.join(target_root, p))
                    return p
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
