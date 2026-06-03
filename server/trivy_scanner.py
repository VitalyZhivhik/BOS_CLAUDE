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
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.logger import get_server_logger
from common.bundle_paths import application_base_dir, bundle_resources_root, tools_dir

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

    def _windows_trivy_candidates(self) -> list[str]:
        if os.name != "nt":
            return []
        pf = os.environ.get("ProgramFiles", "")
        pf86 = os.environ.get("ProgramFiles(x86)", "")
        local = os.environ.get("LOCALAPPDATA", "")
        user = os.environ.get("USERPROFILE", "")
        choco = os.environ.get("ChocolateyInstall", "")
        programdata = os.environ.get("ProgramData", r"C:\ProgramData")
        candidates = [
            os.path.join(pf, "Trivy", "trivy.exe"),
            os.path.join(pf86, "Trivy", "trivy.exe"),
            os.path.join(pf, "trivy", "trivy.exe"),
            os.path.join(pf86, "trivy", "trivy.exe"),
            os.path.join(local, "Programs", "trivy", "trivy.exe"),
            os.path.join(local, "Programs", "Trivy", "trivy.exe"),
            os.path.join(choco, "bin", "trivy.exe") if choco else "",
            os.path.join(programdata, "chocolatey", "bin", "trivy.exe"),
            os.path.join(user, "scoop", "shims", "trivy.exe"),
            os.path.join(user, "scoop", "apps", "trivy", "current", "trivy.exe"),
        ]
        out: list[str] = []
        for p in candidates:
            s = str(p or "").strip()
            if not s:
                continue
            s = os.path.expandvars(os.path.expanduser(s))
            out.append(s)
        return out

    def _find_trivy(self) -> str:
        """Поиск исполняемого файла Trivy."""
        base_dir = bundle_resources_root()
        tools_root = tools_dir()

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

        for path in self._windows_trivy_candidates():
            logger.debug(f"[TRIVY] Проверка (Windows): {path}")
            if os.path.isfile(path):
                logger.info(f"[TRIVY] ✅ Найден (Windows): {path}")
                return path

        for path in ("trivy.exe", "trivy"):
            logger.debug(f"[TRIVY] Проверка PATH: {path}")
            resolved = shutil.which(path) or ""
            if resolved and os.path.isfile(resolved):
                logger.info(f"[TRIVY] ✅ В PATH: {resolved}")
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
                    logger.info(f"[TRIVY] ✅ В PATH: {path}")
                    return path
            except Exception:
                continue

        logger.warning(
            f"[TRIVY] ❌ Исполняемый файл Trivy не найден. Проверенные пути: {possible_paths}"
        )
        return ""

    def _default_cache_dir(self) -> str:
        env_keys = (
            "BOS_TRIVY_CACHE_DIR",
            "TRIVY_CACHE_DIR",
        )
        for k in env_keys:
            v = str(os.environ.get(k, "") or "").strip()
            if not v:
                continue
            p = os.path.abspath(os.path.expandvars(os.path.expanduser(v)))
            return p

        local = os.environ.get("LOCALAPPDATA", "")
        default_local = os.path.join(local, "BOS_CLAUDE", "trivy_cache") if local else os.path.join(tempfile.gettempdir(), "BOS_CLAUDE", "trivy_cache")

        bundled_candidates: list[str] = []
        try:
            bundled_candidates.append(os.path.join(tools_dir(), "trivy_cache"))
        except Exception:
            pass
        try:
            bundled_candidates.append(os.path.join(application_base_dir(), "tools", "trivy_cache"))
        except Exception:
            pass

        for p in bundled_candidates:
            if p and self._trivy_db_present(p):
                return os.path.abspath(p)

        if local:
            return default_local
        return default_local

    def _is_writable_dir(self, path: str) -> bool:
        p = os.path.abspath(os.path.expandvars(os.path.expanduser(str(path or "").strip())))
        if not p:
            return False
        if os.path.isdir(p):
            return os.access(p, os.W_OK)
        parent = os.path.dirname(p)
        return bool(parent) and os.path.isdir(parent) and os.access(parent, os.W_OK)

    def _trivy_db_present(self, cache_dir: str) -> bool:
        cd = os.path.abspath(os.path.expandvars(os.path.expanduser(str(cache_dir or "").strip())))
        if not cd or not os.path.isdir(cd):
            return False
        db_dir = os.path.join(cd, "db")
        if not os.path.isdir(db_dir):
            return False
        markers = [
            os.path.join(db_dir, "metadata.json"),
            os.path.join(db_dir, "trivy.db"),
        ]
        for p in markers:
            if os.path.isfile(p):
                return True
        try:
            for f in os.listdir(db_dir):
                if f.lower().endswith(".db"):
                    return True
        except Exception:
            return False
        return False

    def _download_db(self, cache_dir: str, trivy_home: str, env: dict, startupinfo) -> tuple[bool, list[str]]:
        cmd = [
            self.trivy_path,
            "fs",
            "--download-db-only",
            "--cache-dir",
            cache_dir,
        ]
        output_lines: list[str] = []
        try:
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                cwd=trivy_home or None,
                env=env,
            )
            for raw in p.stdout:
                line = (raw or "").strip()
                if line:
                    output_lines.append(line)
            p.wait()
        except Exception as e:
            output_lines.append(f"download error: {e}")
        ok = self._trivy_db_present(cache_dir)
        return ok, output_lines

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
                cache_dir = self._default_cache_dir()
            cache_dir = os.path.abspath(cache_dir)
            try:
                os.makedirs(cache_dir, exist_ok=True)
            except Exception:
                cache_dir = os.path.abspath(os.path.join(tempfile.gettempdir(), "BOS_CLAUDE", "trivy_cache"))
                os.makedirs(cache_dir, exist_ok=True)

            skip_db_update = scan_options.get("skip_db_update", None)
            if skip_db_update is None:
                v = str(os.environ.get("BOS_TRIVY_SKIP_DB_UPDATE", "") or "").strip().lower()
                skip_db_update = v in ("1", "true", "yes", "on")

            trivy_home = (
                os.path.dirname(os.path.abspath(self.trivy_path))
                if self.trivy_path and os.path.isfile(self.trivy_path)
                else ""
            )
            env = os.environ.copy()
            if trivy_home:
                env["PATH"] = trivy_home + os.pathsep + env.get("PATH", "")

            startupinfo = None
            if os.name == "nt":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            if self._trivy_db_present(cache_dir) and not self._is_writable_dir(cache_dir):
                seeded_from = cache_dir
                cache_dir = os.path.abspath(self._default_cache_dir())
                try:
                    os.makedirs(cache_dir, exist_ok=True)
                    shutil.copytree(
                        os.path.join(seeded_from, "db"),
                        os.path.join(cache_dir, "db"),
                        dirs_exist_ok=True,
                    )
                except Exception:
                    cache_dir = seeded_from

            if not self._trivy_db_present(cache_dir):
                if skip_db_update:
                    result.error = (
                        "TRIVY_DB_MISSING: база Trivy отсутствует в кэше. "
                        f"Путь кэша: {cache_dir}. "
                        "Скачайте базу на ПК с интернетом (trivy fs --download-db-only --cache-dir <dir>) "
                        "и перенесите папку кэша на этот компьютер."
                    )
                    self.last_result = result
                    return result
                self.progress_callback(12, "Trivy скачивает базу уязвимостей...")
                ok, dl_lines = self._download_db(cache_dir, trivy_home, env, startupinfo)
                if not ok:
                    tail = " | ".join(dl_lines[-3:]) if dl_lines else "нет вывода"
                    result.error = (
                        "TRIVY_DB_MISSING: не удалось скачать базу Trivy. "
                        f"Путь кэша: {cache_dir}. "
                        f"Детали: {tail}"
                    )
                    self.last_result = result
                    return result

            cmd = [
                self.trivy_path,
                "fs",  # Filesystem scan
                target_path,
                "--format", "json",
                "--output", output_path,
                "--scanners",
                "--exit-code", "0",
                "--timeout", f"{timeout_minutes}m",
                "--parallel", str(scan_threads),
                "--cache-dir", cache_dir,
                "--pkg-types", "os,library",
            ]

            scanners_opt = scan_options.get("scanners", None)
            scanners: list[str] = []
            if isinstance(scanners_opt, str):
                scanners = [s.strip().lower() for s in scanners_opt.split(",") if s.strip()]
            elif isinstance(scanners_opt, (list, tuple, set)):
                scanners = [str(s).strip().lower() for s in scanners_opt if str(s).strip()]
            if not scanners:
                scanners = ["vuln"]
            allowed_scanners = {"vuln", "misconfig", "secret", "license"}
            scanners = [s for s in scanners if s in allowed_scanners]
            if not scanners:
                scanners = ["vuln"]
            cmd[cmd.index("--scanners") + 1:cmd.index("--scanners") + 1] = [",".join(dict.fromkeys(scanners))]

            severities_opt = scan_options.get("severities", None)
            severities: list[str] = []
            if isinstance(severities_opt, str):
                severities = [s.strip().upper() for s in severities_opt.split(",") if s.strip()]
            elif isinstance(severities_opt, (list, tuple, set)):
                severities = [str(s).strip().upper() for s in severities_opt if str(s).strip()]
            if severities:
                allowed_sev = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                severities = [s for s in severities if s in allowed_sev]
            if severities:
                cmd.extend(["--severity", ",".join(dict.fromkeys(severities))])

            offline_scan = scan_options.get("offline_scan", None)
            if offline_scan is None:
                v = str(os.environ.get("BOS_TRIVY_OFFLINE_SCAN", "") or "").strip().lower()
                offline_scan = v in ("1", "true", "yes", "on")
            if offline_scan:
                cmd.append("--offline-scan")

            if "secret" in scanners:
                skip_dirs: list[str] = []
                tp = os.path.abspath(target_path)
                if os.name == "nt" and len(tp) == 3 and tp[1:] == ":\\":  # C:\
                    skip_dirs.extend([
                        os.path.join(tp, "$Recycle.Bin"),
                        os.path.join(tp, "System Volume Information"),
                        os.path.join(tp, "Windows"),
                        os.path.join(tp, "Program Files"),
                        os.path.join(tp, "Program Files (x86)"),
                        os.path.join(tp, "ProgramData"),
                    ])
                extra_skip_dirs = scan_options.get("skip_dirs", None)
                if isinstance(extra_skip_dirs, str) and extra_skip_dirs.strip():
                    skip_dirs.extend([s.strip() for s in extra_skip_dirs.split(",") if s.strip()])
                elif isinstance(extra_skip_dirs, (list, tuple, set)):
                    skip_dirs.extend([str(s).strip() for s in extra_skip_dirs if str(s).strip()])
                for d in dict.fromkeys(skip_dirs):
                    cmd.extend(["--skip-dirs", d])

                skip_files: list[str] = [
                    "*.exe",
                    "*.dll",
                    "*.sys",
                    "*.msi",
                    "*.cab",
                    "*.zip",
                    "*.7z",
                    "*.rar",
                    "*.iso",
                ]
                extra_skip_files = scan_options.get("skip_files", None)
                if isinstance(extra_skip_files, str) and extra_skip_files.strip():
                    skip_files.extend([s.strip() for s in extra_skip_files.split(",") if s.strip()])
                elif isinstance(extra_skip_files, (list, tuple, set)):
                    skip_files.extend([str(s).strip() for s in extra_skip_files if str(s).strip()])
                for f in dict.fromkeys(skip_files):
                    cmd.extend(["--skip-files", f])

            if skip_db_update:
                cmd.append("--skip-db-update")

            logger.info(f"  Цель сканирования: {target_path}")
            logger.info(f"  Cache dir: {cache_dir}")
            logger.info(f"  Команда: {' '.join(cmd)}")
            self.progress_callback(15, "Trivy анализирует установленное ПО...")

            # Запускаем процесс
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
                    vulnerabilities_list = []

                if vulnerabilities_list:
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

                misconfigs = res.get("Misconfigurations", [])
                if isinstance(misconfigs, list) and misconfigs:
                    for mc in misconfigs:
                        if not isinstance(mc, dict):
                            continue
                        sev = str(mc.get("Severity", "") or "UNKNOWN").upper().strip() or "UNKNOWN"
                        vid = str(mc.get("ID", "") or mc.get("AVDID", "") or mc.get("Type", "") or "MISCONFIG").strip()
                        title = str(mc.get("Title", "") or vid).strip()
                        msg = str(mc.get("Message", "") or mc.get("Description", "") or "").strip()
                        pkg = str(target or mc.get("Target", "") or "misconfig").strip()
                        vulnerabilities.append(
                            TrivyVulnerability(
                                vuln_id=f"MISCONFIG:{vid}",
                                pkg_name=pkg,
                                installed_version="",
                                fixed_version="",
                                severity=sev,
                                title=title,
                                description=msg,
                                references=[str(mc.get("PrimaryURL", "") or "").strip()] if mc.get("PrimaryURL") else [],
                                cwe_ids=[],
                                capec_ids=[],
                                vendor_severity="",
                                status=str(mc.get("Status", "") or "").strip(),
                            )
                        )

                secrets = res.get("Secrets", [])
                if isinstance(secrets, list) and secrets:
                    for s in secrets:
                        if not isinstance(s, dict):
                            continue
                        sev = str(s.get("Severity", "") or "UNKNOWN").upper().strip() or "UNKNOWN"
                        rid = str(s.get("RuleID", "") or s.get("ID", "") or "SECRET").strip()
                        title = str(s.get("Title", "") or rid).strip()
                        match = str(s.get("Match", "") or s.get("Message", "") or "").strip()
                        pkg = str(target or s.get("Target", "") or "secret").strip()
                        start = s.get("StartLine", None)
                        end = s.get("EndLine", None)
                        loc = ""
                        if isinstance(start, int) and isinstance(end, int) and start > 0 and end >= start:
                            loc = f" (lines {start}-{end})"
                        vulnerabilities.append(
                            TrivyVulnerability(
                                vuln_id=f"SECRET:{rid}",
                                pkg_name=pkg,
                                installed_version="",
                                fixed_version="",
                                severity=sev,
                                title=title,
                                description=(match + loc).strip(),
                                references=[],
                                cwe_ids=[],
                                capec_ids=[],
                                vendor_severity="",
                                status="",
                            )
                        )

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
