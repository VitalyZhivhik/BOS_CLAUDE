"""
Серверный агент — графический интерфейс PyQt6.
НОВЫЕ ВОЗМОЖНОСТИ:
  - Вкладка «История отчётов» с управлением
  - Вкладка «Выбор вектора атаки» (ручной выбор для учебных целей)
  - Новые схемы в отчёте:
      3. Сравнение уязвимостей (сервер vs атакующий)
      4. Уязвимости и как их устранить
      5. Уязвимости и как их использовать (ПО + команды)
  - Полная дедупликация результатов
  - Интеграция AttackToolkit и ReportHistory
  - Вкладка «Обнаруженное ПО» (показ сырых данных от сканера)
"""
import sys, os, json, socket, threading, webbrowser, ctypes, time, subprocess, re, tempfile
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox,
        QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
        QFrame, QMessageBox, QStatusBar, QProgressBar, QFileDialog,
        QComboBox, QListWidget, QListWidgetItem, QSplitter,
        QScrollArea, QDialog, QDialogButtonBox, QFormLayout, QLineEdit, QAbstractItemView, QInputDialog
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QFont, QColor, QTextCursor
except Exception:
    print("GUI не может запуститься: PyQt6 не установлен или недоступен.")
    print("Установите зависимости: pip install -r requirements.txt")
    sys.exit(1)
_BOOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BOOT_DIR)
from common.config import SERVER_HOST, SERVER_PORT
from common.bundle_paths import application_base_dir, bundle_resources_root, tools_dir
from common.models import from_json_scan_result, AttackVector, Severity
from common.logger import get_server_logger, GUILogHandler
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator
from server.attack_toolkit import AttackToolkit, validate_tools_database_at_startup
from server.report_history import ReportHistory, ReportRecord
from server.scan_history import ScanHistory, ScanRecord
from server.local_vuln_scanner import LocalVulnScanner, ScanReport
from server.correlation_profiles import list_profiles as list_correlation_profiles, save_profile as save_correlation_profile
from server.trivy_history import TrivyHistory
logger = get_server_logger()
PROJECT_DIR = application_base_dir()
BUNDLE_ROOT = bundle_resources_root()
DEFAULT_CORRELATION_SETTINGS = {
    "max_score": 100,
    "feasible_threshold": 60,
    "partially_feasible_threshold": 40,
    "not_feasible_threshold": 20,
    "network_weight": 30,
    "trivy_weight": 35,
    "software_weight": 20,
    "scanner_weight": 30,
    "patch_weight": 10,
    "protection_weight": 5,
}
TRIVY_SCAN_PROFILES = {
    "Fast": {
        "timeout_minutes": 8,
        "severities": ["HIGH", "CRITICAL"],
        "scanners": ["vuln"],
        "threads": 8,
        "security_checks": False,
    },
    "Balanced": {
        "timeout_minutes": 15,
        "severities": ["MEDIUM", "HIGH", "CRITICAL"],
        "scanners": ["vuln"],
        "threads": 5,
        "security_checks": False,
    },
    "Accurate": {
        "timeout_minutes": 30,
        "severities": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "scanners": ["vuln", "secret"],
        "threads": 3,
        "security_checks": True,
    },
}

TRIVY_PROFILE_MAP = {
    "Быстрый (Fast)": "Fast",
    "Сбалансированный (Balanced)": "Balanced",
    "Точный (Accurate)": "Accurate",
    "Fast": "Fast",
    "Balanced": "Balanced",
    "Accurate": "Accurate",
}

NUCLEI_SCAN_PROFILES = {
    "Fast": {
        "concurrency": 80,
        "timeout": 2,
        "retries": 0,
        "max_host_errors": 100000,
    },
    "Balanced": {
        "concurrency": 50,
        "timeout": 3,
        "retries": 1,
        "max_host_errors": 100000,
    },
    "Accurate": {
        "concurrency": 25,
        "timeout": 5,
        "retries": 2,
        "max_host_errors": 100000,
    },
}

NUCLEI_PROFILE_MAP = {
    "Быстрый (Fast)": "Fast",
    "Сбалансированный (Balanced)": "Balanced",
    "Точный (Accurate)": "Accurate",
    "Fast": "Fast",
    "Balanced": "Balanced",
    "Accurate": "Accurate",
}

SCAN_HISTORY_DIR = "data"
SCAN_HISTORY_SUFFIX = ".json"
NMAP_HISTORY_PREFIX = "nmap_scan_"
NUCLEI_HISTORY_PREFIX = "nuclei_scan_"
# ─────────────────────────────────────────
#  Стили
# ─────────────────────────────────────────
STYLE = """
QMainWindow { background: #121212; }
QWidget { color: #d0d0d0; font-family: 'Segoe UI', 'Consolas'; }
QGroupBox {
    background: #1a1a1a; border: 1px solid #333; border-radius: 4px;
    margin-top: 14px; padding-top: 22px; font-weight: 600; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; color: #909090; }
QPushButton {
    padding: 10px 16px; border-radius: 4px; font-weight: 600; font-size: 11px;
    border: 1px solid #444; color: #d0d0d0; background: #252525;
    min-height: 36px;
}
QPushButton:hover { background: #333; border-color: #555; }
QPushButton:pressed { background: #1a1a1a; }
QPushButton:disabled { background: #1a1a1a; color: #555; border-color: #2a2a2a; }
QTextEdit {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; font-family: 'Consolas'; font-size: 11px; padding: 6px;
}
QTableWidget {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; gridline-color: #222; font-size: 11px;
}
QTableWidget::item { padding: 4px 6px; }
QTableWidget::item:selected { background: #2a2a2a; color: #e0e0e0; }
QHeaderView::section {
    background: #181818; color: #888; border: none; padding: 6px; font-weight: 600;
}
QTabWidget::pane { border: 1px solid #333; border-radius: 3px; background: #1a1a1a; }
QTabBar::tab {
    background: #181818; color: #777; padding: 8px 18px; border: 1px solid #2a2a2a;
    border-bottom: none; border-top-left-radius: 3px; border-top-right-radius: 3px;
    margin-right: 2px;
}
QTabBar::tab:selected { background: #1a1a1a; color: #d0d0d0; border-color: #333; }
QSpinBox {
    background: #0e0e0e; color: #d0d0d0; border: 1px solid #333;
    border-radius: 3px; padding: 4px;
}
QProgressBar {
    background: #0e0e0e; border: 1px solid #333; border-radius: 3px;
    text-align: center; color: #999; font-weight: 600; font-size: 10px;
}
QProgressBar::chunk { background: #555; border-radius: 2px; }
QStatusBar { background: #0e0e0e; color: #666; border-top: 1px solid #222; }
QLabel { color: #b0b0b0; }
QComboBox {
    background: #0e0e0e; color: #d0d0d0; border: 1px solid #333;
    border-radius: 3px; padding: 4px 8px; font-size: 11px;
}
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background: #1a1a1a; color: #d0d0d0; border: 1px solid #333; }
QListWidget {
    background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a;
    border-radius: 3px; font-size: 11px;
}
QListWidget::item:selected { background: #2a4070; color: #e0e0e0; }
QListWidget::item:hover { background: #222; }
QLineEdit {
    background: #0e0e0e; color: #d0d0d0; border: 1px solid #333;
    border-radius: 3px; padding: 4px 8px;
}
QSplitter::handle { background: #333; width: 1px; }
"""

_HINT_NEUTRAL = (
    "background:#1a1a1a;border:1px solid #333;border-radius:3px;"
    "padding:6px;color:#888;font-size:10px;"
)
_HINT_ACCENT = (
    "background:#1e2a2a;border:1px solid #2a4a4a;border-radius:3px;"
    "padding:6px;color:#7a9a9a;font-size:10px;"
)

def is_port_available(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        r = s.connect_ex(("127.0.0.1", port))
        s.close()
        if r == 0:
            return False, f"Порт {port} уже занят"
        return True, f"Порт {port} свободен"
    except Exception as e:
        return True, str(e)
# ─────────────────────────────────────────
#  Рабочие потоки
# ─────────────────────────────────────────
class AnalysisWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    def run(self):
        try:
            a = SystemAnalyzer()
            info = a.analyze()
            s = a.get_summary()
            self.finished.emit({"info": info, "summary": s, "analyzer": a})
        except Exception as e:
            logger.error(f"Ошибка анализа: {e}", exc_info=True)
            self.error.emit(str(e))
class DBLoadWorker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    def run(self):
        try:
            db = VulnerabilityDatabase(BUNDLE_ROOT)
            db.load_all()
            self.finished.emit(db)
        except Exception as e:
            logger.error(f"Ошибка загрузки БД: {e}", exc_info=True)
            self.error.emit(str(e))
class VulnScanWorker(QThread):
    finished = pyqtSignal(object)
    progress = pyqtSignal(int, int, str)
    error = pyqtSignal(str)
    def run(self):
        try:
            sc = LocalVulnScanner()
            sc.progress_callback = lambda c, t, m: self.progress.emit(c, t, m)
            res = sc.scan_all()
            self.finished.emit(res)
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}", exc_info=True)
            self.error.emit(str(e))
class ToolkitLoadWorker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    def run(self):
        try:
            tk = AttackToolkit(BUNDLE_ROOT)
            tk.load()
            self.finished.emit(tk)
        except Exception as e:
            logger.error(f"Ошибка загрузки toolkit: {e}", exc_info=True)
            self.error.emit(str(e))

class TrivyScanWorker(QThread):
    finished = pyqtSignal(object)  # dict summary
    progress = pyqtSignal(int, str)  # percent, message
    error = pyqtSignal(str)
    
    def __init__(self, system_analyzer, trivy_path="", scan_options=None):
        super().__init__()
        self.system_analyzer = system_analyzer
        self.trivy_path = trivy_path
        self.scan_options = scan_options or {}
    
    def run(self):
        try:
            self.progress.emit(0, "Запуск сканирования Trivy...")
            prev_cb = getattr(self.system_analyzer, "progress_callback", None)
            try:
                self.system_analyzer.progress_callback = lambda p, m: self.progress.emit(int(p), str(m))
                result = self.system_analyzer.run_trivy_scan(self.trivy_path, self.scan_options)
            finally:
                try:
                    self.system_analyzer.progress_callback = prev_cb
                except Exception:
                    pass
            self.progress.emit(100, "Сканирование Trivy завершено")
            self.finished.emit(result)
        except Exception as e:
            logger.error(f"Ошибка сканирования Trivy: {e}", exc_info=True)
            self.error.emit(str(e))


class LocalNmapScanWorker(QThread):
    finished = pyqtSignal(list, float)  # vulns, elapsed
    error = pyqtSignal(str)

    def __init__(self, target: str, ports: list[int], settings=None):
        super().__init__()
        self.target = target
        self.ports = [int(p) for p in (ports or []) if isinstance(p, int) and p > 0]
        self.settings = settings or {}

    def run(self):
        try:
            if not self.ports:
                self.finished.emit([], 0.0)
                return
            from nmap_integration import NmapScanner
            t0 = time.time()
            try:
                scanner = NmapScanner(self.target, settings=self.settings, scanner_location="server")
            except TypeError:
                scanner = NmapScanner(self.target, settings=self.settings)
            vulns = scanner.scan_vulnerabilities(self.ports)
            self.finished.emit(vulns or [], time.time() - t0)
        except Exception as e:
            logger.error(f"[LOCAL-NMAP] Ошибка: {e}", exc_info=True)
            self.error.emit(str(e))


class LocalNucleiScanWorker(QThread):
    finished = pyqtSignal(list, float)  # vulns, elapsed
    error = pyqtSignal(str)

    def __init__(self, target: str, ports: list[int], settings=None):
        super().__init__()
        self.target = target
        self.ports = [int(p) for p in (ports or []) if isinstance(p, int) and p > 0]
        self.settings = settings or {}

    def run(self):
        try:
            if not self.ports:
                self.finished.emit([], 0.0)
                return
            from nmap_integration import NucleiScanner
            t0 = time.time()
            scanner = NucleiScanner(self.target, settings=self.settings, scanner_location="server")
            vulns = scanner.scan_vulnerabilities(self.ports)
            self.finished.emit(vulns or [], time.time() - t0)
        except Exception as e:
            logger.error(f"[LOCAL-NUCLEI] Ошибка: {e}", exc_info=True)
            self.error.emit(str(e))


class ServerNucleiWorker(QThread):
    progress = pyqtSignal(str, int)
    log_msg = pyqtSignal(str)
    finished = pyqtSignal(list, float)  # vulns, elapsed
    error = pyqtSignal(str)

    def __init__(self, target: str, ports: list[int], settings=None):
        super().__init__()
        self.target = target
        self.ports = [int(p) for p in (ports or []) if isinstance(p, int) and p > 0]
        self.settings = settings or {}
        self.nuclei_path = ""
        for p in (
            os.path.join(tools_dir(), "nuclei.exe"),
            os.path.join(tools_dir(), "nuclei", "nuclei.exe"),
        ):
            if os.path.isfile(p):
                self.nuclei_path = p
                break
        if not self.nuclei_path:
            self.nuclei_path = "nuclei"

    def run(self):
        t_start = time.time()
        vulns = []

        try:
            if os.path.isfile(self.nuclei_path) and not os.path.exists(self.nuclei_path):
                self.error.emit(f"Nuclei не найден: {self.nuclei_path}")
                self.finished.emit([], 0.0)
                return

            urls = []
            for port in self.ports:
                urls.append(f"{self.target}:{port}")
            if not urls:
                urls = [self.target]

            fd, temp_path = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            fd_url, url_list_path = tempfile.mkstemp(suffix=".txt")
            os.close(fd_url)
            with open(url_list_path, "w", encoding="utf-8") as f:
                f.write("\n".join(urls))

            try:
                from nmap_integration import _resolve_nuclei_templates_dir
                templates_dir = _resolve_nuclei_templates_dir()
            except Exception:
                templates_dir = ""

            # Если шаблоны не найдены, выводим предупреждение и отменяем сканирование
            if not templates_dir:
                self.log_msg.emit("[⚠️] Директория с шаблонами Nuclei не найдена. Сканирование отменено.")
                self.log_msg.emit("   Убедитесь, что шаблоны установлены в папке tools/nuclei-templates")
                self.finished.emit([], 0)
                return

            cmd = [
                self.nuclei_path,
                "-l", url_list_path,
                "-json-export", temp_path,
                "-ni", "-duc",
                "-t", templates_dir,
                "-mhe", str(self.settings.get("max_host_errors", 100000)),
                "-c", str(self.settings.get("concurrency", 50)),
                "-timeout", str(self.settings.get("timeout", 3)),
                "-retries", str(self.settings.get("retries", 1)),
                "-stats", "-si", "2",
            ]

            startupinfo = subprocess.STARTUPINFO() if os.name == 'nt' else None
            if startupinfo:
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            cwd = os.path.dirname(os.path.abspath(self.nuclei_path)) if os.path.isfile(self.nuclei_path) else None

            self.log_msg.emit("═" * 60)
            self.log_msg.emit(f"  🚀 NUCLEI (СЕРВЕР)  [{datetime.now().strftime('%H:%M:%S')}]")
            self.log_msg.emit("═" * 60)
            self.log_msg.emit(f"  ▸ Цель:        {self.target}")
            self.log_msg.emit(f"  ▸ URL-ы:       {', '.join(urls)}")
            self.log_msg.emit(f"  ▸ Параллельно: {self.settings.get('concurrency', 50)} шаблонов")
            self.log_msg.emit(f"  ▸ Timeout/Retry: {self.settings.get('timeout', 3)}s / {self.settings.get('retries', 1)}")
            self.log_msg.emit("")

            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1, universal_newlines=True,
                    startupinfo=startupinfo,
                    cwd=cwd,
                )
            except PermissionError as e:
                if os.name == "nt" and os.path.isfile(self.nuclei_path):
                    try:
                        subprocess.run(
                            [
                                "powershell",
                                "-NoProfile",
                                "-ExecutionPolicy", "Bypass",
                                "-Command",
                                f"Unblock-File -LiteralPath '{self.nuclei_path}'",
                            ],
                            capture_output=True,
                            text=True,
                            timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                        process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, universal_newlines=True,
                            startupinfo=startupinfo,
                            cwd=cwd,
                        )
                    except Exception:
                        raise e
                else:
                    raise e

            for line in process.stdout:
                clean_line = (line or "").strip()
                if not clean_line:
                    continue
                stat_match = re.search(r'(?:reqs?|Requests):\s*(\d+)/(\d+)', clean_line, re.IGNORECASE)
                if stat_match:
                    tot = int(stat_match.group(2))
                    pct = int((int(stat_match.group(1)) / tot) * 100) if tot > 0 else 0
                    self.progress.emit(f"{stat_match.group(1)} из {tot} запросов", pct)
                    continue
                self.log_msg.emit(f"  {clean_line}")

            process.wait()
            elapsed = time.time() - t_start

            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                with open(temp_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            item = json.loads(line)
                        except Exception:
                            continue
                        if isinstance(item, list):
                            items = item
                        else:
                            items = [item]
                        for it in items:
                            if not isinstance(it, dict):
                                continue
                            info = it.get("info") or {}
                            if isinstance(info, list) and info:
                                info = info[0] if isinstance(info[0], dict) else {}
                            if not isinstance(info, dict):
                                info = {}
                            classification = info.get("classification") or {}
                            if not isinstance(classification, dict):
                                classification = {}
                            cve_raw = classification.get("cve-id", "")
                            cve_id = ""
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
                            port = it.get("port", None)
                            try:
                                port_int = int(port) if port is not None and str(port).isdigit() else 0
                            except Exception:
                                port_int = 0
                            vulns.append({
                                "cve_id": str(cve_id or "").strip().upper(),
                                "cwe_id": str(cwe_id or "").strip().upper(),
                                "port": port_int,
                                "protocol": "tcp",
                                "service": (it.get("service") or {}).get("name", "unknown") if isinstance(it.get("service"), dict) else "unknown",
                                "severity": str(info.get("severity", "medium")).upper(),
                                "description": str(info.get("name", "") or it.get("template-id", "Nuclei finding")),
                                "source": "Nuclei",
                                "template": str(it.get("template-id", "") or ""),
                                "scanner_location": "server",
                                "scanner_label": "Сервер",
                                "target": str(it.get("host", "") or self.target),
                            })

            self.finished.emit(vulns, elapsed)
        except Exception as e:
            logger.error(f"[LOCAL-NUCLEI] Ошибка: {e}", exc_info=True)
            self.error.emit(str(e))
            self.finished.emit([], 0.0)
        finally:
            try:
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            try:
                if 'url_list_path' in locals() and os.path.exists(url_list_path):
                    os.remove(url_list_path)
            except Exception:
                pass


class CorrelationRestartWorker(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int, str)
    error = pyqtSignal(str)

    def __init__(
        self,
        system_info,
        vuln_db,
        trivy_result,
        last_scan_data,
        toolkit,
        vuln_scan_report,
        system_summary,
        settings,
    ):
        super().__init__()
        self.system_info = system_info
        self.vuln_db = vuln_db
        self.trivy_result = trivy_result
        self.last_scan_data = last_scan_data
        self.toolkit = toolkit
        self.vuln_scan_report = vuln_scan_report
        self.system_summary = system_summary
        self.settings = settings

    def run(self):
        try:
            self.progress.emit(0, "🔄 Перезапуск корреляции...")
            sr = from_json_scan_result(self.last_scan_data)
            profiles = []
            try:
                profiles = list_correlation_profiles(PROJECT_DIR)
            except Exception:
                profiles = []

            results_by_profile = {}
            summaries_by_profile = {}
            profiles_meta = {}
            settings_by_profile = {}

            ordered_ids = []
            for p in profiles:
                pid = p.get("file") or p.get("id")
                if not pid or pid in ordered_ids:
                    continue
                profiles_meta[pid] = {"id": pid, "name": p.get("name", pid), "description": p.get("description", "")}
                if isinstance(p.get("settings"), dict):
                    settings_by_profile[pid] = dict(p.get("settings"))
                ordered_ids.append(pid)

            if not ordered_ids:
                pid = "_default"
                profiles_meta[pid] = {"id": pid, "name": "По умолчанию", "description": ""}
                settings_by_profile[pid] = dict(DEFAULT_CORRELATION_SETTINGS)
                ordered_ids.append(pid)

            default_profile_id = "standard.json" if "standard.json" in ordered_ids else ordered_ids[0]
            total_profiles = max(1, len(ordered_ids))

            for pid in ordered_ids:
                if pid not in settings_by_profile:
                    settings_by_profile[pid] = dict(DEFAULT_CORRELATION_SETTINGS)

            for idx, pid in enumerate(ordered_ids, 1):
                settings = settings_by_profile.get(pid, dict(DEFAULT_CORRELATION_SETTINGS) if pid == "_default" else {})

                cor = AttackCorrelator(
                    self.system_info,
                    self.vuln_db,
                    trivy_result=self.trivy_result,
                    correlation_settings=settings,
                )

                def _mk_cb(base_idx, pid_label):
                    def _cb(pct, msg):
                        base = int(((base_idx - 1) / total_profiles) * 100)
                        span = int(100 / total_profiles)
                        overall = min(99, base + int((pct / 100) * span))
                        self.progress.emit(overall, f"{pid_label}: {msg}")
                    return _cb

                cor.set_progress_callback(_mk_cb(idx, profiles_meta.get(pid, {}).get("name", pid)))
                results = cor.correlate(sr)
                summary = cor.get_summary()
                results_by_profile[pid] = results
                summaries_by_profile[pid] = summary

            results = results_by_profile.get(default_profile_id, [])
            summary = summaries_by_profile.get(default_profile_id, {})

            rd = os.path.join(PROJECT_DIR, "reports")
            os.makedirs(rd, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rep = ReportGenerator(
                self.system_summary or {},
                results,
                summary,
                toolkit=self.toolkit,
                local_scan_report=self.vuln_scan_report,
                attacker_scan_data=self.last_scan_data,
                correlation_results_by_profile=results_by_profile,
                summaries_by_profile=summaries_by_profile,
                profiles_meta=profiles_meta,
                default_profile_id=default_profile_id,
            )
            hp = rep.generate_html(os.path.join(rd, f"report_{ts}.html"))
            jp = rep.generate_json(os.path.join(rd, f"report_{ts}.json"))

            settings_used = settings_by_profile.get(default_profile_id, dict(DEFAULT_CORRELATION_SETTINGS))
            def _to_details(items):
                out = []
                for r in items:
                    out.append({
                        "cve_id": str(r.cve_id) if getattr(r, "cve_id", None) else "",
                        "attack_name": str(r.attack_name) if getattr(r, "attack_name", None) else "",
                        "severity": getattr(r.severity, "name", str(r.severity)),
                        "feasibility": __import__("common.models", fromlist=["normalize_feasibility"]).normalize_feasibility(getattr(r, "feasibility", None)),
                        "description": str(r.description) if getattr(r, "description", None) else "",
                        "recommendation": str(r.recommendation) if getattr(r, "recommendation", None) else "",
                    })
                return out
            details_by_profile = {pid: _to_details(res) for pid, res in results_by_profile.items()}
            payload = {
                "status": "success",
                "correlation_id": ts,
                "summary": summary,
                "settings_used": settings_used,
                "profiles_meta": profiles_meta,
                "default_profile_id": default_profile_id,
                "settings_by_profile": settings_by_profile,
                "summaries_by_profile": summaries_by_profile,
                "html_report": hp,
                "results_count": len(results),
                "details": details_by_profile.get(default_profile_id, []),
                "details_by_profile": details_by_profile,
            }
            self.progress.emit(100, "✅ Корреляция перезапущена")
            self.finished.emit({
                "results": results,
                "summary": summary,
                "html_path": hp,
                "json_path": jp,
                "correlation_id": ts,
                "payload": payload,
                "results_by_profile": results_by_profile,
                "summaries_by_profile": summaries_by_profile,
                "profiles_meta": profiles_meta,
                "default_profile_id": default_profile_id,
                "settings_by_profile": settings_by_profile,
            })
        except Exception as e:
            logger.error(f"Ошибка перезапуска корреляции: {e}", exc_info=True)
            self.error.emit(str(e))
# ─────────────────────────────────────────
#  Главное окно
# ─────────────────────────────────────────
class ServerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)
    client_connected_signal = pyqtSignal(str)
    analysis_done_signal = pyqtSignal(dict, str)
    update_results_signal = pyqtSignal(object)
    correlation_bundle_signal = pyqtSignal(object)
    correlation_progress_signal = pyqtSignal(int, str)  # Прогресс корреляции
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Assessment — Серверный агент v2.0")
        self.setMinimumSize(1600, 900)  # Увеличиваем размер окна для широкой панели
        # Состояние
        self.system_info = None
        self.system_summary = None
        self.vuln_db = None
        self.vuln_scan_report = None
        self.toolkit = None
        self.trivy_summary = None  # Результаты Trivy
        self.trivy_available = False  # Доступен ли Trivy
        self.report_history = ReportHistory(PROJECT_DIR)
        self.scan_history = ScanHistory(PROJECT_DIR)
        self.http_server = None
        self.server_thread = None
        self.server_running = False
        self.last_report_path = None
        self.actual_server_port = None
        self._last_scan_data = {}        # Данные от атакующего (для схем)
        self._last_results = []          # Результаты корреляции
        self.server_scan_vectors = []    # Результаты Nmap/Nuclei на сервере (векторы)
        self.server_scan_vulns = {"nmap": [], "nuclei": []}  # Сырые находки серверных сканеров
        self._server_scan_running = {"nmap": False, "nuclei": False}
        self._server_scan_ports = {"nmap": [], "nuclei": []}
        self._correlation_results_by_profile = {}
        self._correlation_summaries_by_profile = {}
        self._correlation_profiles_meta = {}
        self._correlation_settings_by_profile = {}
        self._selected_profile_id = ""
        self.restart_correlation_worker = None
        self._build_ui()
        self.setStyleSheet(STYLE)
        self.update_results_signal.connect(self._update_results_table_slot)
        self.correlation_bundle_signal.connect(self._apply_correlation_bundle_slot)
        self.correlation_progress_signal.connect(self._on_correlation_progress_update)
        self.log_signal.connect(self._append_log)
        gh = GUILogHandler(self._on_log_message)
        gh.setLevel(10)
        logger.addHandler(gh)
        validate_tools_database_at_startup(BUNDLE_ROOT)
        self.client_connected_signal.connect(self._on_client_connected)
        self.analysis_done_signal.connect(self._on_server_analysis_done)
        # Синхронизируем историю с диском при старте
        QTimer.singleShot(500, self._sync_history)
    # ─────────────────────────────────────────
    #  Построение интерфейса
    # ─────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        ml = QHBoxLayout(central)
        ml.setSpacing(8)
        ml.setContentsMargins(8, 8, 8, 8)
        # Левая панель управления - значительно расширена
        left = self._build_left_panel()
        ml.addWidget(left)
        # Правая панель с вкладками - уменьшена
        self.tabs = QTabWidget()
        self._build_system_tab()
        self._build_software_tab() # НОВАЯ ВКЛАДКА
        self._build_trivy_tab()  # НОВАЯ ВКЛАДКА TRIVY
        self._build_scanners_tab()
        self._build_scan_history_tab()
        self._build_vuln_tab()
        self._build_correlation_tab()
        self._build_settings_tab()  # НОВАЯ ВКЛАДКА НАСТРОЙКИ
        self._build_history_tab()
        self._build_log_tab()
        ml.addWidget(self.tabs, 1)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Готов к работе")
    def _build_left_panel(self) -> QWidget:
        # Создаём контейнер с скроллом для левой панели
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setStyleSheet("""
            QScrollArea {
                background: #121212;
                border: none;
            }
            QScrollBar:vertical {
                background: #121212;
                width: 6px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: #444;
                border-radius: 3px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #555;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
                border: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: #121212;
            }
        """)
        
        left = QWidget()
        left.setFixedWidth(265)  # Увеличенная ширина левой панели
        left.setStyleSheet("background: #121212;")
        ll = QVBoxLayout(left)
        ll.setSpacing(6)
        ll.setContentsMargins(4, 4, 4, 4)
        t = QLabel("СЕРВЕРНЫЙ АГЕНТ")
        t.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        t.setStyleSheet("color:#999;padding:8px 0;letter-spacing:2px;")
        ll.addWidget(t)
        # Статус
        self.status_frame = QFrame()
        self.status_frame.setStyleSheet(
            "background:#1e1e1e;border:1px solid #3a3a3a;border-radius:6px;padding:12px;"
        )
        sf = QVBoxLayout(self.status_frame)
        sf.setSpacing(4)
        self.status_icon = QLabel("● Сервер не запущен")
        self.status_icon.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.status_icon.setStyleSheet("color:#666;")
        sf.addWidget(self.status_icon)
        self.connection_label = QLabel("Клиенты: нет подключений")
        self.connection_label.setStyleSheet("color:#555;font-size:10px;")
        self.connection_label.setWordWrap(True)
        sf.addWidget(self.connection_label)
        self.port_display = QLabel("")
        self.port_display.setFont(QFont("Consolas", 10))
        self.port_display.setStyleSheet("color:#666;")
        self.port_display.setWordWrap(True)
        sf.addWidget(self.port_display)
        ll.addWidget(self.status_frame)
        # Управление - значительно увеличен
        cg = QGroupBox("Управление")
        cg.setStyleSheet("QGroupBox { font-size: 13px; font-weight: bold; padding-top: 24px; }")
        cl = QVBoxLayout(cg)
        cl.setSpacing(8)
        cl.setContentsMargins(8, 12, 8, 12)

        # Кнопки управления - динамический размер
        btn_style = """
            QPushButton { 
                padding: 10px 14px; 
                font-size: 11px; 
                min-height: 36px; 
                text-align: center;
            }
        """

        self.btn_analyze = QPushButton("1. Анализ системы")
        self.btn_analyze.setStyleSheet(btn_style)
        self.btn_analyze.clicked.connect(self._start_analysis)
        cl.addWidget(self.btn_analyze)

        self.btn_load_db = QPushButton("2. Загрузить базы CVE/CWE/CAPEC/MITRE")
        self.btn_load_db.setStyleSheet(btn_style)
        self.btn_load_db.setEnabled(False)
        self.btn_load_db.setToolTip(
            "Читает JSON из папки databases/: cve_database, cwe_database, capec_database, "
            "mitre_attack. Используются при поиске CVE по портам/ПО и при корреляции."
        )
        self.btn_load_db.clicked.connect(self._load_databases)
        cl.addWidget(self.btn_load_db)

        self.btn_load_toolkit = QPushButton("2б. Загрузить базу инструментов")
        self.btn_load_toolkit.setStyleSheet(btn_style)
        self.btn_load_toolkit.setEnabled(False)
        self.btn_load_toolkit.clicked.connect(self._load_toolkit)
        cl.addWidget(self.btn_load_toolkit)

        self.btn_vuln_scan = QPushButton("3. Локальное сканирование уязвимостей")
        self.btn_vuln_scan.setStyleSheet(btn_style)
        self.btn_vuln_scan.setEnabled(False)
        self.btn_vuln_scan.setToolTip(
            "Встроенные проверки Windows (PowerShell/WMI): обновления, политики, файрвол, RDP, SMB и др. "
            "Результат — вкладка «Локальный скан»."
        )
        self.btn_vuln_scan.clicked.connect(self._start_vuln_scan)
        cl.addWidget(self.btn_vuln_scan)

        self.vuln_progress = QProgressBar()
        self.vuln_progress.setFixedHeight(20)
        self.vuln_progress.setVisible(False)
        cl.addWidget(self.vuln_progress)

        # Кнопка Trivy
        self.btn_trivy_scan = QPushButton("3б. Сканирование Trivy (CVE/CWE/CAPEC)")
        self.btn_trivy_scan.setStyleSheet(btn_style)
        self.btn_trivy_scan.setEnabled(False)
        self.btn_trivy_scan.setToolTip(
            "Запускает Trivy по установленному ПО. CVE — из баз уязвимостей Trivy; CWE — из карточки уязвимости; "
            "CAPEC дополняется из локальной базы при отображении."
        )
        self.btn_trivy_scan.clicked.connect(self._start_trivy_scan)
        cl.addWidget(self.btn_trivy_scan)

        self.trivy_progress = QProgressBar()
        self.trivy_progress.setFixedHeight(20)
        self.trivy_progress.setVisible(False)
        cl.addWidget(self.trivy_progress)

        self.btn_local_nmap = QPushButton("3в. Nmap (сервер, локально)  ➕")
        self.btn_local_nmap.setStyleSheet(btn_style)
        self.btn_local_nmap.setEnabled(False)
        self.btn_local_nmap.clicked.connect(self._start_local_nmap_scan)
        cl.addWidget(self.btn_local_nmap)

        self.local_nmap_progress = QProgressBar()
        self.local_nmap_progress.setFixedHeight(18)
        self.local_nmap_progress.setVisible(False)
        cl.addWidget(self.local_nmap_progress)

        self.btn_local_nuclei = QPushButton("3г. Nuclei (сервер, локально)  ➕")
        self.btn_local_nuclei.setStyleSheet(btn_style)
        self.btn_local_nuclei.setEnabled(False)
        self.btn_local_nuclei.clicked.connect(self._start_local_nuclei_scan)
        cl.addWidget(self.btn_local_nuclei)

        self.local_nuclei_progress = QProgressBar()
        self.local_nuclei_progress.setFixedHeight(18)
        self.local_nuclei_progress.setVisible(False)
        cl.addWidget(self.local_nuclei_progress)

        sep_scan = QFrame()
        sep_scan.setFrameShape(QFrame.Shape.HLine)
        sep_scan.setStyleSheet("color:#333;")
        cl.addWidget(sep_scan)

        self.btn_local_parallel_scan = QPushButton("⚡ Параллельный скан (Nmap + Nuclei)")
        self.btn_local_parallel_scan.setStyleSheet(btn_style + "QPushButton { background: #2a3a4a; }")
        self.btn_local_parallel_scan.setEnabled(False)
        self.btn_local_parallel_scan.clicked.connect(self._start_local_parallel_scan)
        cl.addWidget(self.btn_local_parallel_scan)

        self.btn_server = QPushButton("4. Запустить сервер")
        self.btn_server.setStyleSheet(btn_style + "QPushButton { background: #2a4a2a; }")
        self.btn_server.setEnabled(False)
        self.btn_server.clicked.connect(self._toggle_server)
        cl.addWidget(self.btn_server)

        ll.addWidget(cg)

        sg = QGroupBox("Справка: данные и пайплайн")
        sg.setStyleSheet("QGroupBox { font-size: 11px; padding-top: 18px; }")
        sgl = QVBoxLayout(sg)
        sgl.setSpacing(4)
        sgl.setContentsMargins(6, 10, 6, 8)
        db_hint = QLabel(
            "Базы: CVE — записи об уязвимостях (идентификатор, описание, привязка к портам, "
            "службам и ПО); CWE — классы ошибок в ПО; CAPEC — шаблоны атак; MITRE ATT&CK — техники "
            "противника; база инструментов — средства и тексты для разделов отчёта.\n\n"
            "Типичный порядок: анализ системы → загрузка справочников → локальный скан Windows → "
            "(опционально) Trivy → запуск API → приём данных от атакующего → корреляция → HTML/JSON отчёт.\n\n"
            "Локальный скан формирует находки с полями ID проверки, категорией (политика, сеть, службы…), "
            "статусом (уязвимо/защищено/неизвестно), серьёзностью и описанием.\n\n"
            "Trivy сопоставляет установленные пакеты с CVE из своих баз; CWE и CAPEC берутся из метаданных "
            "уязвимости и локальных JSON-справочников при отображении.\n\n"
            "Корреляция сопоставляет векторы атакующего с конфигурацией сервера, портами, ПО и данными Trivy; "
            "на выходе — оценка реализуемости атак, сводка и рекомендации в отчёте."
        )
        db_hint.setStyleSheet(_HINT_NEUTRAL)
        db_hint.setWordWrap(True)
        sgl.addWidget(db_hint)
        ll.addWidget(sg)

        # Параметры - уменьшены
        pg = QGroupBox("Параметры")
        pg.setStyleSheet("QGroupBox { font-size: 11px; padding-top: 18px; }")
        pl = QVBoxLayout(pg)
        pl.setSpacing(4)
        pl.setContentsMargins(6, 10, 6, 8)

        r = QHBoxLayout()
        r.addWidget(QLabel("Порт API:"))
        r.setSpacing(4)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(SERVER_PORT)
        self.port_spin.setFixedHeight(24)
        r.addWidget(self.port_spin)
        pl.addLayout(r)

        small_btn_style = "QPushButton { padding: 4px 10px; font-size: 10px; min-height: 24px; }"
        self.btn_check_port = QPushButton("Проверить порт")
        self.btn_check_port.setStyleSheet(small_btn_style)
        self.btn_check_port.clicked.connect(self._check_port_availability)
        pl.addWidget(self.btn_check_port)

        self.port_status_label = QLabel("")
        self.port_status_label.setStyleSheet("font-size:9px;")
        self.port_status_label.setWordWrap(True)
        pl.addWidget(self.port_status_label)

        ll.addWidget(pg)

        # Отчёт - уменьшены
        rg = QGroupBox("Отчёт")
        rg.setStyleSheet("QGroupBox { font-size: 11px; padding-top: 18px; }")
        rl = QVBoxLayout(rg)
        rl.setSpacing(4)
        rl.setContentsMargins(6, 10, 6, 8)

        self.btn_open_report = QPushButton("Открыть последний отчёт")
        self.btn_open_report.setStyleSheet(small_btn_style)
        self.btn_open_report.setEnabled(False)
        self.btn_open_report.clicked.connect(self._open_report)
        rl.addWidget(self.btn_open_report)

        self.btn_generate_manual = QPushButton("Сгенерировать отчёт вручную")
        self.btn_generate_manual.setStyleSheet(small_btn_style)
        self.btn_generate_manual.setEnabled(False)
        self.btn_generate_manual.setToolTip("Сгенерировать отчёт на основе выбранного вектора атаки")
        self.btn_generate_manual.clicked.connect(self._generate_manual_report)
        rl.addWidget(self.btn_generate_manual)

        self.btn_export_log = QPushButton("Экспорт лога")
        self.btn_export_log.setStyleSheet(small_btn_style)
        self.btn_export_log.clicked.connect(self._export_log)
        rl.addWidget(self.btn_export_log)
        ll.addWidget(rg)
        ll.addStretch()
        # Статистика
        sf2 = QFrame()
        sf2.setStyleSheet("background:#1e1e1e;border:1px solid #3a3a3a;border-radius:6px;padding:12px;")
        sl = QVBoxLayout(sf2)
        sl.setSpacing(4)
        self.lbl_stats = QLabel("Статистика недоступна")
        self.lbl_stats.setStyleSheet("color:#777;font-size:11px;")
        self.lbl_stats.setWordWrap(True)
        sl.addWidget(self.lbl_stats)
        self.lbl_history_stats = QLabel("")
        self.lbl_history_stats.setStyleSheet("color:#666;font-size:11px;")
        sl.addWidget(self.lbl_history_stats)
        ll.addWidget(sf2)
        
        scroll.setWidget(left)
        return scroll

    def _apply_trivy_profile(self):
        profile_key = TRIVY_PROFILE_MAP.get(self.trivy_profile_combo.currentText(), "Balanced")
        preset = TRIVY_SCAN_PROFILES.get(profile_key, TRIVY_SCAN_PROFILES["Balanced"])
        self.trivy_timeout_spin.setValue(preset["timeout_minutes"])
        self.trivy_severity_combo.setCurrentText(",".join(preset["severities"]))
        self.trivy_checks_combo.setCurrentText(",".join(preset["scanners"]))
        self.trivy_threads_spin.setValue(preset["threads"])

    def _get_local_hw_profile(self):
        cpu_cores = max(1, os.cpu_count() or 1)
        ram_gb = 8
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            mem = MEMORYSTATUSEX()
            mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
            ram_gb = max(1, int(mem.ullTotalPhys / (1024 ** 3)))
        except Exception:
            logger.debug("Не удалось определить ОЗУ для Trivy-рекомендаций", exc_info=True)
        return cpu_cores, ram_gb

    def _apply_recommended_trivy_resources(self):
        cpu_cores, ram_gb = self._get_local_hw_profile()
        if cpu_cores <= 4 or ram_gb <= 8:
            self.trivy_profile_combo.setCurrentText("Точный (Accurate)")
            threads = max(2, cpu_cores - 1)
        elif cpu_cores >= 12 and ram_gb >= 24:
            self.trivy_profile_combo.setCurrentText("Быстрый (Fast)")
            threads = min(16, cpu_cores)
        else:
            self.trivy_profile_combo.setCurrentText("Сбалансированный (Balanced)")
            threads = min(10, max(3, cpu_cores // 2))
        self.trivy_threads_spin.setValue(threads)
        self.trivy_hw_info_label.setText(f"Обнаружено: CPU ядер {cpu_cores}, ОЗУ ~{ram_gb} ГБ")

    def _get_trivy_scan_options(self):
        severities = [s.strip().upper() for s in self.trivy_severity_combo.currentText().split(",") if s.strip()]
        scanners = [s.strip() for s in self.trivy_checks_combo.currentText().split(",") if s.strip()]
        options = {
            "timeout_minutes": max(1, min(self.trivy_timeout_spin.value(), 120)),
            "severities": severities or ["MEDIUM", "HIGH", "CRITICAL"],
            "scanners": scanners or ["vuln"],
            "threads": max(1, min(self.trivy_threads_spin.value(), 32)),
            "security_checks": "secret" in scanners,
        }
        logger.info(f"[TRIVY] Применённые настройки: {options}")
        return options

    def _apply_nuclei_profile(self):
        preset_key = NUCLEI_PROFILE_MAP.get(self.nuclei_profile_combo.currentText(), "Balanced")
        preset = NUCLEI_SCAN_PROFILES.get(preset_key, NUCLEI_SCAN_PROFILES["Balanced"])
        self.nuclei_concurrency_spin.setValue(int(preset.get("concurrency", 50)))
        self.nuclei_timeout_spin.setValue(int(preset.get("timeout", 3)))
        self.nuclei_retries_spin.setValue(int(preset.get("retries", 1)))
        self.nuclei_mhe_spin.setValue(int(preset.get("max_host_errors", 100000)))

    def _get_nuclei_settings(self):
        options = {
            "concurrency": max(5, min(self.nuclei_concurrency_spin.value(), 150)),
            "timeout": max(1, min(self.nuclei_timeout_spin.value(), 30)),
            "retries": max(0, min(self.nuclei_retries_spin.value(), 5)),
            "max_host_errors": max(1000, min(self.nuclei_mhe_spin.value(), 200000)),
        }
        logger.info(f"[NUCLEI] Применённые настройки (сервер): {options}")
        return options

    def _build_system_tab(self):
        st = QWidget()
        stl = QVBoxLayout(st)
        sy = QLabel(
            "Сводка с хоста после шага «Анализ системы»: ОС, сеть, установленное ПО и открытые порты "
            "по данным SystemAnalyzer. Эти сведения участвуют в корреляции с векторами атакующего."
        )
        sy.setStyleSheet(_HINT_NEUTRAL)
        sy.setWordWrap(True)
        stl.addWidget(sy)
        self.sys_table = QTableWidget(0, 2)
        self.sys_table.setHorizontalHeaderLabels(["Параметр", "Значение"])
        self.sys_table.horizontalHeader().setStretchLastSection(True)
        self.sys_table.setColumnWidth(0, 220)
        self.sys_table.verticalHeader().setVisible(False)
        self.sys_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        stl.addWidget(self.sys_table)
        self.tabs.addTab(st, "🖥️ Система")

    def _build_software_tab(self):
        """Новая вкладка для реального ПО от сканера"""
        st = QWidget()
        stl = QVBoxLayout(st)
        label = QLabel(
            "Реестр ПО и сетевых служб, которые сервер «видит» у себя локально (установленные программы "
            "и прослушиваемые порты). Используется для сопоставления с CVE и с результатами Trivy при "
            "оценке реализуемости атак."
        )
        label.setStyleSheet(_HINT_NEUTRAL)
        label.setWordWrap(True)
        stl.addWidget(label)

        self.software_table = QTableWidget(0, 3)
        self.software_table.setHorizontalHeaderLabels(["Тип", "Название / Компонент", "Порт / Версия"])
        self.software_table.horizontalHeader().setStretchLastSection(True)
        self.software_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        stl.addWidget(self.software_table)
        self.tabs.addTab(st, "📦 Обнаруженное ПО")

    def _build_trivy_tab(self):
        """Вкладка для отображения результатов сканирования Trivy"""
        st = QWidget()
        stl = QVBoxLayout(st)
        
        # Заголовок
        title = QLabel("🔍 Результаты сканирования Trivy (CVE/CWE/CAPEC)")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        stl.addWidget(title)
        tri_expl = QLabel(
            "Trivy сравнивает установленные пакеты и их версии с известными уязвимостями. "
            "CVE-ID приходит из отчёта Trivy (базы NVD и др.). CWE — из метаданных уязвимости. "
            "Колонка CWE/CAPEC объединяет идентификаторы слабости и шаблона атаки (CAPEC подгружается "
            "из локальной базы, если есть связь). «Исправлено» — версия пакета, в которой проблема закрыта."
        )
        tri_expl.setStyleSheet(_HINT_ACCENT)
        tri_expl.setWordWrap(True)
        stl.addWidget(tri_expl)

        # Панель управления Trivy
        ctrl_layout = QHBoxLayout()
        self.btn_load_trivy = QPushButton("📂 Загрузить отчёт из файла (История)")
        self.btn_load_trivy.clicked.connect(self._load_trivy_report)
        ctrl_layout.addWidget(self.btn_load_trivy)
        ctrl_layout.addStretch()
        stl.addLayout(ctrl_layout)
        
        # Статус
        self.trivy_status_label = QLabel("⚪ Trivy не запущен")
        self.trivy_status_label.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        stl.addWidget(self.trivy_status_label)
        
        # Таблица уязвимостей
        self.trivy_table = QTableWidget(0, 7)
        self.trivy_table.setHorizontalHeaderLabels([
            "CVE-ID", "ПО", "Версия", "Исправлено", "Серьёзность", "Заголовок", "CWE/CAPEC"
        ])
        self.trivy_table.horizontalHeader().setStretchLastSection(True)
        self.trivy_table.setColumnWidth(0, 140)
        self.trivy_table.setColumnWidth(1, 150)
        self.trivy_table.setColumnWidth(2, 90)
        self.trivy_table.setColumnWidth(3, 90)
        self.trivy_table.setColumnWidth(4, 90)
        self.trivy_table.setColumnWidth(5, 250)
        self.trivy_table.verticalHeader().setVisible(False)
        self.trivy_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        stl.addWidget(self.trivy_table)
        
        # Сводка
        self.trivy_summary_label = QLabel("")
        self.trivy_summary_label.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        self.trivy_summary_label.setWordWrap(True)
        stl.addWidget(self.trivy_summary_label)
        
        self.tabs.addTab(st, "🛡️ Trivy")

    def _build_scanners_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        nmap_panel = QWidget()
        nmap_layout = QVBoxLayout(nmap_panel)
        nmap_layout.setContentsMargins(0, 0, 0, 0)
        nmap_layout.setSpacing(8)

        nmap_title = QLabel("🛰️ Nmap (сервер, локально)")
        nmap_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        nmap_title.setStyleSheet("color:#888;padding:6px 0;")
        nmap_layout.addWidget(nmap_title)

        self.server_nmap_status = QLabel("⚪ Nmap не запускался")
        self.server_nmap_status.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        nmap_layout.addWidget(self.server_nmap_status)

        self.server_nmap_progress = QProgressBar()
        self.server_nmap_progress.setFixedHeight(18)
        self.server_nmap_progress.setVisible(True)
        self.server_nmap_progress.setValue(0)
        self.server_nmap_progress.setFormat("—")
        nmap_layout.addWidget(self.server_nmap_progress)

        self.server_nmap_table = QTableWidget(0, 6)
        self.server_nmap_table.setHorizontalHeaderLabels(["CVE", "Серьёзность", "Порт", "Сервис", "Script", "Описание"])
        self.server_nmap_table.horizontalHeader().setStretchLastSection(True)
        self.server_nmap_table.setColumnWidth(0, 135)
        self.server_nmap_table.setColumnWidth(1, 90)
        self.server_nmap_table.setColumnWidth(2, 60)
        self.server_nmap_table.setColumnWidth(3, 120)
        self.server_nmap_table.setColumnWidth(4, 180)
        self.server_nmap_table.verticalHeader().setVisible(False)
        self.server_nmap_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        nmap_layout.addWidget(self.server_nmap_table, 1)

        self.server_nmap_log = QTextEdit()
        self.server_nmap_log.setReadOnly(True)
        self.server_nmap_log.setFixedHeight(180)
        nmap_layout.addWidget(self.server_nmap_log)

        splitter.addWidget(nmap_panel)

        nuclei_panel = QWidget()
        nuclei_layout = QVBoxLayout(nuclei_panel)
        nuclei_layout.setContentsMargins(0, 0, 0, 0)
        nuclei_layout.setSpacing(8)

        nuclei_title = QLabel("🧪 Nuclei (сервер, локально)")
        nuclei_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        nuclei_title.setStyleSheet("color:#888;padding:6px 0;")
        nuclei_layout.addWidget(nuclei_title)

        self.server_nuclei_status = QLabel("⚪ Nuclei не запускался")
        self.server_nuclei_status.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        nuclei_layout.addWidget(self.server_nuclei_status)

        self.server_nuclei_progress = QProgressBar()
        self.server_nuclei_progress.setFixedHeight(18)
        self.server_nuclei_progress.setVisible(True)
        self.server_nuclei_progress.setValue(0)
        self.server_nuclei_progress.setFormat("—")
        nuclei_layout.addWidget(self.server_nuclei_progress)

        self.server_nuclei_table = QTableWidget(0, 6)
        self.server_nuclei_table.setHorizontalHeaderLabels(["CVE", "CWE", "Серьёзность", "Порт", "Template", "Описание"])
        self.server_nuclei_table.horizontalHeader().setStretchLastSection(True)
        self.server_nuclei_table.setColumnWidth(0, 135)
        self.server_nuclei_table.setColumnWidth(1, 110)
        self.server_nuclei_table.setColumnWidth(2, 90)
        self.server_nuclei_table.setColumnWidth(3, 60)
        self.server_nuclei_table.setColumnWidth(4, 220)
        self.server_nuclei_table.verticalHeader().setVisible(False)
        self.server_nuclei_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        nuclei_layout.addWidget(self.server_nuclei_table, 1)

        self.server_nuclei_log = QTextEdit()
        self.server_nuclei_log.setReadOnly(True)
        self.server_nuclei_log.setFixedHeight(180)
        nuclei_layout.addWidget(self.server_nuclei_log)

        splitter.addWidget(nuclei_panel)

        trivy_panel = QWidget()
        trivy_layout = QVBoxLayout(trivy_panel)
        trivy_layout.setContentsMargins(0, 0, 0, 0)
        trivy_layout.setSpacing(8)

        trivy_title = QLabel("🛡️ Trivy (сервер)")
        trivy_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        trivy_title.setStyleSheet("color:#888;padding:6px 0;")
        trivy_layout.addWidget(trivy_title)

        self.server_trivy_status = QLabel("⚪ Trivy не запущен")
        self.server_trivy_status.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        trivy_layout.addWidget(self.server_trivy_status)

        self.server_trivy_progress = QProgressBar()
        self.server_trivy_progress.setFixedHeight(18)
        self.server_trivy_progress.setVisible(True)
        self.server_trivy_progress.setValue(0)
        self.server_trivy_progress.setFormat("—")
        trivy_layout.addWidget(self.server_trivy_progress)

        self.server_trivy_table = QTableWidget(0, 7)
        self.server_trivy_table.setHorizontalHeaderLabels([
            "CVE-ID", "ПО", "Версия", "Исправлено", "Серьёзность", "Заголовок", "CWE/CAPEC"
        ])
        self.server_trivy_table.horizontalHeader().setStretchLastSection(True)
        self.server_trivy_table.setColumnWidth(0, 140)
        self.server_trivy_table.setColumnWidth(1, 150)
        self.server_trivy_table.setColumnWidth(2, 90)
        self.server_trivy_table.setColumnWidth(3, 90)
        self.server_trivy_table.setColumnWidth(4, 90)
        self.server_trivy_table.setColumnWidth(5, 250)
        self.server_trivy_table.verticalHeader().setVisible(False)
        self.server_trivy_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        trivy_layout.addWidget(self.server_trivy_table, 1)

        self.server_trivy_log = QTextEdit()
        self.server_trivy_log.setReadOnly(True)
        self.server_trivy_log.setFixedHeight(180)
        trivy_layout.addWidget(self.server_trivy_log)

        splitter.addWidget(trivy_panel)
        splitter.setSizes([700, 700, 700])
        layout.addWidget(splitter)

        self.tabs.addTab(tab, "🖥️ Сканеры")

    def _build_scan_history_tab(self):
        tab = QWidget()
        outer = QVBoxLayout(tab)

        title = QLabel("📂 История сканирований")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        outer.addWidget(title)

        top_ctrl = QHBoxLayout()
        self.btn_refresh_scan_hist = QPushButton("🔄 Обновить")
        self.btn_refresh_scan_hist.clicked.connect(self._refresh_scan_histories)
        top_ctrl.addWidget(self.btn_refresh_scan_hist)
        top_ctrl.addStretch()
        outer.addLayout(top_ctrl)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        trivy_panel = QWidget()
        trivy_layout = QVBoxLayout(trivy_panel)
        trivy_layout.setContentsMargins(0, 0, 0, 0)
        trivy_layout.setSpacing(8)
        trivy_layout.addWidget(QLabel("🛡️ Trivy"))

        trivy_ctrl = QHBoxLayout()
        self.btn_load_trivy_hist = QPushButton("📥 Загрузить")
        self.btn_load_trivy_hist.clicked.connect(self._load_selected_trivy_history)
        self.btn_load_trivy_hist.setEnabled(False)
        trivy_ctrl.addWidget(self.btn_load_trivy_hist)
        self.btn_delete_trivy_hist = QPushButton("🗑️ Удалить")
        self.btn_delete_trivy_hist.clicked.connect(self._delete_selected_trivy_history)
        self.btn_delete_trivy_hist.setEnabled(False)
        trivy_ctrl.addWidget(self.btn_delete_trivy_hist)
        trivy_ctrl.addStretch()
        trivy_layout.addLayout(trivy_ctrl)

        self.trivy_hist_table = QTableWidget(0, 4)
        self.trivy_hist_table.setHorizontalHeaderLabels(["Дата и Время", "Уязвимостей", "Критических", "Файл"])
        self.trivy_hist_table.horizontalHeader().setStretchLastSection(True)
        self.trivy_hist_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.trivy_hist_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.trivy_hist_table.itemSelectionChanged.connect(self._sync_trivy_hist_buttons)
        trivy_layout.addWidget(self.trivy_hist_table)
        splitter.addWidget(trivy_panel)

        nmap_panel = QWidget()
        nmap_layout = QVBoxLayout(nmap_panel)
        nmap_layout.setContentsMargins(0, 0, 0, 0)
        nmap_layout.setSpacing(8)
        nmap_layout.addWidget(QLabel("🛰️ Nmap"))

        nmap_ctrl = QHBoxLayout()
        self.btn_load_nmap_hist = QPushButton("📥 Загрузить")
        self.btn_load_nmap_hist.clicked.connect(self._load_selected_nmap_history)
        self.btn_load_nmap_hist.setEnabled(False)
        nmap_ctrl.addWidget(self.btn_load_nmap_hist)
        self.btn_delete_nmap_hist = QPushButton("🗑️ Удалить")
        self.btn_delete_nmap_hist.clicked.connect(self._delete_selected_nmap_history)
        self.btn_delete_nmap_hist.setEnabled(False)
        nmap_ctrl.addWidget(self.btn_delete_nmap_hist)
        nmap_ctrl.addStretch()
        nmap_layout.addLayout(nmap_ctrl)

        self.nmap_hist_table = QTableWidget(0, 4)
        self.nmap_hist_table.setHorizontalHeaderLabels(["Дата и Время", "Уязвимостей", "CRITICAL/HIGH", "Файл"])
        self.nmap_hist_table.horizontalHeader().setStretchLastSection(True)
        self.nmap_hist_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.nmap_hist_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.nmap_hist_table.itemSelectionChanged.connect(self._sync_nmap_hist_buttons)
        nmap_layout.addWidget(self.nmap_hist_table)
        splitter.addWidget(nmap_panel)

        nuclei_panel = QWidget()
        nuclei_layout = QVBoxLayout(nuclei_panel)
        nuclei_layout.setContentsMargins(0, 0, 0, 0)
        nuclei_layout.setSpacing(8)
        nuclei_layout.addWidget(QLabel("🧪 Nuclei"))

        nuclei_ctrl = QHBoxLayout()
        self.btn_load_nuclei_hist = QPushButton("📥 Загрузить")
        self.btn_load_nuclei_hist.clicked.connect(self._load_selected_nuclei_history)
        self.btn_load_nuclei_hist.setEnabled(False)
        nuclei_ctrl.addWidget(self.btn_load_nuclei_hist)
        self.btn_delete_nuclei_hist = QPushButton("🗑️ Удалить")
        self.btn_delete_nuclei_hist.clicked.connect(self._delete_selected_nuclei_history)
        self.btn_delete_nuclei_hist.setEnabled(False)
        nuclei_ctrl.addWidget(self.btn_delete_nuclei_hist)
        nuclei_ctrl.addStretch()
        nuclei_layout.addLayout(nuclei_ctrl)

        self.nuclei_hist_table = QTableWidget(0, 4)
        self.nuclei_hist_table.setHorizontalHeaderLabels(["Дата и Время", "Уязвимостей", "CRITICAL/HIGH", "Файл"])
        self.nuclei_hist_table.horizontalHeader().setStretchLastSection(True)
        self.nuclei_hist_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.nuclei_hist_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.nuclei_hist_table.itemSelectionChanged.connect(self._sync_nuclei_hist_buttons)
        nuclei_layout.addWidget(self.nuclei_hist_table)
        splitter.addWidget(nuclei_panel)

        splitter.setSizes([600, 600, 600])
        outer.addWidget(splitter, 1)

        self.tabs.addTab(tab, "📜 История сканирований")

    def _update_software_tab(self, system_info):
        """Заполнение вкладки реальным ПО"""
        self.software_table.setRowCount(0)
        row = 0
        for port_info in getattr(system_info, 'open_ports', []):
            self.software_table.insertRow(row)
            self.software_table.setItem(row, 0, QTableWidgetItem("Сетевая служба"))
            port_num = getattr(port_info, 'port', None)
            if port_num is None and isinstance(port_info, dict):
                port_num = port_info.get("port", "Неизвестно")
            self.software_table.setItem(row, 1, QTableWidgetItem(f"Служба на порту {port_num}"))
            self.software_table.setItem(row, 2, QTableWidgetItem(str(port_num)))
            row += 1
            
        for sw in getattr(system_info, 'installed_software', []):
            self.software_table.insertRow(row)
            self.software_table.setItem(row, 0, QTableWidgetItem("Установленное ПО"))
            sw_name = getattr(sw, 'name', None)
            if sw_name is None and isinstance(sw, dict):
                sw_name = sw.get("name", "Неизвестное ПО")
            sw_version = getattr(sw, 'version', None)
            if sw_version is None and isinstance(sw, dict):
                sw_version = sw.get("version", "")
            self.software_table.setItem(row, 1, QTableWidgetItem(str(sw_name)))
            self.software_table.setItem(row, 2, QTableWidgetItem(str(sw_version)))
            row += 1

    def _build_vuln_tab(self):
        vt = QWidget()
        vtl = QVBoxLayout(vt)
        self.vuln_table = QTableWidget(0, 5)
        self.vuln_table.setHorizontalHeaderLabels(["ID", "Серьёзность", "Статус", "Категория", "Описание"])
        self.vuln_table.horizontalHeader().setStretchLastSection(True)
        self.vuln_table.setColumnWidth(0, 70)
        self.vuln_table.setColumnWidth(1, 85)
        self.vuln_table.setColumnWidth(2, 100)
        self.vuln_table.setColumnWidth(3, 80)
        self.vuln_table.verticalHeader().setVisible(False)
        self.vuln_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        vtl.addWidget(self.vuln_table)
        self.vuln_summary_label = QLabel("")
        self.vuln_summary_label.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        vtl.addWidget(self.vuln_summary_label)
        self.tabs.addTab(vt, "🔍 Локальный скан")
    def _build_correlation_tab(self):
        rt = QWidget()
        rtl = QVBoxLayout(rt)
        info = QLabel("📊 Результаты корреляции атак. Двойной клик для деталей. Отчёт открывается кнопкой 'Открыть последний отчёт'")
        info.setStyleSheet("color:#888;font-size:10px;padding:4px;")
        info.setWordWrap(True)
        rtl.addWidget(info)

        # Прогресс корреляции
        self.correlation_progress_label = QLabel("⚪ Ожидание данных от атакующего...")
        self.correlation_progress_label.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        rtl.addWidget(self.correlation_progress_label)

        self.correlation_progress_bar = QProgressBar()
        self.correlation_progress_bar.setFixedHeight(20)
        self.correlation_progress_bar.setVisible(False)
        self.correlation_progress_bar.setValue(0)
        rtl.addWidget(self.correlation_progress_bar)

        prof_row = QHBoxLayout()
        prof_row.addWidget(QLabel("Профиль корреляции:"))
        self.correlation_profile_combo = QComboBox()
        self.correlation_profile_combo.addItem("—")
        self.correlation_profile_combo.setEnabled(False)
        self.correlation_profile_combo.currentIndexChanged.connect(self._on_correlation_profile_changed)
        prof_row.addWidget(self.correlation_profile_combo, 1)
        rtl.addLayout(prof_row)

        self.correlation_profile_settings_text = QTextEdit()
        self.correlation_profile_settings_text.setReadOnly(True)
        self.correlation_profile_settings_text.setFixedHeight(140)
        self.correlation_profile_settings_text.setPlainText("Параметры профиля: —")
        rtl.addWidget(self.correlation_profile_settings_text)

        self.results_table = QTableWidget(0, 5)
        self.results_table.setHorizontalHeaderLabels(["CVE", "Серьёзность", "Реализуемость", "Атака", "Описание"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setColumnWidth(0, 130)
        self.results_table.setColumnWidth(1, 85)
        self.results_table.setColumnWidth(2, 130)
        self.results_table.setColumnWidth(3, 180)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.results_table.doubleClicked.connect(self._on_result_double_click)
        rtl.addWidget(self.results_table)
        self.correlation_summary = QLabel("")
        self.correlation_summary.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        rtl.addWidget(self.correlation_summary)
        self.tabs.addTab(rt, "📊 Корреляция")
    def _build_settings_tab(self):
        """Вкладка настроек: корреляция + сканирование."""
        # Создаём основной контейнер с возможностью скролла
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setStyleSheet("""
            QScrollArea {
                background: #1a1a1a;
                border: 1px solid #333;
                border-radius: 3px;
            }
            QScrollBar:vertical {
                background: #1a1a1a;
                width: 6px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: #444;
                border-radius: 3px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #555;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0;
                border: none;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: #1a1a1a;
            }
            QScrollBar:horizontal {
                background: #1a1a1a;
                height: 6px;
                border: none;
            }
            QScrollBar::handle:horizontal {
                background: #444;
                border-radius: 3px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #555;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0;
                border: none;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: #1a1a1a;
            }
        """)
        
        # Создаём контейнер для содержимого
        content_widget = QWidget()
        content_widget.setStyleSheet("background: #1a1a1a;")
        stl = QVBoxLayout(content_widget)
        stl.setSpacing(10)
        stl.setContentsMargins(15, 15, 15, 15)

        # Заголовок
        title = QLabel("⚙️ НАСТРОЙКИ КОРРЕЛЯЦИИ АТАК")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        stl.addWidget(title)

        # Описание
        desc = QLabel(
            "Настройте параметры оценки реализуемости атак. "
            "Эти параметры используются при корреляции векторов атак с конфигурацией сервера. "
            "Сначала нажмите «Применить настройки» или «Применить профиль», затем при наличии данных от атакующего — «Перезапустить корреляцию»."
        )
        desc.setStyleSheet(_HINT_NEUTRAL)
        desc.setWordWrap(True)
        stl.addWidget(desc)
        
        # Добавляем разделитель
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        separator.setStyleSheet("color:#333;")
        stl.addWidget(separator)

        # Группа параметров - Пороги реализуемости
        thresholds_group = QGroupBox("Пороги реализуемости (Score)")
        thresholds_layout = QVBoxLayout(thresholds_group)

        # Максимальное значение score
        max_score_layout = QHBoxLayout()
        max_score_layout.addWidget(QLabel("Максимальное значение score:"))
        self.max_score_spin = QSpinBox()
        self.max_score_spin.setRange(50, 200)
        self.max_score_spin.setValue(100)
        self.max_score_spin.setFixedWidth(80)
        max_score_layout.addWidget(self.max_score_spin)
        thresholds_layout.addLayout(max_score_layout)

        # Порог для FEASIBLE
        feasible_layout = QHBoxLayout()
        feasible_layout.addWidget(QLabel("Порог для РЕАЛИЗУЕМА (>=):"))
        self.feasible_threshold_spin = QSpinBox()
        self.feasible_threshold_spin.setRange(30, 150)
        self.feasible_threshold_spin.setValue(60)
        self.feasible_threshold_spin.setFixedWidth(80)
        feasible_layout.addWidget(self.feasible_threshold_spin)
        thresholds_layout.addLayout(feasible_layout)

        # Порог для PARTIALLY_FEASIBLE
        partially_layout = QHBoxLayout()
        partially_layout.addWidget(QLabel("Порог для ЧАСТИЧНО РЕАЛИЗУЕМА (>=):"))
        self.partially_threshold_spin = QSpinBox()
        self.partially_threshold_spin.setRange(20, 80)
        self.partially_threshold_spin.setValue(40)
        self.partially_threshold_spin.setFixedWidth(80)
        partially_layout.addWidget(self.partially_threshold_spin)
        thresholds_layout.addLayout(partially_layout)

        # Порог для NOT_FEASIBLE
        not_feasible_layout = QHBoxLayout()
        not_feasible_layout.addWidget(QLabel("Порог для НЕ РЕАЛИЗУЕМА (<=):"))
        self.not_feasible_threshold_spin = QSpinBox()
        self.not_feasible_threshold_spin.setRange(10, 50)
        self.not_feasible_threshold_spin.setValue(20)
        self.not_feasible_threshold_spin.setFixedWidth(80)
        not_feasible_layout.addWidget(self.not_feasible_threshold_spin)
        thresholds_layout.addLayout(not_feasible_layout)

        stl.addWidget(thresholds_group)

        # Группа параметров - Веса факторов
        weights_group = QGroupBox("Веса факторов (баллы)")
        weights_layout = QVBoxLayout(weights_group)

        # Вес для сетевой доступности
        network_weight_layout = QHBoxLayout()
        network_weight_layout.addWidget(QLabel("Сетевая доступность:"))
        self.network_weight_spin = QSpinBox()
        self.network_weight_spin.setRange(10, 50)
        self.network_weight_spin.setValue(30)
        self.network_weight_spin.setFixedWidth(80)
        network_weight_layout.addWidget(self.network_weight_spin)
        weights_layout.addLayout(network_weight_layout)

        # Вес для подтверждения Trivy
        trivy_weight_layout = QHBoxLayout()
        trivy_weight_layout.addWidget(QLabel("Подтверждение Trivy:"))
        self.trivy_weight_spin = QSpinBox()
        self.trivy_weight_spin.setRange(10, 50)
        self.trivy_weight_spin.setValue(35)
        self.trivy_weight_spin.setFixedWidth(80)
        trivy_weight_layout.addWidget(self.trivy_weight_spin)
        weights_layout.addLayout(trivy_weight_layout)

        # Вес для уязвимого ПО
        software_weight_layout = QHBoxLayout()
        software_weight_layout.addWidget(QLabel("Уязвимое ПО обнаружено:"))
        self.software_weight_spin = QSpinBox()
        self.software_weight_spin.setRange(10, 40)
        self.software_weight_spin.setValue(20)
        self.software_weight_spin.setFixedWidth(80)
        software_weight_layout.addWidget(self.software_weight_spin)
        weights_layout.addLayout(software_weight_layout)

        # Вес для подтверждения сканером
        scanner_weight_layout = QHBoxLayout()
        scanner_weight_layout.addWidget(QLabel("Подтверждение сканером:"))
        self.scanner_weight_spin = QSpinBox()
        self.scanner_weight_spin.setRange(10, 50)
        self.scanner_weight_spin.setValue(30)
        self.scanner_weight_spin.setFixedWidth(80)
        scanner_weight_layout.addWidget(self.scanner_weight_spin)
        weights_layout.addLayout(scanner_weight_layout)

        patch_weight_layout = QHBoxLayout()
        patch_weight_layout.addWidget(QLabel("Состояние обновлений:"))
        self.patch_weight_spin = QSpinBox()
        self.patch_weight_spin.setRange(0, 50)
        self.patch_weight_spin.setValue(10)
        self.patch_weight_spin.setFixedWidth(80)
        patch_weight_layout.addWidget(self.patch_weight_spin)
        weights_layout.addLayout(patch_weight_layout)

        protection_weight_layout = QHBoxLayout()
        protection_weight_layout.addWidget(QLabel("Ослабление защиты (FW/AV):"))
        self.protection_weight_spin = QSpinBox()
        self.protection_weight_spin.setRange(0, 30)
        self.protection_weight_spin.setValue(5)
        self.protection_weight_spin.setFixedWidth(80)
        protection_weight_layout.addWidget(self.protection_weight_spin)
        weights_layout.addLayout(protection_weight_layout)

        stl.addWidget(weights_group)

        # Группа профилей корреляции
        profiles_group = QGroupBox("Готовые профили корреляции")
        profiles_layout = QVBoxLayout(profiles_group)
        
        # Выбор профиля
        profile_layout = QHBoxLayout()
        profile_layout.addWidget(QLabel("Выберите профиль:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("-- Выберите профиль --")
        self.profile_combo.addItem("Стандартный (баланс)")
        self.profile_combo.addItem("Приоритетный для анализа на сервере")
        self.profile_combo.addItem("Приоритетный для анализа атакующим")
        self._profile_name_to_file = {
            "Стандартный (баланс)": "standard.json",
            "Приоритетный для анализа на сервере": "server_priority.json",
            "Приоритетный для анализа атакующим": "attacker_priority.json",
        }
        try:
            existing = list_correlation_profiles(PROJECT_DIR)
            built_in_files = set(self._profile_name_to_file.values())
            for p in existing:
                pf = p.get("file") or p.get("id")
                if not pf or pf in built_in_files:
                    continue
                label = str(p.get("name") or pf.replace(".json", ""))
                if label in self._profile_name_to_file:
                    label = f"{label} ({pf})"
                self._profile_name_to_file[label] = pf
                self.profile_combo.addItem(label)
        except Exception:
            pass
        self.profile_combo.addItem("Загрузить из файла...")
        self.profile_combo.currentTextChanged.connect(self._on_profile_selected)
        profile_layout.addWidget(self.profile_combo)
        profiles_layout.addLayout(profile_layout)
        
        # Описание профиля
        self.profile_description = QLabel("Выберите профиль для просмотра описания")
        self.profile_description.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        self.profile_description.setWordWrap(True)
        profiles_layout.addWidget(self.profile_description)
        
        # Кнопка применения профиля
        self.btn_apply_profile = QPushButton("📊 Применить профиль")
        self.btn_apply_profile.clicked.connect(self._apply_profile)
        self.btn_apply_profile.setEnabled(False)
        profiles_layout.addWidget(self.btn_apply_profile)
        self.btn_apply_profile.setVisible(False)

        self.btn_save_new_profile = QPushButton("➕ Добавить профиль")
        self.btn_save_new_profile.clicked.connect(self._save_new_profile_from_current_settings)
        profiles_layout.addWidget(self.btn_save_new_profile)

        self.btn_overwrite_profile = QPushButton("📝 Перезаписать выбранный профиль")
        self.btn_overwrite_profile.clicked.connect(self._overwrite_selected_profile_from_current_settings)
        self.btn_overwrite_profile.setEnabled(False)
        profiles_layout.addWidget(self.btn_overwrite_profile)
        self.btn_overwrite_profile.setVisible(False)

        self.btn_copy_to_profile = QPushButton("📋 Записать настройки в другой профиль")
        self.btn_copy_to_profile.clicked.connect(self._copy_current_settings_to_other_profile)
        profiles_layout.addWidget(self.btn_copy_to_profile)
        self.btn_copy_to_profile.setVisible(False)
        
        stl.addWidget(profiles_group)

        # Кнопка применения настроек (только сохранение в состояние сервера, без пересчёта)
        self.btn_apply_settings = QPushButton("✅ Применить настройки")
        self.btn_apply_settings.setStyleSheet("QPushButton { background: #2a4a2a; }")
        self.btn_apply_settings.clicked.connect(self._apply_correlation_settings)
        stl.addWidget(self.btn_apply_settings)
        self.btn_apply_settings.setVisible(False)

        # Кнопка сброса к значениям по умолчанию
        self.btn_reset_settings = QPushButton("🔙 Сбросить к значениям по умолчанию")
        self.btn_reset_settings.clicked.connect(self._reset_correlation_settings)
        stl.addWidget(self.btn_reset_settings)
        self.btn_reset_settings.setVisible(False)

        # Пересчёт по последним данным атакующего (после применения настроек или профиля)
        self.btn_restart_correlation = QPushButton("🔄 Провести корреляцию для всех профилей")
        self.btn_restart_correlation.setToolTip("Пересчитать результаты по последним данным от атакующего для всех профилей корреляции.")
        self.btn_restart_correlation.setStyleSheet("QPushButton { background: #4a2a4a; }")
        self.btn_restart_correlation.clicked.connect(self._restart_correlation)
        self.btn_restart_correlation.setEnabled(False)
        stl.addWidget(self.btn_restart_correlation)

        # Статус применения настроек
        self.settings_status_label = QLabel("⚪ Настройки не применены")
        self.settings_status_label.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        stl.addWidget(self.settings_status_label)

        # Текущие параметры корреляции (информационно)
        current_settings_group = QGroupBox("Текущие параметры корреляции")
        current_settings_layout = QVBoxLayout(current_settings_group)
        self.current_settings_text = QTextEdit()
        self.current_settings_text.setReadOnly(True)
        self.current_settings_text.setFixedHeight(120)
        self.current_settings_text.setPlainText(
            "Текущие параметры будут отображены после загрузки баз данных и выполнения корреляции."
        )
        current_settings_layout.addWidget(self.current_settings_text)
        stl.addWidget(current_settings_group)

        # Устанавливаем содержимое корреляции в скролл-область
        scroll_area.setWidget(content_widget)

        # Подвкладка 2: Настройки сканирования (Trivy)
        scan_settings = QWidget()
        scan_layout = QVBoxLayout(scan_settings)
        scan_layout.setContentsMargins(12, 12, 12, 12)
        scan_layout.setSpacing(10)

        scan_title = QLabel("⚙️ Настройки сканирования Trivy")
        scan_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        scan_title.setStyleSheet("color:#888;padding:6px 0;")
        scan_layout.addWidget(scan_title)

        scan_desc = QLabel(
            "Параметры управляют скоростью и полнотой сканирования Trivy. "
            "Более быстрые режимы сокращают время, но могут пропускать часть находок."
        )
        scan_desc.setStyleSheet(_HINT_NEUTRAL)
        scan_desc.setWordWrap(True)
        scan_layout.addWidget(scan_desc)

        trivy_group = QGroupBox("Параметры Trivy")
        trivy_layout = QFormLayout(trivy_group)
        self.trivy_profile_combo = QComboBox()
        self.trivy_profile_combo.addItems([
            "Быстрый (Fast)",
            "Сбалансированный (Balanced)",
            "Точный (Accurate)",
        ])
        self.trivy_profile_combo.setCurrentText("Сбалансированный (Balanced)")
        trivy_layout.addRow("Профиль сканирования:", self.trivy_profile_combo)
        self.trivy_hw_info_label = QLabel("Обнаружено: CPU/ОЗУ — нажмите рекомендацию")
        self.trivy_hw_info_label.setStyleSheet("color:#777;font-size:10px;padding:2px 0;")
        trivy_layout.addRow(self.trivy_hw_info_label)
        self.btn_trivy_recommend = QPushButton("Рекомендовать по ресурсам сервера")
        self.btn_trivy_recommend.setToolTip(
            "Подбор числа потоков Trivy и профиля на основе ядер CPU и объёма ОЗУ."
        )
        self.btn_trivy_recommend.clicked.connect(self._apply_recommended_trivy_resources)
        trivy_layout.addRow(self.btn_trivy_recommend)

        self.trivy_timeout_spin = QSpinBox()
        self.trivy_timeout_spin.setRange(1, 120)
        trivy_layout.addRow("Таймаут сканирования (мин):", self.trivy_timeout_spin)
        self.trivy_threads_spin = QSpinBox()
        self.trivy_threads_spin.setRange(1, 32)
        trivy_layout.addRow("Потоки сканирования:", self.trivy_threads_spin)

        self.trivy_severity_combo = QComboBox()
        self.trivy_severity_combo.addItems([
            "HIGH,CRITICAL",
            "MEDIUM,HIGH,CRITICAL",
            "LOW,MEDIUM,HIGH,CRITICAL",
        ])
        trivy_layout.addRow("Уровни критичности:", self.trivy_severity_combo)

        self.trivy_checks_combo = QComboBox()
        self.trivy_checks_combo.addItems(["vuln", "vuln,secret"])
        trivy_layout.addRow("Типы проверок:", self.trivy_checks_combo)
        scan_layout.addWidget(trivy_group)

        nuclei_group = QGroupBox("Параметры Nuclei (сервер)")
        nuclei_layout = QFormLayout(nuclei_group)
        self.nuclei_profile_combo = QComboBox()
        self.nuclei_profile_combo.addItems([
            "Быстрый (Fast)",
            "Сбалансированный (Balanced)",
            "Точный (Accurate)",
        ])
        self.nuclei_profile_combo.setCurrentText("Сбалансированный (Balanced)")
        nuclei_layout.addRow("Профиль сканирования:", self.nuclei_profile_combo)
        self.nuclei_concurrency_spin = QSpinBox()
        self.nuclei_concurrency_spin.setRange(5, 150)
        self.nuclei_timeout_spin = QSpinBox()
        self.nuclei_timeout_spin.setRange(1, 30)
        self.nuclei_retries_spin = QSpinBox()
        self.nuclei_retries_spin.setRange(0, 5)
        self.nuclei_mhe_spin = QSpinBox()
        self.nuclei_mhe_spin.setRange(1000, 200000)
        self.nuclei_mhe_spin.setSingleStep(5000)
        nuclei_layout.addRow("Потоки/параллелизм (-c):", self.nuclei_concurrency_spin)
        nuclei_layout.addRow("Таймаут запроса (сек):", self.nuclei_timeout_spin)
        nuclei_layout.addRow("Количество повторов:", self.nuclei_retries_spin)
        nuclei_layout.addRow("Предел ошибок хоста (-mhe):", self.nuclei_mhe_spin)
        scan_layout.addWidget(nuclei_group)

        scan_help = QLabel(
            "Пояснение: «Типы проверок» = vuln (поиск CVE), secret (поиск секретов в файлах). "
            "Профиль применяет рекомендуемые значения, после чего можно скорректировать поля вручную."
        )
        scan_help.setStyleSheet(_HINT_NEUTRAL)
        scan_help.setWordWrap(True)
        scan_layout.addWidget(scan_help)
        scan_layout.addStretch()

        self.trivy_profile_combo.currentTextChanged.connect(lambda _p: self._apply_trivy_profile())
        self._apply_trivy_profile()
        self.nuclei_profile_combo.currentTextChanged.connect(lambda _p: self._apply_nuclei_profile())
        self._apply_nuclei_profile()

        # Корневой контейнер вкладки "Настройки" с подвкладками
        settings_root = QWidget()
        settings_root_layout = QVBoxLayout(settings_root)
        settings_root_layout.setContentsMargins(0, 0, 0, 0)
        settings_root_layout.setSpacing(6)
        sub_tabs = QTabWidget()
        sub_tabs.addTab(scroll_area, "Настройки корреляции")
        sub_tabs.addTab(scan_settings, "Настройки сканирования")
        settings_root_layout.addWidget(sub_tabs)
        self.tabs.addTab(settings_root, "⚙️ Настройки")
    def _apply_correlation_settings(self):
        """Применить пользовательские настройки корреляции."""
        try:
            # Собираем настройки
            settings = {
                'max_score': self.max_score_spin.value(),
                'feasible_threshold': self.feasible_threshold_spin.value(),
                'partially_feasible_threshold': self.partially_threshold_spin.value(),
                'not_feasible_threshold': self.not_feasible_threshold_spin.value(),
                'network_weight': self.network_weight_spin.value(),
                'trivy_weight': self.trivy_weight_spin.value(),
                'software_weight': self.software_weight_spin.value(),
                'scanner_weight': self.scanner_weight_spin.value(),
                'patch_weight': self.patch_weight_spin.value(),
                'protection_weight': self.protection_weight_spin.value(),
            }

            # Сохраняем настройки в глобальном состоянии
            from server.api_server import state
            state.correlation_settings = settings

            # Обновляем статус
            self.settings_status_label.setText("✅ Настройки применены")
            self.settings_status_label.setStyleSheet("color:#8a8;font-size:11px;padding:4px;")

            # Обновляем текст текущих параметров
            self._update_current_settings_text(settings)

            hint = (
                "Параметры сохранены. Чтобы пересчитать таблицу и отчёт по уже полученным данным атакующего, "
                "нажмите «Перезапустить корреляцию»."
                if self._last_scan_data
                else "Параметры сохранены. После получения данных от атакующего корреляция выполнится с этими "
                "параметрами; для повторного пересчёта используйте «Перезапустить корреляцию»."
            )
            QMessageBox.information(self, "Настройки применены", hint)
            self._sync_restart_correlation_button_state()

        except Exception as e:
            logger.error(f"Ошибка применения настроек: {e}", exc_info=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось применить настройки:\n{e}")
    def _reset_correlation_settings(self):
        """Сбросить настройки к значениям по умолчанию."""
        try:
            # Значения по умолчанию
            self.max_score_spin.setValue(100)
            self.feasible_threshold_spin.setValue(60)
            self.partially_threshold_spin.setValue(40)
            self.not_feasible_threshold_spin.setValue(20)
            self.network_weight_spin.setValue(30)
            self.trivy_weight_spin.setValue(35)
            self.software_weight_spin.setValue(20)
            self.scanner_weight_spin.setValue(30)
            self.patch_weight_spin.setValue(10)
            self.protection_weight_spin.setValue(5)

            # Сбрасываем настройки в глобальном состоянии
            from server.api_server import state
            state.correlation_settings = None

            # Обновляем статус
            self.settings_status_label.setText("ℹ️ Используются значения по умолчанию")
            self.settings_status_label.setStyleSheet("color:#666;font-size:11px;padding:4px;")

            # Обновляем текст текущих параметров
            default_settings = {
                'max_score': 100,
                'feasible_threshold': 60,
                'partially_feasible_threshold': 40,
                'not_feasible_threshold': 20,
                'network_weight': 30,
                'trivy_weight': 35,
                'software_weight': 20,
                'scanner_weight': 30,
                'patch_weight': 10,
                'protection_weight': 5,
            }
            self._update_current_settings_text(default_settings)

            QMessageBox.information(
                self, "Настройки сброшены",
                "Параметры корреляции сброшены к значениям по умолчанию. "
                "Для пересчёта по данным атакующего нажмите «Перезапустить корреляцию», если такие данные уже есть.",
            )
            self._sync_restart_correlation_button_state()

        except Exception as e:
            logger.error(f"Ошибка сброса настроек: {e}", exc_info=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось сбросить настройки:\n{e}")
    def _update_current_settings_text(self, settings):
        """Обновить текст с текущими параметрами корреляции."""
        try:
            text = "ТЕКУЩИЕ ПАРАМЕТРЫ КОРРЕЛЯЦИИ:\n\n"
            text += f"📊 Пороги реализуемости:\n"
            text += f"   • Максимальный score: {settings['max_score']}\n"
            text += f"   • РЕАЛИЗУЕМА (>=): {settings['feasible_threshold']}\n"
            text += f"   • ЧАСТИЧНО РЕАЛИЗУЕМА (>=): {settings['partially_feasible_threshold']}\n"
            text += f"   • НЕ РЕАЛИЗУЕМА (<=): {settings['not_feasible_threshold']}\n\n"
            text += f"⚖️  Веса факторов:\n"
            text += f"   • Сетевая доступность: {settings['network_weight']} баллов\n"
            text += f"   • Подтверждение Trivy: {settings['trivy_weight']} баллов\n"
            text += f"   • Уязвимое ПО: {settings['software_weight']} баллов\n"
            text += f"   • Подтверждение сканером: {settings['scanner_weight']} баллов\n\n"
            text += f"   • Состояние обновлений: {settings.get('patch_weight', 10)} баллов\n"
            text += f"   • Ослабление защиты (FW/AV): {settings.get('protection_weight', 5)} баллов\n\n"
            text += "💡 Эти параметры используются для оценки реализуемости атак."

            self.current_settings_text.setPlainText(text)

        except Exception as e:
            logger.error(f"Ошибка обновления текста параметров: {e}", exc_info=True)
            self.current_settings_text.setPlainText(
                f"Ошибка отображения параметров: {e}"
            )
    def _build_attack_selector_tab(self):
        """Вкладка ручного выбора вектора атаки."""
        at = QWidget()
        atl = QVBoxLayout(at)
        # Заголовок
        title = QLabel("⚔️ Ручной выбор вектора атаки (учебные цели)")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        atl.addWidget(title)
        warn = QLabel("⚠️ Только для авторизованных учебных Red Team / Blue Team учений!")
        warn.setStyleSheet("color:#c44;font-size:11px;padding:4px 0;")
        atl.addWidget(warn)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        # Левая часть — выбор
        left_w = QWidget()
        left_l = QVBoxLayout(left_w)
        left_l.setContentsMargins(0, 0, 0, 0)
        # Фильтр по типу атаки
        filter_g = QGroupBox("Фильтр")
        filter_l = QVBoxLayout(filter_g)
        filter_l.addWidget(QLabel("Тип атаки:"))
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItem("Все типы")
        self.attack_type_combo.currentTextChanged.connect(self._filter_attack_vectors)
        filter_l.addWidget(self.attack_type_combo)
        filter_l.addWidget(QLabel("Поиск по CVE / названию:"))
        self.attack_search = QLineEdit()
        self.attack_search.setPlaceholderText("Введите CVE ID или название...")
        self.attack_search.textChanged.connect(self._filter_attack_vectors)
        filter_l.addWidget(self.attack_search)
        left_l.addWidget(filter_g)
        # Список векторов атак
        vectors_g = QGroupBox("Доступные векторы атак")
        vectors_l = QVBoxLayout(vectors_g)
        self.attack_vectors_list = QListWidget()
        self.attack_vectors_list.currentItemChanged.connect(self._on_attack_vector_selected)
        vectors_l.addWidget(self.attack_vectors_list)
        left_l.addWidget(vectors_g)
        # IP цели
        ip_g = QGroupBox("Параметры атаки")
        ip_l = QFormLayout(ip_g)
        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText("192.168.1.100")
        self.target_ip_edit.setText("<TARGET_IP>")
        ip_l.addRow("IP цели:", self.target_ip_edit)
        left_l.addWidget(ip_g)
        self.btn_show_attack = QPushButton("🔍 Показать инструменты атаки")
        self.btn_show_attack.clicked.connect(self._show_attack_details)
        self.btn_show_attack.setEnabled(False)
        left_l.addWidget(self.btn_show_attack)
        self.btn_gen_attack_report = QPushButton("📄 Создать отчёт по выбранному вектору")
        self.btn_gen_attack_report.clicked.connect(self._generate_attack_report)
        self.btn_gen_attack_report.setEnabled(False)
        left_l.addWidget(self.btn_gen_attack_report)
        splitter.addWidget(left_w)
        # Правая часть — детали
        right_w = QWidget()
        right_l = QVBoxLayout(right_w)
        right_l.setContentsMargins(0, 0, 0, 0)
        details_g = QGroupBox("Детали вектора атаки")
        details_l = QVBoxLayout(details_g)
        self.attack_details_text = QTextEdit()
        self.attack_details_text.setReadOnly(True)
        self.attack_details_text.setFont(QFont("Consolas", 10))
        details_l.addWidget(self.attack_details_text)
        right_l.addWidget(details_g)
        splitter.addWidget(right_w)
        splitter.setSizes([350, 650])
        atl.addWidget(splitter, 1)
        self.tabs.addTab(at, "⚔️ Выбор атаки")
        self._attack_vectors_data = []
    def _build_history_tab(self):
        """Вкладка истории отчётов."""
        ht = QWidget()
        htl = QVBoxLayout(ht)
        title = QLabel("📋 История отчётов")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color:#888;padding:6px 0;")
        htl.addWidget(title)
        # Панель управления историей
        ctrl = QHBoxLayout()
        self.btn_refresh_history = QPushButton("🔄 Обновить")
        self.btn_refresh_history.clicked.connect(self._refresh_history)
        ctrl.addWidget(self.btn_refresh_history)
        self.btn_open_history_report = QPushButton("📂 Открыть")
        self.btn_open_history_report.clicked.connect(self._open_history_report)
        self.btn_open_history_report.setEnabled(False)
        ctrl.addWidget(self.btn_open_history_report)
        self.btn_delete_history = QPushButton("🗑️ Удалить запись")
        self.btn_delete_history.clicked.connect(self._delete_history_record)
        self.btn_delete_history.setEnabled(False)
        ctrl.addWidget(self.btn_delete_history)
        self.btn_delete_with_files = QPushButton("🗑️ Удалить с файлами")
        self.btn_delete_with_files.clicked.connect(self._delete_history_with_files)
        self.btn_delete_with_files.setEnabled(False)
        ctrl.addWidget(self.btn_delete_with_files)
        ctrl.addStretch()
        htl.addLayout(ctrl)
        # Таблица истории
        self.history_table = QTableWidget(0, 8)
        self.history_table.setHorizontalHeaderLabels([
            "Дата", "Хост", "ОС", "Всего", "Реализуемых", "CRITICAL", "HIGH", "Уровень риска"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(False)
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.history_table.setColumnWidth(2, 80)
        self.history_table.setColumnWidth(3, 60)
        self.history_table.setColumnWidth(4, 90)
        self.history_table.setColumnWidth(5, 70)
        self.history_table.setColumnWidth(6, 55)
        self.history_table.setColumnWidth(7, 100)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.itemSelectionChanged.connect(self._on_history_selection_changed)
        self.history_table.doubleClicked.connect(self._open_history_report)
        htl.addWidget(self.history_table, 1)
        # Детали выбранной записи
        self.history_detail = QLabel("Выберите запись для просмотра деталей")
        self.history_detail.setStyleSheet("color:#666;font-size:11px;padding:4px;")
        self.history_detail.setWordWrap(True)
        htl.addWidget(self.history_detail)
        self.tabs.addTab(ht, "📋 История")
    def _build_log_tab(self):
        lt = QWidget()
        ltl = QVBoxLayout(lt)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        ltl.addWidget(self.log_output)
        self.tabs.addTab(lt, "📝 Лог")
    # ─────────────────────────────────────────
    #  Логирование
    # ─────────────────────────────────────────
    def _on_log_message(self, msg, level):
        self.log_signal.emit(msg, level)
    def _append_log(self, msg, level):
        c = {"ERROR": "#b55", "WARNING": "#a85", "CRITICAL": "#c44"}.get(level, "#888")
        self.log_output.append(f'<span style="color:{c}">{msg}</span>')
        self.log_output.moveCursor(QTextCursor.MoveOperation.End)
    # ─────────────────────────────────────────
    #  Проверка порта
    # ─────────────────────────────────────────
    def _check_port_availability(self):
        p = self.port_spin.value()
        ok, d = is_port_available(p)
        if ok:
            self.port_status_label.setText(f"Порт {p} свободен")
            self.port_status_label.setStyleSheet("color:#8a8;font-size:10px;")
        else:
            self.port_status_label.setText(f"ЗАНЯТ: {d}")
            self.port_status_label.setStyleSheet("color:#b55;font-size:10px;")
    # ─────────────────────────────────────────
    #  Анализ системы
    # ─────────────────────────────────────────
    def _start_analysis(self):
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Анализ системы...")
        self.analysis_worker = AnalysisWorker()
        self.analysis_worker.finished.connect(self._on_analysis_done)
        self.analysis_worker.error.connect(self._on_analysis_error)
        self.analysis_worker.start()
    def _on_analysis_done(self, result):
        self.system_info = result["info"]
        self.system_summary = result["summary"]
        self.system_analyzer = result["analyzer"]  # Сохраняем анализатор для Trivy
        self.sys_table.setRowCount(0)
        rows = [
            ("ОС", self.system_summary.get("os", "?")),
            ("Имя хоста", self.system_summary.get("hostname", "?")),
            ("IP-адреса", ", ".join(self.system_summary.get("ip_addresses", []))),
            ("ПО", str(self.system_summary.get("installed_software_count", 0))),
            ("Службы", str(self.system_summary.get("running_services_count", 0))),
            ("Порты", str(self.system_summary.get("open_ports_count", 0))),
            ("Файрвол", "Активен" if self.system_summary.get("firewall") else "Не активен"),
            ("Антивирус", "Активен" if self.system_summary.get("antivirus") else "Не активен"),
            ("RDP", "Вкл" if self.system_summary.get("has_rdp") else "Выкл"),
            ("SMB", "Да" if self.system_summary.get("has_smb") else "Нет"),
            ("БД", ", ".join(self.system_summary.get("database_types", [])) or "Нет"),
        ]
        for p, v in rows:
            r = self.sys_table.rowCount()
            self.sys_table.insertRow(r)
            self.sys_table.setItem(r, 0, QTableWidgetItem(str(p)))
            self.sys_table.setItem(r, 1, QTableWidgetItem(str(v)))

        self._update_software_tab(self.system_info) # Обновляем вкладку ПО

        # Сохраняем результат сканирования в историю
        import time
        scan_start = time.time()
        record = ScanHistory.from_system_info(
            self.system_info, 
            self.system_summary,
            scan_duration=0.0,  # Время анализа не измеряется точно здесь
            notes="Автоматическое сканирование системы"
        )
        self.scan_history.add_record(record)
        self._update_stats()

        self.btn_analyze.setText("1. Анализ системы (выполнен)")
        self.btn_analyze.setEnabled(True)
        self.btn_load_db.setEnabled(True)
        self.btn_load_toolkit.setEnabled(True)
        self.btn_trivy_scan.setEnabled(True)  # Включаем кнопку Trivy
        self.btn_local_nmap.setEnabled(True)
        self.btn_local_nuclei.setEnabled(True)
        self.btn_local_parallel_scan.setEnabled(True)
    def _on_analysis_error(self, e):
        self.btn_analyze.setText("1. Анализ системы")
        self.btn_analyze.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", f"Ошибка анализа:\n{e}")
    # ─────────────────────────────────────────
    #  Загрузка баз данных
    # ─────────────────────────────────────────
    def _load_databases(self):
        self.btn_load_db.setEnabled(False)
        self.btn_load_db.setText("Загрузка...")
        self.db_worker = DBLoadWorker()
        self.db_worker.finished.connect(self._on_db_loaded)
        self.db_worker.error.connect(self._on_db_error)
        self.db_worker.start()
    def _on_db_loaded(self, db):
        self.vuln_db = db
        self.btn_load_db.setText("2. Базы (загружены)")
        self.btn_load_db.setEnabled(True)
        self.btn_vuln_scan.setEnabled(True)
        # НЕ разблокируем кнопку сервера здесь - ждём Trivy
        self._update_stats()
        self._sync_restart_correlation_button_state()
    def _on_db_error(self, e):
        self.btn_load_db.setText("2. Загрузить базы CVE/CWE/CAPEC/MITRE")
        self.btn_load_db.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", f"Ошибка БД:\n{e}")
    # ─────────────────────────────────────────
    #  Загрузка Toolkit (инструменты атак/защиты)
    # ─────────────────────────────────────────
    def _load_toolkit(self):
        self.btn_load_toolkit.setEnabled(False)
        self.btn_load_toolkit.setText("Загрузка инструментов...")
        self.tk_worker = ToolkitLoadWorker()
        self.tk_worker.finished.connect(self._on_toolkit_loaded)
        self.tk_worker.error.connect(self._on_toolkit_error)
        self.tk_worker.start()
    def _on_toolkit_loaded(self, tk):
        self.toolkit = tk
        self.btn_load_toolkit.setText("2б. Инструменты (загружены)")
        self.btn_load_toolkit.setEnabled(True)
        self.btn_generate_manual.setEnabled(True)
        logger.info(f"[TOOLKIT] Загружено {len(tk.tools_db)} инструментов атаки, {len(tk.defense_db)} мер защиты")
    def _on_toolkit_error(self, e):
        self.btn_load_toolkit.setText("2б. Загрузить базу инструментов")
        self.btn_load_toolkit.setEnabled(True)
        QMessageBox.warning(self, "Предупреждение", f"Не удалось загрузить базу инструментов:\n{e}\n\nОтчёты будут создаваться без детальных инструкций.")
    # ─────────────────────────────────────────
    #  Вкладка выбора вектора атаки
    # ─────────────────────────────────────────
    def _populate_attack_selector(self):
        """Заполнить список векторов атак из toolkit."""
        if not self.toolkit:
            return
        # Типы атак в фильтр
        self.attack_type_combo.blockSignals(True)
        self.attack_type_combo.clear()
        self.attack_type_combo.addItem("Все типы")
        for at in self.toolkit.get_all_attack_types():
            self.attack_type_combo.addItem(at)
        self.attack_type_combo.blockSignals(False)
        # Векторы
        self._attack_vectors_data = self.toolkit.get_available_attack_vectors()
        self._update_attack_vectors_list(self._attack_vectors_data)
    def _update_attack_vectors_list(self, vectors: list):
        self.attack_vectors_list.clear()
        for v in vectors:
            cve = v.get("cve_id", "")
            tool = v.get("tool_name", "")
            skill = v.get("skill_level", "")
            label = f"{cve}  —  {tool}  [{skill}]"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, v)
            skill_colors = {
                "Beginner": QColor("#3fb950"),
                "Intermediate": QColor("#d29922"),
                "Advanced": QColor("#e67e22"),
                "Expert": QColor("#e74c3c"),
            }
            item.setForeground(skill_colors.get(skill, QColor("#888")))
            self.attack_vectors_list.addItem(item)
    def _filter_attack_vectors(self):
        if not self._attack_vectors_data:
            return
        attack_type = self.attack_type_combo.currentText()
        search = self.attack_search.text().lower()
        filtered = []
        for v in self._attack_vectors_data:
            if attack_type != "Все типы" and attack_type not in v.get("attack_types", []):
                continue
            if search and search not in v.get("cve_id", "").lower() and search not in v.get("tool_name", "").lower():
                continue
            filtered.append(v)
        self._update_attack_vectors_list(filtered)
    def _on_attack_vector_selected(self, current, previous):
        if not current:
            self.btn_show_attack.setEnabled(False)
            self.btn_gen_attack_report.setEnabled(False)
            return
        self.btn_show_attack.setEnabled(True)
        self.btn_gen_attack_report.setEnabled(bool(self.vuln_db and self.system_info))
    def _show_attack_details(self):
        item = self.attack_vectors_list.currentItem()
        if not item:
            return
        v = item.data(Qt.ItemDataRole.UserRole)
        if not v:
            return
        cve_id = v.get("cve_id", "")
        tool_name = v.get("tool_name", "")
        target_ip = self.target_ip_edit.text().strip() or "<TARGET_IP>"
        text = f"═══════════════════════════════════════\n"
        text += f"  ВЕКТОР АТАКИ: {cve_id}\n"
        text += f"  Инструмент:   {tool_name}\n"
        text += f"  Уровень:      {v.get('skill_level', '?')}\n"
        text += f"  Фазы:         {', '.join(v.get('phases', []))}\n"
        text += f"═══════════════════════════════════════\n\n"
        if self.toolkit:
            tools = self.toolkit.get_attack_commands(cve_id, target_ip)
            if tools:
                for tool in tools:
                    text += f"▸ Инструмент: {tool['tool_name']}\n"
                    text += f"  Тип: {tool['tool_type']}\n"
                    text += f"  Описание: {tool['description']}\n"
                    text += f"  URL: {tool.get('url', '—')}\n"
                    text += f"\n  Команды:\n"
                    for cmd in tool.get("commands", []):
                        text += f"  {cmd}\n"
                    text += "\n"
            # Меры защиты
            defense = self.toolkit.get_defense_tools(cve_id)
            if defense:
                text += "═══════════════════════════════════════\n"
                text += "  МЕРЫ ЗАЩИТЫ:\n"
                text += "═══════════════════════════════════════\n\n"
                for d in defense:
                    text += f"▸ {d.get('tool_name', '')} — {d.get('defense_name', '')}\n"
                    text += f"  Приоритет: {d.get('priority', '?')}\n"
                    text += f"  Описание: {d.get('tool_description', d.get('description', ''))}\n"
                    cmds = d.get("commands", [])
                    if cmds:
                        text += "\n  Команды защиты:\n"
                        for cmd in cmds:
                            text += f"  {cmd}\n"
                    text += "\n"
        self.attack_details_text.setPlainText(text)
    def _generate_attack_report(self):
        """Генерировать отчёт по выбранному вектору атаки."""
        item = self.attack_vectors_list.currentItem()
        if not item or not self.vuln_db or not self.system_info:
            QMessageBox.warning(self, "Предупреждение", "Сначала выполните анализ системы и загрузите базы данных.")
            return
        v = item.data(Qt.ItemDataRole.UserRole)
        cve_id = v.get("cve_id", "")
        target_ip = self.target_ip_edit.text().strip() or "<TARGET_IP>"
        # Создаём ScanResult с одним вектором
        from common.models import ScanResult, AttackVector as AV
        scan_result = ScanResult(
            scanner_ip=target_ip,
            target_ip=self.system_summary.get("ip_addresses", [""])[0] if self.system_summary else "",
            scan_timestamp=datetime.now().isoformat(),
        )
        scan_result.attack_vectors.append(AV(
            id=cve_id,
            name=f"Ручной выбор: {cve_id}",
            description=f"Вектор атаки выбран вручную: {cve_id}",
            target_service=v.get("attack_types", [""])[0] if v.get("attack_types") else "",
        ))
        cor = AttackCorrelator(self.system_info, self.vuln_db, trivy_result=getattr(self, 'trivy_result', None))
        results = cor.correlate(scan_result)
        summary = cor.get_summary()
        rd = os.path.join(PROJECT_DIR, "reports")
        os.makedirs(rd, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rep = ReportGenerator(
            self.system_summary or {},
            results,
            summary,
            toolkit=self.toolkit,
            attacker_scan_data={"target_ip": target_ip},
        )
        hp = rep.generate_html(os.path.join(rd, f"report_{ts}.html"))
        rep.generate_json(os.path.join(rd, f"report_{ts}.json"))
        self.last_report_path = hp
        self.btn_open_report.setEnabled(True)
        self._add_to_history(results, summary, ts, hp, os.path.join(rd, f"report_{ts}.json"))
        self.update_results_signal.emit(results)
        webbrowser.open(f"file:///{hp}")
    # ─────────────────────────────────────────
    #  Локальное сканирование
    # ─────────────────────────────────────────
    def _start_vuln_scan(self):
        self.btn_vuln_scan.setEnabled(False)
        self.btn_vuln_scan.setText("Сканирование...")
        self.vuln_progress.setVisible(True)
        self.vuln_progress.setValue(0)
        self.vuln_table.setRowCount(0)
        self.vuln_worker = VulnScanWorker()
        self.vuln_worker.finished.connect(self._on_vuln_scan_done)
        self.vuln_worker.progress.connect(self._on_vuln_scan_progress)
        self.vuln_worker.error.connect(self._on_vuln_scan_error)
        self.vuln_worker.start()
    def _on_vuln_scan_progress(self, c, t, m):
        self.vuln_progress.setValue(int(c / t * 100) if t else 0)
        self.vuln_progress.setFormat(f"{m} ({c}/{t})")
    def _on_vuln_scan_done(self, report):
        self.vuln_scan_report = report
        self.vuln_progress.setValue(100)
        self.vuln_progress.setVisible(False)
        self.vuln_table.setRowCount(0)
        so = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for f in sorted(report.findings, key=lambda x: so.get(x.severity, 5)):
            r = self.vuln_table.rowCount()
            self.vuln_table.insertRow(r)
            self.vuln_table.setItem(r, 0, QTableWidgetItem(str(f.check_id)))
            si = QTableWidgetItem(str(f.severity))
            si.setForeground(QColor({"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "INFO": "#668"}.get(f.severity, "#888")))
            self.vuln_table.setItem(r, 1, si)
            sti = QTableWidgetItem(str(f.status))
            sti.setForeground(QColor({"VULNERABLE": "#b55", "SECURE": "#696", "UNKNOWN": "#888"}.get(f.status, "#888")))
            self.vuln_table.setItem(r, 2, sti)
            self.vuln_table.setItem(r, 3, QTableWidgetItem(str(f.category)))
            d = str(f.title) + (f" | {f.recommendation}" if f.recommendation else "")
            self.vuln_table.setItem(r, 4, QTableWidgetItem(d))
        self.vuln_summary_label.setText(
            f"Проверок:{report.total_checks}  Уязвимо:{report.vulnerable}  "
            f"Защищено:{report.secure}  Риск:{report.risk_score:.1f}/100"
        )
        self.btn_vuln_scan.setText("3. Локальный скан (выполнен)")
        self.btn_vuln_scan.setEnabled(True)
        self.tabs.setCurrentIndex(1)
    def _on_vuln_scan_error(self, e):
        self.vuln_progress.setVisible(False)
        self.btn_vuln_scan.setText("3. Локальное сканирование")
        self.btn_vuln_scan.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", str(e))
    
    # ─────────────────────────────────────────
    #  Trivy сканирование
    # ─────────────────────────────────────────
    def _start_trivy_scan(self):
        """Запуск сканирования Trivy"""
        if not self.system_info:
            QMessageBox.warning(self, "Предупреждение", "Сначала выполните анализ системы!")
            return
        
        self.btn_trivy_scan.setEnabled(False)
        self.btn_trivy_scan.setText("Сканирование Trivy...")
        self.trivy_progress.setVisible(True)
        self.trivy_progress.setValue(0)
        self.trivy_table.setRowCount(0)
        self.trivy_status_label.setText("🔄 Сканирование Trivy...")
        self.trivy_status_label.setStyleSheet("color:#a85;font-size:11px;padding:4px;")
        
        scan_options = self._get_trivy_scan_options()
        self.trivy_worker = TrivyScanWorker(
            self.system_analyzer if hasattr(self, 'system_analyzer') else None,
            scan_options=scan_options,
        )
        self.trivy_worker.finished.connect(self._on_trivy_scan_done)
        self.trivy_worker.progress.connect(self._on_trivy_scan_progress)
        self.trivy_worker.error.connect(self._on_trivy_scan_error)
        self.trivy_worker.start()
    
    def _on_trivy_scan_progress(self, percent, message):
        """Обновление прогресса Trivy"""
        self.trivy_progress.setValue(percent)
        self.trivy_progress.setFormat(f"{message} ({percent}%)")
        if hasattr(self, "server_trivy_progress"):
            self.server_trivy_progress.setValue(percent)
            self.server_trivy_progress.setFormat(f"{message} ({percent}%)")
        if hasattr(self, "server_trivy_status"):
            self.server_trivy_status.setText(f"🔄 {message}")
        if hasattr(self, "server_trivy_log"):
            self.server_trivy_log.append(f"{datetime.now().strftime('%H:%M:%S')}  {message} ({percent}%)")
            self.server_trivy_log.moveCursor(QTextCursor.MoveOperation.End)
    
    def _on_trivy_scan_done(self, summary):
        """Обработка результатов Trivy"""
        self.trivy_progress.setValue(100)
        self.trivy_progress.setVisible(False)
        if hasattr(self, "server_trivy_progress"):
            self.server_trivy_progress.setValue(100)
            self.server_trivy_progress.setFormat("Готово")
        
        if summary.get("error"):
            err = str(summary.get("error") or "")
            err_low = err.lower()
            is_db_net = ("failed to download" in err_low) or ("db error" in err_low) or ("connection attempt failed" in err_low) or ("connectex" in err_low)
            if is_db_net:
                self.trivy_status_label.setText("⚠️ Trivy недоступен (нет доступа к DB). Продолжаем без Trivy.")
                self.trivy_status_label.setStyleSheet("color:#d29922;font-size:11px;padding:4px;")
                QMessageBox.information(
                    self,
                    "Trivy (офлайн)",
                    "Trivy не смог скачать/обновить базу уязвимостей (скорее всего нет доступа к ghcr.io / ecr / gcr).\n\n"
                    "Сканирование Trivy будет пропущено, корреляция продолжит работать без подтверждения Trivy."
                )
                self.trivy_summary = {"error": err, "skipped": True}
                self.trivy_result = None
                try:
                    from server.api_server import state
                    state.trivy_result = None
                except ImportError:
                    pass
                if self.system_info and self.vuln_db:
                    self.btn_server.setEnabled(True)
                self.btn_trivy_scan.setText("3б. Сканирование Trivy (пропущено)")
                self.btn_trivy_scan.setEnabled(True)
                if hasattr(self, "server_trivy_status"):
                    self.server_trivy_status.setText("⚠️ Trivy пропущен (нет доступа к DB)")
                if hasattr(self, "server_trivy_log"):
                    self.server_trivy_log.append("Trivy пропущен: нет доступа к базе уязвимостей.")
                return
            self.trivy_status_label.setText(f"❌ Ошибка: {err}")
            self.trivy_status_label.setStyleSheet("color:#b55;font-size:11px;padding:4px;")
            QMessageBox.warning(self, "Ошибка Trivy", f"Не удалось завершить сканирование:\n{err}")
            self.btn_trivy_scan.setText("3б. Сканирование Trivy (ошибка)")
            self.btn_trivy_scan.setEnabled(True)
            if hasattr(self, "server_trivy_status"):
                self.server_trivy_status.setText("❌ Ошибка Trivy")
            return
        
        # Сохраняем сводку
        self.trivy_summary = summary
        
        # Сохраняем полный результат Trivy для корреляции
        if hasattr(self, 'system_analyzer') and self.system_analyzer:
            self.trivy_result = getattr(self.system_analyzer.system_info, 'trivy_scan_result', None)
            
            # Динамически обновляем глобальный state API-сервера, если он уже запущен
            try:
                from server.api_server import state
                state.trivy_result = self.trivy_result
            except ImportError:
                pass

        # Обновляем статус
        total = summary.get("total_vulns", 0)
        self.trivy_status_label.setText(f"✅ Сканирование завершено! Найдено {total} уязвимостей")
        self.trivy_status_label.setStyleSheet("color:#8a8;font-size:11px;padding:4px;")

        # Разблокируем кнопку запуска сервера
        if self.system_info and self.vuln_db:
            self.btn_server.setEnabled(True)
        
        # Заполняем таблицу
        self.trivy_table.setRowCount(0)
        
        # Получаем уязвимости из system_info
        if self.system_info and self.system_info.trivy_scan_result:
            vulnerabilities = self.system_info.trivy_scan_result.get("vulnerabilities", [])
            
            # Сортируем по серьёзности
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "INFO": 5}
            sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.get("severity", "UNKNOWN"), 4))
            
            for vuln in sorted_vulns:
                row = self.trivy_table.rowCount()
                self.trivy_table.insertRow(row)
                
                # CVE-ID
                self.trivy_table.setItem(row, 0, QTableWidgetItem(vuln.get("vuln_id", "")))
                
                # ПО
                self.trivy_table.setItem(row, 1, QTableWidgetItem(vuln.get("pkg_name", "")))
                
                # Версия
                self.trivy_table.setItem(row, 2, QTableWidgetItem(vuln.get("installed_version", "")))
                
                # Исправлено
                fixed = vuln.get("fixed_version", "")
                fixed_item = QTableWidgetItem(fixed if fixed else "Нет исправления")
                if not fixed:
                    fixed_item.setForeground(QColor("#888"))
                self.trivy_table.setItem(row, 3, fixed_item)
                
                # Серьёзность
                sev = vuln.get("severity", "UNKNOWN")
                sev_item = QTableWidgetItem(sev)
                sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "UNKNOWN": "#888", "INFO": "#668"}.get(sev, "#888")
                sev_item.setForeground(QColor(sev_color))
                self.trivy_table.setItem(row, 4, sev_item)
                
                # Заголовок
                self.trivy_table.setItem(row, 5, QTableWidgetItem(vuln.get("title", "")[:200]))
                
                # CWE/CAPEC
                cwe_capec = ""
                cwe_ids = vuln.get("cwe_ids", [])
                capec_ids = vuln.get("capec_ids", [])
                if cwe_ids:
                    cwe_capec += "CWE: " + ", ".join(cwe_ids[:3])
                if capec_ids:
                    if cwe_capec:
                        cwe_capec += " | "
                    cwe_capec += "CAPEC: " + ", ".join(capec_ids[:3])
                self.trivy_table.setItem(row, 6, QTableWidgetItem(cwe_capec if cwe_capec else "—"))

            if hasattr(self, "server_trivy_table"):
                self.server_trivy_table.setRowCount(0)
                for vuln in sorted_vulns:
                    row = self.server_trivy_table.rowCount()
                    self.server_trivy_table.insertRow(row)
                    self.server_trivy_table.setItem(row, 0, QTableWidgetItem(vuln.get("vuln_id", "")))
                    self.server_trivy_table.setItem(row, 1, QTableWidgetItem(vuln.get("pkg_name", "")))
                    self.server_trivy_table.setItem(row, 2, QTableWidgetItem(vuln.get("installed_version", "")))
                    fixed = vuln.get("fixed_version", "")
                    fixed_item = QTableWidgetItem(fixed if fixed else "Нет исправления")
                    if not fixed:
                        fixed_item.setForeground(QColor("#888"))
                    self.server_trivy_table.setItem(row, 3, fixed_item)
                    sev = vuln.get("severity", "UNKNOWN")
                    sev_item = QTableWidgetItem(sev)
                    sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "UNKNOWN": "#888", "INFO": "#668"}.get(sev, "#888")
                    sev_item.setForeground(QColor(sev_color))
                    self.server_trivy_table.setItem(row, 4, sev_item)
                    self.server_trivy_table.setItem(row, 5, QTableWidgetItem(vuln.get("title", "")[:200]))
                    cwe_capec = ""
                    cwe_ids = vuln.get("cwe_ids", [])
                    capec_ids = vuln.get("capec_ids", [])
                    if cwe_ids:
                        cwe_capec += "CWE: " + ", ".join(cwe_ids[:3])
                    if capec_ids:
                        if cwe_capec:
                            cwe_capec += " | "
                        cwe_capec += "CAPEC: " + ", ".join(capec_ids[:3])
                    self.server_trivy_table.setItem(row, 6, QTableWidgetItem(cwe_capec if cwe_capec else "—"))
        
        # Обновляем сводку
        self.trivy_summary_label.setText(
            f"Всего уязвимостей: {summary.get('total_vulns', 0)}  |  "
            f"🔴 CRITICAL: {summary.get('critical', 0)}  |  "
            f"🟠 HIGH: {summary.get('high', 0)}  |  "
            f"🟡 MEDIUM: {summary.get('medium', 0)}  |  "
            f"🟢 LOW: {summary.get('low', 0)}  |  "
            f"Время: {summary.get('scan_duration', '?')}"
        )
        
        self.btn_trivy_scan.setText("3б. Сканирование Trivy (выполнено)")
        self.btn_trivy_scan.setEnabled(True)
        if hasattr(self, "server_trivy_status"):
            total = summary.get("total_vulns", 0)
            self.server_trivy_status.setText(f"✅ Trivy: найдено {total} уязвимостей")
        
        # Переключаемся на вкладку Trivy
        # Находим индекс вкладки Trivy
        for i in range(self.tabs.count()):
            if "Trivy" in self.tabs.tabText(i):
                self.tabs.setCurrentIndex(i)
                break
    
    def _on_trivy_scan_error(self, e):
        """Обработка ошибки Trivy"""
        self.trivy_progress.setVisible(False)
        self.trivy_status_label.setText(f"❌ Ошибка: {str(e)}")
        self.trivy_status_label.setStyleSheet("color:#b55;font-size:11px;padding:4px;")
        self.btn_trivy_scan.setText("3б. Сканирование Trivy (ошибка)")
        self.btn_trivy_scan.setEnabled(True)
        if hasattr(self, "server_trivy_status"):
            self.server_trivy_status.setText("❌ Ошибка Trivy")
        QMessageBox.critical(self, "Ошибка Trivy", str(e))

    def _ports_for_local_scanners(self) -> list[int]:
        if not self.system_info:
            return []
        ports = []
        for p in getattr(self.system_info, "open_ports", []) or []:
            try:
                ports.append(int(getattr(p, "port", 0)))
            except Exception:
                continue
        return sorted(set([p for p in ports if p > 0]))

    def _append_scanner_log(self, text: str):
        self._on_log_message(text, "INFO")

    def _start_local_nmap_scan(self):
        ports = self._ports_for_local_scanners()
        if not ports:
            QMessageBox.warning(self, "Предупреждение", "Нет портов для сканирования. Сначала выполните «Анализ системы».")
            return
        if self._server_scan_running.get("nmap"):
            return
        self._server_scan_running["nmap"] = True
        self._server_scan_ports["nmap"] = list(ports or [])
        self.btn_local_nmap.setEnabled(False)
        self.btn_local_parallel_scan.setEnabled(False)
        self.local_nmap_progress.setVisible(True)
        self.local_nmap_progress.setRange(0, 0)
        self.local_nmap_progress.setFormat("Nmap: сканирование...")
        if hasattr(self, "server_nmap_progress"):
            self.server_nmap_progress.setRange(0, 0)
            self.server_nmap_progress.setValue(0)
            self.server_nmap_progress.setFormat("Сканирование…")
        if hasattr(self, "server_nmap_status"):
            self.server_nmap_status.setText("🔄 Nmap: сканирование…")
        if hasattr(self, "server_nmap_log"):
            self.server_nmap_log.append(f"🔄 Запуск: портов {len(ports)}")
            self.server_nmap_log.moveCursor(QTextCursor.MoveOperation.End)
        self._append_scanner_log(f"[LOCAL] Запуск Nmap на сервере (localhost), портов: {len(ports)}")
        self.local_nmap_worker = LocalNmapScanWorker("127.0.0.1", ports)
        self.local_nmap_worker.finished.connect(self._on_local_nmap_done)
        self.local_nmap_worker.error.connect(self._on_local_nmap_error)
        self.local_nmap_worker.start()

    def _on_local_nmap_done(self, vulns: list, elapsed: float):
        self.server_scan_vulns["nmap"] = vulns or []
        vectors = self._vectors_from_scanner_vulns(vulns or [], found_by_prefix="Сервер: Nmap")
        self._merge_server_vectors(vectors)
        if hasattr(self, "server_nmap_progress"):
            self.server_nmap_progress.setRange(0, 100)
            self.server_nmap_progress.setValue(100)
            self.server_nmap_progress.setFormat(f"Готово ({len(vectors)} CVE, {elapsed:.1f}s)")
        if hasattr(self, "server_nmap_status"):
            self.server_nmap_status.setText(f"✅ Nmap: {len(vectors)} CVE, {elapsed:.1f}s")
        if hasattr(self, "server_nmap_log"):
            self.server_nmap_log.append(f"✅ Завершено: {len(vectors)} CVE-векторов, {elapsed:.1f}s")
            self.server_nmap_log.moveCursor(QTextCursor.MoveOperation.End)
        if hasattr(self, "server_nmap_table"):
            self.server_nmap_table.setRowCount(0)
            for v in (vulns or []):
                if not isinstance(v, dict):
                    continue
                row = self.server_nmap_table.rowCount()
                self.server_nmap_table.insertRow(row)
                self.server_nmap_table.setItem(row, 0, QTableWidgetItem(str(v.get("cve_id", "") or "")))
                sev = str(v.get("severity", "") or "").upper()
                sev_item = QTableWidgetItem(sev)
                sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "INFO": "#668"}.get(sev, "#888")
                sev_item.setForeground(QColor(sev_color))
                self.server_nmap_table.setItem(row, 1, sev_item)
                self.server_nmap_table.setItem(row, 2, QTableWidgetItem(str(v.get("port", "") or "")))
                self.server_nmap_table.setItem(row, 3, QTableWidgetItem(str(v.get("service", "") or "")[:120]))
                self.server_nmap_table.setItem(row, 4, QTableWidgetItem(str(v.get("script", "") or "")[:180]))
                self.server_nmap_table.setItem(row, 5, QTableWidgetItem(str(v.get("description", "") or "")[:300]))
        self._save_simple_scanner_history(
            NMAP_HISTORY_PREFIX,
            scanner_name="Nmap",
            target="127.0.0.1",
            ports=self._server_scan_ports.get("nmap") or [],
            elapsed=elapsed,
            vulnerabilities=vulns or [],
        )
        self._refresh_scan_histories()
        self.local_nmap_progress.setRange(0, 100)
        self.local_nmap_progress.setValue(100)
        self.local_nmap_progress.setFormat(f"Nmap: готово ({len(vectors)} CVE, {elapsed:.1f}s)")
        self._append_scanner_log(f"[LOCAL] Nmap завершён: {len(vectors)} CVE-векторов, {elapsed:.1f}s")
        self._server_scan_running["nmap"] = False
        self.btn_local_nmap.setEnabled(True)
        self.btn_local_parallel_scan.setEnabled(True and not self._server_scan_running.get("nuclei"))
        QTimer.singleShot(2000, lambda: self.local_nmap_progress.setVisible(False))

    def _on_local_nmap_error(self, e: str):
        self._append_scanner_log(f"[LOCAL] Ошибка Nmap: {e}")
        self.local_nmap_progress.setVisible(False)
        if hasattr(self, "server_nmap_status"):
            self.server_nmap_status.setText("❌ Ошибка Nmap")
        if hasattr(self, "server_nmap_progress"):
            self.server_nmap_progress.setRange(0, 100)
            self.server_nmap_progress.setValue(0)
            self.server_nmap_progress.setFormat("Ошибка")
        if hasattr(self, "server_nmap_log"):
            self.server_nmap_log.append(f"❌ {e}")
            self.server_nmap_log.moveCursor(QTextCursor.MoveOperation.End)
        self._server_scan_running["nmap"] = False
        self.btn_local_nmap.setEnabled(True)
        self.btn_local_parallel_scan.setEnabled(True and not self._server_scan_running.get("nuclei"))
        QMessageBox.warning(self, "Ошибка Nmap", str(e))

    def _start_local_nuclei_scan(self):
        ports = self._ports_for_local_scanners()
        if not ports:
            QMessageBox.warning(self, "Предупреждение", "Нет портов для сканирования. Сначала выполните «Анализ системы».")
            return
        if self._server_scan_running.get("nuclei"):
            return
        self._server_scan_running["nuclei"] = True
        self.btn_local_nuclei.setEnabled(False)
        self.btn_local_parallel_scan.setEnabled(False)
        self.local_nuclei_progress.setVisible(True)
        self.local_nuclei_progress.setRange(0, 100)
        self.local_nuclei_progress.setValue(0)
        self.local_nuclei_progress.setFormat("Nuclei: запуск...")
        self._append_scanner_log(f"[LOCAL] Запуск Nuclei на сервере (localhost), портов: {len(ports)}")
        self._server_scan_ports["nuclei"] = list(ports or [])
        nuclei_settings = self._get_nuclei_settings() if hasattr(self, "nuclei_concurrency_spin") else {}
        self.local_nuclei_worker = ServerNucleiWorker("127.0.0.1", ports, nuclei_settings)
        self.local_nuclei_worker.progress.connect(self._on_local_nuclei_progress)
        self.local_nuclei_worker.log_msg.connect(self._on_local_nuclei_log)
        self.local_nuclei_worker.finished.connect(self._on_local_nuclei_done)
        self.local_nuclei_worker.error.connect(self._on_local_nuclei_error)
        self.local_nuclei_worker.start()

    def _on_local_nuclei_progress(self, msg: str, percent: int):
        self.local_nuclei_progress.setValue(max(0, min(int(percent), 100)))
        self.local_nuclei_progress.setFormat(f"Nuclei: {msg} ({percent}%)")
        if hasattr(self, "server_nuclei_progress"):
            self.server_nuclei_progress.setValue(max(0, min(int(percent), 100)))
            self.server_nuclei_progress.setFormat(f"{msg} ({percent}%)")
        if hasattr(self, "server_nuclei_status"):
            self.server_nuclei_status.setText(f"🔄 Nuclei: {msg}")

    def _on_local_nuclei_log(self, msg: str):
        if hasattr(self, "server_nuclei_log"):
            self.server_nuclei_log.append(msg)
            self.server_nuclei_log.moveCursor(QTextCursor.MoveOperation.End)

    def _on_local_nuclei_done(self, vulns: list, elapsed: float):
        self.server_scan_vulns["nuclei"] = vulns or []
        vectors = self._vectors_from_scanner_vulns(vulns or [], found_by_prefix="Сервер: Nuclei")
        self._merge_server_vectors(vectors)
        self._save_simple_scanner_history(
            NUCLEI_HISTORY_PREFIX,
            scanner_name="Nuclei",
            target="127.0.0.1",
            ports=self._server_scan_ports.get("nuclei") or [],
            elapsed=elapsed,
            vulnerabilities=vulns or [],
        )
        self._refresh_scan_histories()
        self.local_nuclei_progress.setValue(100)
        self.local_nuclei_progress.setFormat(f"Nuclei: готово ({len(vectors)} CVE, {elapsed:.1f}s)")
        self._append_scanner_log(f"[LOCAL] Nuclei завершён: {len(vectors)} CVE-векторов, {elapsed:.1f}s")
        if hasattr(self, "server_nuclei_status"):
            self.server_nuclei_status.setText(f"✅ Nuclei: {len(vectors)} CVE, {elapsed:.1f}s")
        if hasattr(self, "server_nuclei_table"):
            self.server_nuclei_table.setRowCount(0)
            for v in (vulns or []):
                if not isinstance(v, dict):
                    continue
                row = self.server_nuclei_table.rowCount()
                self.server_nuclei_table.insertRow(row)
                self.server_nuclei_table.setItem(row, 0, QTableWidgetItem(str(v.get("cve_id", "") or "")))
                self.server_nuclei_table.setItem(row, 1, QTableWidgetItem(str(v.get("cwe_id", "") or "")))
                sev_item = QTableWidgetItem(str(v.get("severity", "") or ""))
                sev = str(v.get("severity", "") or "").upper()
                sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "INFO": "#668"}.get(sev, "#888")
                sev_item.setForeground(QColor(sev_color))
                self.server_nuclei_table.setItem(row, 2, sev_item)
                self.server_nuclei_table.setItem(row, 3, QTableWidgetItem(str(v.get("port", "") or "")))
                self.server_nuclei_table.setItem(row, 4, QTableWidgetItem(str(v.get("template", "") or "")[:200]))
                self.server_nuclei_table.setItem(row, 5, QTableWidgetItem(str(v.get("description", "") or "")[:300]))
        self._server_scan_running["nuclei"] = False
        self.btn_local_nuclei.setEnabled(True)
        self.btn_local_parallel_scan.setEnabled(True and not self._server_scan_running.get("nmap"))
        QTimer.singleShot(2000, lambda: self.local_nuclei_progress.setVisible(False))

    def _on_local_nuclei_error(self, e: str):
        self._append_scanner_log(f"[LOCAL] Ошибка Nuclei: {e}")
        self.local_nuclei_progress.setVisible(False)
        if hasattr(self, "server_nuclei_status"):
            self.server_nuclei_status.setText("❌ Ошибка Nuclei")
        if hasattr(self, "server_nuclei_progress"):
            self.server_nuclei_progress.setValue(0)
            self.server_nuclei_progress.setFormat("Ошибка")
        if hasattr(self, "server_nuclei_log"):
            self.server_nuclei_log.append(f"❌ {e}")
            self.server_nuclei_log.moveCursor(QTextCursor.MoveOperation.End)
        self._server_scan_running["nuclei"] = False
        self.btn_local_nuclei.setEnabled(True)
        self.btn_local_parallel_scan.setEnabled(True and not self._server_scan_running.get("nmap"))
        QMessageBox.warning(self, "Ошибка Nuclei", str(e))

    def _start_local_parallel_scan(self):
        ports = self._ports_for_local_scanners()
        if not ports:
            QMessageBox.warning(self, "Предупреждение", "Нет портов для сканирования. Сначала выполните «Анализ системы».")
            return
        if self._server_scan_running.get("nmap") or self._server_scan_running.get("nuclei"):
            return
        self.btn_local_parallel_scan.setEnabled(False)
        self.btn_local_nmap.setEnabled(False)
        self.btn_local_nuclei.setEnabled(False)
        self._append_scanner_log(f"[LOCAL] Параллельный запуск Nmap+Nuclei (localhost), портов: {len(ports)}")
        self._start_local_nmap_scan()
        self._start_local_nuclei_scan()

    def _vectors_from_scanner_vulns(self, vulns: list[dict], found_by_prefix: str) -> list[AttackVector]:
        out = []
        for v in vulns or []:
            if not isinstance(v, dict):
                continue
            cve_id = str(v.get("cve_id", "") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            src = str(v.get("source", "") or "Scanner").strip()
            sev = str(v.get("severity", "") or "MEDIUM").upper()
            desc = str(v.get("description", "") or "")
            service = str(v.get("service", "") or "")
            port = v.get("port", None)
            try:
                port_int = int(port) if port not in (None, "", "0", 0) else None
            except Exception:
                port_int = None
            out.append(AttackVector(
                id=f"AV-SERVER-{src.upper()}-{cve_id}",
                name=f"{cve_id} ({src}, Сервер)",
                description=f"{desc} (обнаружено на сервере; порт {port_int if port_int is not None else 'N/A'})",
                target_port=port_int,
                target_service=service,
                attack_type="known_vulnerability",
                severity=sev if sev in [s.value for s in Severity] else Severity.MEDIUM.value,
                tools_used=src,
                found_by=found_by_prefix,
                representative_cve_ids=[cve_id],
            ))
        return out

    def _merge_server_vectors(self, vectors: list[AttackVector]) -> None:
        existing_ids = set()
        for v in self.server_scan_vectors or []:
            try:
                existing_ids.add(getattr(v, "id", ""))
            except Exception:
                continue
        merged = list(self.server_scan_vectors or [])
        for v in vectors or []:
            vid = getattr(v, "id", "")
            if not vid or vid in existing_ids:
                continue
            existing_ids.add(vid)
            merged.append(v)
        self.server_scan_vectors = merged

    def _scan_data_dir(self) -> str:
        base_dir = PROJECT_DIR or application_base_dir()
        return os.path.join(base_dir, SCAN_HISTORY_DIR)

    def _severity_counters_from_vulns(self, vulns: list) -> dict:
        counters = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "INFO": 0}
        for v in vulns or []:
            if not isinstance(v, dict):
                continue
            sev = str(v.get("severity", "") or "UNKNOWN").upper()
            if sev not in counters:
                sev = "UNKNOWN"
            counters[sev] += 1
        return counters

    def _save_simple_scanner_history(
        self,
        prefix: str,
        scanner_name: str,
        target: str,
        ports: list,
        elapsed: float,
        vulnerabilities: list,
    ) -> str:
        try:
            data_dir = self._scan_data_dir()
            os.makedirs(data_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            fname = f"{prefix}{timestamp}{SCAN_HISTORY_SUFFIX}"
            fpath = os.path.join(data_dir, fname)
            counters = self._severity_counters_from_vulns(vulnerabilities or [])
            payload = {
                "scan_info": {
                    "timestamp": timestamp,
                    "scanner": str(scanner_name or ""),
                    "target": str(target or ""),
                    "ports": [int(p) for p in (ports or []) if str(p).isdigit()],
                    "elapsed_seconds": float(elapsed or 0.0),
                },
                "summary": {
                    "total_vulns": int(len(vulnerabilities or [])),
                    "critical": int(counters.get("CRITICAL", 0)),
                    "high": int(counters.get("HIGH", 0)),
                    "medium": int(counters.get("MEDIUM", 0)),
                    "low": int(counters.get("LOW", 0)),
                },
                "vulnerabilities": vulnerabilities or [],
            }
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            return fpath
        except Exception:
            return ""

    def _list_simple_scanner_history_records(self, prefix: str) -> list[dict]:
        out = []
        data_dir = self._scan_data_dir()
        if not os.path.isdir(data_dir):
            return out
        for fname in sorted(os.listdir(data_dir), reverse=True):
            if not (fname.startswith(prefix) and fname.endswith(SCAN_HISTORY_SUFFIX)):
                continue
            fpath = os.path.join(data_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    continue
                summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
                timestamp = ""
                scan_info = data.get("scan_info") if isinstance(data.get("scan_info"), dict) else {}
                timestamp = str(scan_info.get("timestamp", "") or "")
                if not timestamp:
                    timestamp = fname[len(prefix) : -len(SCAN_HISTORY_SUFFIX)]
                total = int(summary.get("total_vulns", 0) or 0)
                crit = int(summary.get("critical", 0) or 0)
                high = int(summary.get("high", 0) or 0)
                out.append(
                    {
                        "record_id": fname,
                        "filename": fname,
                        "filepath": fpath,
                        "timestamp": timestamp,
                        "total_vulns": total,
                        "critical": crit,
                        "high": high,
                    }
                )
            except Exception:
                continue
        return out

    def _refresh_scan_histories(self):
        try:
            self._refresh_trivy_history()
        except Exception:
            pass
        try:
            self._refresh_nmap_history()
        except Exception:
            pass
        try:
            self._refresh_nuclei_history()
        except Exception:
            pass

    def _refresh_nmap_history(self):
        if not hasattr(self, "nmap_hist_table"):
            return
        self.nmap_hist_table.setRowCount(0)
        records = self._list_simple_scanner_history_records(NMAP_HISTORY_PREFIX)
        for rec in records:
            row = self.nmap_hist_table.rowCount()
            self.nmap_hist_table.insertRow(row)
            self.nmap_hist_table.setItem(row, 0, QTableWidgetItem(str(rec.get("timestamp", ""))))
            self.nmap_hist_table.setItem(row, 1, QTableWidgetItem(str(rec.get("total_vulns", 0))))
            self.nmap_hist_table.setItem(row, 2, QTableWidgetItem(f"{rec.get('critical', 0)}/{rec.get('high', 0)}"))
            file_item = QTableWidgetItem(str(rec.get("filename", "")))
            file_item.setData(Qt.ItemDataRole.UserRole, rec.get("filepath", ""))
            file_item.setData(Qt.ItemDataRole.UserRole + 1, rec.get("record_id", ""))
            self.nmap_hist_table.setItem(row, 3, file_item)
        self._sync_nmap_hist_buttons()

    def _refresh_nuclei_history(self):
        if not hasattr(self, "nuclei_hist_table"):
            return
        self.nuclei_hist_table.setRowCount(0)
        records = self._list_simple_scanner_history_records(NUCLEI_HISTORY_PREFIX)
        for rec in records:
            row = self.nuclei_hist_table.rowCount()
            self.nuclei_hist_table.insertRow(row)
            self.nuclei_hist_table.setItem(row, 0, QTableWidgetItem(str(rec.get("timestamp", ""))))
            self.nuclei_hist_table.setItem(row, 1, QTableWidgetItem(str(rec.get("total_vulns", 0))))
            self.nuclei_hist_table.setItem(row, 2, QTableWidgetItem(f"{rec.get('critical', 0)}/{rec.get('high', 0)}"))
            file_item = QTableWidgetItem(str(rec.get("filename", "")))
            file_item.setData(Qt.ItemDataRole.UserRole, rec.get("filepath", ""))
            file_item.setData(Qt.ItemDataRole.UserRole + 1, rec.get("record_id", ""))
            self.nuclei_hist_table.setItem(row, 3, file_item)
        self._sync_nuclei_hist_buttons()

    def _sync_nmap_hist_buttons(self):
        has_sel = bool(self.nmap_hist_table.selectedItems()) if hasattr(self, "nmap_hist_table") else False
        if hasattr(self, "btn_load_nmap_hist"):
            self.btn_load_nmap_hist.setEnabled(has_sel)
        if hasattr(self, "btn_delete_nmap_hist"):
            self.btn_delete_nmap_hist.setEnabled(has_sel)

    def _sync_nuclei_hist_buttons(self):
        has_sel = bool(self.nuclei_hist_table.selectedItems()) if hasattr(self, "nuclei_hist_table") else False
        if hasattr(self, "btn_load_nuclei_hist"):
            self.btn_load_nuclei_hist.setEnabled(has_sel)
        if hasattr(self, "btn_delete_nuclei_hist"):
            self.btn_delete_nuclei_hist.setEnabled(has_sel)

    def _load_selected_nmap_history(self):
        row = self.nmap_hist_table.currentRow()
        if row < 0:
            return
        fpath = self.nmap_hist_table.item(row, 3).data(Qt.ItemDataRole.UserRole)
        if not fpath or not os.path.exists(fpath):
            return
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
            vulns = vulns if isinstance(vulns, list) else []
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить файл:\n{e}")
            return
        self.server_scan_vulns["nmap"] = vulns or []
        vectors = self._vectors_from_scanner_vulns(vulns or [], found_by_prefix="Сервер: Nmap (история)")
        self._merge_server_vectors(vectors)
        if hasattr(self, "server_nmap_table"):
            self.server_nmap_table.setRowCount(0)
            for v in (vulns or []):
                if not isinstance(v, dict):
                    continue
                r = self.server_nmap_table.rowCount()
                self.server_nmap_table.insertRow(r)
                self.server_nmap_table.setItem(r, 0, QTableWidgetItem(str(v.get("cve_id", "") or "")))
                sev = str(v.get("severity", "") or "").upper()
                sev_item = QTableWidgetItem(sev)
                sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "INFO": "#668"}.get(sev, "#888")
                sev_item.setForeground(QColor(sev_color))
                self.server_nmap_table.setItem(r, 1, sev_item)
                self.server_nmap_table.setItem(r, 2, QTableWidgetItem(str(v.get("port", "") or "")))
                self.server_nmap_table.setItem(r, 3, QTableWidgetItem(str(v.get("service", "") or "")[:120]))
                self.server_nmap_table.setItem(r, 4, QTableWidgetItem(str(v.get("script", "") or "")[:180]))
                self.server_nmap_table.setItem(r, 5, QTableWidgetItem(str(v.get("description", "") or "")[:300]))
        if hasattr(self, "server_nmap_status"):
            self.server_nmap_status.setText(f"✅ Nmap (история): {len(vectors)} CVE")
        if hasattr(self, "server_nmap_progress"):
            self.server_nmap_progress.setRange(0, 100)
            self.server_nmap_progress.setValue(100)
            self.server_nmap_progress.setFormat(f"Загружено ({len(vectors)} CVE)")
        if hasattr(self, "server_nmap_log"):
            self.server_nmap_log.append(f"📥 Загружено из истории: {len(vectors)} CVE-векторов")
            self.server_nmap_log.moveCursor(QTextCursor.MoveOperation.End)

    def _load_selected_nuclei_history(self):
        row = self.nuclei_hist_table.currentRow()
        if row < 0:
            return
        fpath = self.nuclei_hist_table.item(row, 3).data(Qt.ItemDataRole.UserRole)
        if not fpath or not os.path.exists(fpath):
            return
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
            vulns = vulns if isinstance(vulns, list) else []
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить файл:\n{e}")
            return
        self.server_scan_vulns["nuclei"] = vulns or []
        vectors = self._vectors_from_scanner_vulns(vulns or [], found_by_prefix="Сервер: Nuclei (история)")
        self._merge_server_vectors(vectors)
        if hasattr(self, "server_nuclei_table"):
            self.server_nuclei_table.setRowCount(0)
            for v in (vulns or []):
                if not isinstance(v, dict):
                    continue
                r = self.server_nuclei_table.rowCount()
                self.server_nuclei_table.insertRow(r)
                self.server_nuclei_table.setItem(r, 0, QTableWidgetItem(str(v.get("cve_id", "") or "")))
                self.server_nuclei_table.setItem(r, 1, QTableWidgetItem(str(v.get("cwe_id", "") or "")))
                sev = str(v.get("severity", "") or "").upper()
                sev_item = QTableWidgetItem(sev)
                sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "INFO": "#668"}.get(sev, "#888")
                sev_item.setForeground(QColor(sev_color))
                self.server_nuclei_table.setItem(r, 2, sev_item)
                self.server_nuclei_table.setItem(r, 3, QTableWidgetItem(str(v.get("port", "") or "")))
                self.server_nuclei_table.setItem(r, 4, QTableWidgetItem(str(v.get("template", "") or "")[:200]))
                self.server_nuclei_table.setItem(r, 5, QTableWidgetItem(str(v.get("description", "") or "")[:300]))
        if hasattr(self, "server_nuclei_status"):
            self.server_nuclei_status.setText(f"✅ Nuclei (история): {len(vectors)} CVE")
        if hasattr(self, "server_nuclei_progress"):
            self.server_nuclei_progress.setRange(0, 100)
            self.server_nuclei_progress.setValue(100)
            self.server_nuclei_progress.setFormat(f"Загружено ({len(vectors)} CVE)")
        if hasattr(self, "server_nuclei_log"):
            self.server_nuclei_log.append(f"📥 Загружено из истории: {len(vectors)} CVE-векторов")
            self.server_nuclei_log.moveCursor(QTextCursor.MoveOperation.End)

    def _delete_selected_nmap_history(self):
        row = self.nmap_hist_table.currentRow()
        if row < 0:
            return
        item = self.nmap_hist_table.item(row, 3)
        record_id = item.data(Qt.ItemDataRole.UserRole + 1) if item else None
        if not record_id:
            return
        reply = QMessageBox.question(
            self,
            "Удаление",
            "Удалить выбранную запись из истории Nmap? (Файл будет удалён с диска)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            fpath = self._safe_history_path(record_id, NMAP_HISTORY_PREFIX)
            if fpath and os.path.exists(fpath):
                os.remove(fpath)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить запись:\n{e}")
            return
        self._refresh_nmap_history()

    def _delete_selected_nuclei_history(self):
        row = self.nuclei_hist_table.currentRow()
        if row < 0:
            return
        item = self.nuclei_hist_table.item(row, 3)
        record_id = item.data(Qt.ItemDataRole.UserRole + 1) if item else None
        if not record_id:
            return
        reply = QMessageBox.question(
            self,
            "Удаление",
            "Удалить выбранную запись из истории Nuclei? (Файл будет удалён с диска)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            fpath = self._safe_history_path(record_id, NUCLEI_HISTORY_PREFIX)
            if fpath and os.path.exists(fpath):
                os.remove(fpath)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить запись:\n{e}")
            return
        self._refresh_nuclei_history()

    def _safe_history_path(self, record_id: str, prefix: str) -> str:
        rid = str(record_id or "").strip()
        if not rid:
            return ""
        if "/" in rid or "\\" in rid:
            return ""
        if not (rid.startswith(prefix) and rid.endswith(SCAN_HISTORY_SUFFIX)):
            return ""
        fpath = os.path.join(self._scan_data_dir(), rid)
        return fpath

    def _load_trivy_report(self):
        """Загрузка результатов Trivy из сохраненного JSON-файла."""
        path, _ = QFileDialog.getOpenFileName(self, "Загрузить отчёт Trivy", PROJECT_DIR, "JSON Files (*.json)")
        if not path:
            return
        self._process_trivy_file(path)

    def _refresh_trivy_history(self):
        """Обновляет таблицу истории Trivy из папки data"""
        self.trivy_hist_table.setRowCount(0)
        try:
            history = TrivyHistory(PROJECT_DIR)
            records = history.list_records()
        except Exception:
            records = []
        for rec in records:
            row = self.trivy_hist_table.rowCount()
            self.trivy_hist_table.insertRow(row)
            self.trivy_hist_table.setItem(row, 0, QTableWidgetItem(rec.timestamp))
            self.trivy_hist_table.setItem(row, 1, QTableWidgetItem(str(rec.total_vulns)))
            self.trivy_hist_table.setItem(row, 2, QTableWidgetItem(str(rec.critical)))
            file_item = QTableWidgetItem(rec.filename)
            file_item.setData(Qt.ItemDataRole.UserRole, rec.filepath)
            file_item.setData(Qt.ItemDataRole.UserRole + 1, rec.record_id)
            self.trivy_hist_table.setItem(row, 3, file_item)
        self._sync_trivy_hist_buttons()

    def _load_selected_trivy_history(self):
        """Загрузка отчета Trivy выбранного в таблице истории"""
        row = self.trivy_hist_table.currentRow()
        if row < 0: return
        fpath = self.trivy_hist_table.item(row, 3).data(Qt.ItemDataRole.UserRole)
        if not fpath or not os.path.exists(fpath): return
        self._process_trivy_file(fpath)

    def _sync_trivy_hist_buttons(self):
        has_sel = bool(self.trivy_hist_table.selectedItems())
        self.btn_load_trivy_hist.setEnabled(has_sel)
        self.btn_delete_trivy_hist.setEnabled(has_sel)

    def _delete_selected_trivy_history(self):
        row = self.trivy_hist_table.currentRow()
        if row < 0:
            return
        item = self.trivy_hist_table.item(row, 3)
        record_id = item.data(Qt.ItemDataRole.UserRole + 1) if item else None
        if not record_id:
            return
        reply = QMessageBox.question(
            self,
            "Удаление",
            "Удалить выбранную запись из истории Trivy? (Файл будет удалён с диска)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            history = TrivyHistory(PROJECT_DIR)
            history.delete_record(str(record_id))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить запись:\n{e}")
            return
        self._refresh_trivy_history()

    def _process_trivy_file(self, path):
        """Общая логика парсинга JSON от Trivy и заполнения интерфейса"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Проверка формата (поддержка сырого Trivy или нашего отформатированного)
            vulns = data.get("vulnerabilities") or []
            if not vulns and "Results" in data:
                for res in data.get("Results", []):
                    for v in res.get("Vulnerabilities", []):
                        vulns.append({
                            "vuln_id": v.get("VulnerabilityID", ""),
                            "pkg_name": v.get("PkgName", ""),
                            "installed_version": v.get("InstalledVersion", ""),
                            "fixed_version": v.get("FixedVersion", ""),
                            "severity": v.get("Severity", "UNKNOWN"),
                            "title": v.get("Title", "") or "Без названия",
                            "cwe_ids": v.get("CweIDs") or []
                        })
            
            # Считаем статистику
            crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
            high = sum(1 for v in vulns if v.get("severity") == "HIGH")
            med = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
            low = sum(1 for v in vulns if v.get("severity") == "LOW")
            
            self.trivy_summary = {
                "total_vulns": len(vulns),
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "scan_duration": "Загружено из истории"
            }
            
            # Сохраняем в формат, понятный коррелятору
            self.trivy_result = {"vulnerabilities": vulns}
            
            if self.system_info:
                self.system_info.trivy_scan_result = self.trivy_result
                
            # Динамически обновляем глобальный state API-сервера
            try:
                from server.api_server import state
                state.trivy_result = self.trivy_result
            except ImportError:
                pass
            
            # Заполняем таблицу
            self.trivy_table.setRowCount(0)
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "INFO": 5}
            sorted_vulns = sorted(vulns, key=lambda v: sev_order.get(v.get("severity", "UNKNOWN"), 4))
            
            for vuln in sorted_vulns:
                row = self.trivy_table.rowCount()
                self.trivy_table.insertRow(row)
                self.trivy_table.setItem(row, 0, QTableWidgetItem(vuln.get("vuln_id", "")))
                self.trivy_table.setItem(row, 1, QTableWidgetItem(vuln.get("pkg_name", "")))
                self.trivy_table.setItem(row, 2, QTableWidgetItem(vuln.get("installed_version", "")))
                
                fixed = vuln.get("fixed_version", "")
                fixed_item = QTableWidgetItem(str(fixed) if fixed else "Нет исправления")
                if not fixed: fixed_item.setForeground(QColor("#888"))
                self.trivy_table.setItem(row, 3, fixed_item)
                
                sev = vuln.get("severity", "UNKNOWN")
                sev_item = QTableWidgetItem(sev)
                sev_color = {"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696", "UNKNOWN": "#888", "INFO": "#668"}.get(sev, "#888")
                sev_item.setForeground(QColor(sev_color))
                self.trivy_table.setItem(row, 4, sev_item)
                self.trivy_table.setItem(row, 5, QTableWidgetItem(str(vuln.get("title", ""))[:200]))
                
                cwe_list = vuln.get("cwe_ids") or []
                cwe = ", ".join(cwe_list[:3])
                self.trivy_table.setItem(row, 6, QTableWidgetItem(f"CWE: {cwe}" if cwe else "—"))
                
            # Обновляем сводку и переключаем вкладку напрямую, без вызова _on_trivy_scan_done
            self.trivy_summary_label.setText(
                f"Всего уязвимостей: {self.trivy_summary.get('total_vulns', 0)}  |  "
                f"🔴 CRITICAL: {self.trivy_summary.get('critical', 0)}  |  "
                f"🟠 HIGH: {self.trivy_summary.get('high', 0)}  |  "
                f"🟡 MEDIUM: {self.trivy_summary.get('medium', 0)}  |  "
                f"🟢 LOW: {self.trivy_summary.get('low', 0)}  |  "
                f"Время: {self.trivy_summary.get('scan_duration', '?')}"
            )
            for i in range(self.tabs.count()):
                if "Trivy" in self.tabs.tabText(i):
                    self.tabs.setCurrentIndex(i)
                    break
                    
            self.trivy_status_label.setText(f"✅ Загружено из истории: {len(vulns)} уязвимостей")
            self.btn_trivy_scan.setText("3б. Сканирование Trivy (загружено из истории)")
            self.btn_trivy_scan.setEnabled(True)
            
            # Принудительно разблокируем кнопку запуска сервера после подгрузки
            self.btn_server.setEnabled(True)
            
        except Exception as e:
            logger.error(f"Ошибка загрузки Trivy: {e}", exc_info=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить файл:\n{e}")

    # ─────────────────────────────────────────
    #  HTTP Сервер
    # ─────────────────────────────────────────
    def _toggle_server(self):
        # Проверяем что Trivy был запущен
        if not self.trivy_summary:
            reply = QMessageBox.warning(
                self,
                "⚠️ Trivy не запущен",
                "⚠️ Сканирование Trivy не было выполнено!\n\n"
                "Без данных Trivy корреляция атак будет неполной:\n"
                "• Реализуемость атак НЕ будет подтверждена\n"
                "• Уязвимости ПО не будут учтены\n"
                "• Отчёт будет менее точным\n\n"
                "Рекомендуется выполнить сканирование Trivy перед запуском сервера.\n\n"
                "Всё равно запустить сервер?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return
        
        if self.server_running:
            self._stop_server()
        else:
            self._start_server()
    def _start_server(self):
        port = self.port_spin.value()
        ok, desc = is_port_available(port)
        if not ok:
            QMessageBox.critical(self, "Порт занят", f"Порт {port} уже используется!\n\nВыберите другой порт.")
            return
        gui = self
        from server.api_server import state
        state.base_dir = PROJECT_DIR
        state.system_info = self.system_info
        state.system_summary = self.system_summary if isinstance(self.system_summary, dict) else {}
        state.vuln_db = self.vuln_db
        state.trivy_result = getattr(self, 'trivy_result', None)  # Результаты Trivy
        state.ready = bool(self.system_info and self.vuln_db)
        state.on_client_connected = lambda ip: gui.client_connected_signal.emit(ip)
        state.on_analysis_complete = lambda s, p: gui.analysis_done_signal.emit(s, p)
        state.on_correlation_progress = lambda p, m: gui.correlation_progress_signal.emit(p, m)
        if not hasattr(state, "last_correlation_lock"):
            state.last_correlation_lock = threading.Lock()
        with state.last_correlation_lock:
            state.last_correlation_payload = None
            state.last_correlation_id = None
        
        class Handler(BaseHTTPRequestHandler):
            def _sync_state(self):
                state.base_dir = PROJECT_DIR
                state.system_info = gui.system_info
                state.system_summary = gui.system_summary if isinstance(gui.system_summary, dict) else {}
                state.vuln_db = getattr(gui, "vuln_db", None)
                state.trivy_result = getattr(gui, "trivy_result", None)
                state.ready = bool(state.system_info and state.vuln_db)

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()

            def do_GET(self):
                ip = self.client_address[0]
                try:
                    self._sync_state()
                    ss = state.system_summary if isinstance(state.system_summary, dict) else {}
                    hn = ss.get("hostname", "")
                    path_only = self.path.split("?", 1)[0]
                    if path_only == "/playbooks":
                        from server import api_server as api
                        q = {}
                        if "?" in self.path:
                            try:
                                from urllib.parse import unquote_plus
                            except Exception:
                                def unquote_plus(x):  # type: ignore
                                    return x
                            for part in self.path.split("?", 1)[1].split("&"):
                                if "=" in part:
                                    k, v = part.split("=", 1)
                                    q[k] = unquote_plus(v)
                        vector_q = (q.get("vector") or "").strip()
                        cve_q = (q.get("cve") or "").strip().upper()
                        with state.playbook_lock:
                            db = api._load_playbooks()
                        if vector_q:
                            entry = (db.get("vectors") or {}).get(vector_q, None)
                            self._r(200, {"vector_id": vector_q, "playbook": entry or {}})
                        elif cve_q:
                            entry = (db.get("cves") or {}).get(cve_q, None)
                            self._r(200, {"cve_id": cve_q, "playbook": entry or {}})
                        else:
                            self._r(200, db)
                    elif path_only == "/ping":
                        if ip not in state.connected_clients:
                            state.connected_clients.append(ip)
                            if state.on_client_connected:
                                state.on_client_connected(ip)
                        self._r(200, {"status": "pong", "ready": state.ready, "hostname": hn})
                    elif path_only == "/status":
                        self._r(200, {"status": "running", "ready": state.ready, "hostname": hn, "clients": state.connected_clients})
                    elif path_only == "/system-info":
                        self._r(200, ss)
                    elif path_only == "/last-correlation":
                        with state.last_correlation_lock:
                            payload = getattr(state, "last_correlation_payload", None)
                        if payload:
                            self._r(200, payload)
                        else:
                            self._r(404, {"status": "empty", "error": "Корреляция ещё не выполнялась"})
                    else:
                        self._r(200, {"message": "Security Assessment Server", "ready": state.ready})
                except Exception as e:
                    self._r(500, {"error": str(e)})
            def do_POST(self):
                ip = self.client_address[0]
                logger.info(f"[API] POST {self.path} от {ip}")
                path_only = self.path.split("?", 1)[0]
                if path_only == "/playbooks":
                    from server import api_server as api
                    try:
                        ln = int(self.headers.get("Content-Length", 0))
                        if ln == 0:
                            self._r(400, {"error": "Пустое тело"})
                            return
                        body = self.rfile.read(ln).decode("utf-8")
                        payload = json.loads(body)
                        vector_id = str(payload.get("vector_id", "") or "").strip()
                        cve_id = str(payload.get("cve_id", "") or "").strip().upper()
                        playbook = payload.get("playbook", None)
                        if not vector_id and not cve_id:
                            self._r(400, {"error": "Нужно указать vector_id или cve_id"})
                            return
                        if cve_id and not cve_id.startswith("CVE-"):
                            self._r(400, {"error": "Некорректный cve_id"})
                            return
                        if vector_id and len(vector_id) > 600:
                            self._r(400, {"error": "Слишком длинный vector_id"})
                            return
                        if not isinstance(playbook, dict):
                            self._r(400, {"error": "playbook должен быть объектом"})
                            return
                        attacks = playbook.get("attacks", [])
                        defenses = playbook.get("defenses", [])
                        if not isinstance(attacks, list) or not isinstance(defenses, list):
                            self._r(400, {"error": "attacks/defenses должны быть списками"})
                            return
                        if not hasattr(state, "playbook_lock"):
                            state.playbook_lock = threading.Lock()
                        with state.playbook_lock:
                            db = api._load_playbooks()
                            entry = {
                                "attacks": attacks,
                                "defenses": defenses,
                                "meta": playbook.get("meta", {}) if isinstance(playbook.get("meta", {}), dict) else {},
                                "updated_at": datetime.now().isoformat(),
                            }
                            if vector_id:
                                vectors = db.setdefault("vectors", {})
                                vectors[vector_id] = entry
                            else:
                                cves = db.setdefault("cves", {})
                                cves[cve_id] = entry
                            api._save_playbooks(db)
                        try:
                            logger.info(f"[PLAYBOOK] Saved: {'vector' if vector_id else 'cve'}={vector_id or cve_id}")
                        except Exception:
                            pass
                        if vector_id:
                            self._r(200, {"status": "ok", "vector_id": vector_id})
                        else:
                            self._r(200, {"status": "ok", "cve_id": cve_id})
                    except json.JSONDecodeError as e:
                        self._r(400, {"error": f"Некорректный JSON: {e}"})
                    except Exception as e:
                        logger.error(f"[API] Ошибка сохранения playbooks: {e}", exc_info=True)
                        self._r(500, {"error": str(e)})
                    return
                if path_only != "/analyze":
                    self._r(404, {"error": "Not Found"})
                    return
                self._sync_state()
                if not state.system_info or not state.vuln_db:
                    parts = []
                    if not state.system_info:
                        parts.append("анализ системы не выполнен")
                    if not state.vuln_db:
                        parts.append("базы данных не загружены")
                    self._r(503, {"error": "Сервер не готов: " + "; ".join(parts), "ready": False, "hint": "Выполните шаги 1–2 в gui_server"})
                    return
                try:
                    ln = int(self.headers.get("Content-Length", 0))
                    if ln == 0:
                        self._r(400, {"error": "Пустое тело"})
                        return
                    body = self.rfile.read(ln).decode("utf-8")
                    scan_data = json.loads(body)
                    logger.info(f"[API] Данные от {ip}: {len(scan_data.get('open_ports', []))} портов, {len(scan_data.get('attack_vectors', []))} векторов")
                    if ip not in state.connected_clients:
                        state.connected_clients.append(ip)
                        if state.on_client_connected:
                            state.on_client_connected(ip)
                    sr = from_json_scan_result(scan_data)
                    try:
                        extra = getattr(gui, "server_scan_vectors", None) or []
                        if extra:
                            sr.attack_vectors.extend(extra)
                    except Exception:
                        pass
                    profiles = []
                    try:
                        profiles = list_correlation_profiles(PROJECT_DIR)
                    except Exception:
                        profiles = []

                    results_by_profile = {}
                    summaries_by_profile = {}
                    profiles_meta = {}
                    settings_by_profile = {}

                    ordered_ids = []
                    for p in profiles:
                        pid = p.get("file") or p.get("id")
                        if not pid or pid in ordered_ids:
                            continue
                        profiles_meta[pid] = {"id": pid, "name": p.get("name", pid), "description": p.get("description", "")}
                        if isinstance(p.get("settings"), dict):
                            settings_by_profile[pid] = dict(p.get("settings"))
                        ordered_ids.append(pid)

                    if not ordered_ids:
                        pid = "_default"
                        profiles_meta[pid] = {"id": pid, "name": "По умолчанию", "description": ""}
                        settings_by_profile[pid] = dict(DEFAULT_CORRELATION_SETTINGS)
                        ordered_ids.append(pid)

                    default_profile_id = "standard.json" if "standard.json" in ordered_ids else ordered_ids[0]

                    for pid in ordered_ids:
                        if pid not in settings_by_profile:
                            settings_by_profile[pid] = dict(DEFAULT_CORRELATION_SETTINGS)

                    for pid in ordered_ids:
                        settings = settings_by_profile.get(pid, dict(DEFAULT_CORRELATION_SETTINGS) if pid == "_default" else {})
                        cor = AttackCorrelator(
                            state.system_info,
                            state.vuln_db,
                            trivy_result=state.trivy_result,
                            correlation_settings=settings,
                        )
                        results_by_profile[pid] = cor.correlate(sr)
                        summaries_by_profile[pid] = cor.get_summary()

                    results = results_by_profile.get(default_profile_id, [])
                    summary = summaries_by_profile.get(default_profile_id, {})
                    # Сохраняем данные для генерации расширенного отчёта
                    gui._last_scan_data = scan_data
                    gui._last_results = results
                    rd = os.path.join(PROJECT_DIR, "reports")
                    os.makedirs(rd, exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    rep = ReportGenerator(
                        state.system_summary or {},
                        results,
                        summary,
                        toolkit=gui.toolkit,
                        local_scan_report=gui.vuln_scan_report,
                        attacker_scan_data=scan_data,
                        correlation_results_by_profile=results_by_profile,
                        summaries_by_profile=summaries_by_profile,
                        profiles_meta=profiles_meta,
                        default_profile_id=default_profile_id,
                    )
                    hp = rep.generate_html(os.path.join(rd, f"report_{ts}.html"))
                    jp = rep.generate_json(os.path.join(rd, f"report_{ts}.json"))
                    gui.last_report_path = hp
                    # Добавляем в историю
                    gui._add_to_history(results, summary, ts, hp, jp)
                    settings_used = settings_by_profile.get(default_profile_id, dict(DEFAULT_CORRELATION_SETTINGS))

                    def _to_details(items):
                        out = []
                        for r in items:
                            out.append({
                                "cve_id": str(r.cve_id) if getattr(r, "cve_id", None) else "",
                                "attack_name": str(r.attack_name) if getattr(r, "attack_name", None) else "",
                                "severity": getattr(r.severity, "name", str(r.severity)),
                                "feasibility": __import__("common.models", fromlist=["normalize_feasibility"]).normalize_feasibility(getattr(r, "feasibility", None)),
                                "description": str(r.description) if getattr(r, "description", None) else "",
                                "recommendation": str(r.recommendation) if getattr(r, "recommendation", None) else "",
                            })
                        return out

                    details_by_profile = {pid: _to_details(res) for pid, res in results_by_profile.items()}
                    resp = {
                        "status": "success",
                        "correlation_id": ts,
                        "summary": summary,
                        "settings_used": settings_used,
                        "profiles_meta": profiles_meta,
                        "default_profile_id": default_profile_id,
                        "settings_by_profile": settings_by_profile,
                        "summaries_by_profile": summaries_by_profile,
                        "html_report": hp,
                        "results_count": len(results),
                        "details": details_by_profile.get(default_profile_id, []),
                        "details_by_profile": details_by_profile,
                    }
                    with state.last_correlation_lock:
                        state.last_correlation_payload = resp
                        state.last_correlation_id = ts
                    self._r(200, resp)
                    logger.info(f"[API] Ответ 200 OK. Результатов: {len(results)}")
                    if state.on_analysis_complete:
                        state.on_analysis_complete(summary, hp)
                    gui.correlation_bundle_signal.emit({
                        "results_by_profile": results_by_profile,
                        "summaries_by_profile": summaries_by_profile,
                        "profiles_meta": profiles_meta,
                        "default_profile_id": default_profile_id,
                        "settings_by_profile": settings_by_profile,
                    })
                except json.JSONDecodeError as e:
                    logger.error(f"[API] Ошибка JSON: {e}")
                    self._r(400, {"error": f"Некорректный JSON: {e}"})
                except Exception as e:
                    logger.error(f"[API] Ошибка: {e}", exc_info=True)
                    self._r(500, {"error": str(e)})
            def _r(self, code, data):
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.end_headers()
                self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))
            def log_message(self, *a):
                pass
        try:
            self.http_server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
            self.http_server.daemon_threads = True
            self.actual_server_port = port
            self.server_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            self.server_thread.start()
            self.server_running = True
            self.status_icon.setText("● Сервер запущен")
            self.status_icon.setStyleSheet("color:#8a8;")
            self.port_display.setText(f"Порт: {port}\nURL: http://0.0.0.0:{port}")
            self.port_display.setStyleSheet("color:#8a8;")
            self.btn_server.setText("4. Остановить сервер")
            self.btn_open_report.setEnabled(True)
            self.port_spin.setEnabled(False)
            self.statusBar().showMessage(f"Сервер на порту {port}. Ожидание подключений...")
            logger.info(f"[SRV] HTTP-сервер запущен на порту {port}")
        except OSError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
            logger.error(f"[SRV] Ошибка запуска: {e}")
    def _stop_server(self):
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None
        self.server_running = False
        self.actual_server_port = None
        self.status_icon.setText("● Сервер остановлен")
        self.status_icon.setStyleSheet("color:#666;")
        self.port_display.setText("")
        self.btn_server.setText("4. Запустить сервер")
        self.port_spin.setEnabled(True)
        logger.info("[SRV] HTTP-сервер остановлен")
    # ─────────────────────────────────────────
    #  Подключение клиента
    # ─────────────────────────────────────────
    def _on_client_connected(self, ip):
        from server.api_server import state
        n = len(state.connected_clients)
        cs = ", ".join(state.connected_clients[-3:])
        self.connection_label.setText(f"Клиентов: {n}\nПоследние: {cs}")
        self.statusBar().showMessage(f"Клиент подключён: {ip}")
    def _on_server_analysis_done(self, summary, path):
        self.last_report_path = path
        self.tabs.setCurrentIndex(2)  # Вкладка корреляции
        self.btn_open_report.setEnabled(True)
    
    def _on_correlation_progress_update(self, percent, message):
        """Обновление прогресса корреляции из GUI потока."""
        self.correlation_progress_label.setText(f"🔄 {message}")
        self.correlation_progress_label.setStyleSheet("color:#a85;font-size:11px;padding:4px;")
        self.correlation_progress_bar.setVisible(True)
        self.correlation_progress_bar.setValue(percent)
        self.correlation_progress_bar.setFormat(f"{message} ({percent}%)")
        
        if percent >= 100:
            # Скрываем прогресс бар через 2 секунды после завершения
            QTimer.singleShot(2000, lambda: self.correlation_progress_bar.setVisible(False))
            self.correlation_progress_label.setText("✅ Корреляция завершена")
            self.correlation_progress_label.setStyleSheet("color:#8a8;font-size:11px;padding:4px;")

    def _apply_correlation_bundle_slot(self, bundle):
        try:
            bundle = bundle if isinstance(bundle, dict) else {}
            self._correlation_results_by_profile = bundle.get("results_by_profile") if isinstance(bundle.get("results_by_profile"), dict) else {}
            self._correlation_summaries_by_profile = bundle.get("summaries_by_profile") if isinstance(bundle.get("summaries_by_profile"), dict) else {}
            self._correlation_profiles_meta = bundle.get("profiles_meta") if isinstance(bundle.get("profiles_meta"), dict) else {}
            self._correlation_settings_by_profile = bundle.get("settings_by_profile") if isinstance(bundle.get("settings_by_profile"), dict) else {}
            default_pid = str(bundle.get("default_profile_id") or "").strip()

            if not hasattr(self, "correlation_profile_combo"):
                return

            self.correlation_profile_combo.blockSignals(True)
            self.correlation_profile_combo.clear()

            pids = list(self._correlation_results_by_profile.keys())
            for pid in pids:
                meta = self._correlation_profiles_meta.get(pid, {}) if isinstance(self._correlation_profiles_meta.get(pid), dict) else {}
                label = str(meta.get("name") or pid)
                self.correlation_profile_combo.addItem(label, pid)

            self.correlation_profile_combo.setEnabled(bool(pids))
            self.correlation_profile_combo.blockSignals(False)

            if not pids:
                self._selected_profile_id = ""
                self.correlation_profile_settings_text.setPlainText("Параметры профиля: —")
                return

            chosen = default_pid if default_pid in pids else (pids[0] if pids else "")
            idx = self.correlation_profile_combo.findData(chosen)
            if idx >= 0:
                self.correlation_profile_combo.setCurrentIndex(idx)
            self._set_correlation_profile(chosen)
        except Exception as e:
            logger.error(f"[UI] Ошибка применения профилей корреляции: {e}", exc_info=True)

    def _on_correlation_profile_changed(self):
        try:
            pid = self.correlation_profile_combo.currentData()
            pid = str(pid or "").strip()
            if not pid:
                return
            self._set_correlation_profile(pid)
        except Exception as e:
            logger.error(f"[UI] Ошибка смены профиля: {e}", exc_info=True)

    def _set_correlation_profile(self, pid: str):
        pid = str(pid or "").strip()
        if not pid:
            return
        self._selected_profile_id = pid
        results = self._correlation_results_by_profile.get(pid, [])
        self.update_results_signal.emit(results)

        settings = self._correlation_settings_by_profile.get(pid, {})
        if not isinstance(settings, dict):
            settings = {}
        ordered = [
            "max_score",
            "feasible_threshold",
            "partially_feasible_threshold",
            "not_feasible_threshold",
            "network_weight",
            "trivy_weight",
            "software_weight",
            "scanner_weight",
            "patch_weight",
            "protection_weight",
        ]
        lines = ["ПАРАМЕТРЫ ПРОФИЛЯ"]
        meta = self._correlation_profiles_meta.get(pid, {}) if isinstance(self._correlation_profiles_meta.get(pid), dict) else {}
        name = str(meta.get("name") or pid)
        desc = str(meta.get("description") or "").strip()
        lines.append("")
        lines.append(f"Профиль: {name}")
        if desc:
            lines.append(f"Описание: {desc}")
        lines.append("")
        for k in ordered:
            lines.append(f"• {k}: {settings.get(k, DEFAULT_CORRELATION_SETTINGS.get(k, '-'))}")
        self.correlation_profile_settings_text.setPlainText("\n".join(lines))
    # ─────────────────────────────────────────
    #  Таблица корреляции
    # ─────────────────────────────────────────
    def _update_results_table_slot(self, results):
        try:
            self.results_table.setRowCount(0)
            # Дедупликация для таблицы GUI
            seen = set()
            unique_results = []
            for r in results:
                cve = str(r.cve_id or "Нет CVE")
                name = str(r.attack_name or "Неизвестная атака")
                key = f"{cve}_{name}"
                if key not in seen:
                    seen.add(key)
                    unique_results.append(r)
            logger.debug(f"[UI] Обновление таблицы. Уникальных строк: {len(unique_results)} из {len(results)}")
            from common.models import feasibility_counters
            counters = feasibility_counters(unique_results)
            for r in unique_results:
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                cve = str(r.cve_id or "Нет CVE")
                sev = str(r.severity or "INFO")
                from common.models import normalize_feasibility
                feas = normalize_feasibility(getattr(r, "feasibility", None))
                name = str(r.attack_name or "Неизвестная атака")
                desc = str(r.description or "")[:150]
                self.results_table.setItem(row, 0, QTableWidgetItem(cve))
                si = QTableWidgetItem(sev)
                si.setForeground(QColor({"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696"}.get(sev, "#888")))
                self.results_table.setItem(row, 1, si)
                fi = QTableWidgetItem(feas)
                # ВАЖНО: проверяем ЧАСТИЧНО раньше РЕАЛИЗУЕМА (иначе частичные попадают как реализуемые)
                if "ЧАСТИЧНО" in feas:
                    fi.setForeground(QColor("#d29922"))
                elif feas == "НЕ РЕАЛИЗУЕМА":
                    fi.setForeground(QColor("#696"))
                elif feas == "РЕАЛИЗУЕМА":
                    fi.setForeground(QColor("#b55"))
                else:
                    fi.setForeground(QColor("#888"))
                self.results_table.setItem(row, 2, fi)
                self.results_table.setItem(row, 3, QTableWidgetItem(name))
                self.results_table.setItem(row, 4, QTableWidgetItem(desc))
            self.correlation_summary.setText(
                f"Всего (уникальных): {len(unique_results)}  |  "
                f"🔴 Реализуемых: {counters['feasible']}  |  "
                f"🟡 Частичных: {counters['partially_feasible']}  |  "
                f"🟢 Нереализуемых: {counters['not_feasible']}  |  "
                f"⚪ Требуют анализа: {counters['requires_analysis']}"
            )
            self._sync_restart_correlation_button_state()
        except Exception as e:
            logger.error(f"[UI] Сбой при заполнении таблицы: {e}", exc_info=True)
    def _on_result_double_click(self, index):
        """Двойной клик на строке результата — показываем детали."""
        row = index.row()
        if row < 0:
            return
        cve = self.results_table.item(row, 0).text() if self.results_table.item(row, 0) else ""
        sev = self.results_table.item(row, 1).text() if self.results_table.item(row, 1) else ""
        feas = self.results_table.item(row, 2).text() if self.results_table.item(row, 2) else ""
        name = self.results_table.item(row, 3).text() if self.results_table.item(row, 3) else ""
        desc = self.results_table.item(row, 4).text() if self.results_table.item(row, 4) else ""
        msg = f"CVE: {cve}\nСерьёзность: {sev}\nСтатус: {feas}\nАтака: {name}\nОписание: {desc}"
        QMessageBox.information(self, f"Детали: {cve}", msg)
    # ─────────────────────────────────────────
    #  История отчётов
    # ─────────────────────────────────────────
    def _sync_history(self):
        """Синхронизация истории с файлами на диске."""
        rd = os.path.join(PROJECT_DIR, "reports")
        self.report_history.sync_from_disk(rd)
        self._refresh_history_table()
        self._refresh_scan_histories()
        self._update_stats()
        
    def _update_stats(self):
        """Обновление общей статистики."""
        stats = self.report_history.stats
        scan_stats = self.scan_history.stats
        
        stats_text = ""
        if self.vuln_db:
            stats_text = f"CVE:{len(self.vuln_db.cve_db)} CWE:{len(self.vuln_db.cwe_db)} CAPEC:{len(self.vuln_db.capec_db)}"
        else:
            stats_text = "Базы не загружены"
        self.lbl_stats.setText(stats_text)
        
        self.lbl_history_stats.setText(
            f"История: {stats['total']} отчётов "
            f"({stats['critical_reports']} с CRITICAL)\n"
            f"Сканирования: {scan_stats['total']} | "
            f"Хостов: {scan_stats['unique_hosts']}"
        )
    def _refresh_history(self):
        """Обновить историю отчётов."""
        rd = os.path.join(PROJECT_DIR, "reports")
        self.report_history.sync_from_disk(rd)
        self._refresh_history_table()
    def _refresh_history_table(self):
        """Обновить таблицу истории."""
        self.history_table.setRowCount(0)
        records = self.report_history.get_all()
        for rec in records:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            # Дата
            dt_item = QTableWidgetItem(rec.formatted_timestamp)
            if not rec.exists_on_disk:
                dt_item.setForeground(QColor("#555"))  # Файл не существует
            self.history_table.setItem(row, 0, dt_item)
            self.history_table.setItem(row, 1, QTableWidgetItem(rec.hostname or "—"))
            self.history_table.setItem(row, 2, QTableWidgetItem(rec.os_name[:15] if rec.os_name else "—"))
            self.history_table.setItem(row, 3, QTableWidgetItem(str(rec.total_vulnerabilities)))
            self.history_table.setItem(row, 4, QTableWidgetItem(str(rec.feasible_count)))
            ci = QTableWidgetItem(str(rec.critical_count))
            if rec.critical_count > 0:
                ci.setForeground(QColor("#c44"))
            self.history_table.setItem(row, 5, ci)
            hi = QTableWidgetItem(str(rec.high_count))
            if rec.high_count > 0:
                hi.setForeground(QColor("#a85"))
            self.history_table.setItem(row, 6, hi)
            ri = QTableWidgetItem(rec.risk_level)
            ri.setForeground(QColor(rec.risk_color))
            self.history_table.setItem(row, 7, ri)
            # Сохраняем ID в данных строки
            self.history_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, rec.report_id)
        stats = self.report_history.stats
        self.lbl_history_stats.setText(
            f"История: {stats['total']} отчётов | C файлами: {stats['with_files']}"
        )
    def _on_history_selection_changed(self):
        selected = self.history_table.selectedItems()
        has_selection = bool(selected)
        self.btn_open_history_report.setEnabled(has_selection)
        self.btn_delete_history.setEnabled(has_selection)
        self.btn_delete_with_files.setEnabled(has_selection)
        if has_selection:
            row = self.history_table.currentRow()
            report_id = self.history_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if self.history_table.item(row, 0) else None
            if report_id:
                rec = self.report_history.get_by_id(report_id)
                if rec:
                    detail = (
                        f"ID: {rec.report_id} | "
                        f"Дата: {rec.formatted_timestamp} | "
                        f"Хост: {rec.hostname} | "
                        f"Атакующий: {rec.scanner_ip or '—'} | "
                        f"Файл: {'✅ Существует' if rec.exists_on_disk else '❌ Не найден'}"
                    )
                    self.history_detail.setText(detail)
    def _open_history_report(self):
        row = self.history_table.currentRow()
        if row < 0:
            return
        report_id = self.history_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if self.history_table.item(row, 0) else None
        if not report_id:
            return
        rec = self.report_history.get_by_id(report_id)
        if not rec:
            return
        if rec.exists_on_disk:
            webbrowser.open(f"file:///{rec.html_path}")
        else:
            QMessageBox.warning(self, "Файл не найден", f"Файл отчёта не найден:\n{rec.html_path}")
    def _delete_history_record(self):
        row = self.history_table.currentRow()
        if row < 0:
            return
        report_id = self.history_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if self.history_table.item(row, 0) else None
        if not report_id:
            return
        reply = QMessageBox.question(
            self, "Удаление", "Удалить запись из истории? (Файлы отчёта останутся на диске)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.report_history.delete_record(report_id)
            self._refresh_history_table()
    def _delete_history_with_files(self):
        row = self.history_table.currentRow()
        if row < 0:
            return
        report_id = self.history_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if self.history_table.item(row, 0) else None
        if not report_id:
            return
        reply = QMessageBox.question(
            self, "Удаление с файлами",
            "Удалить запись И файлы отчёта (HTML + JSON) с диска?\nЭто действие необратимо!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.report_history.delete_with_files(report_id)
            self._refresh_history_table()
    def _add_to_history(self, results, summary, ts, html_path, json_path=""):
        """Добавить результат в историю отчётов."""
        try:
            from dataclasses import asdict
            rec = ReportRecord(
                report_id=ts,
                timestamp=datetime.now().isoformat(),
                html_path=html_path,
                json_path=json_path,
                hostname=self.system_summary.get("hostname", "") if self.system_summary else "",
                os_name=self.system_summary.get("os", "") if self.system_summary else "",
                target_ip=summary.get("target_ip", ""),
                scanner_ip=summary.get("scanner_ip", ""),
                total_vulnerabilities=len(results),
                feasible_count=summary.get("feasible_attacks", 0),
                not_feasible_count=summary.get("not_feasible_attacks", 0),
                critical_count=summary.get("critical_count", 0),
                high_count=summary.get("high_count", 0),
                medium_count=summary.get("medium_count", 0),
                low_count=summary.get("low_count", 0),
            )
            self.report_history.add_record(rec)
            self._refresh_history_table()
        except Exception as e:
            logger.error(f"[HISTORY] Ошибка добавления записи: {e}")
    # ─────────────────────────────────────────
    #  Открытие отчётов
    # ─────────────────────────────────────────
    def _open_report(self):
        if self.last_report_path and os.path.exists(self.last_report_path):
            webbrowser.open(f"file:///{self.last_report_path}")
            return
        rd = os.path.join(PROJECT_DIR, "reports")
        if os.path.exists(rd):
            fs = sorted([f for f in os.listdir(rd) if f.endswith(".html")], reverse=True)
            if fs:
                webbrowser.open(f"file:///{os.path.join(rd, fs[0])}")
                return
        QMessageBox.information(self, "Отчёт", "Отчёт не создан.")
    def _generate_manual_report(self):
        """Генерировать отчёт на основе последних результатов с инструментами."""
        if not self._last_results and not self.vuln_db:
            QMessageBox.warning(self, "Нет данных", "Нет данных для генерации. Запустите анализ и отправьте данные с атакующего агента.")
            return
        results = self._last_results or []
        summary = {}
        if self.vuln_db and self.system_info and not results:
            from common.models import ScanResult
            sr = ScanResult(scanner_ip="manual", target_ip="manual", scan_timestamp=datetime.now().isoformat())
            cor = AttackCorrelator(self.system_info, self.vuln_db, trivy_result=getattr(self, 'trivy_result', None))
            results = cor.correlate(sr)
            summary = cor.get_summary()
        rd = os.path.join(PROJECT_DIR, "reports")
        os.makedirs(rd, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rep = ReportGenerator(
            self.system_summary or {},
            results,
            summary,
            toolkit=self.toolkit,
            local_scan_report=self.vuln_scan_report,
            attacker_scan_data=self._last_scan_data,
        )
        hp = rep.generate_html(os.path.join(rd, f"report_{ts}.html"))
        jp = rep.generate_json(os.path.join(rd, f"report_{ts}.json"))
        self.last_report_path = hp
        self._add_to_history(results, summary, ts, hp, jp)
        webbrowser.open(f"file:///{hp}")
    # ─────────────────────────────────────────
    #  Экспорт лога
    # ─────────────────────────────────────────
    def _export_log(self):
        t = self.log_output.toPlainText()
        if not t:
            QMessageBox.information(self, "Экспорт", "Лог пуст.")
            return
        p, _ = QFileDialog.getSaveFileName(
            self, "Сохранить лог",
            f"server_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        if p:
            open(p, "w", encoding="utf-8").write(t)
    
    # ─────────────────────────────────────────
    #  Методы для работы с профилями корреляции
    # ─────────────────────────────────────────
    def _on_profile_selected(self, profile_name):
        """Обработка выбора профиля."""
        logger.info(f"[PROFILE] Выбран профиль: {profile_name}")
        
        if profile_name == "-- Выберите профиль --":
            self.profile_description.setText("Выберите профиль для просмотра описания")
            self.btn_apply_profile.setEnabled(False)
            self.btn_overwrite_profile.setEnabled(False)
            return
        
        if profile_name == "Загрузить из файла...":
            self._load_profile_from_file()
            return
        
        profile_file_map = {
            "Стандартный (баланс)": "standard.json",
            "Приоритетный для анализа на сервере": "server_priority.json",
            "Приоритетный для анализа атакующим": "attacker_priority.json",
        }
        profile_file = None
        if hasattr(self, "_profile_name_to_file") and profile_name in getattr(self, "_profile_name_to_file", {}):
            profile_file = self._profile_name_to_file[profile_name]
        else:
            profile_file = profile_file_map.get(profile_name, f"{profile_name.lower().replace(' ', '_')}.json")

        if os.path.isabs(profile_file):
            profile_path = profile_file
        else:
            profile_path = os.path.join(PROJECT_DIR, "profiles", profile_file)
            if not os.path.exists(profile_path):
                profile_path = os.path.join(BUNDLE_ROOT, "profiles", profile_file)
        logger.info(f"[PROFILE] Путь к профилю: {profile_path}")
        
        if os.path.exists(profile_path):
            try:
                with open(profile_path, 'r', encoding='utf-8') as f:
                    profile = json.load(f)
                
                logger.info(f"[PROFILE] Профиль загружен: {profile.get('name', profile_name)}")
                logger.info(f"[PROFILE] Параметры профиля: max_score={profile.get('max_score')}, "
                          f"feasible_threshold={profile.get('feasible_threshold')}, "
                          f"network_weight={profile.get('network_weight')}")
                
                self.profile_description.setText(f"{profile.get('name', profile_name)}\n\n{profile.get('description', '')}")
                self.btn_apply_profile.setEnabled(True)
                
                # Сохраняем текущий профиль для применения
                self._current_profile = profile
                self._current_profile_path = profile_path
                self.btn_overwrite_profile.setEnabled(
                    os.path.abspath(profile_path).startswith(os.path.abspath(os.path.join(PROJECT_DIR, "profiles")) + os.sep)
                )
                
            except Exception as e:
                logger.error(f"Ошибка загрузки профиля {profile_name}: {e}", exc_info=True)
                self.profile_description.setText(f"Ошибка загрузки профиля: {e}")
                self.btn_apply_profile.setEnabled(False)
                self.btn_overwrite_profile.setEnabled(False)
        else:
            logger.warning(f"[PROFILE] Файл профиля не найден: {profile_path}")
            self.profile_description.setText(f"Файл профиля не найден: {profile_path}")
            self.btn_apply_profile.setEnabled(False)
            self.btn_overwrite_profile.setEnabled(False)
    
    def _load_profile_from_file(self):
        """Загрузка профиля из файла."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Загрузить профиль корреляции", 
            PROJECT_DIR, 
            "JSON Files (*.json)"
        )
        if not path:
            self.profile_combo.setCurrentIndex(0)
            return
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                profile = json.load(f)
            
            # Проверяем обязательные поля
            required_fields = ['max_score', 'feasible_threshold', 'partially_feasible_threshold', 
                             'not_feasible_threshold', 'network_weight', 'trivy_weight', 
                             'software_weight', 'scanner_weight']
            
            for field in required_fields:
                if field not in profile:
                    raise ValueError(f"Отсутствует обязательное поле: {field}")
            
            # Добавляем профиль в комбобокс
            profile_name = profile.get('name', os.path.basename(path).replace('.json', ''))
            self.profile_combo.addItem(profile_name)
            self.profile_combo.setCurrentText(profile_name)
            if hasattr(self, "_profile_name_to_file"):
                self._profile_name_to_file[profile_name] = path
            
            # Сохраняем профиль
            self._current_profile = profile
            self._current_profile_path = path
            self.profile_description.setText(f"{profile.get('name', 'Пользовательский профиль')}\n\n{profile.get('description', 'Загружен из файла')}")
            self.btn_apply_profile.setEnabled(True)
            self.btn_overwrite_profile.setEnabled(
                os.path.abspath(path).startswith(os.path.abspath(os.path.join(PROJECT_DIR, "profiles")) + os.sep)
            )
            
        except Exception as e:
            logger.error(f"Ошибка загрузки профиля из файла: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить профиль:\n{e}")
            self.profile_combo.setCurrentIndex(0)
            self.btn_overwrite_profile.setEnabled(False)
    
    def _apply_profile(self):
        """Применить выбранный профиль к настройкам."""
        logger.info(f"[PROFILE] Попытка применения профиля")
        
        if not hasattr(self, '_current_profile') or not self._current_profile:
            logger.warning("[PROFILE] Нет текущего профиля для применения")
            return
        
        try:
            profile = self._current_profile
            logger.info(f"[PROFILE] Применение профиля: {profile.get('name', 'Пользовательский')}")
            logger.info(f"[PROFILE] Устанавливаем значения: max_score={profile['max_score']}, "
                      f"feasible_threshold={profile['feasible_threshold']}, "
                      f"network_weight={profile['network_weight']}")
            
            # Устанавливаем значения из профиля
            self.max_score_spin.setValue(profile['max_score'])
            self.feasible_threshold_spin.setValue(profile['feasible_threshold'])
            self.partially_threshold_spin.setValue(profile['partially_feasible_threshold'])
            self.not_feasible_threshold_spin.setValue(profile['not_feasible_threshold'])
            self.network_weight_spin.setValue(profile['network_weight'])
            self.trivy_weight_spin.setValue(profile['trivy_weight'])
            self.software_weight_spin.setValue(profile['software_weight'])
            self.scanner_weight_spin.setValue(profile['scanner_weight'])
            self.patch_weight_spin.setValue(profile.get('patch_weight', 10))
            self.protection_weight_spin.setValue(profile.get('protection_weight', 5))
            
            logger.info(f"[PROFILE] Значения установлены в интерфейсе")
            
            # Сохраняем настройки в глобальном состоянии
            from server.api_server import state
            state.correlation_settings = profile
            logger.info(f"[PROFILE] Настройки сохранены в глобальном состоянии")
            
            # Обновляем статус
            self.settings_status_label.setText(f"✅ Применён профиль: {profile.get('name', 'Пользовательский')}")
            self.settings_status_label.setStyleSheet("color:#8a8;font-size:11px;padding:4px;")
            
            # Обновляем текст текущих параметров
            self._update_current_settings_text(profile)
            
            self._sync_restart_correlation_button_state()
            logger.info("[PROFILE] Состояние кнопки перезапуска корреляции обновлено")

            extra = (
                "\n\nНажмите «Перезапустить корреляцию», чтобы пересчитать результаты по текущим данным атакующего."
                if self._last_scan_data
                else "\n\nПосле получения данных от атакующего станет доступна кнопка «Перезапустить корреляцию» для пересчёта с этим профилем."
            )
            QMessageBox.information(
                self, "Профиль применён",
                f"Профиль «{profile.get('name', 'Пользовательский')}» применён.{extra}",
            )
            
            logger.info(f"[PROFILE] Профиль успешно применён")
            
        except Exception as e:
            logger.error(f"Ошибка применения профиля: {e}", exc_info=True)
            QMessageBox.critical(self, "Ошибка", f"Не удалось применить профиль:\n{e}")

    def _collect_current_correlation_settings(self) -> dict:
        return {
            "max_score": self.max_score_spin.value(),
            "feasible_threshold": self.feasible_threshold_spin.value(),
            "partially_feasible_threshold": self.partially_threshold_spin.value(),
            "not_feasible_threshold": self.not_feasible_threshold_spin.value(),
            "network_weight": self.network_weight_spin.value(),
            "trivy_weight": self.trivy_weight_spin.value(),
            "software_weight": self.software_weight_spin.value(),
            "scanner_weight": self.scanner_weight_spin.value(),
            "patch_weight": self.patch_weight_spin.value(),
            "protection_weight": self.protection_weight_spin.value(),
        }

    def _save_new_profile_from_current_settings(self):
        name, ok = QInputDialog.getText(self, "Новый профиль", "Название профиля:")
        if not ok:
            return
        name = str(name or "").strip()
        if not name:
            QMessageBox.warning(self, "Профиль", "Название профиля не задано.")
            return
        desc, _ok2 = QInputDialog.getText(self, "Новый профиль", "Описание (необязательно):")
        if not _ok2:
            desc = ""

        settings = self._collect_current_correlation_settings()
        try:
            saved = save_correlation_profile(PROJECT_DIR, name=name, description=desc, settings=settings, profile_id=None)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить профиль:\n{e}")
            return

        label = name
        if hasattr(self, "_profile_name_to_file") and label in self._profile_name_to_file:
            label = f"{name} ({saved.get('file')})"
        if not hasattr(self, "_profile_name_to_file"):
            self._profile_name_to_file = {}
        self._profile_name_to_file[label] = saved.get("file")
        if self.profile_combo.findText(label) < 0:
            self.profile_combo.addItem(label)
        self.profile_combo.setCurrentText(label)
        QMessageBox.information(self, "Профиль сохранён", f"Профиль сохранён: {saved.get('file')}")

    def _overwrite_selected_profile_from_current_settings(self):
        profile_path = getattr(self, "_current_profile_path", "") or ""
        if not profile_path or not os.path.exists(profile_path):
            return
        base_profiles_dir = os.path.abspath(os.path.join(PROJECT_DIR, "profiles")) + os.sep
        if not os.path.abspath(profile_path).startswith(base_profiles_dir):
            QMessageBox.warning(self, "Профиль", "Перезапись разрешена только для профилей в папке profiles проекта.")
            return

        reply = QMessageBox.question(
            self,
            "Перезапись профиля",
            "Перезаписать выбранный профиль текущими настройками?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            with open(profile_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = {}

        name = str(existing.get("name") or self.profile_combo.currentText() or "Профиль")
        desc = str(existing.get("description") or "")
        settings = self._collect_current_correlation_settings()
        try:
            saved = save_correlation_profile(
                PROJECT_DIR,
                name=name,
                description=desc,
                settings=settings,
                profile_id=os.path.basename(profile_path),
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось перезаписать профиль:\n{e}")
            return

        QMessageBox.information(self, "Профиль обновлён", f"Профиль обновлён: {saved.get('file')}")

    def _copy_current_settings_to_other_profile(self):
        if not hasattr(self, "_profile_name_to_file"):
            return
        options = []
        for label, pf in self._profile_name_to_file.items():
            if os.path.isabs(pf):
                continue
            ppath = os.path.join(PROJECT_DIR, "profiles", pf)
            if os.path.exists(ppath):
                options.append(label)
        options = sorted(options)
        if not options:
            QMessageBox.information(self, "Профили", "Не найдено профилей для записи в папке profiles.")
            return

        target_label, ok = QInputDialog.getItem(self, "Выбор профиля", "Куда записать настройки:", options, 0, False)
        if not ok:
            return

        target_file = self._profile_name_to_file.get(target_label)
        if not target_file:
            return
        target_path = os.path.join(PROJECT_DIR, "profiles", target_file)
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = {}

        name = str(existing.get("name") or target_label)
        desc = str(existing.get("description") or "")
        settings = self._collect_current_correlation_settings()
        try:
            saved = save_correlation_profile(
                PROJECT_DIR,
                name=name,
                description=desc,
                settings=settings,
                profile_id=target_file,
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось записать настройки:\n{e}")
            return

        QMessageBox.information(self, "Готово", f"Настройки записаны в профиль: {saved.get('file')}")
    
    def _sync_restart_correlation_button_state(self):
        """Включает «Перезапустить корреляцию», если есть данные последнего скана и готовность к расчёту."""
        if not hasattr(self, "btn_restart_correlation"):
            return
        can = bool(self._last_scan_data) and self.system_info is not None and self.vuln_db is not None
        self.btn_restart_correlation.setEnabled(can)

    def _restart_correlation(self):
        """Перезапустить корреляцию с новыми параметрами."""
        if not self.system_info or not self.vuln_db:
            QMessageBox.warning(self, "Нет данных", "Сначала выполните анализ системы и загрузите базы данных.")
            return
        
        if not self._last_scan_data:
            QMessageBox.warning(self, "Нет данных от атакующего", "Нет данных от атакующего для перезапуска корреляции.")
            return

        # Показываем прогресс
        self.correlation_progress_label.setText("🔄 Перезапуск корреляции...")
        self.correlation_progress_label.setStyleSheet("color:#a85;font-size:11px;padding:4px;")
        self.correlation_progress_bar.setVisible(True)
        self.correlation_progress_bar.setValue(0)
        self.btn_restart_correlation.setEnabled(False)

        self.restart_correlation_worker = CorrelationRestartWorker(
            system_info=self.system_info,
            vuln_db=self.vuln_db,
            trivy_result=getattr(self, 'trivy_result', None),
            last_scan_data=self._last_scan_data,
            toolkit=self.toolkit,
            vuln_scan_report=self.vuln_scan_report,
            system_summary=self.system_summary,
            settings=None,
        )
        self.restart_correlation_worker.progress.connect(self.correlation_progress_signal.emit)
        self.restart_correlation_worker.finished.connect(self._on_restart_correlation_finished)
        self.restart_correlation_worker.error.connect(self._on_restart_correlation_error)
        self.restart_correlation_worker.finished.connect(self._on_restart_correlation_worker_finished)
        self.restart_correlation_worker.error.connect(self._on_restart_correlation_worker_finished)
        self.restart_correlation_worker.start()

    def _on_restart_correlation_finished(self, data):
        results = data["results"]
        summary = data["summary"]
        hp = data["html_path"]
        jp = data["json_path"]
        ts = data["correlation_id"]

        self._last_results = results
        self.last_report_path = hp
        self._add_to_history(results, summary, ts, hp, jp)

        from server.api_server import state
        if not hasattr(state, "last_correlation_lock"):
            state.last_correlation_lock = threading.Lock()
        with state.last_correlation_lock:
            state.last_correlation_payload = data["payload"]
            state.last_correlation_id = ts

        if isinstance(data.get("results_by_profile"), dict):
            self._apply_correlation_bundle_slot({
                "results_by_profile": data.get("results_by_profile"),
                "summaries_by_profile": data.get("summaries_by_profile"),
                "profiles_meta": data.get("profiles_meta"),
                "default_profile_id": data.get("default_profile_id"),
                "settings_by_profile": data.get("settings_by_profile"),
            })
        else:
            self.update_results_signal.emit(results)
        self.correlation_progress_label.setText("✅ Корреляция перезапущена")
        self.correlation_progress_label.setStyleSheet("color:#8a8;font-size:11px;padding:4px;")
        QMessageBox.information(
            self, "Корреляция перезапущена",
            f"Корреляция успешно перезапущена с новыми параметрами.\n\n"
            f"Найдено {len(results)} результатов.\n"
            f"Отчёт сохранён: {os.path.basename(hp)}"
        )
        QTimer.singleShot(2000, lambda: self.correlation_progress_bar.setVisible(False))
        self._sync_restart_correlation_button_state()

    def _on_restart_correlation_error(self, error):
        self.correlation_progress_bar.setVisible(False)
        self.correlation_progress_label.setText("❌ Ошибка перезапуска")
        self.correlation_progress_label.setStyleSheet("color:#b55;font-size:11px;padding:4px;")
        QMessageBox.critical(self, "Ошибка", f"Не удалось перезапустить корреляцию:\n{error}")
        self._sync_restart_correlation_button_state()

    def _on_restart_correlation_worker_finished(self, *_):
        self.restart_correlation_worker = None
    
    # ─────────────────────────────────────────
    #  Закрытие
    # ─────────────────────────────────────────
    def closeEvent(self, e):
        if self.server_running:
            reply = QMessageBox.question(
                self, "Выход", "Остановить сервер и выйти?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                e.ignore()
                return
            self._stop_server()
        e.accept()
# ─────────────────────────────────────────
#  Запуск
# ─────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = ServerGUI()
    w.show()
    sys.exit(app.exec())
if __name__ == "__main__":
    main()
