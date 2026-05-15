"""
API сервера для приёма результатов сканирования от атакующего агента.
Использует встроенный http.server.

ИСПРАВЛЕНИЯ v2.1:
  - /ping и /status ВСЕГДА возвращают 200 (даже если сервер не ready)
  - /analyze возвращает 503 только когда система не проанализирована
  - Логирование КАЖДОГО запроса (метод, путь, IP)
  - Защита от NoneType в system_summary
  - ✅ ИСПРАВЛЕНО: Передача toolkit, local_scan_report, attacker_scan_data в ReportGenerator
  - ✅ ИСПРАВЛЕНО: Дедупликация результатов (дубликаты в отчётах устранены)
  - ✅ НОВОЕ: Сохранение в историю отчётов через ReportHistory
  - ✅ НОВОЕ: Шкала прогресса корреляции для отслеживания прогресса
"""

import json
import os
import sys
import threading
import logging
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.config import SERVER_HOST, SERVER_PORT
from common.models import from_json_scan_result
from common.logger import get_server_logger
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator
from server.trivy_scanner import TrivyScanResult

logger = get_server_logger()

PLAYBOOK_DB_PATH = "databases/attack_playbooks.json"


class ServerState:
    """Глобальное состояние сервера."""

    def __init__(self):
        self.system_analyzer = None
        self.system_info = None
        self.system_summary = None
        self.vuln_db = None
        self.toolkit = None           # AttackToolkit — для схем 3,4,5
        self.local_scan_report = None # ScanReport   — для схемы 3
        # Заполняется после «3б. Сканирование Trivy» в gui_server. Пока None — этап [4/4] в
        # AttackCorrelator пропускается (нет подтверждения CVE по установленным пакетам).
        self.trivy_result = None      # TrivyScanResult | dict | None
        self.base_dir = ""
        self.ready = False
        self.connected_clients = []
        self.on_client_connected = None
        self.on_analysis_complete = None
        # Прогресс корреляции
        self.correlation_progress = 0  # 0-100
        self.correlation_message = ""  # Текущее сообщение
        self.on_correlation_progress = None  # Callback для GUI
        self.last_correlation_payload = None
        self.last_correlation_id = None
        self.last_correlation_lock = threading.Lock()
        self.playbook_lock = threading.Lock()


state = ServerState()

def _playbook_path() -> str:
    base = state.base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, PLAYBOOK_DB_PATH)

def _load_playbooks() -> dict:
    path = _playbook_path()
    try:
        if not os.path.exists(path):
            return {"schema_version": 2, "updated_at": "", "cves": {}, "vectors": {}}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"schema_version": 2, "updated_at": "", "cves": {}, "vectors": {}}
        if "cves" not in data or not isinstance(data.get("cves"), dict):
            data["cves"] = {}
        if "vectors" not in data or not isinstance(data.get("vectors"), dict):
            data["vectors"] = {}
        if "schema_version" not in data:
            data["schema_version"] = 2
        if "updated_at" not in data:
            data["updated_at"] = ""
        return data
    except Exception as e:
        logger.warning(f"[PLAYBOOK] Ошибка чтения {path}: {e}")
        return {"schema_version": 2, "updated_at": "", "cves": {}, "vectors": {}}

def _save_playbooks(db: dict) -> None:
    path = _playbook_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass
    db = db if isinstance(db, dict) else {"schema_version": 2, "updated_at": "", "cves": {}, "vectors": {}}
    if "cves" not in db or not isinstance(db.get("cves"), dict):
        db["cves"] = {}
    if "vectors" not in db or not isinstance(db.get("vectors"), dict):
        db["vectors"] = {}
    if "schema_version" not in db:
        db["schema_version"] = 2
    db["updated_at"] = datetime.now().isoformat()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def _safe_hostname() -> str:
    """Безопасное получение hostname из system_summary."""
    if state.system_summary and isinstance(state.system_summary, dict):
        return state.system_summary.get("hostname", "")
    return ""


def _save_to_history(results: list, summary: dict, ts: str,
                     html_path: str, json_path: str, scan_data: dict):
    """Сохранение результатов в историю отчётов (если ReportHistory доступен)."""
    try:
        from server.report_history import ReportHistory, ReportRecord
        history = ReportHistory(state.base_dir)
        rec = ReportRecord(
            report_id=ts,
            timestamp=datetime.now().isoformat(),
            html_path=html_path,
            json_path=json_path,
            hostname=state.system_summary.get("hostname", "") if isinstance(state.system_summary, dict) else "",
            os_name=state.system_summary.get("os", "") if isinstance(state.system_summary, dict) else "",
            target_ip=scan_data.get("target_ip", ""),
            scanner_ip=scan_data.get("scanner_ip", ""),
            total_vulnerabilities=len(results),
            feasible_count=summary.get("feasible_attacks", 0),
            not_feasible_count=summary.get("not_feasible_attacks", 0),
            critical_count=summary.get("critical_count", 0),
            high_count=summary.get("high_count", 0),
            medium_count=summary.get("medium_count", 0),
            low_count=summary.get("low_count", 0),
        )
        history.add_record(rec)
        logger.info(f"[HISTORY] Запись добавлена: {ts}")
    except ImportError:
        logger.debug("[HISTORY] ReportHistory недоступен — пропускаем")
    except Exception as e:
        logger.warning(f"[HISTORY] Ошибка сохранения в историю: {e}")


class RequestHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP-запросов."""

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        client_ip = self.client_address[0]
        logger.info(f"[HTTP-IN] GET {self.path} от {client_ip}")
        try:
            u = urlparse(self.path)
            path = u.path
            qs = parse_qs(u.query or "")
            if path == "/status":
                self._respond(200, {
                    "status": "running",
                    "ready": state.ready,
                    "hostname": _safe_hostname(),
                    "timestamp": datetime.now().isoformat(),
                    "clients": state.connected_clients,
                })

            elif path == "/system-info":
                if state.system_summary and isinstance(state.system_summary, dict):
                    self._respond(200, state.system_summary)
                else:
                    self._respond(200, {"error": "Система ещё не проанализирована", "ready": False})

            elif path == "/ping":
                # /ping ВСЕГДА возвращает 200
                if client_ip not in state.connected_clients:
                    state.connected_clients.append(client_ip)
                    logger.info(f"[HTTP-IN] НОВЫЙ КЛИЕНТ: {client_ip}")
                    if state.on_client_connected:
                        state.on_client_connected(client_ip)
                self._respond(200, {
                    "status": "pong",
                    "ready": state.ready,
                    "hostname": _safe_hostname(),
                })

            elif path == "/":
                self._respond(200, {
                    "message": "Security Assessment Server API v2.1",
                    "ready": state.ready,
                    "endpoints": ["/ping", "/status", "/system-info", "/analyze (POST)"],
                })

            elif path == "/playbooks":
                cve_q = (qs.get("cve") or [None])[0]
                vector_q = (qs.get("vector") or [None])[0]
                with state.playbook_lock:
                    db = _load_playbooks()
                if vector_q:
                    key = str(vector_q).strip()
                    entry = (db.get("vectors") or {}).get(key, None)
                    self._respond(200, {"vector_id": key, "playbook": entry or {}})
                elif cve_q:
                    entry = (db.get("cves") or {}).get(str(cve_q).upper(), None)
                    self._respond(200, {"cve_id": str(cve_q).upper(), "playbook": entry or {}})
                else:
                    self._respond(200, db)

            else:
                self._respond(404, {"error": "Не найдено"})

        except Exception as e:
            logger.error(f"[HTTP-IN] Ошибка GET {self.path}: {e}", exc_info=True)
            self._respond(500, {"error": f"Внутренняя ошибка: {e}"})

    def do_POST(self):
        client_ip = self.client_address[0]
        logger.info(f"[HTTP-IN] POST {self.path} от {client_ip}")

        u = urlparse(self.path)
        path = u.path

        if path == "/playbooks":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length == 0:
                    self._respond(400, {"error": "Пустое тело запроса"})
                    return
                body = self.rfile.read(content_length).decode("utf-8")
                payload = json.loads(body)
                vector_id = str(payload.get("vector_id", "") or "").strip()
                cve_id = str(payload.get("cve_id", "") or "").strip().upper()
                playbook = payload.get("playbook", None)
                if not vector_id and not cve_id:
                    self._respond(400, {"error": "Нужно указать vector_id или cve_id"})
                    return
                if cve_id and not cve_id.startswith("CVE-"):
                    self._respond(400, {"error": "Некорректный cve_id"})
                    return
                if vector_id and len(vector_id) > 300:
                    self._respond(400, {"error": "Слишком длинный vector_id"})
                    return
                if not isinstance(playbook, dict):
                    self._respond(400, {"error": "playbook должен быть объектом"})
                    return
                attacks = playbook.get("attacks", [])
                defenses = playbook.get("defenses", [])
                if not isinstance(attacks, list) or not isinstance(defenses, list):
                    self._respond(400, {"error": "attacks/defenses должны быть списками"})
                    return
                with state.playbook_lock:
                    db = _load_playbooks()
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
                    _save_playbooks(db)
                resp = {"status": "ok"}
                if vector_id:
                    resp["vector_id"] = vector_id
                if cve_id:
                    resp["cve_id"] = cve_id
                self._respond(200, resp)
            except json.JSONDecodeError as e:
                self._respond(400, {"error": f"Некорректный JSON: {e}"})
            except Exception as e:
                logger.error(f"[PLAYBOOK] Ошибка сохранения: {e}", exc_info=True)
                self._respond(500, {"error": str(e)})
            return

        if path == "/analyze":
            # Проверяем готовность сервера
            if not state.system_info:
                logger.warning(f"[HTTP-IN] POST /analyze от {client_ip}: НЕ ГОТОВ (анализ системы не выполнен)")
                self._respond(503, {
                    "error": "Сервер не готов: анализ системы не выполнен",
                    "ready": False,
                    "hint": "Выполните: 1) Анализ системы"
                })
                return
            
            if not state.vuln_db:
                logger.warning(f"[HTTP-IN] POST /analyze от {client_ip}: НЕ ГОТОВ (базы данных не загружены)")
                self._respond(503, {
                    "error": "Сервер не готов: базы данных не загружены",
                    "ready": False,
                    "hint": "Выполните: 2) Загрузка баз данных"
                })
                return
            
            if not state.ready:
                logger.warning(f"[HTTP-IN] POST /analyze от {client_ip}: НЕ ГОТОВ (сервер не запущен)")
                self._respond(503, {
                    "error": "Сервер не готов: сервер не запущен",
                    "ready": False,
                    "hint": "Выполните: 3) Запуск сервера"
                })
                return

            try:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length == 0:
                    self._respond(400, {"error": "Пустое тело запроса"})
                    return

                body = self.rfile.read(content_length).decode("utf-8")
                scan_data = json.loads(body)

                logger.info(
                    f"[HTTP-IN] Данные от {client_ip}: "
                    f"{len(scan_data.get('open_ports', []))} портов, "
                    f"{len(scan_data.get('attack_vectors', []))} атак"
                )

                if client_ip not in state.connected_clients:
                    state.connected_clients.append(client_ip)
                    if state.on_client_connected:
                        state.on_client_connected(client_ip)

                scan_result = from_json_scan_result(scan_data)

                # Корреляция с прогрессом
                logger.info(f"[HTTP-IN] Начинаем корреляцию...")
                state.correlation_progress = 0
                state.correlation_message = "Начало корреляции..."
                if state.on_correlation_progress:
                    state.on_correlation_progress(0, "Начало корреляции...")

                # trivy_result: если выполнен скан Trivy на сервере — усиливает корреляцию и
                # подтверждение CVE; иначе correlator работает без слоя Trivy (см. attack_correlator).
                correlator = AttackCorrelator(
                    state.system_info,
                    state.vuln_db,
                    trivy_result=state.trivy_result,
                )
                
                # Устанавливаем callback для прогресса
                def progress_callback(percent, message):
                    state.correlation_progress = percent
                    state.correlation_message = message
                    logger.info(f"[CORRELATION] {percent}% - {message}")
                    if state.on_correlation_progress:
                        state.on_correlation_progress(percent, message)
                
                correlator.set_progress_callback(progress_callback)
                
                results = correlator.correlate(scan_result)
                summary = correlator.get_summary()

                state.correlation_progress = 100
                state.correlation_message = "Корреляция завершена"
                if state.on_correlation_progress:
                    state.on_correlation_progress(100, "Корреляция завершена")

                # Генерация отчётов
                reports_dir = os.path.join(state.base_dir, "reports")
                os.makedirs(reports_dir, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")

                # ─── КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ ───────────────────────────────────────
                # Передаём toolkit, local_scan_report и attacker_scan_data
                # Без этого схемы 3,4,5 не работали (были пустые)
                # ──────────────────────────────────────────────────────────────────
                reporter = ReportGenerator(
                    system_summary=state.system_summary if isinstance(state.system_summary, dict) else {},
                    correlation_results=results,
                    summary=summary,
                    toolkit=state.toolkit,              # AttackToolkit для схем 4 и 5
                    local_scan_report=state.local_scan_report,  # ScanReport для схемы 3
                    attacker_scan_data=scan_data,       # Данные атакующего для схемы 3
                    system_info=state.system_info,      # для точного сопоставления ПО в отчёте
                    trivy_result=state.trivy_result,
                )

                html_path = reporter.generate_html(os.path.join(reports_dir, f"report_{ts}.html"))
                json_path = reporter.generate_json(os.path.join(reports_dir, f"report_{ts}.json"))

                logger.info(f"[HTTP-IN] Отчёты сгенерированы: {html_path}")

                # Сохранение в историю отчётов
                _save_to_history(results, summary, ts, html_path, json_path, scan_data)

                response = {
                    "status": "success",
                    "summary": summary,
                    "html_report": html_path,
                    "json_report": json_path,
                    "results_count": len(results),
                    "details": [
                        {
                            "cve_id": r.cve_id,
                            "attack_name": r.attack_name,
                            "severity": r.severity,
                            "feasibility": __import__("common.models", fromlist=["normalize_feasibility"]).normalize_feasibility(getattr(r, "feasibility", None)),
                            "reason": r.reason,
                            "recommendation": r.recommendation,
                            "description": r.description,
                        }
                        for r in results
                    ]
                }

                self._respond(200, response)
                logger.info(f"[HTTP-IN] Корреляция завершена: {len(results)} уникальных результатов")

                if state.on_analysis_complete:
                    state.on_analysis_complete(summary, html_path)

            except json.JSONDecodeError as e:
                logger.error(f"[HTTP-IN] Некорректный JSON: {e}")
                self._respond(400, {"error": f"Некорректный JSON: {e}"})
            except Exception as e:
                logger.error(f"[HTTP-IN] Ошибка анализа: {e}", exc_info=True)
                self._respond(500, {"error": str(e)})
        else:
            self._respond(404, {"error": "Не найдено"})

    def _respond(self, code: int, data: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))

    def log_message(self, format, *args):
        # Подавляем стандартные логи — используем свой логгер
        pass


def start_server(base_dir: str = "", port: int = None):
    """Инициализация и запуск серверного агента (консольный режим)."""
    state.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    srv_port = port or SERVER_PORT

    logger.info("=" * 60)
    logger.info(" СЕРВЕРНЫЙ АГЕНТ АНАЛИЗА БЕЗОПАСНОСТИ v2.1")
    logger.info("=" * 60)

    # 1. Анализ системы
    state.system_analyzer = SystemAnalyzer()
    state.system_info = state.system_analyzer.analyze()
    state.system_summary = state.system_analyzer.get_summary()

    # 2. Загрузка баз уязвимостей
    state.vuln_db = VulnerabilityDatabase(state.base_dir)
    state.vuln_db.load_all()

    # 3. Загрузка базы инструментов (опционально)
    try:
        from server.attack_toolkit import AttackToolkit, validate_tools_database_at_startup
        state.toolkit = AttackToolkit(state.base_dir)
        state.toolkit.load()
        validate_tools_database_at_startup(state.base_dir, state.toolkit)
        logger.info("[SRV] База инструментов загружена")
    except Exception as e:
        logger.warning(f"[SRV] База инструментов недоступна: {e}")

    state.ready = True
    logger.info("Сервер ГОТОВ к приёму данных")

    # 4. HTTP-сервер
    server = ThreadingHTTPServer(("0.0.0.0", srv_port), RequestHandler)
    logger.info(f"Сервер запущен: http://0.0.0.0:{srv_port}")
    logger.info(f"Ожидание данных: POST http://<IP>:{srv_port}/analyze")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Сервер остановлен.")
        server.shutdown()


if __name__ == "__main__":
    start_server()
