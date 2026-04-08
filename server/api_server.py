"""
API сервера для приёма результатов сканирования от атакующего агента.
Использует встроенный http.server.

ИСПРАВЛЕНИЯ:
  - /ping и /status ВСЕГДА возвращают 200 (даже если сервер не ready)
  - /analyze возвращает 503 только когда система не проанализирована
  - Логирование КАЖДОГО запроса (метод, путь, IP)
  - Защита от NoneType в system_summary
"""

import json
import os
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.config import SERVER_HOST, SERVER_PORT
from common.models import from_json_scan_result
from common.logger import get_server_logger
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator

logger = get_server_logger()


class ServerState:
    """Глобальное состояние сервера."""
    def __init__(self):
        self.system_analyzer = None
        self.system_info = None
        self.system_summary = None
        self.vuln_db = None
        self.base_dir = ""
        self.ready = False
        self.connected_clients = []
        self.on_client_connected = None
        self.on_analysis_complete = None


state = ServerState()


def _safe_hostname() -> str:
    """Безопасное получение hostname из system_summary."""
    if state.system_summary and isinstance(state.system_summary, dict):
        return state.system_summary.get("hostname", "")
    return ""


class RequestHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP-запросов."""

    def do_GET(self):
        client_ip = self.client_address[0]
        logger.info(f"[HTTP-IN] GET {self.path} от {client_ip}")

        try:
            if self.path == "/status":
                self._respond(200, {
                    "status": "running",
                    "ready": state.ready,
                    "hostname": _safe_hostname(),
                    "timestamp": datetime.now().isoformat(),
                    "clients": state.connected_clients,
                })

            elif self.path == "/system-info":
                if state.system_summary and isinstance(state.system_summary, dict):
                    self._respond(200, state.system_summary)
                else:
                    self._respond(200, {"error": "Система ещё не проанализирована", "ready": False})

            elif self.path == "/ping":
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

            elif self.path == "/":
                self._respond(200, {
                    "message": "Security Assessment Server API",
                    "ready": state.ready,
                    "endpoints": ["/ping", "/status", "/system-info", "/analyze (POST)"],
                })
            else:
                self._respond(404, {"error": "Не найдено"})

        except Exception as e:
            logger.error(f"[HTTP-IN] Ошибка GET {self.path}: {e}", exc_info=True)
            self._respond(500, {"error": f"Внутренняя ошибка: {e}"})

    def do_POST(self):
        client_ip = self.client_address[0]
        logger.info(f"[HTTP-IN] POST {self.path} от {client_ip}")

        if self.path == "/analyze":
            if not state.ready or not state.system_info or not state.vuln_db:
                parts = []
                if not state.system_info:
                    parts.append("анализ системы не выполнен")
                if not state.vuln_db:
                    parts.append("базы данных не загружены")
                reason = "; ".join(parts) if parts else "сервер не готов"

                logger.warning(f"[HTTP-IN] POST /analyze от {client_ip}: НЕ ГОТОВ ({reason})")
                self._respond(503, {
                    "error": f"Сервер не готов: {reason}",
                    "ready": False,
                    "hint": "Выполните: 1) Анализ системы, 2) Загрузка баз, 3) Запуск сервера"
                })
                return

            try:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length == 0:
                    self._respond(400, {"error": "Пустое тело запроса"})
                    return

                body = self.rfile.read(content_length).decode("utf-8")
                scan_data = json.loads(body)

                logger.info(f"[HTTP-IN] Данные от {client_ip}: "
                            f"{len(scan_data.get('open_ports', []))} портов, "
                            f"{len(scan_data.get('attack_vectors', []))} атак")

                if client_ip not in state.connected_clients:
                    state.connected_clients.append(client_ip)
                if state.on_client_connected:
                    state.on_client_connected(client_ip)

                scan_result = from_json_scan_result(scan_data)

                # Корреляция
                correlator = AttackCorrelator(state.system_info, state.vuln_db)
                results = correlator.correlate(scan_result)
                summary = correlator.get_summary()

                # Генерация отчётов
                reports_dir = os.path.join(state.base_dir, "reports")
                os.makedirs(reports_dir, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")

                reporter = ReportGenerator(
                    state.system_summary if isinstance(state.system_summary, dict) else {},
                    results, summary
                )
                html_path = reporter.generate_html(os.path.join(reports_dir, f"report_{ts}.html"))
                json_path = reporter.generate_json(os.path.join(reports_dir, f"report_{ts}.json"))

                response = {
                    "status": "success",
                    "summary": summary,
                    "html_report": html_path,
                    "json_report": json_path,
                    "results_count": len(results),
                    "details": [
                        {
                            "cve_id": r.cve_id, "attack_name": r.attack_name,
                            "severity": r.severity, "feasibility": r.feasibility,
                            "reason": r.reason, "recommendation": r.recommendation,
                            "description": r.description,
                        }
                        for r in results
                    ]
                }
                self._respond(200, response)
                logger.info(f"[HTTP-IN] Корреляция завершена: {len(results)} результатов")

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
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))

    def log_message(self, format, *args):
        # Подавляем стандартные логи — используем свой логгер
        pass


def start_server(base_dir: str = "", port: int = None):
    """Инициализация и запуск серверного агента."""
    state.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    srv_port = port or SERVER_PORT

    logger.info("=" * 60)
    logger.info("  СЕРВЕРНЫЙ АГЕНТ АНАЛИЗА БЕЗОПАСНОСТИ")
    logger.info("=" * 60)

    # 1. Анализ системы
    state.system_analyzer = SystemAnalyzer()
    state.system_info = state.system_analyzer.analyze()
    state.system_summary = state.system_analyzer.get_summary()

    # 2. Загрузка баз
    state.vuln_db = VulnerabilityDatabase(state.base_dir)
    state.vuln_db.load_all()

    state.ready = True
    logger.info("Сервер ГОТОВ к приёму данных")

    # 3. HTTP-сервер
    server = HTTPServer(("0.0.0.0", srv_port), RequestHandler)
    logger.info(f"Сервер запущен: http://0.0.0.0:{srv_port}")
    logger.info(f"Ожидание данных: POST http://<server_ip>:{srv_port}/analyze")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Сервер остановлен.")
        server.shutdown()


if __name__ == "__main__":
    start_server()
