"""
API сервера для приёма результатов сканирования от атакующего агента.
Использует встроенный http.server.
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
        self.ready = False  # Флаг готовности к приёму данных
        self.connected_clients = []  # Список подключавшихся клиентов
        self.on_client_connected = None  # Callback при подключении клиента
        self.on_analysis_complete = None  # Callback при завершении анализа


state = ServerState()


class RequestHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP-запросов."""

    def do_GET(self):
        if self.path == "/status":
            self._respond(200, {
                "status": "running",
                "ready": state.ready,
                "hostname": state.system_summary.get("hostname", "unknown") if state.system_summary else "not_analyzed",
                "timestamp": datetime.now().isoformat(),
            })
            logger.debug(f"GET /status от {self.client_address[0]}")

        elif self.path == "/system-info":
            if state.system_summary:
                self._respond(200, state.system_summary)
            else:
                self._respond(503, {"error": "Система ещё не проанализирована", "ready": False})

        elif self.path == "/ping":
            # Простой пинг для проверки связи
            client_ip = self.client_address[0]
            logger.info(f"PING от клиента {client_ip}")
            if client_ip not in state.connected_clients:
                state.connected_clients.append(client_ip)
            if state.on_client_connected:
                state.on_client_connected(client_ip)
            self._respond(200, {
                "status": "pong",
                "ready": state.ready,
                "hostname": state.system_summary.get("hostname", "") if state.system_summary else "",
            })

        elif self.path == "/":
            self._respond(200, {"message": "Security Assessment Server API", "ready": state.ready})
        else:
            self._respond(404, {"error": "Не найдено"})

    def do_POST(self):
        if self.path == "/analyze":
            if not state.ready:
                logger.warning(f"POST /analyze от {self.client_address[0]}, но сервер НЕ ГОТОВ")
                self._respond(503, {
                    "error": "Сервер не готов. Необходимо сначала выполнить анализ системы и загрузить базы данных.",
                    "ready": False
                })
                return

            try:
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length == 0:
                    self._respond(400, {"error": "Пустое тело запроса"})
                    return

                body = self.rfile.read(content_length).decode("utf-8")
                scan_data = json.loads(body)

                client_ip = self.client_address[0]
                logger.info(f"=" * 50)
                logger.info(f"ПОЛУЧЕНЫ ДАННЫЕ СКАНИРОВАНИЯ от {client_ip}")
                logger.info(f"  Источник: {scan_data.get('scanner_ip', '?')}")
                logger.info(f"  Цель: {scan_data.get('target_ip', '?')}")
                logger.info(f"  Портов: {len(scan_data.get('open_ports', []))}")
                logger.info(f"  Атак: {len(scan_data.get('attack_vectors', []))}")

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

                reporter = ReportGenerator(state.system_summary, results, summary)
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
                        }
                        for r in results
                    ]
                }

                self._respond(200, response)

                logger.info(f"КОРРЕЛЯЦИЯ ЗАВЕРШЕНА")
                logger.info(f"  Реализуемых: {summary['feasible_attacks']}")
                logger.info(f"  Частично: {summary['partially_feasible']}")
                logger.info(f"  Нереализуемых: {summary['not_feasible_attacks']}")
                logger.info(f"  Отчёт: {html_path}")

                if state.on_analysis_complete:
                    state.on_analysis_complete(summary, html_path)

            except json.JSONDecodeError as e:
                logger.error(f"Некорректный JSON от клиента: {e}")
                self._respond(400, {"error": f"Некорректный JSON: {e}"})
            except Exception as e:
                logger.error(f"Ошибка при анализе: {e}", exc_info=True)
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
        # Подавляем стандартные логи HTTP (мы используем свой логгер)
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
