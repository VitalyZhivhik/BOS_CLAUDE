"""
Серверный агент — графический интерфейс PyQt6.
Анализирует систему, принимает данные от атакующего, генерирует отчёты.
"""

import sys
import os
import json
import threading
import webbrowser
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QTabWidget, QFrame,
    QMessageBox, QStatusBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor, QIcon

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from common.config import SERVER_HOST, SERVER_PORT
from common.models import from_json_scan_result
from common.logger import get_server_logger, GUILogHandler
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator

logger = get_server_logger()

# ─── Стиль ───
STYLE = """
QMainWindow { background: #1a1a2e; }
QWidget { color: #e0e0e0; font-family: 'Segoe UI'; }
QGroupBox {
    background: #16213e; border: 1px solid #2a3a5e; border-radius: 8px;
    margin-top: 12px; padding-top: 20px; font-weight: bold; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #48cae4; }
QPushButton {
    padding: 10px 16px; border-radius: 6px; font-weight: bold; font-size: 12px;
    border: none; color: white;
}
QPushButton:disabled { background: #3a3a4e; color: #666; }
QPushButton:hover { opacity: 0.9; }
QTextEdit {
    background: #0d1117; color: #c9d1d9; border: 1px solid #21262d;
    border-radius: 6px; font-family: 'Consolas'; font-size: 11px; padding: 8px;
}
QTableWidget {
    background: #0d1117; color: #c9d1d9; border: 1px solid #21262d;
    border-radius: 6px; gridline-color: #21262d; font-size: 11px;
}
QTableWidget::item { padding: 4px 8px; }
QHeaderView::section {
    background: #161b22; color: #8b949e; border: none;
    padding: 6px; font-weight: bold;
}
QTabWidget::pane { border: 1px solid #2a3a5e; border-radius: 6px; background: #16213e; }
QTabBar::tab {
    background: #16213e; color: #8b949e; padding: 8px 20px;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
}
QTabBar::tab:selected { background: #1f2d4a; color: #48cae4; }
QSpinBox {
    background: #0d1117; color: #e0e0e0; border: 1px solid #2a3a5e;
    border-radius: 4px; padding: 4px;
}
QStatusBar { background: #0f1923; color: #8b949e; }
QLabel { color: #e0e0e0; }
"""


class AnalysisWorker(QThread):
    """Фоновый поток для анализа системы."""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def run(self):
        try:
            analyzer = SystemAnalyzer()
            info = analyzer.analyze()
            summary = analyzer.get_summary()
            self.finished.emit({"info": info, "summary": summary, "analyzer": analyzer})
        except Exception as e:
            logger.error(f"Ошибка анализа: {e}", exc_info=True)
            self.error.emit(str(e))


class DBLoadWorker(QThread):
    """Фоновый поток для загрузки баз данных."""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def run(self):
        try:
            db = VulnerabilityDatabase(PROJECT_DIR)
            db.load_all()
            self.finished.emit(db)
        except Exception as e:
            logger.error(f"Ошибка загрузки БД: {e}", exc_info=True)
            self.error.emit(str(e))


class ServerGUI(QMainWindow):
    # Сигналы для потокобезопасного обновления UI из HTTP-потока
    log_signal = pyqtSignal(str, str)
    client_connected_signal = pyqtSignal(str)
    analysis_done_signal = pyqtSignal(dict, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Серверный агент анализа безопасности")
        self.setMinimumSize(1100, 700)

        # Состояние
        self.system_info = None
        self.system_summary = None
        self.vuln_db = None
        self.http_server = None
        self.server_thread = None
        self.server_running = False
        self.last_report_path = None

        self._build_ui()
        self.setStyleSheet(STYLE)

        # Подключаем логгер к GUI
        gui_handler = GUILogHandler(self._on_log_message)
        gui_handler.setLevel(10)  # DEBUG
        logger.addHandler(gui_handler)

        # Сигналы
        self.log_signal.connect(self._append_log)
        self.client_connected_signal.connect(self._on_client_connected)
        self.analysis_done_signal.connect(self._on_server_analysis_done)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # ─── Левая панель ───
        left_panel = QWidget()
        left_panel.setFixedWidth(300)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(6)

        # Заголовок
        title = QLabel("🛡 Серверный агент")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #48cae4; padding: 8px;")
        left_layout.addWidget(title)

        # Индикатор статуса
        self.status_frame = QFrame()
        self.status_frame.setStyleSheet("background: #2d1b1b; border-radius: 8px; padding: 8px;")
        sf_layout = QVBoxLayout(self.status_frame)
        self.status_icon = QLabel("🔴  Сервер не запущен")
        self.status_icon.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.status_icon.setStyleSheet("color: #e63946;")
        sf_layout.addWidget(self.status_icon)
        self.connection_label = QLabel("Клиенты: нет подключений")
        self.connection_label.setStyleSheet("color: #8b949e; font-size: 10px;")
        sf_layout.addWidget(self.connection_label)
        left_layout.addWidget(self.status_frame)

        # Группа управления
        ctrl_group = QGroupBox("Управление")
        ctrl_layout = QVBoxLayout(ctrl_group)

        self.btn_analyze = QPushButton("1. Анализ системы")
        self.btn_analyze.setStyleSheet("background: #00b4d8;")
        self.btn_analyze.clicked.connect(self._run_analysis)
        ctrl_layout.addWidget(self.btn_analyze)

        self.btn_load_db = QPushButton("2. Загрузить базы CVE/CWE/CAPEC/MITRE")
        self.btn_load_db.setStyleSheet("background: #00b4d8;")
        self.btn_load_db.setEnabled(False)
        self.btn_load_db.clicked.connect(self._load_databases)
        ctrl_layout.addWidget(self.btn_load_db)

        self.btn_start = QPushButton("3. Запустить сервер")
        self.btn_start.setStyleSheet("background: #2dc653;")
        self.btn_start.setEnabled(False)
        self.btn_start.clicked.connect(self._toggle_server)
        ctrl_layout.addWidget(self.btn_start)
        left_layout.addWidget(ctrl_group)

        # Настройки
        settings_group = QGroupBox("Настройки")
        settings_layout = QHBoxLayout(settings_group)
        settings_layout.addWidget(QLabel("Порт API:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(SERVER_PORT)
        settings_layout.addWidget(self.port_spin)
        left_layout.addWidget(settings_group)

        # Отчёты
        report_group = QGroupBox("Отчёты")
        report_layout = QVBoxLayout(report_group)
        self.btn_open_report = QPushButton("📄 Открыть последний отчёт")
        self.btn_open_report.setStyleSheet("background: #6c757d;")
        self.btn_open_report.setEnabled(False)
        self.btn_open_report.clicked.connect(self._open_report)
        report_layout.addWidget(self.btn_open_report)

        self.btn_open_folder = QPushButton("📁 Папка отчётов")
        self.btn_open_folder.setStyleSheet("background: #6c757d;")
        self.btn_open_folder.clicked.connect(self._open_reports_folder)
        report_layout.addWidget(self.btn_open_folder)
        left_layout.addWidget(report_group)

        # Статистика системы
        stats_group = QGroupBox("Информация о системе")
        stats_layout = QVBoxLayout(stats_group)
        self.stats_label = QLabel("Ожидает анализа...")
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet("color: #8b949e; font-size: 10px;")
        stats_layout.addWidget(self.stats_label)
        left_layout.addWidget(stats_group)

        left_layout.addStretch()
        main_layout.addWidget(left_panel)

        # ─── Правая панель — вкладки ───
        self.tabs = QTabWidget()

        # Вкладка "Журнал"
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.tabs.addTab(self.log_text, "📋 Журнал событий")

        # Вкладка "Средства защиты"
        self.security_table = QTableWidget()
        self.security_table.setColumnCount(3)
        self.security_table.setHorizontalHeaderLabels(["Средство защиты", "Статус", "Описание"])
        self.security_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.security_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tabs.addTab(self.security_table, "🔒 Средства защиты")

        # Вкладка "Установленное ПО"
        self.software_table = QTableWidget()
        self.software_table.setColumnCount(3)
        self.software_table.setHorizontalHeaderLabels(["Программа", "Версия", "Издатель"])
        self.software_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.software_table, "💿 Установленное ПО")

        # Вкладка "Результаты корреляции"
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["CVE", "Серьёзность", "Реализуемость", "Описание", "Причина"])
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.results_table, "📊 Результаты корреляции")

        main_layout.addWidget(self.tabs, 1)

        # Статусная строка
        self.statusBar().showMessage("Готов к работе")

    # ─── Логирование ───
    def _on_log_message(self, message: str, level: str):
        """Callback от GUILogHandler — вызывается из любого потока."""
        self.log_signal.emit(message, level)

    def _append_log(self, message: str, level: str):
        """Добавление сообщения в журнал (только из главного потока)."""
        color_map = {
            "DEBUG": "#6c757d", "INFO": "#c9d1d9", "WARNING": "#f4a261",
            "ERROR": "#e63946", "CRITICAL": "#ff0040",
        }
        color = color_map.get(level, "#c9d1d9")
        self.log_text.append(f'<span style="color:{color}">{message}</span>')
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)

    # ─── Анализ системы ───
    def _run_analysis(self):
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Анализ системы...")
        self.statusBar().showMessage("Выполняется анализ системы...")

        self.analysis_worker = AnalysisWorker()
        self.analysis_worker.finished.connect(self._on_analysis_done)
        self.analysis_worker.error.connect(self._on_analysis_error)
        self.analysis_worker.start()

    def _on_analysis_done(self, result):
        self.system_info = result["info"]
        self.system_summary = result["summary"]

        self.btn_analyze.setText("✔ Анализ системы выполнен")
        self.btn_analyze.setEnabled(True)
        self.btn_load_db.setEnabled(True)
        self.statusBar().showMessage("Анализ системы завершён")

        # Обновляем статистику
        s = self.system_summary
        self.stats_label.setText(
            f"ОС: {s['os']}\n"
            f"Имя: {s['hostname']}\n"
            f"IP: {', '.join(s['ip_addresses'])}\n"
            f"ПО: {s['installed_software_count']} программ\n"
            f"Сервисы: {s['running_services_count']} работающих\n"
            f"Порты: {s['open_ports_count']} открытых\n"
            f"БД: {'Да — ' + ', '.join(s['database_types']) if s['has_database'] else 'Нет'}\n"
            f"Веб-сервер: {'Да — ' + ', '.join(s['web_server_types']) if s['has_web_server'] else 'Нет'}\n"
            f"RDP: {'Вкл' if s['has_rdp'] else 'Выкл'} | SMB: {'Вкл' if s['has_smb'] else 'Выкл'}\n"
            f"Firewall: {'✔' if s['firewall'] else '✘'} | Антивирус: {'✔' if s['antivirus'] else '✘'}"
        )

        # Таблица средств защиты
        measures = s.get("security_measures", [])
        self.security_table.setRowCount(len(measures))
        for i, m in enumerate(measures):
            self.security_table.setItem(i, 0, QTableWidgetItem(m["name"]))
            status_item = QTableWidgetItem(m["status"])
            if m["status"] == "active":
                status_item.setForeground(QColor("#2dc653"))
            elif m["status"] == "inactive":
                status_item.setForeground(QColor("#e63946"))
            else:
                status_item.setForeground(QColor("#f4a261"))
            self.security_table.setItem(i, 1, status_item)
            self.security_table.setItem(i, 2, QTableWidgetItem(m["details"]))

        # Таблица ПО
        sw_list = self.system_info.installed_software
        self.software_table.setRowCount(len(sw_list))
        for i, sw in enumerate(sw_list):
            name = sw.name if hasattr(sw, 'name') else sw.get('name', '')
            ver = sw.version if hasattr(sw, 'version') else sw.get('version', '')
            pub = sw.publisher if hasattr(sw, 'publisher') else sw.get('publisher', '')
            self.software_table.setItem(i, 0, QTableWidgetItem(name))
            self.software_table.setItem(i, 1, QTableWidgetItem(ver))
            self.software_table.setItem(i, 2, QTableWidgetItem(pub))

    def _on_analysis_error(self, error_msg):
        self.btn_analyze.setText("1. Анализ системы")
        self.btn_analyze.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", f"Ошибка анализа:\n{error_msg}")

    # ─── Загрузка БД ───
    def _load_databases(self):
        self.btn_load_db.setEnabled(False)
        self.btn_load_db.setText("Загрузка баз...")
        self.statusBar().showMessage("Загрузка баз данных уязвимостей...")

        self.db_worker = DBLoadWorker()
        self.db_worker.finished.connect(self._on_db_loaded)
        self.db_worker.error.connect(self._on_db_error)
        self.db_worker.start()

    def _on_db_loaded(self, db):
        self.vuln_db = db
        total = len(db.cve_db) + len(db.cwe_db) + len(db.capec_db) + len(db.mitre_db)
        self.btn_load_db.setText(f"✔ Базы загружены ({total} записей)")
        self.btn_load_db.setEnabled(True)
        self.btn_start.setEnabled(True)
        self.statusBar().showMessage(f"Базы загружены: {total} записей")

    def _on_db_error(self, error_msg):
        self.btn_load_db.setText("2. Загрузить базы CVE/CWE/CAPEC/MITRE")
        self.btn_load_db.setEnabled(True)
        QMessageBox.critical(self, "Ошибка", f"Ошибка загрузки БД:\n{error_msg}")

    # ─── HTTP-сервер ───
    def _toggle_server(self):
        if self.server_running:
            self._stop_server()
        else:
            self._start_server()

    def _start_server(self):
        port = self.port_spin.value()
        gui = self

        # Импортируем state из api_server и настраиваем его
        from server.api_server import state
        state.base_dir = PROJECT_DIR
        state.system_info = self.system_info
        state.system_summary = self.system_summary
        state.vuln_db = self.vuln_db
        state.ready = True
        state.on_client_connected = lambda ip: gui.client_connected_signal.emit(ip)
        state.on_analysis_complete = lambda s, p: gui.analysis_done_signal.emit(s, p)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/status":
                    self._resp(200, {"status": "running", "ready": True,
                                     "hostname": state.system_summary.get("hostname", "")})
                elif self.path == "/ping":
                    ip = self.client_address[0]
                    logger.info(f"PING от клиента {ip}")
                    if ip not in state.connected_clients:
                        state.connected_clients.append(ip)
                    if state.on_client_connected:
                        state.on_client_connected(ip)
                    self._resp(200, {"status": "pong", "ready": True,
                                     "hostname": state.system_summary.get("hostname", "")})
                elif self.path == "/system-info":
                    self._resp(200, state.system_summary or {})
                else:
                    self._resp(200, {"message": "Security Assessment Server"})

            def do_POST(self):
                if self.path == "/analyze":
                    try:
                        length = int(self.headers.get("Content-Length", 0))
                        body = self.rfile.read(length).decode("utf-8")
                        scan_data = json.loads(body)

                        ip = self.client_address[0]
                        logger.info(f"ПОЛУЧЕНЫ ДАННЫЕ от {ip}: "
                                    f"{len(scan_data.get('open_ports', []))} портов, "
                                    f"{len(scan_data.get('attack_vectors', []))} атак")

                        if ip not in state.connected_clients:
                            state.connected_clients.append(ip)
                        if state.on_client_connected:
                            state.on_client_connected(ip)

                        scan_result = from_json_scan_result(scan_data)
                        correlator = AttackCorrelator(state.system_info, state.vuln_db)
                        results = correlator.correlate(scan_result)
                        summary = correlator.get_summary()

                        reports_dir = os.path.join(PROJECT_DIR, "reports")
                        os.makedirs(reports_dir, exist_ok=True)
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        reporter = ReportGenerator(state.system_summary, results, summary)
                        html_path = reporter.generate_html(os.path.join(reports_dir, f"report_{ts}.html"))
                        reporter.generate_json(os.path.join(reports_dir, f"report_{ts}.json"))

                        gui.last_report_path = html_path

                        response = {
                            "status": "success", "summary": summary,
                            "html_report": html_path, "results_count": len(results),
                            "details": [
                                {"cve_id": r.cve_id, "attack_name": r.attack_name,
                                 "severity": r.severity, "feasibility": r.feasibility,
                                 "reason": r.reason, "recommendation": r.recommendation}
                                for r in results
                            ]
                        }
                        self._resp(200, response)

                        if state.on_analysis_complete:
                            state.on_analysis_complete(summary, html_path)

                        # Обновляем таблицу результатов в GUI
                        gui._update_results_table(results)

                    except Exception as e:
                        logger.error(f"Ошибка анализа: {e}", exc_info=True)
                        self._resp(500, {"error": str(e)})
                else:
                    self._resp(404, {"error": "Не найдено"})

            def _resp(self, code, data):
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

            def log_message(self, fmt, *args):
                pass

        try:
            self.http_server = HTTPServer(("0.0.0.0", port), Handler)
            self.server_running = True
            self.server_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
            self.server_thread.start()

            self.btn_start.setText("⏹ Остановить сервер")
            self.btn_start.setStyleSheet("background: #e63946;")
            self.port_spin.setEnabled(False)
            self.status_icon.setText(f"🟢  Сервер запущен (порт {port})")
            self.status_icon.setStyleSheet("color: #2dc653;")
            self.status_frame.setStyleSheet("background: #1b2d1b; border-radius: 8px; padding: 8px;")
            self.statusBar().showMessage(f"Сервер запущен на порту {port}. Ожидание подключений...")
            logger.info(f"HTTP-сервер запущен на порту {port}")
        except Exception as e:
            logger.error(f"Не удалось запустить сервер: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить сервер:\n{e}")

    def _stop_server(self):
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None
        self.server_running = False
        self.btn_start.setText("3. Запустить сервер")
        self.btn_start.setStyleSheet("background: #2dc653;")
        self.port_spin.setEnabled(True)
        self.status_icon.setText("🔴  Сервер остановлен")
        self.status_icon.setStyleSheet("color: #e63946;")
        self.status_frame.setStyleSheet("background: #2d1b1b; border-radius: 8px; padding: 8px;")
        self.statusBar().showMessage("Сервер остановлен")
        logger.info("HTTP-сервер остановлен")

    def _on_client_connected(self, ip: str):
        self.connection_label.setText(f"Клиенты: {ip}")
        self.connection_label.setStyleSheet("color: #2dc653; font-size: 10px;")

    def _on_server_analysis_done(self, summary: dict, html_path: str):
        self.last_report_path = html_path
        self.btn_open_report.setEnabled(True)
        self.statusBar().showMessage(
            f"Корреляция завершена: {summary.get('feasible_attacks', 0)} реализуемых, "
            f"{summary.get('not_feasible_attacks', 0)} нереализуемых"
        )

    def _update_results_table(self, results):
        """Обновление таблицы результатов (thread-safe через сигнал)."""
        def update():
            self.results_table.setRowCount(len(results))
            for i, r in enumerate(results):
                self.results_table.setItem(i, 0, QTableWidgetItem(r.cve_id))

                sev_item = QTableWidgetItem(r.severity)
                sev_colors = {"CRITICAL": "#e63946", "HIGH": "#f4a261", "MEDIUM": "#e9c46a", "LOW": "#2dc653"}
                sev_item.setForeground(QColor(sev_colors.get(r.severity, "#c9d1d9")))
                self.results_table.setItem(i, 1, sev_item)

                feas_item = QTableWidgetItem(r.feasibility)
                if "НЕ РЕАЛИЗУЕМА" in r.feasibility:
                    feas_item.setForeground(QColor("#2dc653"))
                elif "ЧАСТИЧНО" in r.feasibility:
                    feas_item.setForeground(QColor("#f4a261"))
                elif "РЕАЛИЗУЕМА" in r.feasibility:
                    feas_item.setForeground(QColor("#e63946"))
                self.results_table.setItem(i, 2, feas_item)

                self.results_table.setItem(i, 3, QTableWidgetItem(r.description))
                self.results_table.setItem(i, 4, QTableWidgetItem(r.reason))

            self.tabs.setCurrentIndex(3)  # Переключаем на вкладку результатов

        # Вызываем из главного потока
        QTimer.singleShot(0, update)

    # ─── Отчёты ───
    def _open_report(self):
        if self.last_report_path and os.path.exists(self.last_report_path):
            webbrowser.open(f"file:///{os.path.abspath(self.last_report_path)}")
        else:
            QMessageBox.information(self, "Отчёт", "Отчёт ещё не сгенерирован.")

    def _open_reports_folder(self):
        reports_dir = os.path.join(PROJECT_DIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        if sys.platform == "win32":
            os.startfile(reports_dir)
        else:
            webbrowser.open(f"file:///{reports_dir}")

    def closeEvent(self, event):
        if self.server_running:
            self._stop_server()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = ServerGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
