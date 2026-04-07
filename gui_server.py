"""
Серверный агент — графический интерфейс PyQt6.
Анализирует систему, принимает данные от атакующего, генерирует отчёты.
Оптимизирован для быстрой работы с большими таблицами баз данных.
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
    QTableWidgetItem, QHeaderView, QTabWidget, QFrame,
    QMessageBox, QProgressBar
)
from PyQt6.QtCore import pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from common.config import SERVER_PORT
from common.models import from_json_scan_result
from common.logger import get_server_logger, GUILogHandler
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator

logger = get_server_logger()

STYLE = """
QMainWindow { background: #1a1a2e; }
QWidget { color: #e0e0e0; font-family: 'Segoe UI'; }
QGroupBox {
    background: #16213e; border: 1px solid #2a3a5e; border-radius: 8px;
    margin-top: 12px; padding-top: 20px; font-weight: bold; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #48cae4; }
QPushButton { padding: 10px 16px; border-radius: 6px; font-weight: bold; font-size: 12px; border: none; color: white; }
QPushButton:disabled { background: #3a3a4e; color: #666; }
QPushButton:hover { opacity: 0.9; }
QTextEdit { background: #0d1117; color: #c9d1d9; border: 1px solid #21262d; border-radius: 6px; font-family: 'Consolas'; font-size: 11px; padding: 8px; }
QTableWidget { background: #0d1117; color: #c9d1d9; border: 1px solid #21262d; border-radius: 6px; gridline-color: #21262d; font-size: 11px; }
QTableWidget::item { padding: 4px 8px; }
QHeaderView::section { background: #161b22; color: #8b949e; border: none; padding: 6px; font-weight: bold; }
QTabWidget::pane { border: 1px solid #2a3a5e; border-radius: 6px; background: #16213e; }
QTabBar::tab { background: #16213e; color: #8b949e; padding: 8px 20px; border-top-left-radius: 6px; border-top-right-radius: 6px; }
QTabBar::tab:selected { background: #1f2d4a; color: #48cae4; }
QSpinBox { background: #0d1117; color: #e0e0e0; border: 1px solid #2a3a5e; border-radius: 4px; padding: 4px; }
QProgressBar { background: #0d1117; border: 1px solid #2a3a5e; border-radius: 4px; text-align: center; color: #e0e0e0; font-weight: bold; }
QProgressBar::chunk { background: #48cae4; border-radius: 3px; }
QStatusBar { background: #0f1923; color: #8b949e; }
"""

class AnalysisWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, str)

    def run(self):
        try:
            analyzer = SystemAnalyzer(progress_callback=self.progress.emit)
            info = analyzer.analyze()
            summary = analyzer.get_summary()
            self.finished.emit({"info": info, "summary": summary, "analyzer": analyzer})
        except Exception as e:
            self.error.emit(str(e))

class DBLoadWorker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def run(self):
        try:
            db = VulnerabilityDatabase(PROJECT_DIR)
            db.load_all()
            self.finished.emit(db)
        except Exception as e:
            self.error.emit(str(e))

class ServerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)
    client_connected_signal = pyqtSignal(str)
    analysis_done_signal = pyqtSignal(dict, str)
    update_results_signal = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Серверный агент анализа безопасности")
        self.setMinimumSize(1100, 700)

        self.system_info = None
        self.system_summary = None
        self.vuln_db = None
        self.http_server = None
        self.server_running = False
        self.last_report_path = None

        self._build_ui()
        self.setStyleSheet(STYLE)

        gui_handler = GUILogHandler(self._on_log_message)
        gui_handler.setLevel(10)
        logger.addHandler(gui_handler)

        self.log_signal.connect(self._append_log)
        self.client_connected_signal.connect(self._on_client_connected)
        self.analysis_done_signal.connect(self._on_server_analysis_done)
        self.update_results_signal.connect(self._update_results_table_slot)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        
        left_panel = QWidget()
        left_panel.setFixedWidth(300)
        left_layout = QVBoxLayout(left_panel)

        title = QLabel("🛡 Серверный агент")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #48cae4; padding: 8px;")
        left_layout.addWidget(title)

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

        ctrl_group = QGroupBox("Управление")
        ctrl_layout = QVBoxLayout(ctrl_group)
        self.btn_analyze = QPushButton("1. Анализ системы")
        self.btn_analyze.setStyleSheet("background: #00b4d8;")
        self.btn_analyze.clicked.connect(self._run_analysis)
        ctrl_layout.addWidget(self.btn_analyze)

        self.btn_load_db = QPushButton("2. Загрузить базы")
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
        
        prog_group = QGroupBox("Прогресс анализа")
        pl = QVBoxLayout(prog_group)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        pl.addWidget(self.progress_bar)
        self.progress_label = QLabel("Готов к работе")
        self.progress_label.setWordWrap(True)
        pl.addWidget(self.progress_label)
        left_layout.addWidget(prog_group)

        settings_group = QGroupBox("Настройки")
        settings_layout = QHBoxLayout(settings_group)
        settings_layout.addWidget(QLabel("Порт API:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(8888)
        settings_layout.addWidget(self.port_spin)
        left_layout.addWidget(settings_group)

        report_group = QGroupBox("Отчёты")
        report_layout = QVBoxLayout(report_group)
        self.btn_open_report = QPushButton("📄 Открыть последний отчёт")
        self.btn_open_report.setStyleSheet("background: #6c757d;")
        self.btn_open_report.setEnabled(False)
        self.btn_open_report.clicked.connect(self._open_report)
        report_layout.addWidget(self.btn_open_report)
        left_layout.addWidget(report_group)

        stats_group = QGroupBox("Информация о системе")
        stats_layout = QVBoxLayout(stats_group)
        self.stats_label = QLabel("Ожидает анализа...")
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet("color: #8b949e; font-size: 10px;")
        stats_layout.addWidget(self.stats_label)
        left_layout.addWidget(stats_group)

        left_layout.addStretch()
        main_layout.addWidget(left_panel)

        self.tabs = QTabWidget()
        self.log_text = QTextEdit()
        self.tabs.addTab(self.log_text, "📋 Журнал событий")

        self.security_table = QTableWidget()
        self.security_table.setColumnCount(3)
        self.security_table.setHorizontalHeaderLabels(["Средство защиты", "Статус", "Описание"])
        self.security_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.security_table, "🔒 Средства защиты")

        self.software_table = QTableWidget()
        self.software_table.setColumnCount(3)
        self.software_table.setHorizontalHeaderLabels(["Программа", "Версия", "Издатель"])
        self.software_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.software_table, "💿 Установленное ПО")

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["CVE", "Серьёзность", "Реализуемость", "Описание", "Причина"])
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.results_table, "📊 Корреляция")

        main_layout.addWidget(self.tabs, 1)

    def _on_log_message(self, message: str, level: str):
        self.log_signal.emit(message, level)

    def _append_log(self, message: str, level: str):
        color = {"DEBUG": "#6c757d", "INFO": "#c9d1d9", "WARNING": "#f4a261", "ERROR": "#e63946", "CRITICAL": "#ff0040"}.get(level, "#c9d1d9")
        self.log_text.append(f'<span style="color:{color}">{message}</span>')
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)

    def _run_analysis(self):
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Анализ системы...")
        self.progress_bar.setValue(0)
        self.analysis_worker = AnalysisWorker()
        self.analysis_worker.progress.connect(self._update_progress)
        self.analysis_worker.finished.connect(self._on_analysis_done)
        self.analysis_worker.start()

    def _update_progress(self, percent: int, text: str):
        self.progress_bar.setValue(percent)
        self.progress_label.setText(text)

    def _on_analysis_done(self, result):
        self.system_info = result["info"]
        self.system_summary = result["summary"]
        self.btn_analyze.setText("✔ Анализ выполнен")
        self.btn_analyze.setEnabled(True)
        self.btn_load_db.setEnabled(True)
        self.progress_bar.setValue(100)
        self.progress_label.setText("Анализ полностью завершен!")

        s = self.system_summary
        self.stats_label.setText(
            f"ОС: {s['os']}\nИмя: {s['hostname']}\nIP: {', '.join(s['ip_addresses'])}\n"
            f"ПО: {s['installed_software_count']} | Сервисы: {s['running_services_count']} | Порты: {s['open_ports_count']}"
        )

        self.security_table.setUpdatesEnabled(False)
        measures = s.get("security_measures", [])
        self.security_table.setRowCount(len(measures))
        for i, m in enumerate(measures):
            self.security_table.setItem(i, 0, QTableWidgetItem(m["name"]))
            self.security_table.setItem(i, 1, QTableWidgetItem(m["status"]))
            self.security_table.setItem(i, 2, QTableWidgetItem(m["details"]))
        self.security_table.setUpdatesEnabled(True)

        self.software_table.setUpdatesEnabled(False)
        sw_list = self.system_info.installed_software
        self.software_table.setRowCount(len(sw_list))
        for i, sw in enumerate(sw_list):
            self.software_table.setItem(i, 0, QTableWidgetItem(sw.name))
            self.software_table.setItem(i, 1, QTableWidgetItem(sw.version))
        self.software_table.setUpdatesEnabled(True)

    def _load_databases(self):
        self.btn_load_db.setEnabled(False)
        self.db_worker = DBLoadWorker()
        self.db_worker.finished.connect(self._on_db_loaded)
        self.db_worker.start()

    def _on_db_loaded(self, db):
        self.vuln_db = db
        self.btn_load_db.setText("✔ Базы загружены")
        self.btn_load_db.setEnabled(True)
        self.btn_start.setEnabled(True)

    def _toggle_server(self):
        if self.server_running:
            if self.http_server: self.http_server.shutdown()
            self.server_running = False
            self.btn_start.setText("3. Запустить сервер")
            self.btn_start.setStyleSheet("background: #2dc653;")
            self.status_icon.setText("🔴  Сервер остановлен")
            self.status_icon.setStyleSheet("color: #e63946;")
            self.status_frame.setStyleSheet("background: #2d1b1b; border-radius: 8px; padding: 8px;")
        else:
            port = self.port_spin.value()
            gui = self
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
                    if self.path == "/ping":
                        if state.on_client_connected: state.on_client_connected(self.client_address[0])
                        self._resp(200, {"status": "pong", "ready": True, "hostname": state.system_summary.get("hostname", "")})
                    else:
                        self._resp(200, {"message": "Security Assessment Server"})

                def do_POST(self):
                    if self.path == "/analyze":
                        try:
                            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8")
                            scan_data = json.loads(body)
                            scan_result = from_json_scan_result(scan_data)
                            correlator = AttackCorrelator(state.system_info, state.vuln_db)
                            results = correlator.correlate(scan_result)
                            summary = correlator.get_summary()
                            
                            reports_dir = os.path.join(PROJECT_DIR, "reports")
                            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                            reporter = ReportGenerator(state.system_summary, results, summary)
                            html_path = reporter.generate_html(os.path.join(reports_dir, f"report_{ts}.html"))
                            
                            gui.last_report_path = html_path
                            self._resp(200, {"status": "success", "summary": summary, "html_report": html_path, "details": [{"cve_id": r.cve_id, "attack_name": r.attack_name, "severity": r.severity, "feasibility": r.feasibility, "reason": r.reason} for r in results]})
                            if state.on_analysis_complete: state.on_analysis_complete(summary, html_path)
                            
                            # Передаем список результатов в UI безопасно
                            gui.update_results_signal.emit(results)
                        except Exception as e:
                            self._resp(500, {"error": str(e)})

                def _resp(self, code, data):
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))
                def log_message(self, fmt, *args): pass

            try:
                self.http_server = HTTPServer(("0.0.0.0", port), Handler)
                self.server_running = True
                threading.Thread(target=self.http_server.serve_forever, daemon=True).start()
                self.btn_start.setText("⏹ Остановить сервер")
                self.btn_start.setStyleSheet("background: #e63946;")
                self.status_icon.setText(f"🟢  Сервер запущен (порт {port})")
                self.status_icon.setStyleSheet("color: #2dc653;")
                self.status_frame.setStyleSheet("background: #1b2d1b; border-radius: 8px; padding: 8px;")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось запустить сервер:\n{e}")

    def _on_client_connected(self, ip: str):
        self.connection_label.setText(f"Клиенты: {ip}")
        self.connection_label.setStyleSheet("color: #2dc653; font-size: 10px;")

    def _on_server_analysis_done(self, summary: dict, html_path: str):
        self.last_report_path = html_path
        self.btn_open_report.setEnabled(True)

    def _update_results_table_slot(self, results):
        """Мгновенное обновление таблицы результатов с отключением прорисовки."""
        self.results_table.setUpdatesEnabled(False)
        self.results_table.setRowCount(len(results))
        for i, r in enumerate(results):
            self.results_table.setItem(i, 0, QTableWidgetItem(r.cve_id))
            self.results_table.setItem(i, 1, QTableWidgetItem(r.severity))
            self.results_table.setItem(i, 2, QTableWidgetItem(r.feasibility))
            self.results_table.setItem(i, 3, QTableWidgetItem(r.description))
            self.results_table.setItem(i, 4, QTableWidgetItem(r.reason))
        self.results_table.setUpdatesEnabled(True)
        self.tabs.setCurrentIndex(3)

    def _open_report(self):
        webbrowser.open(f"file:///{os.path.abspath(self.last_report_path)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ServerGUI()
    window.show()
    sys.exit(app.exec())