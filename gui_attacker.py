"""
Атакующий агент — графический интерфейс PyQt6.
Использует архитектуру "Оркестратор" (Aggregator) для неблокирующего сканирования.
Оптимизирован для получения больших объемов данных без зависаний.
"""

import sys
import os
import json
import socket
import urllib.request
import urllib.error
from datetime import datetime
from dataclasses import asdict

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QProgressBar, QFrame, QMessageBox, QStatusBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from common.config import TARGET_SERVER_HOST, TARGET_SERVER_PORT, SCAN_PORT_START, SCAN_PORT_END
from common.models import ScanResult, OpenPort
from common.logger import get_attacker_logger, GUILogHandler
from attacker.attacker_agent import FastPortScanner, OrchestratorAggregator

logger = get_attacker_logger()

STYLE = """
QMainWindow { background: #1b1b2f; }
QWidget { color: #e0e0e0; font-family: 'Segoe UI'; }
QGroupBox { background: #1f2833; border: 1px solid #2a3a5e; border-radius: 8px; margin-top: 12px; padding-top: 20px; font-weight: bold; font-size: 12px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #9b5de5; }
QPushButton { padding: 10px 16px; border-radius: 6px; font-weight: bold; font-size: 12px; border: none; color: white; }
QPushButton:disabled { background: #3a3a4e; color: #666; }
QTextEdit { background: #0d1117; color: #c9d1d9; border: 1px solid #21262d; border-radius: 6px; font-family: 'Consolas'; font-size: 11px; padding: 8px; }
QLineEdit, QSpinBox { background: #0d1117; color: #e0e0e0; border: 1px solid #2a3a5e; border-radius: 4px; padding: 6px; font-size: 12px; }
QTableWidget { background: #0d1117; color: #c9d1d9; border: 1px solid #21262d; border-radius: 6px; gridline-color: #21262d; font-size: 11px; }
QTableWidget::item { padding: 4px 8px; }
QHeaderView::section { background: #161b22; color: #8b949e; border: none; padding: 6px; font-weight: bold; }
QTabWidget::pane { border: 1px solid #2a3a5e; border-radius: 6px; background: #1f2833; }
QTabBar::tab { background: #1f2833; color: #8b949e; padding: 8px 20px; border-top-left-radius: 6px; border-top-right-radius: 6px; }
QTabBar::tab:selected { background: #2a1f4a; color: #9b5de5; }
QProgressBar { background: #0d1117; border: 1px solid #2a3a5e; border-radius: 4px; text-align: center; color: #e0e0e0; font-weight: bold; }
QProgressBar::chunk { background: #9b5de5; border-radius: 3px; }
QStatusBar { background: #0f1923; color: #8b949e; }
"""

class PingWorker(QThread):
    finished = pyqtSignal(str, bool)
    error = pyqtSignal(str)
    def __init__(self, target, port):
        super().__init__()
        self.target = target; self.port = port
    def run(self):
        try:
            proxy_handler = urllib.request.ProxyHandler({})
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(f"http://{self.target}:{self.port}/ping", method="GET")
            with opener.open(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                self.finished.emit(data.get("hostname", "?"), data.get("ready", False))
        except Exception as e:
            self.error.emit(str(e))

class OrchestratorWorker(QThread):
    port_found = pyqtSignal(object)
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(list, list) 
    error = pyqtSignal(str)

    def __init__(self, target, port_start, port_end):
        super().__init__()
        self.target = target; self.port_start = port_start; self.port_end = port_end

    def run(self):
        try:
            self.progress.emit(5, "Сканирование открытых портов...")
            scanner = FastPortScanner(self.target, self.port_start, self.port_end)
            ports = scanner.scan()
            
            for p in ports:
                self.port_found.emit(p)

            self.progress.emit(50, "Оркестратор: Запуск внешних сканеров (Nuclei, Nmap)...")
            aggregator = OrchestratorAggregator(self.target, ports)
            vectors = aggregator.run_all_scanners()

            self.progress.emit(100, "Сканирование завершено!")
            self.finished.emit(ports, vectors)
        except Exception as e:
            self.error.emit(str(e))


class SendWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    def __init__(self, url, data):
        super().__init__()
        self.url = url; self.data = data
    def run(self):
        try:
            json_data = json.dumps(self.data, ensure_ascii=False).encode("utf-8")
            proxy_handler = urllib.request.ProxyHandler({})
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(self.url, data=json_data, headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
            with opener.open(req, timeout=120) as resp:
                self.finished.emit(json.loads(resp.read().decode("utf-8")))
        except Exception as e:
            self.error.emit(str(e))


class AttackerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Атакующий агент — Оркестратор уязвимостей")
        self.setMinimumSize(1100, 700)
        self.open_ports = []; self.attack_vectors = []
        self._build_ui()
        self.setStyleSheet(STYLE)
        gui_handler = GUILogHandler(self._on_log_message); gui_handler.setLevel(10); logger.addHandler(gui_handler)
        self.log_signal.connect(self._append_log)

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central); main_layout = QHBoxLayout(central)
        left = QWidget(); left.setFixedWidth(300); ll = QVBoxLayout(left)
        title = QLabel("⚔ Атакующий агент"); title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold)); title.setStyleSheet("color: #9b5de5; padding: 8px;"); ll.addWidget(title)

        self.conn_frame = QFrame(); self.conn_frame.setStyleSheet("background: #2d1b1b; border-radius: 8px; padding: 8px;"); cf_layout = QVBoxLayout(self.conn_frame)
        self.conn_icon = QLabel("🔴  Нет связи с сервером"); self.conn_icon.setStyleSheet("color: #e63946; font-weight: bold;"); cf_layout.addWidget(self.conn_icon)
        self.conn_detail = QLabel(""); self.conn_detail.setStyleSheet("color: #8b949e; font-size: 10px;"); cf_layout.addWidget(self.conn_detail); ll.addWidget(self.conn_frame)

        target_group = QGroupBox("Параметры цели"); tl = QVBoxLayout(target_group)
        tl.addWidget(QLabel("IP-адрес сервера:")); self.target_input = QLineEdit(TARGET_SERVER_HOST); tl.addWidget(self.target_input)
        tl.addWidget(QLabel("Порт API сервера:")); self.port_spin = QSpinBox(); self.port_spin.setRange(1024, 65535); self.port_spin.setValue(8888); tl.addWidget(self.port_spin)
        row = QHBoxLayout(); self.port_start_spin = QSpinBox(); self.port_start_spin.setRange(1, 65535); self.port_start_spin.setValue(SCAN_PORT_START); row.addWidget(self.port_start_spin)
        self.port_end_spin = QSpinBox(); self.port_end_spin.setRange(1, 65535); self.port_end_spin.setValue(SCAN_PORT_END); row.addWidget(self.port_end_spin); tl.addLayout(row); ll.addWidget(target_group)

        action_group = QGroupBox("Действия"); al = QVBoxLayout(action_group)
        self.btn_check = QPushButton("🔗 Проверить связь"); self.btn_check.setStyleSheet("background: #00b4d8;"); self.btn_check.clicked.connect(self._check_connection); al.addWidget(self.btn_check)
        self.btn_scan = QPushButton("🔍 Запуск Оркестратора"); self.btn_scan.setStyleSheet("background: #9b5de5;"); self.btn_scan.clicked.connect(self._start_scan); al.addWidget(self.btn_scan)
        self.btn_send = QPushButton("📤 Отправить результаты"); self.btn_send.setStyleSheet("background: #2dc653;"); self.btn_send.setEnabled(False); self.btn_send.clicked.connect(self._send_to_server); al.addWidget(self.btn_send); ll.addWidget(action_group)

        prog_group = QGroupBox("Прогресс сканирования"); pl = QVBoxLayout(prog_group)
        self.progress_bar = QProgressBar(); self.progress_bar.setValue(0); pl.addWidget(self.progress_bar)
        self.progress_label = QLabel("Ожидание..."); pl.addWidget(self.progress_label); ll.addWidget(prog_group)

        self.summary_label = QLabel("Ожидает сканирования..."); ll.addWidget(self.summary_label); ll.addStretch(); main_layout.addWidget(left)

        self.tabs = QTabWidget()
        self.log_text = QTextEdit(); self.tabs.addTab(self.log_text, "📋 Журнал")
        self.ports_table = QTableWidget(); self.ports_table.setColumnCount(4); self.ports_table.setHorizontalHeaderLabels(["Порт", "Сервис", "Протокол", "Баннер"]); self.tabs.addTab(self.ports_table, "🌐 Открытые порты")
        self.attacks_table = QTableWidget(); self.attacks_table.setColumnCount(5); self.attacks_table.setHorizontalHeaderLabels(["Серьёзность", "Атака", "Тип", "Порт", "Инструменты"]); self.tabs.addTab(self.attacks_table, "💣 Векторы атак")
        self.response_text = QTextEdit(); self.tabs.addTab(self.response_text, "📊 Ответ сервера"); main_layout.addWidget(self.tabs, 1)

    def _on_log_message(self, message, level): self.log_signal.emit(message, level)
    def _append_log(self, message, level):
        colors = {"DEBUG": "#6c757d", "INFO": "#c9d1d9", "WARNING": "#f4a261", "ERROR": "#e63946", "CRITICAL": "#ff0040"}
        self.log_text.append(f'<span style="color:{colors.get(level, "#c9d1d9")}">{message}</span>'); self.log_text.moveCursor(QTextCursor.MoveOperation.End)

    def _check_connection(self):
        self.btn_check.setEnabled(False); self.btn_check.setText("Проверка...")
        self.ping_worker = PingWorker(self.target_input.text(), self.port_spin.value())
        self.ping_worker.finished.connect(self._on_connected); self.ping_worker.error.connect(self._on_connection_failed); self.ping_worker.start()

    def _on_connected(self, hostname, ready):
        self.conn_icon.setText("🟢  Связь установлена"); self.conn_icon.setStyleSheet("color: #2dc653; font-weight: bold;")
        self.conn_detail.setText(f"Сервер: {hostname}\n{'Готов к приёму данных' if ready else 'Не готов'}"); self.btn_check.setText("✔ Связь установлена"); self.btn_check.setEnabled(True)

    def _on_connection_failed(self, error):
        self.conn_icon.setText("🔴  Нет связи"); self.conn_icon.setStyleSheet("color: #e63946; font-weight: bold;")
        self.conn_detail.setText(error[:50]); self.btn_check.setText("🔗 Проверить связь"); self.btn_check.setEnabled(True)

    def _start_scan(self):
        self.open_ports = []; self.ports_table.setRowCount(0); self.attacks_table.setRowCount(0)
        self.btn_scan.setEnabled(False); self.btn_send.setEnabled(False)
        self.worker = OrchestratorWorker(self.target_input.text(), self.port_start_spin.value(), self.port_end_spin.value())
        self.worker.port_found.connect(self._on_port_found)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_scan_done)
        self.worker.error.connect(self._on_scan_error)
        self.worker.start()

    def _on_progress(self, pct, text):
        self.progress_bar.setValue(pct); self.progress_label.setText(text)

    def _on_port_found(self, port: OpenPort):
        row = self.ports_table.rowCount(); self.ports_table.insertRow(row)
        self.ports_table.setItem(row, 0, QTableWidgetItem(str(port.port))); self.ports_table.setItem(row, 1, QTableWidgetItem(port.service))
        self.ports_table.setItem(row, 2, QTableWidgetItem(port.protocol)); self.ports_table.setItem(row, 3, QTableWidgetItem(port.banner[:80] if port.banner else ""))

    def _on_scan_done(self, ports, vectors):
        self.open_ports = ports; self.attack_vectors = vectors
        self.attacks_table.setRowCount(len(vectors))
        for i, av in enumerate(vectors):
            self.attacks_table.setItem(i, 0, QTableWidgetItem(av.severity)); self.attacks_table.setItem(i, 1, QTableWidgetItem(av.name))
            self.attacks_table.setItem(i, 2, QTableWidgetItem(av.attack_type)); self.attacks_table.setItem(i, 3, QTableWidgetItem(str(av.target_port)))
            self.attacks_table.setItem(i, 4, QTableWidgetItem(av.tools_used))
        self.summary_label.setText(f"Найдено портов: {len(ports)}\nВекторов атак: {len(vectors)}")
        self.btn_scan.setEnabled(True); self.btn_send.setEnabled(bool(ports))

    def _on_scan_error(self, error):
        self.btn_scan.setEnabled(True); QMessageBox.critical(self, "Ошибка сканирования", error)

    def _send_to_server(self):
        scan_result = ScanResult(scanner_ip="127.0.0.1", target_ip=self.target_input.text(), open_ports=self.open_ports, discovered_services=[], attack_vectors=self.attack_vectors, os_detection="Windows", scan_timestamp=datetime.now().isoformat())
        self.btn_send.setEnabled(False); self.btn_send.setText("Отправка...")
        self.send_worker = SendWorker(f"http://{self.target_input.text()}:{self.port_spin.value()}/analyze", asdict(scan_result))
        self.send_worker.finished.connect(self._on_response); self.send_worker.error.connect(self._on_send_error); self.send_worker.start()

    def _on_response(self, result):
        self.btn_send.setEnabled(True); self.btn_send.setText("📤 Отправить результаты")
        self.tabs.setCurrentIndex(3); self.response_text.clear()
        
        summary = result.get("summary", {})
        
        # АНТИ-КРАШ: Собираем весь текст в массив и вставляем за одну операцию
        html_blocks = []
        html_blocks.append('<span style="color:#ffffff; font-size:14px; font-weight:bold;">═══════════════════════════════════════════════</span>')
        html_blocks.append('<span style="color:#ffffff; font-size:14px; font-weight:bold;">  РЕЗУЛЬТАТЫ КОРРЕЛЯЦИИ АТАК С КОНФИГУРАЦИЕЙ СЕРВЕРА</span>')
        html_blocks.append('<span style="color:#ffffff; font-size:14px; font-weight:bold;">═══════════════════════════════════════════════</span><br>')
        html_blocks.append(f'<span style="color:#c9d1d9;">  Всего проанализировано:   {summary.get("total_vulnerabilities_analyzed", 0)}</span>')
        html_blocks.append(f'<span style="color:#e63946; font-weight:bold;">  Реализуемые атаки:        {summary.get("feasible_attacks", 0)}</span>')
        html_blocks.append(f'<span style="color:#f4a261;">  Частично реализуемые:     {summary.get("partially_feasible", 0)}</span>')
        html_blocks.append(f'<span style="color:#2dc653;">  Нереализуемые:            {summary.get("not_feasible_attacks", 0)}</span>')
        html_blocks.append(f'<span style="color:#48cae4;">  Требуют анализа:          {summary.get("requires_analysis", 0)}</span><br>')
        html_blocks.append('<span style="color:#666;">─────────────────────────────────────────────</span><br>')

        for d in result.get("details", []):
            feas = d.get("feasibility", "?")
            if "НЕ РЕАЛИЗУЕМА" in feas: color, icon = "#2dc653", "✅"
            elif "ЧАСТИЧНО" in feas: color, icon = "#f4a261", "⚠️"
            elif "РЕАЛИЗУЕМА" in feas: color, icon = "#e63946", "❌"
            else: color, icon = "#48cae4", "❓"

            html_blocks.append(f'<span style="color:{color}; font-weight:bold;">{icon} [{d.get("severity", "?")}] {d.get("cve_id", "?")}</span>')
            html_blocks.append(f'<span style="color:#c9d1d9;">     Атака: {d.get("attack_name", "?")}</span>')
            html_blocks.append(f'<span style="color:{color};">     Статус: {feas}</span>')
            if d.get("reason", ""):
                html_blocks.append(f'<span style="color:#8b949e;">     {d.get("reason", "")}</span><br>')
            else:
                html_blocks.append("<br>")

        # Вставляем весь огромный текст разом! 
        self.response_text.setHtml("<br>".join(html_blocks))

    def _on_send_error(self, error):
        self.btn_send.setEnabled(True); self.btn_send.setText("📤 Отправить результаты")
        QMessageBox.critical(self, "Ошибка отправки", f"Не удалось отправить данные:\n{error}")

if __name__ == "__main__":
    app = QApplication(sys.argv); window = AttackerGUI(); window.show(); sys.exit(app.exec())