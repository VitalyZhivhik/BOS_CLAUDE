"""
Атакующий агент — графический интерфейс PyQt6.
Сканирует цель, генерирует векторы атак, отправляет на сервер.
"""

import sys
import os
import json
import socket
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
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

from common.config import (
    TARGET_SERVER_HOST, TARGET_SERVER_PORT,
    SCAN_PORT_START, SCAN_PORT_END, SCAN_TIMEOUT, KNOWN_PORTS
)
from common.models import ScanResult, OpenPort, AttackVector, Severity
from common.logger import get_attacker_logger, GUILogHandler
from attacker.attacker_agent import AttackVectorGenerator

logger = get_attacker_logger()

# ─── Стиль ───
STYLE = """
QMainWindow { background: #1b1b2f; }
QWidget { color: #e0e0e0; font-family: 'Segoe UI'; }
QGroupBox {
    background: #1f2833; border: 1px solid #2a3a5e; border-radius: 8px;
    margin-top: 12px; padding-top: 20px; font-weight: bold; font-size: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #9b5de5; }
QPushButton {
    padding: 10px 16px; border-radius: 6px; font-weight: bold; font-size: 12px;
    border: none; color: white;
}
QPushButton:disabled { background: #3a3a4e; color: #666; }
QTextEdit {
    background: #0d1117; color: #c9d1d9; border: 1px solid #21262d;
    border-radius: 6px; font-family: 'Consolas'; font-size: 11px; padding: 8px;
}
QLineEdit, QSpinBox {
    background: #0d1117; color: #e0e0e0; border: 1px solid #2a3a5e;
    border-radius: 4px; padding: 6px; font-size: 12px;
}
QTableWidget {
    background: #0d1117; color: #c9d1d9; border: 1px solid #21262d;
    border-radius: 6px; gridline-color: #21262d; font-size: 11px;
}
QTableWidget::item { padding: 4px 8px; }
QHeaderView::section {
    background: #161b22; color: #8b949e; border: none; padding: 6px; font-weight: bold;
}
QTabWidget::pane { border: 1px solid #2a3a5e; border-radius: 6px; background: #1f2833; }
QTabBar::tab {
    background: #1f2833; color: #8b949e; padding: 8px 20px;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
}
QTabBar::tab:selected { background: #2a1f4a; color: #9b5de5; }
QProgressBar {
    background: #0d1117; border: 1px solid #2a3a5e; border-radius: 4px;
    text-align: center; color: #e0e0e0; font-weight: bold;
}
QProgressBar::chunk { background: #9b5de5; border-radius: 3px; }
QStatusBar { background: #0f1923; color: #8b949e; }
"""


class ScanWorker(QThread):
    """Фоновый поток для сканирования портов."""
    port_found = pyqtSignal(object)  # OpenPort
    progress = pyqtSignal(int)       # процент
    finished = pyqtSignal(list)      # [OpenPort]
    error = pyqtSignal(str)

    def __init__(self, target, port_start, port_end):
        super().__init__()
        self.target = target
        self.port_start = port_start
        self.port_end = port_end
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            total = self.port_end - self.port_start + 1
            open_ports = []
            scanned = 0

            logger.info(f"Сканирование {self.target} [{self.port_start}-{self.port_end}]")

            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {
                    executor.submit(self._check_port, p): p
                    for p in range(self.port_start, self.port_end + 1)
                }
                for future in as_completed(futures):
                    if self._cancelled:
                        logger.info("Сканирование отменено пользователем")
                        break
                    scanned += 1
                    pct = int((scanned / total) * 100)
                    if scanned % max(1, total // 100) == 0 or scanned == total:
                        self.progress.emit(pct)
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        self.port_found.emit(result)
                        logger.info(f"  Порт {result.port} ОТКРЫТ ({result.service})")

            open_ports.sort(key=lambda x: x.port)
            self.finished.emit(open_ports)
            logger.info(f"Сканирование завершено: {len(open_ports)} открытых портов")
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}", exc_info=True)
            self.error.emit(str(e))

    def _check_port(self, port):
        if self._cancelled:
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SCAN_TIMEOUT)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                service = KNOWN_PORTS.get(port, "Unknown")
                banner = ""
                try:
                    if port in (80, 443, 8080, 8443):
                        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                    else:
                        sock.sendall(b"\r\n")
                    sock.settimeout(1.0)
                    banner = sock.recv(256).decode("utf-8", errors="replace").strip()[:150]
                except Exception:
                    pass
                sock.close()
                return OpenPort(port=port, service=service, banner=banner)
            sock.close()
        except Exception:
            pass
        return None


class SendWorker(QThread):
    """Фоновый поток для отправки данных на сервер."""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url, data):
        super().__init__()
        self.url = url
        self.data = data

    def run(self):
        try:
            json_data = json.dumps(self.data, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                self.url, data=json_data,
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST"
            )
            logger.info(f"Отправка данных на {self.url} ({len(json_data)} байт)")
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                logger.info("Ответ от сервера получен")
                self.finished.emit(result)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8")
                err_data = json.loads(body)
                body = err_data.get("error", body)
            except Exception:
                pass
            msg = f"HTTP {e.code}: {body or e.reason}"
            logger.error(f"Ошибка HTTP: {msg}")
            self.error.emit(msg)
        except Exception as e:
            logger.error(f"Ошибка отправки: {e}", exc_info=True)
            self.error.emit(str(e))


class AttackerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Атакующий агент — сканирование и анализ уязвимостей")
        self.setMinimumSize(1100, 700)

        self.open_ports = []
        self.attack_vectors = []
        self.scan_worker = None
        self.connected_to_server = False

        self._build_ui()
        self.setStyleSheet(STYLE)

        gui_handler = GUILogHandler(self._on_log_message)
        gui_handler.setLevel(10)
        logger.addHandler(gui_handler)

        self.log_signal.connect(self._append_log)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # ─── Левая панель ───
        left = QWidget()
        left.setFixedWidth(300)
        ll = QVBoxLayout(left)
        ll.setSpacing(6)

        title = QLabel("⚔ Атакующий агент")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #9b5de5; padding: 8px;")
        ll.addWidget(title)

        # Индикатор связи
        self.conn_frame = QFrame()
        self.conn_frame.setStyleSheet("background: #2d1b1b; border-radius: 8px; padding: 8px;")
        cf_layout = QVBoxLayout(self.conn_frame)
        self.conn_icon = QLabel("🔴  Нет связи с сервером")
        self.conn_icon.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.conn_icon.setStyleSheet("color: #e63946;")
        cf_layout.addWidget(self.conn_icon)
        self.conn_detail = QLabel("")
        self.conn_detail.setStyleSheet("color: #8b949e; font-size: 10px;")
        cf_layout.addWidget(self.conn_detail)
        ll.addWidget(self.conn_frame)

        # Параметры цели
        target_group = QGroupBox("Параметры цели")
        tl = QVBoxLayout(target_group)

        tl.addWidget(QLabel("IP-адрес сервера:"))
        self.target_input = QLineEdit(TARGET_SERVER_HOST)
        self.target_input.setFont(QFont("Consolas", 12))
        tl.addWidget(self.target_input)

        tl.addWidget(QLabel("Порт API сервера:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(TARGET_SERVER_PORT)
        tl.addWidget(self.port_spin)

        row = QHBoxLayout()
        row.addWidget(QLabel("Порты от:"))
        self.port_start_spin = QSpinBox()
        self.port_start_spin.setRange(1, 65535)
        self.port_start_spin.setValue(SCAN_PORT_START)
        row.addWidget(self.port_start_spin)
        row.addWidget(QLabel("до:"))
        self.port_end_spin = QSpinBox()
        self.port_end_spin.setRange(1, 65535)
        self.port_end_spin.setValue(SCAN_PORT_END)
        row.addWidget(self.port_end_spin)
        tl.addLayout(row)
        ll.addWidget(target_group)

        # Действия
        action_group = QGroupBox("Действия")
        al = QVBoxLayout(action_group)

        self.btn_check = QPushButton("🔗 Проверить связь с сервером")
        self.btn_check.setStyleSheet("background: #00b4d8;")
        self.btn_check.clicked.connect(self._check_connection)
        al.addWidget(self.btn_check)

        self.btn_scan = QPushButton("🔍 Сканировать порты")
        self.btn_scan.setStyleSheet("background: #9b5de5;")
        self.btn_scan.clicked.connect(self._start_scan)
        al.addWidget(self.btn_scan)

        self.btn_send = QPushButton("📤 Отправить результаты на сервер")
        self.btn_send.setStyleSheet("background: #2dc653;")
        self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self._send_to_server)
        al.addWidget(self.btn_send)
        ll.addWidget(action_group)

        # Прогресс
        prog_group = QGroupBox("Прогресс сканирования")
        pl = QVBoxLayout(prog_group)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        pl.addWidget(self.progress_bar)
        self.progress_label = QLabel("Ожидание...")
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.progress_label.setStyleSheet("color: #8b949e;")
        pl.addWidget(self.progress_label)
        ll.addWidget(prog_group)

        # Краткая сводка
        summary_group = QGroupBox("Сводка")
        sl = QVBoxLayout(summary_group)
        self.summary_label = QLabel("Ожидает сканирования...")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet("color: #8b949e; font-size: 10px;")
        sl.addWidget(self.summary_label)
        ll.addWidget(summary_group)

        ll.addStretch()
        main_layout.addWidget(left)

        # ─── Правая панель — вкладки ───
        self.tabs = QTabWidget()

        # Журнал
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.tabs.addTab(self.log_text, "📋 Журнал")

        # Порты
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(4)
        self.ports_table.setHorizontalHeaderLabels(["Порт", "Сервис", "Протокол", "Баннер"])
        self.ports_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.ports_table, "🌐 Открытые порты")

        # Векторы атак
        self.attacks_table = QTableWidget()
        self.attacks_table.setColumnCount(5)
        self.attacks_table.setHorizontalHeaderLabels(["Серьёзность", "Атака", "Тип", "Порт", "Инструменты"])
        self.attacks_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.attacks_table, "💣 Векторы атак")

        # Ответ сервера
        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)
        self.tabs.addTab(self.response_text, "📊 Ответ сервера")

        main_layout.addWidget(self.tabs, 1)
        self.statusBar().showMessage("Готов к работе")

    # ─── Логирование ───
    def _on_log_message(self, message, level):
        self.log_signal.emit(message, level)

    def _append_log(self, message, level):
        color_map = {
            "DEBUG": "#6c757d", "INFO": "#c9d1d9", "WARNING": "#f4a261",
            "ERROR": "#e63946", "CRITICAL": "#ff0040",
        }
        color = color_map.get(level, "#c9d1d9")
        self.log_text.append(f'<span style="color:{color}">{message}</span>')
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)

    # ─── Проверка связи ───
    def _check_connection(self):
        target = self.target_input.text()
        port = self.port_spin.value()
        self.btn_check.setEnabled(False)
        self.btn_check.setText("Проверка...")

        def check():
            try:
                url = f"http://{target}:{port}/ping"
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
                    hostname = data.get("hostname", "?")
                    ready = data.get("ready", False)
                    QTimer.singleShot(0, lambda: self._on_connected(hostname, ready))
            except Exception as e:
                logger.error(f"Нет связи с {target}:{port}: {e}")
                QTimer.singleShot(0, lambda: self._on_connection_failed(str(e)))

        import threading
        threading.Thread(target=check, daemon=True).start()

    def _on_connected(self, hostname, ready):
        self.connected_to_server = True
        self.conn_icon.setText(f"🟢  Связь установлена")
        self.conn_icon.setStyleSheet("color: #2dc653;")
        self.conn_detail.setText(
            f"Сервер: {hostname}\n"
            f"{'Готов к приёму данных' if ready else 'Не готов (требуется настройка)'}"
        )
        self.conn_frame.setStyleSheet("background: #1b2d1b; border-radius: 8px; padding: 8px;")
        self.btn_check.setText("✔ Связь установлена")
        self.btn_check.setEnabled(True)
        self.statusBar().showMessage(f"Подключено к серверу {hostname}")

    def _on_connection_failed(self, error):
        self.connected_to_server = False
        self.conn_icon.setText("🔴  Нет связи с сервером")
        self.conn_icon.setStyleSheet("color: #e63946;")
        self.conn_detail.setText(f"Ошибка: {error[:80]}")
        self.conn_frame.setStyleSheet("background: #2d1b1b; border-radius: 8px; padding: 8px;")
        self.btn_check.setText("🔗 Проверить связь с сервером")
        self.btn_check.setEnabled(True)
        self.statusBar().showMessage("Нет связи с сервером")

    # ─── Сканирование ───
    def _start_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.btn_scan.setText("🔍 Сканировать порты")
            return

        target = self.target_input.text()
        p_start = self.port_start_spin.value()
        p_end = self.port_end_spin.value()

        self.open_ports = []
        self.ports_table.setRowCount(0)
        self.attacks_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.btn_send.setEnabled(False)

        self.btn_scan.setText("⏹ Остановить сканирование")
        self.btn_scan.setStyleSheet("background: #e63946;")
        self.statusBar().showMessage(f"Сканирование {target}...")

        self.scan_worker = ScanWorker(target, p_start, p_end)
        self.scan_worker.port_found.connect(self._on_port_found)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished.connect(self._on_scan_done)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.start()

    def _on_port_found(self, port: OpenPort):
        row = self.ports_table.rowCount()
        self.ports_table.insertRow(row)
        self.ports_table.setItem(row, 0, QTableWidgetItem(str(port.port)))
        self.ports_table.setItem(row, 1, QTableWidgetItem(port.service))
        self.ports_table.setItem(row, 2, QTableWidgetItem(port.protocol))
        self.ports_table.setItem(row, 3, QTableWidgetItem(port.banner[:80] if port.banner else ""))

    def _on_scan_progress(self, pct):
        self.progress_bar.setValue(pct)
        self.progress_label.setText(f"Сканирование: {pct}%")

    def _on_scan_done(self, ports):
        self.open_ports = ports
        gen = AttackVectorGenerator()
        self.attack_vectors = gen.generate(ports)

        # Заполняем таблицу атак
        self.attacks_table.setRowCount(len(self.attack_vectors))
        for i, av in enumerate(self.attack_vectors):
            sev_item = QTableWidgetItem(av.severity)
            sev_colors = {"CRITICAL": "#e63946", "HIGH": "#f4a261", "MEDIUM": "#e9c46a", "LOW": "#2dc653"}
            sev_item.setForeground(QColor(sev_colors.get(av.severity, "#c9d1d9")))
            self.attacks_table.setItem(i, 0, sev_item)
            self.attacks_table.setItem(i, 1, QTableWidgetItem(av.name))
            self.attacks_table.setItem(i, 2, QTableWidgetItem(av.attack_type))
            self.attacks_table.setItem(i, 3, QTableWidgetItem(str(av.target_port or "—")))
            self.attacks_table.setItem(i, 4, QTableWidgetItem(av.tools_used))

        # Сводка
        crit = sum(1 for a in self.attack_vectors if a.severity == "CRITICAL")
        high = sum(1 for a in self.attack_vectors if a.severity == "HIGH")
        self.summary_label.setText(
            f"Открытых портов: {len(ports)}\n"
            f"Векторов атак: {len(self.attack_vectors)}\n"
            f"  Критических: {crit}\n"
            f"  Высоких: {high}\n"
            f"  Средних: {sum(1 for a in self.attack_vectors if a.severity == 'MEDIUM')}\n"
            f"  Низких: {sum(1 for a in self.attack_vectors if a.severity == 'LOW')}"
        )

        self.btn_scan.setText("🔍 Сканировать порты")
        self.btn_scan.setStyleSheet("background: #9b5de5;")
        self.btn_send.setEnabled(bool(ports))
        self.progress_label.setText(f"Завершено — {len(ports)} портов, {len(self.attack_vectors)} атак")
        self.statusBar().showMessage(f"Сканирование завершено: {len(ports)} портов, {len(self.attack_vectors)} атак")

    def _on_scan_error(self, error):
        self.btn_scan.setText("🔍 Сканировать порты")
        self.btn_scan.setStyleSheet("background: #9b5de5;")
        QMessageBox.critical(self, "Ошибка сканирования", error)

    # ─── Отправка на сервер ───
    def _send_to_server(self):
        target = self.target_input.text()
        port = self.port_spin.value()

        scan_result = ScanResult(
            scanner_ip=socket.gethostbyname(socket.gethostname()),
            target_ip=target,
            open_ports=self.open_ports,
            discovered_services=[f"{p.service} (:{p.port})" for p in self.open_ports],
            attack_vectors=self.attack_vectors,
            os_detection="Windows (fingerprint)",
            scan_timestamp=datetime.now().isoformat(),
        )

        url = f"http://{target}:{port}/analyze"
        data = asdict(scan_result)

        self.btn_send.setEnabled(False)
        self.btn_send.setText("Отправка...")
        self.statusBar().showMessage("Отправка данных на сервер...")

        self.send_worker = SendWorker(url, data)
        self.send_worker.finished.connect(self._on_response)
        self.send_worker.error.connect(self._on_send_error)
        self.send_worker.start()

    def _on_response(self, result):
        self.btn_send.setText("📤 Отправить результаты на сервер")
        self.btn_send.setEnabled(True)

        # Переключаем на вкладку ответа
        self.tabs.setCurrentIndex(3)

        self.response_text.clear()
        summary = result.get("summary", {})

        self.response_text.append(
            '<span style="color:#ffffff; font-size:14px; font-weight:bold;">'
            '═══════════════════════════════════════════════</span>')
        self.response_text.append(
            '<span style="color:#ffffff; font-size:14px; font-weight:bold;">'
            '  РЕЗУЛЬТАТЫ КОРРЕЛЯЦИИ АТАК С КОНФИГУРАЦИЕЙ СЕРВЕРА</span>')
        self.response_text.append(
            '<span style="color:#ffffff; font-size:14px; font-weight:bold;">'
            '═══════════════════════════════════════════════</span>')
        self.response_text.append("")
        self.response_text.append(
            f'<span style="color:#c9d1d9;">  Всего проанализировано:   '
            f'{summary.get("total_vulnerabilities_analyzed", 0)}</span>')
        self.response_text.append(
            f'<span style="color:#e63946; font-weight:bold;">  Реализуемые атаки:        '
            f'{summary.get("feasible_attacks", 0)}</span>')
        self.response_text.append(
            f'<span style="color:#f4a261;">  Частично реализуемые:     '
            f'{summary.get("partially_feasible", 0)}</span>')
        self.response_text.append(
            f'<span style="color:#2dc653;">  Нереализуемые:            '
            f'{summary.get("not_feasible_attacks", 0)}</span>')
        self.response_text.append(
            f'<span style="color:#48cae4;">  Требуют анализа:          '
            f'{summary.get("requires_analysis", 0)}</span>')
        self.response_text.append("")
        self.response_text.append('<span style="color:#666;">─────────────────────────────────────────────</span>')

        for d in result.get("details", []):
            feas = d.get("feasibility", "?")
            if "НЕ РЕАЛИЗУЕМА" in feas:
                color, icon = "#2dc653", "✅"
            elif "ЧАСТИЧНО" in feas:
                color, icon = "#f4a261", "⚠️"
            elif "РЕАЛИЗУЕМА" in feas:
                color, icon = "#e63946", "❌"
            else:
                color, icon = "#48cae4", "❓"

            self.response_text.append(
                f'<span style="color:{color}; font-weight:bold;">{icon} '
                f'[{d.get("severity", "?")}] {d.get("cve_id", "?")}</span>')
            self.response_text.append(
                f'<span style="color:#c9d1d9;">     Атака: {d.get("attack_name", "?")}</span>')
            self.response_text.append(
                f'<span style="color:{color};">     Статус: {feas}</span>')
            reason = d.get("reason", "")
            if reason:
                self.response_text.append(
                    f'<span style="color:#8b949e;">     {reason}</span>')
            self.response_text.append("")

        self.statusBar().showMessage(
            f"Анализ завершён: {summary.get('feasible_attacks', 0)} реализуемых, "
            f"{summary.get('not_feasible_attacks', 0)} нереализуемых")

    def _on_send_error(self, error):
        self.btn_send.setText("📤 Отправить результаты на сервер")
        self.btn_send.setEnabled(True)
        logger.error(f"Ошибка отправки: {error}")
        QMessageBox.critical(self, "Ошибка отправки",
            f"Не удалось отправить данные на сервер:\n\n{error}\n\n"
            f"Убедитесь, что:\n"
            f"1. Серверный агент запущен\n"
            f"2. Выполнен анализ системы и загружены базы\n"
            f"3. IP-адрес и порт указаны правильно\n"
            f"4. Сервер нажал кнопку «Запустить сервер»")


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = AttackerGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
