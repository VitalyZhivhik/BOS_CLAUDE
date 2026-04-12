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
"""
import sys, os, json, socket, threading, webbrowser
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QFrame, QMessageBox, QStatusBar, QProgressBar, QFileDialog,
    QComboBox, QListWidget, QListWidgetItem, QSplitter,
    QScrollArea, QDialog, QDialogButtonBox, QFormLayout, QLineEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)
from common.config import SERVER_HOST, SERVER_PORT
from common.models import from_json_scan_result, AttackVector, Severity
from common.logger import get_server_logger, GUILogHandler
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator
from server.attack_toolkit import AttackToolkit
from server.report_history import ReportHistory, ReportRecord
from server.local_vuln_scanner import LocalVulnScanner, ScanReport
logger = get_server_logger()
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
    padding: 8px 14px; border-radius: 3px; font-weight: 600; font-size: 11px;
    border: 1px solid #444; color: #d0d0d0; background: #252525;
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
            db = VulnerabilityDatabase(PROJECT_DIR)
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
            tk = AttackToolkit(PROJECT_DIR)
            tk.load()
            self.finished.emit(tk)
        except Exception as e:
            logger.error(f"Ошибка загрузки toolkit: {e}", exc_info=True)
            self.error.emit(str(e))
# ─────────────────────────────────────────
#  Главное окно
# ─────────────────────────────────────────
class ServerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)
    client_connected_signal = pyqtSignal(str)
    analysis_done_signal = pyqtSignal(dict, str)
    update_results_signal = pyqtSignal(object)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Assessment — Серверный агент v2.0")
        self.setMinimumSize(1250, 800)
        # Состояние
        self.system_info = None
        self.system_summary = None
        self.vuln_db = None
        self.vuln_scan_report = None
        self.toolkit = None
        self.report_history = ReportHistory(PROJECT_DIR)
        self.http_server = None
        self.server_thread = None
        self.server_running = False
        self.last_report_path = None
        self.actual_server_port = None
        self._last_scan_data = {}        # Данные от атакующего (для схем)
        self._last_results = []          # Результаты корреляции
        self._build_ui()
        self.setStyleSheet(STYLE)
        self.update_results_signal.connect(self._update_results_table_slot)
        gh = GUILogHandler(self._on_log_message)
        gh.setLevel(10)
        logger.addHandler(gh)
        self.log_signal.connect(self._append_log)
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
        # Левая панель управления
        left = self._build_left_panel()
        ml.addWidget(left)
        # Правая панель с вкладками
        self.tabs = QTabWidget()
        self._build_system_tab()
        self._build_vuln_tab()
        self._build_correlation_tab()
        self._build_attack_selector_tab()
        self._build_history_tab()
        self._build_log_tab()
        ml.addWidget(self.tabs, 1)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Готов к работе")
    def _build_left_panel(self) -> QWidget:
        left = QWidget()
        left.setFixedWidth(300)
        ll = QVBoxLayout(left)
        ll.setSpacing(6)
        ll.setContentsMargins(0, 0, 0, 0)
        t = QLabel("СЕРВЕРНЫЙ АГЕНТ")
        t.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        t.setStyleSheet("color:#888;padding:6px 0;letter-spacing:2px;")
        ll.addWidget(t)
        # Статус
        self.status_frame = QFrame()
        self.status_frame.setStyleSheet(
            "background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;"
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
        # Управление
        cg = QGroupBox("Управление")
        cl = QVBoxLayout(cg)
        cl.setSpacing(6)
        self.btn_analyze = QPushButton("1. Анализ системы")
        self.btn_analyze.clicked.connect(self._start_analysis)
        cl.addWidget(self.btn_analyze)
        self.btn_load_db = QPushButton("2. Загрузить базы CVE/CWE/CAPEC/MITRE")
        self.btn_load_db.setEnabled(False)
        self.btn_load_db.clicked.connect(self._load_databases)
        cl.addWidget(self.btn_load_db)
        self.btn_load_toolkit = QPushButton("2б. Загрузить базу инструментов")
        self.btn_load_toolkit.setEnabled(False)
        self.btn_load_toolkit.clicked.connect(self._load_toolkit)
        cl.addWidget(self.btn_load_toolkit)
        self.btn_vuln_scan = QPushButton("3. Локальное сканирование уязвимостей")
        self.btn_vuln_scan.setEnabled(False)
        self.btn_vuln_scan.clicked.connect(self._start_vuln_scan)
        cl.addWidget(self.btn_vuln_scan)
        self.vuln_progress = QProgressBar()
        self.vuln_progress.setFixedHeight(18)
        self.vuln_progress.setVisible(False)
        cl.addWidget(self.vuln_progress)
        self.btn_server = QPushButton("4. Запустить сервер")
        self.btn_server.setEnabled(False)
        self.btn_server.clicked.connect(self._toggle_server)
        cl.addWidget(self.btn_server)
        ll.addWidget(cg)
        # Параметры
        pg = QGroupBox("Параметры")
        pl = QVBoxLayout(pg)
        r = QHBoxLayout()
        r.addWidget(QLabel("Порт API:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(SERVER_PORT)
        r.addWidget(self.port_spin)
        pl.addLayout(r)
        self.btn_check_port = QPushButton("Проверить порт")
        self.btn_check_port.clicked.connect(self._check_port_availability)
        pl.addWidget(self.btn_check_port)
        self.port_status_label = QLabel("")
        self.port_status_label.setStyleSheet("font-size:10px;")
        self.port_status_label.setWordWrap(True)
        pl.addWidget(self.port_status_label)
        ll.addWidget(pg)
        # Отчёт
        rg = QGroupBox("Отчёт")
        rl = QVBoxLayout(rg)
        self.btn_open_report = QPushButton("Открыть последний отчёт")
        self.btn_open_report.setEnabled(False)
        self.btn_open_report.clicked.connect(self._open_report)
        rl.addWidget(self.btn_open_report)
        self.btn_generate_manual = QPushButton("Сгенерировать отчёт вручную")
        self.btn_generate_manual.setEnabled(False)
        self.btn_generate_manual.setToolTip("Сгенерировать отчёт на основе выбранного вектора атаки")
        self.btn_generate_manual.clicked.connect(self._generate_manual_report)
        rl.addWidget(self.btn_generate_manual)
        self.btn_export_log = QPushButton("Экспорт лога")
        self.btn_export_log.clicked.connect(self._export_log)
        rl.addWidget(self.btn_export_log)
        ll.addWidget(rg)
        ll.addStretch()
        # Статистика
        sf2 = QFrame()
        sf2.setStyleSheet("background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        sl = QVBoxLayout(sf2)
        sl.setSpacing(2)
        self.lbl_stats = QLabel("Статистика недоступна")
        self.lbl_stats.setStyleSheet("color:#666;font-size:10px;")
        self.lbl_stats.setWordWrap(True)
        sl.addWidget(self.lbl_stats)
        self.lbl_history_stats = QLabel("")
        self.lbl_history_stats.setStyleSheet("color:#555;font-size:10px;")
        sl.addWidget(self.lbl_history_stats)
        ll.addWidget(sf2)
        return left
    def _build_system_tab(self):
        st = QWidget()
        stl = QVBoxLayout(st)
        self.sys_table = QTableWidget(0, 2)
        self.sys_table.setHorizontalHeaderLabels(["Параметр", "Значение"])
        self.sys_table.horizontalHeader().setStretchLastSection(True)
        self.sys_table.setColumnWidth(0, 220)
        self.sys_table.verticalHeader().setVisible(False)
        self.sys_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        stl.addWidget(self.sys_table)
        self.tabs.addTab(st, "🖥️ Система")
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
        self.btn_analyze.setText("1. Анализ системы (выполнен)")
        self.btn_analyze.setEnabled(True)
        self.btn_load_db.setEnabled(True)
        self.btn_load_toolkit.setEnabled(True)
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
        self.btn_server.setEnabled(True)
        self.lbl_stats.setText(
            f"CVE:{len(db.cve_db)} CWE:{len(db.cwe_db)} "
            f"CAPEC:{len(db.capec_db)} MITRE:{len(db.mitre_db)}"
        )
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
        # Заполняем вкладку выбора вектора атаки
        self._populate_attack_selector()
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
        cor = AttackCorrelator(self.system_info, self.vuln_db)
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
    #  HTTP Сервер
    # ─────────────────────────────────────────
    def _toggle_server(self):
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
        state.ready = bool(self.system_info and self.vuln_db)
        state.on_client_connected = lambda ip: gui.client_connected_signal.emit(ip)
        state.on_analysis_complete = lambda s, p: gui.analysis_done_signal.emit(s, p)
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                ip = self.client_address[0]
                try:
                    ss = state.system_summary if isinstance(state.system_summary, dict) else {}
                    hn = ss.get("hostname", "")
                    if self.path == "/ping":
                        if ip not in state.connected_clients:
                            state.connected_clients.append(ip)
                            if state.on_client_connected:
                                state.on_client_connected(ip)
                        self._r(200, {"status": "pong", "ready": state.ready, "hostname": hn})
                    elif self.path == "/status":
                        self._r(200, {"status": "running", "ready": state.ready, "hostname": hn, "clients": state.connected_clients})
                    elif self.path == "/system-info":
                        self._r(200, ss)
                    else:
                        self._r(200, {"message": "Security Assessment Server", "ready": state.ready})
                except Exception as e:
                    self._r(500, {"error": str(e)})
            def do_POST(self):
                ip = self.client_address[0]
                logger.info(f"[API] POST {self.path} от {ip}")
                if self.path != "/analyze":
                    self._r(404, {"error": "Not Found"})
                    return
                if not state.ready or not state.system_info or not state.vuln_db:
                    self._r(503, {"error": "Сервер не готов", "ready": False, "hint": "Выполните шаги 1-2"})
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
                    cor = AttackCorrelator(state.system_info, state.vuln_db)
                    results = cor.correlate(sr)
                    summary = cor.get_summary()
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
                    )
                    hp = rep.generate_html(os.path.join(rd, f"report_{ts}.html"))
                    jp = rep.generate_json(os.path.join(rd, f"report_{ts}.json"))
                    gui.last_report_path = hp
                    # Добавляем в историю
                    gui._add_to_history(results, summary, ts, hp, jp)
                    resp = {
                        "status": "success",
                        "summary": summary,
                        "html_report": hp,
                        "results_count": len(results),
                        "details": [
                            {
                                "cve_id": r.cve_id,
                                "attack_name": r.attack_name,
                                "severity": r.severity,
                                "feasibility": r.feasibility,
                                "description": r.description,
                                "recommendation": r.recommendation,
                            }
                            for r in results
                        ],
                    }
                    self._r(200, resp)
                    logger.info(f"[API] Ответ 200 OK. Результатов: {len(results)}")
                    if state.on_analysis_complete:
                        state.on_analysis_complete(summary, hp)
                    gui.update_results_signal.emit(results)
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
                self.end_headers()
                self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))
            def log_message(self, *a):
                pass
        try:
            self.http_server = HTTPServer(("0.0.0.0", port), Handler)
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
            feasible_cnt = 0
            not_feasible_cnt = 0
            for r in unique_results:
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                cve = str(r.cve_id or "Нет CVE")
                sev = str(r.severity or "INFO")
                feas = str(r.feasibility or "UNKNOWN")
                name = str(r.attack_name or "Неизвестная атака")
                desc = str(r.description or "")[:150]
                self.results_table.setItem(row, 0, QTableWidgetItem(cve))
                si = QTableWidgetItem(sev)
                si.setForeground(QColor({"CRITICAL": "#c44", "HIGH": "#a85", "MEDIUM": "#997", "LOW": "#696"}.get(sev, "#888")))
                self.results_table.setItem(row, 1, si)
                fi = QTableWidgetItem(feas)
                if "НЕ РЕАЛИЗУЕМА" in feas:
                    fi.setForeground(QColor("#696"))
                    not_feasible_cnt += 1
                elif "РЕАЛИЗУЕМА" in feas:
                    fi.setForeground(QColor("#b55"))
                    feasible_cnt += 1
                self.results_table.setItem(row, 2, fi)
                self.results_table.setItem(row, 3, QTableWidgetItem(name))
                self.results_table.setItem(row, 4, QTableWidgetItem(desc))
            self.correlation_summary.setText(
                f"Всего (уникальных): {len(unique_results)}  |  "
                f"🔴 Реализуемых: {feasible_cnt}  |  "
                f"🟢 Нереализуемых: {not_feasible_cnt}"
            )
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
        stats = self.report_history.stats
        self.lbl_history_stats.setText(
            f"История: {stats['total']} отчётов "
            f"({stats['critical_reports']} с CRITICAL)"
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
            cor = AttackCorrelator(self.system_info, self.vuln_db)
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
