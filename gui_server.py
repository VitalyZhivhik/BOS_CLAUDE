"""
Серверный агент — графический интерфейс PyQt6.
ИСПРАВЛЕНИЯ:
  - Существенно расширено логирование HTTP-запросов и внутреннего состояния.
"""

import sys, os, json, socket, threading, webbrowser
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QTabWidget, QFrame,
    QMessageBox, QStatusBar, QProgressBar, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from common.config import SERVER_HOST, SERVER_PORT
from common.models import from_json_scan_result
from common.logger import get_server_logger, GUILogHandler
from server.system_analyzer import SystemAnalyzer
from server.vulnerability_db import VulnerabilityDatabase
from server.attack_correlator import AttackCorrelator
from server.report_generator import ReportGenerator
from server.local_vuln_scanner import LocalVulnScanner, ScanReport

logger = get_server_logger()

STYLE = """
QMainWindow { background: #121212; }
QWidget { color: #d0d0d0; font-family: 'Segoe UI', 'Consolas'; }
QGroupBox { background: #1a1a1a; border: 1px solid #333; border-radius: 4px; margin-top: 14px; padding-top: 22px; font-weight: 600; font-size: 12px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; color: #909090; }
QPushButton { padding: 8px 14px; border-radius: 3px; font-weight: 600; font-size: 11px; border: 1px solid #444; color: #d0d0d0; background: #252525; }
QPushButton:hover { background: #333; border-color: #555; }
QPushButton:pressed { background: #1a1a1a; }
QPushButton:disabled { background: #1a1a1a; color: #555; border-color: #2a2a2a; }
QTextEdit { background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a; border-radius: 3px; font-family: 'Consolas'; font-size: 11px; padding: 6px; }
QTableWidget { background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a; border-radius: 3px; gridline-color: #222; font-size: 11px; }
QTableWidget::item { padding: 4px 6px; }
QTableWidget::item:selected { background: #2a2a2a; color: #e0e0e0; }
QHeaderView::section { background: #181818; color: #888; border: none; padding: 6px; font-weight: 600; }
QTabWidget::pane { border: 1px solid #333; border-radius: 3px; background: #1a1a1a; }
QTabBar::tab { background: #181818; color: #777; padding: 8px 18px; border: 1px solid #2a2a2a; border-bottom: none; border-top-left-radius: 3px; border-top-right-radius: 3px; margin-right: 2px; }
QTabBar::tab:selected { background: #1a1a1a; color: #d0d0d0; border-color: #333; }
QSpinBox { background: #0e0e0e; color: #d0d0d0; border: 1px solid #333; border-radius: 3px; padding: 4px; }
QProgressBar { background: #0e0e0e; border: 1px solid #333; border-radius: 3px; text-align: center; color: #999; font-weight: 600; font-size: 10px; }
QProgressBar::chunk { background: #555; border-radius: 2px; }
QStatusBar { background: #0e0e0e; color: #666; border-top: 1px solid #222; }
QLabel { color: #b0b0b0; }
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

class AnalysisWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    def run(self):
        try:
            logger.info("[SYS] Запущен глубокий анализ системы...")
            a = SystemAnalyzer(); info = a.analyze(); s = a.get_summary()
            logger.debug(f"[SYS] Найденные службы: {s.get('running_services_count')}, Порты: {s.get('open_ports_count')}")
            self.finished.emit({"info": info, "summary": s, "analyzer": a})
        except Exception as e:
            logger.error(f"Ошибка анализа: {e}", exc_info=True); self.error.emit(str(e))

class DBLoadWorker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    def run(self):
        try:
            logger.info("[DB] Начинается загрузка баз уязвимостей с диска...")
            db = VulnerabilityDatabase(PROJECT_DIR); db.load_all()
            logger.info(f"[DB] Загрузка успешна. Размеры баз - CVE: {len(db.cve_db)}, CWE: {len(db.cwe_db)}, CAPEC: {len(db.capec_db)}, MITRE: {len(db.mitre_db)}")
            self.finished.emit(db)
        except Exception as e:
            logger.error(f"Ошибка загрузки БД: {e}", exc_info=True); self.error.emit(str(e))

class VulnScanWorker(QThread):
    finished = pyqtSignal(object)
    progress = pyqtSignal(int, int, str)
    error = pyqtSignal(str)
    def run(self):
        try:
            logger.info("[SCAN] Запуск локального сканирования политик...")
            sc = LocalVulnScanner()
            sc.progress_callback = lambda c, t, m: self.progress.emit(c, t, m)
            res = sc.scan_all()
            logger.info(f"[SCAN] Локальное сканирование завершено. Уязвимо: {res.vulnerable}")
            self.finished.emit(res)
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}", exc_info=True); self.error.emit(str(e))

class ServerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)
    client_connected_signal = pyqtSignal(str)
    analysis_done_signal = pyqtSignal(dict, str)
    update_results_signal = pyqtSignal(object) 

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Assessment — Серверный агент")
        self.setMinimumSize(1150, 750)
        self.system_info = None; self.system_summary = None; self.vuln_db = None
        self.vuln_scan_report = None; self.http_server = None; self.server_thread = None
        self.server_running = False; self.last_report_path = None; self.actual_server_port = None
        
        self._build_ui(); self.setStyleSheet(STYLE)
        
        self.update_results_signal.connect(self._update_results_table_slot)
        
        gh = GUILogHandler(self._on_log_message); gh.setLevel(10); logger.addHandler(gh)
        self.log_signal.connect(self._append_log)
        self.client_connected_signal.connect(self._on_client_connected)
        self.analysis_done_signal.connect(self._on_server_analysis_done)

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        ml = QHBoxLayout(central); ml.setSpacing(8); ml.setContentsMargins(8,8,8,8)
        left = QWidget(); left.setFixedWidth(290)
        ll = QVBoxLayout(left); ll.setSpacing(6); ll.setContentsMargins(0,0,0,0)
        t = QLabel("СЕРВЕРНЫЙ АГЕНТ"); t.setFont(QFont("Segoe UI",14,QFont.Weight.Bold))
        t.setStyleSheet("color:#888;padding:6px 0;letter-spacing:2px;"); ll.addWidget(t)

        self.status_frame = QFrame()
        self.status_frame.setStyleSheet("background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        sf = QVBoxLayout(self.status_frame); sf.setSpacing(4)
        self.status_icon = QLabel("●  Сервер не запущен")
        self.status_icon.setFont(QFont("Segoe UI",11,QFont.Weight.Bold))
        self.status_icon.setStyleSheet("color:#666;"); sf.addWidget(self.status_icon)
        self.connection_label = QLabel("Клиенты: нет подключений")
        self.connection_label.setStyleSheet("color:#555;font-size:10px;"); self.connection_label.setWordWrap(True)
        sf.addWidget(self.connection_label)
        self.port_display = QLabel(""); self.port_display.setFont(QFont("Consolas",10))
        self.port_display.setStyleSheet("color:#666;"); self.port_display.setWordWrap(True)
        sf.addWidget(self.port_display)
        ll.addWidget(self.status_frame)

        cg = QGroupBox("Управление"); cl = QVBoxLayout(cg); cl.setSpacing(6)
        self.btn_analyze = QPushButton("1. Анализ системы"); self.btn_analyze.clicked.connect(self._start_analysis); cl.addWidget(self.btn_analyze)
        self.btn_load_db = QPushButton("2. Загрузить базы CVE/CWE/CAPEC/MITRE"); self.btn_load_db.setEnabled(False); self.btn_load_db.clicked.connect(self._load_databases); cl.addWidget(self.btn_load_db)
        self.btn_vuln_scan = QPushButton("3. Локальное сканирование уязвимостей"); self.btn_vuln_scan.setEnabled(False); self.btn_vuln_scan.clicked.connect(self._start_vuln_scan); cl.addWidget(self.btn_vuln_scan)
        self.vuln_progress = QProgressBar(); self.vuln_progress.setFixedHeight(18); self.vuln_progress.setVisible(False); cl.addWidget(self.vuln_progress)
        self.btn_server = QPushButton("4. Запустить сервер"); self.btn_server.setEnabled(False); self.btn_server.clicked.connect(self._toggle_server); cl.addWidget(self.btn_server)
        ll.addWidget(cg)

        pg = QGroupBox("Параметры"); pl = QVBoxLayout(pg)
        r = QHBoxLayout(); r.addWidget(QLabel("Порт API:"))
        self.port_spin = QSpinBox(); self.port_spin.setRange(1024,65535); self.port_spin.setValue(SERVER_PORT); r.addWidget(self.port_spin); pl.addLayout(r)
        self.btn_check_port = QPushButton("Проверить порт"); self.btn_check_port.clicked.connect(self._check_port_availability); pl.addWidget(self.btn_check_port)
        self.port_status_label = QLabel(""); self.port_status_label.setStyleSheet("font-size:10px;"); self.port_status_label.setWordWrap(True); pl.addWidget(self.port_status_label)
        ll.addWidget(pg)

        rg = QGroupBox("Отчёт"); rl = QVBoxLayout(rg)
        self.btn_open_report = QPushButton("Открыть последний отчёт"); self.btn_open_report.setEnabled(False); self.btn_open_report.clicked.connect(self._open_report); rl.addWidget(self.btn_open_report)
        self.btn_export_log = QPushButton("Экспорт лога"); self.btn_export_log.clicked.connect(self._export_log); rl.addWidget(self.btn_export_log)
        ll.addWidget(rg); ll.addStretch()

        sf2 = QFrame(); sf2.setStyleSheet("background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        sl = QVBoxLayout(sf2); sl.setSpacing(2)
        self.lbl_stats = QLabel("Статистика недоступна"); self.lbl_stats.setStyleSheet("color:#666;font-size:10px;"); self.lbl_stats.setWordWrap(True); sl.addWidget(self.lbl_stats)
        ll.addWidget(sf2); ml.addWidget(left)

        self.tabs = QTabWidget()
        st = QWidget(); stl = QVBoxLayout(st)
        self.sys_table = QTableWidget(0,2); self.sys_table.setHorizontalHeaderLabels(["Параметр","Значение"])
        self.sys_table.horizontalHeader().setStretchLastSection(True); self.sys_table.setColumnWidth(0,220)
        self.sys_table.verticalHeader().setVisible(False); self.sys_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        stl.addWidget(self.sys_table); self.tabs.addTab(st,"Система")
        
        vt = QWidget(); vtl = QVBoxLayout(vt)
        self.vuln_table = QTableWidget(0,5); self.vuln_table.setHorizontalHeaderLabels(["ID","Серьёзность","Статус","Категория","Описание"])
        self.vuln_table.horizontalHeader().setStretchLastSection(True); self.vuln_table.setColumnWidth(0,70); self.vuln_table.setColumnWidth(1,85); self.vuln_table.setColumnWidth(2,100); self.vuln_table.setColumnWidth(3,80)
        self.vuln_table.verticalHeader().setVisible(False); self.vuln_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        vtl.addWidget(self.vuln_table)
        self.vuln_summary_label = QLabel(""); self.vuln_summary_label.setStyleSheet("color:#888;font-size:11px;padding:4px;"); vtl.addWidget(self.vuln_summary_label)
        self.tabs.addTab(vt,"Локальный скан")
        
        rt = QWidget(); rtl = QVBoxLayout(rt)
        self.results_table = QTableWidget(0,5); self.results_table.setHorizontalHeaderLabels(["CVE","Серьёзность","Реализуемость","Атака","Описание"])
        self.results_table.horizontalHeader().setStretchLastSection(True); self.results_table.setColumnWidth(0,130); self.results_table.setColumnWidth(1,85); self.results_table.setColumnWidth(2,130); self.results_table.setColumnWidth(3,180)
        self.results_table.verticalHeader().setVisible(False); self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        rtl.addWidget(self.results_table); self.tabs.addTab(rt,"Корреляция")
        
        lt = QWidget(); ltl = QVBoxLayout(lt); self.log_output = QTextEdit(); self.log_output.setReadOnly(True); ltl.addWidget(self.log_output); self.tabs.addTab(lt,"Лог")
        ml.addWidget(self.tabs,1)
        self.setStatusBar(QStatusBar()); self.statusBar().showMessage("Готов к работе")

    def _on_log_message(self, msg, level): self.log_signal.emit(msg, level)
    def _append_log(self, msg, level):
        c = {"ERROR":"#b55","WARNING":"#a85","CRITICAL":"#c44"}.get(level,"#888")
        self.log_output.append(f'<span style="color:{c};">{msg}</span>')
        self.log_output.moveCursor(QTextCursor.MoveOperation.End)

    def _check_port_availability(self):
        p = self.port_spin.value(); ok, d = is_port_available(p)
        if ok: self.port_status_label.setText(f"Порт {p} свободен"); self.port_status_label.setStyleSheet("color:#8a8;font-size:10px;")
        else: self.port_status_label.setText(f"ЗАНЯТ: {d}"); self.port_status_label.setStyleSheet("color:#b55;font-size:10px;")

    def _start_analysis(self):
        self.btn_analyze.setEnabled(False); self.btn_analyze.setText("Анализ системы...")
        self.analysis_worker = AnalysisWorker(); self.analysis_worker.finished.connect(self._on_analysis_done); self.analysis_worker.error.connect(self._on_analysis_error); self.analysis_worker.start()

    def _on_analysis_done(self, result):
        self.system_info = result["info"]; self.system_summary = result["summary"]
        self.sys_table.setRowCount(0)
        for p,v in [("ОС",self.system_summary.get("os","?")),("Имя хоста",self.system_summary.get("hostname","?")),("IP-адреса",", ".join(self.system_summary.get("ip_addresses",[]))),("ПО",str(self.system_summary.get("installed_software_count",0))),("Службы",str(self.system_summary.get("running_services_count",0))),("Порты",str(self.system_summary.get("open_ports_count",0))),("Файрвол","Активен" if self.system_summary.get("firewall") else "Не активен"),("Антивирус","Активен" if self.system_summary.get("antivirus") else "Не активен"),("RDP","Вкл" if self.system_summary.get("has_rdp") else "Выкл"),("SMB","Да" if self.system_summary.get("has_smb") else "Нет"),("БД",", ".join(self.system_summary.get("database_types",[])) or "Нет")]:
            r = self.sys_table.rowCount(); self.sys_table.insertRow(r); self.sys_table.setItem(r,0,QTableWidgetItem(str(p))); self.sys_table.setItem(r,1,QTableWidgetItem(str(v)))
        self.btn_analyze.setText("1. Анализ системы (выполнен)"); self.btn_analyze.setEnabled(True); self.btn_load_db.setEnabled(True)

    def _on_analysis_error(self, e):
        self.btn_analyze.setText("1. Анализ системы"); self.btn_analyze.setEnabled(True); QMessageBox.critical(self,"Ошибка",f"Ошибка анализа:\n{e}")

    def _load_databases(self):
        self.btn_load_db.setEnabled(False); self.btn_load_db.setText("Загрузка...")
        self.db_worker = DBLoadWorker(); self.db_worker.finished.connect(self._on_db_loaded); self.db_worker.error.connect(self._on_db_error); self.db_worker.start()

    def _on_db_loaded(self, db):
        self.vuln_db = db; self.btn_load_db.setText("2. Базы (загружены)"); self.btn_load_db.setEnabled(True); self.btn_vuln_scan.setEnabled(True); self.btn_server.setEnabled(True)
        self.lbl_stats.setText(f"CVE:{len(db.cve_db)} CWE:{len(db.cwe_db)} CAPEC:{len(db.capec_db)} MITRE:{len(db.mitre_db)}")

    def _on_db_error(self, e):
        self.btn_load_db.setText("2. Загрузить базы CVE/CWE/CAPEC/MITRE"); self.btn_load_db.setEnabled(True); QMessageBox.critical(self,"Ошибка",f"Ошибка БД:\n{e}")

    def _start_vuln_scan(self):
        self.btn_vuln_scan.setEnabled(False); self.btn_vuln_scan.setText("Сканирование..."); self.vuln_progress.setVisible(True); self.vuln_progress.setValue(0); self.vuln_table.setRowCount(0)
        self.vuln_worker = VulnScanWorker(); self.vuln_worker.finished.connect(self._on_vuln_scan_done); self.vuln_worker.progress.connect(self._on_vuln_scan_progress); self.vuln_worker.error.connect(self._on_vuln_scan_error); self.vuln_worker.start()

    def _on_vuln_scan_progress(self, c, t, m): self.vuln_progress.setValue(int(c/t*100) if t else 0); self.vuln_progress.setFormat(f"{m} ({c}/{t})")

    def _on_vuln_scan_done(self, report):
        self.vuln_scan_report = report; self.vuln_progress.setValue(100); self.vuln_progress.setVisible(False)
        self.vuln_table.setRowCount(0); so = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        for f in sorted(report.findings, key=lambda x: so.get(x.severity,5)):
            r = self.vuln_table.rowCount(); self.vuln_table.insertRow(r)
            self.vuln_table.setItem(r,0,QTableWidgetItem(str(f.check_id)))
            si = QTableWidgetItem(str(f.severity)); si.setForeground(QColor({"CRITICAL":"#c44","HIGH":"#a85","MEDIUM":"#997","LOW":"#696","INFO":"#668"}.get(f.severity,"#888"))); self.vuln_table.setItem(r,1,si)
            sti = QTableWidgetItem(str(f.status)); sti.setForeground(QColor({"VULNERABLE":"#b55","SECURE":"#696","UNKNOWN":"#888"}.get(f.status,"#888"))); self.vuln_table.setItem(r,2,sti)
            self.vuln_table.setItem(r,3,QTableWidgetItem(str(f.category)))
            d = str(f.title) + (f" | {f.recommendation}" if f.recommendation else ""); self.vuln_table.setItem(r,4,QTableWidgetItem(d))
        self.vuln_summary_label.setText(f"Проверок:{report.total_checks} Уязвимо:{report.vulnerable} Защищено:{report.secure} Риск:{report.risk_score:.1f}/100")
        self.btn_vuln_scan.setText("3. Локальный скан (выполнен)"); self.btn_vuln_scan.setEnabled(True); self.tabs.setCurrentIndex(1)

    def _on_vuln_scan_error(self, e): self.vuln_progress.setVisible(False); self.btn_vuln_scan.setText("3. Локальное сканирование"); self.btn_vuln_scan.setEnabled(True); QMessageBox.critical(self,"Ошибка",str(e))

    def _toggle_server(self):
        if self.server_running: self._stop_server()
        else: self._start_server()

    def _start_server(self):
        port = self.port_spin.value()
        ok, desc = is_port_available(port)
        if not ok:
            QMessageBox.critical(self,"Порт занят",f"Порт {port} уже используется!\n\nВыберите другой порт или освободите его.")
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
                logger.debug(f"[API] Входящий GET запрос: {self.path} от {ip}")
                try:
                    ss = state.system_summary if isinstance(state.system_summary, dict) else {}
                    hn = ss.get("hostname", "")
                    if self.path == "/ping":
                        if ip not in state.connected_clients:
                            state.connected_clients.append(ip)
                            logger.info(f"[API] Зарегистрирован новый клиент: {ip}")
                        if state.on_client_connected:
                            state.on_client_connected(ip)
                        self._r(200, {"status":"pong","ready":state.ready,"hostname":hn,"server_port":port})
                    elif self.path == "/status":
                        self._r(200, {"status":"running","ready":state.ready,"hostname":hn,"clients":state.connected_clients})
                    elif self.path == "/system-info":
                        self._r(200, ss)
                    else:
                        self._r(200, {"message":"Security Assessment Server","ready":state.ready,"endpoints":["/ping","/status","/analyze (POST)"]})
                except Exception as e:
                    logger.error(f"[API] Ошибка обработки GET {self.path}: {e}", exc_info=True)
                    self._r(500, {"error":str(e)})

            def do_POST(self):
                ip = self.client_address[0]
                logger.info(f"[API] Получен POST запрос {self.path} от {ip}")
                if self.path != "/analyze":
                    self._r(404, {"error":"Not Found"}); return
                if not state.ready or not state.system_info or not state.vuln_db:
                    logger.warning(f"[API] Отказ {ip}: Сервер не готов (не нажаты кнопки 1 и 2).")
                    self._r(503, {"error":f"Сервер не готов","ready":False,"hint":"Выполните шаги 1-2 на сервере"}); return
                try:
                    ln = int(self.headers.get("Content-Length",0))
                    if ln == 0: 
                        logger.warning(f"[API] Отказ {ip}: Пустое тело запроса.")
                        self._r(400,{"error":"Пустое тело"}); return
                    
                    body = self.rfile.read(ln).decode("utf-8")
                    logger.debug(f"[API] Размер полученного payload: {ln} байт. Первые 200 символов: {body[:200]}...")
                    
                    scan_data = json.loads(body)
                    logger.info(f"[API] Распакованы данные от {ip}: {len(scan_data.get('open_ports',[]))} портов, {len(scan_data.get('attack_vectors',[]))} векторов атак")
                    
                    if ip not in state.connected_clients: state.connected_clients.append(ip)
                    if state.on_client_connected: state.on_client_connected(ip)
                    
                    logger.debug("[CORE] Запуск AttackCorrelator (сопоставление векторов атак с ОС)...")
                    sr = from_json_scan_result(scan_data)
                    cor = AttackCorrelator(state.system_info, state.vuln_db)
                    results = cor.correlate(sr)
                    summary = cor.get_summary()
                    
                    logger.info(f"[CORE] Корреляция завершена. Итоговых уязвимостей: {len(results)}")
                    
                    rd = os.path.join(PROJECT_DIR,"reports"); os.makedirs(rd,exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    rep = ReportGenerator(state.system_summary or {}, results, summary)
                    hp = rep.generate_html(os.path.join(rd,f"report_{ts}.html"))
                    rep.generate_json(os.path.join(rd,f"report_{ts}.json"))
                    
                    gui.last_report_path = hp
                    logger.debug(f"[CORE] Отчеты сохранены. HTML: {hp}")
                    
                    resp = {"status":"success","summary":summary,"html_report":hp,"results_count":len(results),
                            "details":[{"cve_id":r.cve_id,"attack_name":r.attack_name,"severity":r.severity,"feasibility":r.feasibility,"description":r.description,"recommendation":r.recommendation} for r in results]}
                    
                    self._r(200, resp)
                    logger.info(f"[API] Ответ 200 OK успешно отправлен клиенту {ip}")
                    
                    if state.on_analysis_complete: state.on_analysis_complete(summary, hp)
                    
                    gui.update_results_signal.emit(results)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"[API] Ошибка парсинга JSON: {e}"); self._r(400,{"error":f"Некорректный JSON: {e}"})
                except Exception as e:
                    logger.error(f"[API] Критическая ошибка POST обработчика: {e}", exc_info=True); self._r(500,{"error":str(e)})

            def _r(self, code, data):
                self.send_response(code)
                self.send_header("Content-Type","application/json; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin","*")
                self.end_headers()
                self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))
            def log_message(self, *a): pass

        try:
            self.http_server = HTTPServer(("0.0.0.0", port), Handler)
            self.actual_server_port = port
            self.server_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True); self.server_thread.start()
            self.server_running = True
            self.status_icon.setText(f"●  Сервер запущен"); self.status_icon.setStyleSheet("color:#8a8;")
            self.port_display.setText(f"Порт: {port}\nURL: http://0.0.0.0:{port}\nАтакующий должен указать этот порт!")
            self.port_display.setStyleSheet("color:#8a8;")
            self.btn_server.setText("4. Остановить сервер"); self.btn_open_report.setEnabled(True); self.port_spin.setEnabled(False)
            self.statusBar().showMessage(f"Сервер на порту {port}. Ожидание подключений...")
            logger.info(f"[SRV] HTTP-сервер успешно стартовал на порту {port}")
        except OSError as e:
            if "10048" in str(e) or "in use" in str(e).lower():
                QMessageBox.critical(self,"Порт занят",f"Порт {port} занят!\nnetstat -ano | findstr :{port}")
            else: QMessageBox.critical(self,"Ошибка",str(e))
            logger.error(f"[SRV] Ошибка запуска на порту {port}: {e}")
        except Exception as e:
            QMessageBox.critical(self,"Ошибка",str(e)); logger.error(f"Ошибка: {e}")

    def _stop_server(self):
        if self.http_server: self.http_server.shutdown(); self.http_server = None
        self.server_running = False; self.actual_server_port = None
        self.status_icon.setText("●  Сервер остановлен"); self.status_icon.setStyleSheet("color:#666;")
        self.port_display.setText(""); self.btn_server.setText("4. Запустить сервер"); self.port_spin.setEnabled(True)
        logger.info("[SRV] HTTP-сервер остановлен пользователем")

    def _on_client_connected(self, ip):
        from server.api_server import state
        n = len(state.connected_clients); cs = ", ".join(state.connected_clients[-5:])
        self.connection_label.setText(f"Клиентов: {n}\nПоследние: {cs}")
        self.statusBar().showMessage(f"Клиент подключён: {ip}")

    def _on_server_analysis_done(self, summary, path):
        self.last_report_path = path; self.tabs.setCurrentIndex(2); self.btn_open_report.setEnabled(True)

    def _update_results_table_slot(self, results):
        try:
            self.results_table.setRowCount(0)
            
            # ФИЛЬТРАЦИЯ ДУБЛИКАТОВ ДЛЯ ИНТЕРФЕЙСА СЕРВЕРА
            seen = set()
            unique_results = []
            for r in results:
                cve = str(r.cve_id or "Нет CVE")
                name = str(r.attack_name or "Неизвестная атака")
                key = f"{cve}_{name}"
                if key not in seen:
                    seen.add(key)
                    unique_results.append(r)
            
            logger.debug(f"[UI] Обновление таблицы корреляции. Уникальных строк: {len(unique_results)}")
            
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
                si.setForeground(QColor({"CRITICAL":"#c44","HIGH":"#a85","MEDIUM":"#997","LOW":"#696"}.get(sev, "#888")))
                self.results_table.setItem(row, 1, si)
                
                fi = QTableWidgetItem(feas)
                if feas == "РЕАЛИЗУЕМА": fi.setForeground(QColor("#b55"))
                elif feas == "НЕ РЕАЛИЗУЕМА": fi.setForeground(QColor("#696"))
                self.results_table.setItem(row, 2, fi)
                
                self.results_table.setItem(row, 3, QTableWidgetItem(name))
                self.results_table.setItem(row, 4, QTableWidgetItem(desc))
        except Exception as e:
            logger.error(f"[UI] Сбой при заполнении таблицы GUI: {e}", exc_info=True)
            
    def _open_report(self):
        if self.last_report_path and os.path.exists(self.last_report_path): webbrowser.open(f"file:///{self.last_report_path}"); return
        rd = os.path.join(PROJECT_DIR,"reports")
        if os.path.exists(rd):
            fs = sorted([f for f in os.listdir(rd) if f.endswith(".html")], reverse=True)
            if fs: webbrowser.open(f"file:///{os.path.join(rd,fs[0])}"); return
        QMessageBox.information(self,"Отчёт","Отчёт не создан.")

    def _export_log(self):
        t = self.log_output.toPlainText()
        if not t: QMessageBox.information(self,"Экспорт","Лог пуст."); return
        p,_ = QFileDialog.getSaveFileName(self,"Сохранить лог",f"server_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt","Text Files (*.txt)")
        if p: open(p,"w",encoding="utf-8").write(t)

    def closeEvent(self, e):
        if self.server_running:
            if QMessageBox.question(self,"Выход","Остановить сервер и выйти?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No) == QMessageBox.StandardButton.No: e.ignore(); return
            self._stop_server()
        e.accept()

def main():
    app = QApplication(sys.argv); app.setStyle("Fusion"); w = ServerGUI(); w.show(); sys.exit(app.exec())

if __name__ == "__main__": main()