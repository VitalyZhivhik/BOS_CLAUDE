"""
Атакующий агент — графический интерфейс PyQt6.
Сканирует цель, генерирует векторы атак, отправляет на сервер.

ИСПРАВЛЕНИЯ:
  - Лучшая обработка 503: показывает причину и подсказку
  - Глубокий фингерпринтинг (HTTP-зондирование, версии)
  - Строгая монохромная тема
  - Экспорт лога
"""
import sys, os, json, socket, urllib.request, urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QProgressBar, QFrame, QMessageBox, QStatusBar, QCheckBox, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCursor

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from common.config import (TARGET_SERVER_HOST, TARGET_SERVER_PORT, SCAN_PORT_START, SCAN_PORT_END, SCAN_TIMEOUT, KNOWN_PORTS)
from common.models import ScanResult, OpenPort, AttackVector, Severity
from common.logger import get_attacker_logger, GUILogHandler
from attacker.attacker_agent import AttackVectorGenerator, PortScanner

logger = get_attacker_logger()

STYLE = """
QMainWindow { background: #121212; }
QWidget { color: #d0d0d0; font-family: 'Segoe UI', 'Consolas'; }
QGroupBox { background: #1a1a1a; border: 1px solid #333; border-radius: 4px; margin-top: 14px; padding-top: 22px; font-weight: 600; font-size: 12px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; color: #909090; }
QPushButton { padding: 8px 14px; border-radius: 3px; font-weight: 600; font-size: 11px; border: 1px solid #444; color: #d0d0d0; background: #252525; }
QPushButton:hover { background: #333; border-color: #555; }
QPushButton:disabled { background: #1a1a1a; color: #555; border-color: #2a2a2a; }
QTextEdit { background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a; border-radius: 3px; font-family: 'Consolas'; font-size: 11px; padding: 6px; }
QLineEdit { background: #0e0e0e; color: #d0d0d0; border: 1px solid #333; border-radius: 3px; padding: 6px; font-size: 12px; }
QSpinBox { background: #0e0e0e; color: #d0d0d0; border: 1px solid #333; border-radius: 3px; padding: 4px; }
QTableWidget { background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a; border-radius: 3px; gridline-color: #222; font-size: 11px; }
QTableWidget::item { padding: 4px 6px; }
QTableWidget::item:selected { background: #2a2a2a; color: #e0e0e0; }
QHeaderView::section { background: #181818; color: #888; border: none; padding: 6px; font-weight: 600; }
QTabWidget::pane { border: 1px solid #333; border-radius: 3px; background: #1a1a1a; }
QTabBar::tab { background: #181818; color: #777; padding: 8px 18px; border: 1px solid #2a2a2a; border-bottom: none; border-top-left-radius: 3px; border-top-right-radius: 3px; margin-right: 2px; }
QTabBar::tab:selected { background: #1a1a1a; color: #d0d0d0; border-color: #333; }
QProgressBar { background: #0e0e0e; border: 1px solid #333; border-radius: 3px; text-align: center; color: #999; font-weight: 600; font-size: 10px; }
QProgressBar::chunk { background: #555; border-radius: 2px; }
QCheckBox { color: #b0b0b0; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid #444; border-radius: 2px; background: #1a1a1a; }
QCheckBox::indicator:checked { background: #666; border-color: #888; }
QStatusBar { background: #0e0e0e; color: #666; border-top: 1px solid #222; }
QLabel { color: #b0b0b0; }
"""

class ScanWorker(QThread):
    port_found = pyqtSignal(object)
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    def __init__(self, target, ps, pe, timeout=0.5, deep=False):
        super().__init__()
        self.target=target; self.ps=ps; self.pe=pe; self.timeout=timeout; self.deep=deep; self._cancel=False
    def cancel(self): self._cancel=True
    def run(self):
        try:
            ports=[]; total=self.pe-self.ps+1; scanned=0
            sc = PortScanner(self.target, self.ps, self.pe, timeout=self.timeout)
            with ThreadPoolExecutor(max_workers=100) as ex:
                futs={ex.submit(sc._check_port,p):p for p in range(self.ps,self.pe+1)}
                for f in as_completed(futs):
                    if self._cancel: return
                    scanned+=1
                    if scanned%50==0 or scanned==total: self.progress.emit(scanned,total)
                    r=f.result()
                    if r:
                        if self.deep: r=self._df(r)
                        ports.append(r); self.port_found.emit(r)
            ports.sort(key=lambda x:x.port); self.finished.emit(ports)
        except Exception as e: self.error.emit(str(e))

    def _df(self, pi):
        port=pi.port
        try:
            if port in (80,443,8080,8443,8000,8888):
                scheme="https" if port in (443,8443) else "http"
                try:
                    import ssl; ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                    req=urllib.request.Request(f"{scheme}://{self.target}:{port}/",headers={"User-Agent":"SecurityScanner/1.0"},method="HEAD")
                    with urllib.request.urlopen(req,timeout=3,context=ctx) as resp:
                        sv=resp.headers.get("Server",""); pw=resp.headers.get("X-Powered-By","")
                        parts=[]
                        if sv: parts.append(f"Server: {sv}")
                        if pw: parts.append(f"X-Powered-By: {pw}")
                        if parts: pi.banner=" | ".join(parts)
                except Exception: pass
            elif port in (21,22,25,110,143):
                try:
                    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(3); s.connect((self.target,port))
                    b=s.recv(1024).decode("utf-8",errors="replace").strip(); s.close()
                    if b: pi.banner=b[:200]
                except Exception: pass
        except Exception: pass
        return pi

class SendWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    def __init__(self, url, data): super().__init__(); self.url=url; self.data=data
    def run(self):
        try:
            jd=json.dumps(self.data,ensure_ascii=False).encode("utf-8")
            req=urllib.request.Request(self.url,data=jd,headers={"Content-Type":"application/json; charset=utf-8"},method="POST")
            logger.info(f"Отправка на {self.url} ({len(jd)} байт)")
            with urllib.request.urlopen(req,timeout=120) as resp:
                r=json.loads(resp.read().decode("utf-8")); logger.info("Ответ получен"); self.finished.emit(r)
        except urllib.error.HTTPError as e:
            body=""
            try:
                body=e.read().decode("utf-8")
                try:
                    ed=json.loads(body)
                    # Извлекаем подробную ошибку
                    err_msg = ed.get("error", "")
                    hint = ed.get("hint", "")
                    if hint:
                        body = f"{err_msg}\n\nПодсказка: {hint}"
                    elif err_msg:
                        body = err_msg
                except (json.JSONDecodeError, KeyError): pass
            except Exception: pass
            msg=f"HTTP {e.code}: {body or e.reason}"
            logger.error(f"Ошибка HTTP: {msg}"); self.error.emit(msg)
        except Exception as e:
            logger.error(f"Ошибка: {e}",exc_info=True); self.error.emit(str(e))

class AttackerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Assessment — Атакующий агент")
        self.setMinimumSize(1150, 750)
        self.open_ports=[]; self.attack_vectors=[]; self.scan_worker=None; self.connected_to_server=False
        self._build_ui(); self.setStyleSheet(STYLE)
        gh=GUILogHandler(self._on_log_message); gh.setLevel(10); logger.addHandler(gh)
        self.log_signal.connect(self._append_log)

    def _build_ui(self):
        central=QWidget(); self.setCentralWidget(central)
        ml=QHBoxLayout(central); ml.setSpacing(8); ml.setContentsMargins(8,8,8,8)
        left=QWidget(); left.setFixedWidth(290)
        ll=QVBoxLayout(left); ll.setSpacing(6); ll.setContentsMargins(0,0,0,0)
        t=QLabel("АТАКУЮЩИЙ АГЕНТ"); t.setFont(QFont("Segoe UI",14,QFont.Weight.Bold))
        t.setStyleSheet("color:#888;padding:6px 0;letter-spacing:2px;"); ll.addWidget(t)

        self.conn_frame=QFrame(); self.conn_frame.setStyleSheet("background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        cf=QVBoxLayout(self.conn_frame); cf.setSpacing(4)
        self.conn_icon=QLabel("●  Нет связи с сервером"); self.conn_icon.setFont(QFont("Segoe UI",11,QFont.Weight.Bold)); self.conn_icon.setStyleSheet("color:#666;"); cf.addWidget(self.conn_icon)
        self.conn_detail=QLabel(""); self.conn_detail.setStyleSheet("color:#555;font-size:10px;"); self.conn_detail.setWordWrap(True); cf.addWidget(self.conn_detail)
        ll.addWidget(self.conn_frame)

        tg=QGroupBox("Параметры цели"); tl=QVBoxLayout(tg); tl.setSpacing(4)
        tl.addWidget(QLabel("IP-адрес сервера:"))
        self.target_input=QLineEdit(TARGET_SERVER_HOST); self.target_input.setFont(QFont("Consolas",12)); tl.addWidget(self.target_input)
        tl.addWidget(QLabel("Порт API сервера:"))
        self.port_spin=QSpinBox(); self.port_spin.setRange(1024,65535); self.port_spin.setValue(TARGET_SERVER_PORT); tl.addWidget(self.port_spin)
        r=QHBoxLayout(); r.addWidget(QLabel("Порты от:"))
        self.ps_spin=QSpinBox(); self.ps_spin.setRange(1,65535); self.ps_spin.setValue(SCAN_PORT_START); r.addWidget(self.ps_spin)
        r.addWidget(QLabel("до:")); self.pe_spin=QSpinBox(); self.pe_spin.setRange(1,65535); self.pe_spin.setValue(SCAN_PORT_END); r.addWidget(self.pe_spin); tl.addLayout(r)
        self.chk_deep=QCheckBox("Глубокий фингерпринтинг"); self.chk_deep.setChecked(True); tl.addWidget(self.chk_deep)
        ll.addWidget(tg)

        ag=QGroupBox("Действия"); al=QVBoxLayout(ag); al.setSpacing(6)
        self.btn_check=QPushButton("1. Проверить связь с сервером"); self.btn_check.clicked.connect(self._check_connection); al.addWidget(self.btn_check)
        self.btn_scan=QPushButton("2. Сканировать порты"); self.btn_scan.clicked.connect(self._start_scan); al.addWidget(self.btn_scan)
        self.progress_bar=QProgressBar(); self.progress_bar.setFixedHeight(18); self.progress_bar.setVisible(False); al.addWidget(self.progress_bar)
        self.btn_send=QPushButton("3. Отправить на сервер для анализа"); self.btn_send.setEnabled(False); self.btn_send.clicked.connect(self._send_results); al.addWidget(self.btn_send)
        self.btn_export=QPushButton("Экспорт лога"); self.btn_export.clicked.connect(self._export_log); al.addWidget(self.btn_export)
        ll.addWidget(ag); ll.addStretch()

        sf=QFrame(); sf.setStyleSheet("background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        sl=QVBoxLayout(sf); self.lbl_stats=QLabel("Ожидание сканирования"); self.lbl_stats.setStyleSheet("color:#666;font-size:10px;"); self.lbl_stats.setWordWrap(True); sl.addWidget(self.lbl_stats)
        ll.addWidget(sf); ml.addWidget(left)

        self.tabs=QTabWidget()
        pt=QWidget(); ptl=QVBoxLayout(pt)
        self.ports_table=QTableWidget(0,4); self.ports_table.setHorizontalHeaderLabels(["Порт","Протокол","Сервис","Баннер"])
        self.ports_table.horizontalHeader().setStretchLastSection(True); self.ports_table.setColumnWidth(0,70); self.ports_table.setColumnWidth(1,70); self.ports_table.setColumnWidth(2,120)
        self.ports_table.verticalHeader().setVisible(False); self.ports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        ptl.addWidget(self.ports_table); self.tabs.addTab(pt,"Порты")

        at=QWidget(); atl=QVBoxLayout(at)
        self.attacks_table=QTableWidget(0,5); self.attacks_table.setHorizontalHeaderLabels(["ID","Серьёзность","Порт","Название","Описание"])
        self.attacks_table.horizontalHeader().setStretchLastSection(True); self.attacks_table.setColumnWidth(0,120); self.attacks_table.setColumnWidth(1,85); self.attacks_table.setColumnWidth(2,60); self.attacks_table.setColumnWidth(3,200)
        self.attacks_table.verticalHeader().setVisible(False); self.attacks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        atl.addWidget(self.attacks_table); self.tabs.addTab(at,"Векторы атак")

        rpt=QWidget(); rtl=QVBoxLayout(rpt)
        self.response_table=QTableWidget(0,5); self.response_table.setHorizontalHeaderLabels(["CVE","Серьёзность","Реализуемость","Атака","Рекомендация"])
        self.response_table.horizontalHeader().setStretchLastSection(True); self.response_table.setColumnWidth(0,130); self.response_table.setColumnWidth(1,85); self.response_table.setColumnWidth(2,130); self.response_table.setColumnWidth(3,180)
        self.response_table.verticalHeader().setVisible(False); self.response_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        rtl.addWidget(self.response_table)
        self.response_summary=QLabel(""); self.response_summary.setStyleSheet("color:#888;font-size:11px;padding:4px;"); rtl.addWidget(self.response_summary)
        self.tabs.addTab(rpt,"Ответ сервера")

        lt=QWidget(); ltl=QVBoxLayout(lt); self.log_output=QTextEdit(); self.log_output.setReadOnly(True); ltl.addWidget(self.log_output); self.tabs.addTab(lt,"Лог")
        ml.addWidget(self.tabs,1)
        self.setStatusBar(QStatusBar()); self.statusBar().showMessage("Готов к работе")

    def _on_log_message(self, msg, level): self.log_signal.emit(msg, level)
    def _append_log(self, msg, level):
        c={"ERROR":"#b55","WARNING":"#a85","CRITICAL":"#c44"}.get(level,"#888")
        self.log_output.append(f'<span style="color:{c};">{msg}</span>')
        self.log_output.moveCursor(QTextCursor.MoveOperation.End)

    def _check_connection(self):
        self.btn_check.setEnabled(False); self.btn_check.setText("Проверка...")
        self.conn_icon.setText("●  Проверка связи..."); self.conn_icon.setStyleSheet("color:#888;")
        target=self.target_input.text(); port=self.port_spin.value()
        def check():
            try:
                url=f"http://{target}:{port}/ping"
                req=urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data=json.loads(resp.read().decode("utf-8"))
                    hn=data.get("hostname","?"); ready=data.get("ready",False)
                    sp=data.get("server_port", port)
                    QTimer.singleShot(0, lambda: self._on_connected(hn, ready, sp))
            except urllib.error.HTTPError as e:
                # Если 503 — значит НЕ НАШ сервер или сервер не готов
                body = ""
                try:
                    body = e.read().decode("utf-8")
                    try:
                        ed = json.loads(body)
                        body = ed.get("error", "") or ed.get("message", "")
                    except: pass
                except: pass
                msg = f"HTTP {e.code}"
                if e.code == 503:
                    msg = (f"Порт {port} отвечает 503 (Service Unavailable).\n\n"
                           f"Возможные причины:\n"
                           f"  1. На этом порту запущен ДРУГОЙ сервис (не наш)\n"
                           f"  2. Сервер запущен, но не готов (шаги 1-2 не выполнены)\n"
                           f"  3. Проверьте порт на сервере — он показан в GUI")
                    if body: msg += f"\n\nОтвет: {body[:200]}"
                else:
                    msg += f": {body or e.reason}"
                logger.error(f"Нет связи с {target}:{port}: HTTP {e.code}")
                QTimer.singleShot(0, lambda: self._on_connection_failed(msg))
            except urllib.error.URLError as e:
                reason = str(e.reason) if hasattr(e, 'reason') else str(e)
                if "10061" in reason or "refused" in reason.lower():
                    msg = (f"Порт {port} закрыт — нет сервера.\n\n"
                           f"Убедитесь что:\n"
                           f"  1. Серверный агент запущен\n"
                           f"  2. Порт совпадает (на сервере показан текущий порт)\n"
                           f"  3. Файрвол не блокирует порт {port}")
                else:
                    msg = f"Ошибка сети: {reason}"
                logger.error(f"Нет связи с {target}:{port}: {e}")
                QTimer.singleShot(0, lambda: self._on_connection_failed(msg))
            except Exception as e:
                logger.error(f"Нет связи с {target}:{port}: {e}")
                QTimer.singleShot(0, lambda: self._on_connection_failed(str(e)))
        import threading; threading.Thread(target=check, daemon=True).start()

    def _on_connected(self, hostname, ready, server_port):
        self.connected_to_server = True
        self.conn_icon.setText("●  Связь установлена"); self.conn_icon.setStyleSheet("color:#8a8;")
        ready_text = "Готов к приёму" if ready else "НЕ ГОТОВ (выполните шаги 1-2 на сервере)"
        self.conn_detail.setText(f"Сервер: {hostname}\n{ready_text}\nПорт сервера: {server_port}")
        self.conn_frame.setStyleSheet("background:#1a1a1a;border:1px solid #3a5a3a;border-radius:4px;padding:8px;")
        self.btn_check.setText("1. Связь установлена"); self.btn_check.setEnabled(True)
        self.statusBar().showMessage(f"Подключено к {hostname} (порт {server_port})")

    def _on_connection_failed(self, error):
        self.connected_to_server = False
        self.conn_icon.setText("●  Нет связи"); self.conn_icon.setStyleSheet("color:#866;")
        self.conn_detail.setText(error[:300])
        self.conn_frame.setStyleSheet("background:#1a1a1a;border:1px solid #5a3a3a;border-radius:4px;padding:8px;")
        self.btn_check.setText("1. Проверить связь с сервером"); self.btn_check.setEnabled(True)
        self.statusBar().showMessage("Нет связи с сервером")

    def _start_scan(self):
        if self.scan_worker and self.scan_worker.isRunning(): self.scan_worker.cancel(); self.btn_scan.setText("2. Сканировать порты"); return
        t=self.target_input.text(); ps=self.ps_spin.value(); pe=self.pe_spin.value(); deep=self.chk_deep.isChecked()
        self.open_ports=[]; self.ports_table.setRowCount(0); self.attacks_table.setRowCount(0); self.progress_bar.setValue(0); self.progress_bar.setVisible(True); self.btn_send.setEnabled(False); self.btn_scan.setText("Остановить")
        logger.info(f"Начало сканирования {t} [{ps}-{pe}]{' (глубокий)' if deep else ''}")
        self.scan_worker=ScanWorker(t,ps,pe,SCAN_TIMEOUT,deep); self.scan_worker.port_found.connect(self._on_port_found); self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished.connect(self._on_scan_done); self.scan_worker.error.connect(self._on_scan_error); self.scan_worker.start()

    def _on_port_found(self, p):
        r=self.ports_table.rowCount(); self.ports_table.insertRow(r)
        self.ports_table.setItem(r,0,QTableWidgetItem(str(p.port))); self.ports_table.setItem(r,1,QTableWidgetItem(p.protocol))
        self.ports_table.setItem(r,2,QTableWidgetItem(p.service)); self.ports_table.setItem(r,3,QTableWidgetItem(p.banner or ""))

    def _on_scan_progress(self, s, t): self.progress_bar.setValue(int(s/t*100) if t else 0); self.progress_bar.setFormat(f"{s}/{t}")

    def _on_scan_done(self, ports):
        self.open_ports=ports; self.progress_bar.setValue(100); self.progress_bar.setVisible(False); self.btn_scan.setText("2. Сканировать порты")
        gen=AttackVectorGenerator(); self.attack_vectors=gen.generate(ports)
        self.attacks_table.setRowCount(0); so={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
        for av in sorted(self.attack_vectors, key=lambda v: so.get(v.severity,5)):
            r=self.attacks_table.rowCount(); self.attacks_table.insertRow(r)
            self.attacks_table.setItem(r,0,QTableWidgetItem(av.id))
            si=QTableWidgetItem(av.severity); si.setForeground(QColor({"CRITICAL":"#c44","HIGH":"#a85","MEDIUM":"#997","LOW":"#696","INFO":"#668"}.get(av.severity,"#888"))); self.attacks_table.setItem(r,1,si)
            self.attacks_table.setItem(r,2,QTableWidgetItem(str(av.target_port or "-"))); self.attacks_table.setItem(r,3,QTableWidgetItem(av.name)); self.attacks_table.setItem(r,4,QTableWidgetItem(av.description))
        cr=sum(1 for v in self.attack_vectors if v.severity=="CRITICAL"); hi=sum(1 for v in self.attack_vectors if v.severity=="HIGH")
        self.lbl_stats.setText(f"Порты: {len(ports)}\nВекторы: {len(self.attack_vectors)}\nCRITICAL: {cr} | HIGH: {hi}")
        self.btn_send.setEnabled(len(ports)>0); self.tabs.setCurrentIndex(1)
        self.statusBar().showMessage(f"Найдено {len(ports)} портов, {len(self.attack_vectors)} векторов")
        logger.info(f"Найдено {len(ports)} портов, {len(self.attack_vectors)} векторов атак")

    def _on_scan_error(self, e): self.progress_bar.setVisible(False); self.btn_scan.setText("2. Сканировать порты"); QMessageBox.critical(self,"Ошибка",e)

    def _send_results(self):
        if not self.open_ports: QMessageBox.warning(self,"Отправка","Нет данных."); return
        t=self.target_input.text(); p=self.port_spin.value()
        sr=ScanResult(scanner_ip=socket.gethostbyname(socket.gethostname()),target_ip=t,open_ports=self.open_ports,
                      discovered_services=[f"{x.service} (:{x.port})" for x in self.open_ports],
                      attack_vectors=self.attack_vectors, os_detection="Windows (fingerprint)", scan_timestamp=datetime.now().isoformat())
        self.btn_send.setEnabled(False); self.btn_send.setText("Отправка...")
        self.send_worker=SendWorker(f"http://{t}:{p}/analyze",asdict(sr))
        self.send_worker.finished.connect(self._on_send_done); self.send_worker.error.connect(self._on_send_error); self.send_worker.start()

    def _on_send_done(self, result):
        self.btn_send.setText("3. Отправить на сервер"); self.btn_send.setEnabled(True)
        if result.get("status")=="success":
            sm=result.get("summary",{}); details=result.get("details",[])
            self.response_table.setRowCount(0)
            for it in details:
                r=self.response_table.rowCount(); self.response_table.insertRow(r)
                self.response_table.setItem(r,0,QTableWidgetItem(it.get("cve_id","")))
                si=QTableWidgetItem(it.get("severity","")); si.setForeground(QColor({"CRITICAL":"#c44","HIGH":"#a85","MEDIUM":"#997","LOW":"#696"}.get(it.get("severity",""),"#888"))); self.response_table.setItem(r,1,si)
                fi=QTableWidgetItem(it.get("feasibility",""))
                if it.get("feasibility")=="РЕАЛИЗУЕМА": fi.setForeground(QColor("#b55"))
                elif it.get("feasibility")=="НЕ РЕАЛИЗУЕМА": fi.setForeground(QColor("#696"))
                self.response_table.setItem(r,2,fi); self.response_table.setItem(r,3,QTableWidgetItem(it.get("attack_name","")))
                self.response_table.setItem(r,4,QTableWidgetItem(it.get("recommendation","")[:150]))
            self.response_summary.setText(f"Всего:{sm.get('total_vulnerabilities_analyzed',0)} Реализуемые:{sm.get('feasible_attacks',0)} Частично:{sm.get('partially_feasible',0)} Нереализуемые:{sm.get('not_feasible_attacks',0)}")
            self.tabs.setCurrentIndex(2); self.statusBar().showMessage(f"Анализ: {result.get('results_count',0)} уязвимостей")
        else:
            QMessageBox.warning(self,"Ответ",f"Ошибка: {result.get('error','?')}")

    def _on_send_error(self, error):
        self.btn_send.setText("3. Отправить на сервер"); self.btn_send.setEnabled(True)
        # Показываем подробную ошибку
        if "503" in error:
            QMessageBox.warning(self, "Сервер не готов", error)
        else:
            QMessageBox.critical(self, "Ошибка отправки", error)

    def _export_log(self):
        t=self.log_output.toPlainText()
        if not t: QMessageBox.information(self,"Экспорт","Лог пуст."); return
        p,_=QFileDialog.getSaveFileName(self,"Сохранить",f"attacker_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt","Text (*.txt)")
        if p: open(p,"w",encoding="utf-8").write(t)

def main():
    app=QApplication(sys.argv); app.setStyle("Fusion"); w=AttackerGUI(); w.show(); sys.exit(app.exec())

if __name__=="__main__": main()
