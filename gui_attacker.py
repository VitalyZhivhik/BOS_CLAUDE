"""
Атакующий агент — графический интерфейс PyQt6.
ИСПРАВЛЕНИЯ:
  - Возвращено нормальное форматирование кода (без сжатия в одну строку).
  - Восстановлена запись Системного лога.
  - Добавлены агрессивные тайм-ауты для Nmap, чтобы избежать зависаний скриптов на 99%.
"""
import sys
import os
import json
import socket
import urllib.request
import urllib.error
import time
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict

proxy_handler = urllib.request.ProxyHandler({})
opener = urllib.request.build_opener(proxy_handler)
urllib.request.install_opener(opener)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox, QSpinBox, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QProgressBar, QFrame, QMessageBox, QStatusBar, QCheckBox, QFileDialog,
    QListWidget, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QTextCursor

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

HISTORY_DIR = os.path.join(PROJECT_DIR, "history")
os.makedirs(HISTORY_DIR, exist_ok=True)

from common.config import (TARGET_SERVER_HOST, TARGET_SERVER_PORT, SCAN_PORT_START, SCAN_PORT_END, SCAN_TIMEOUT)
from common.models import ScanResult, OpenPort, AttackVector
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
QListWidget { background: #0e0e0e; color: #b0b0b0; border: 1px solid #2a2a2a; border-radius: 3px; padding: 4px; }
QListWidget::item:selected { background: #2a2a2a; color: #e0e0e0; }
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


class CheckConnectionWorker(QThread):
    connected_signal = pyqtSignal(str, bool, int)
    failed_signal = pyqtSignal(str)

    def __init__(self, target, port):
        super().__init__()
        self.target = target
        self.port = port

    def run(self):
        try:
            url = f"http://{self.target}:{self.port}/ping"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.connected_signal.emit(data.get("hostname", "?"), data.get("ready", False), data.get("server_port", self.port))
        except urllib.error.HTTPError as e:
            msg = f"HTTP {e.code}: Сервер отклонил запрос."
            if e.code == 503:
                msg = f"Порт {self.port} отвечает 503 (Не готов).\n\nСервер найден, но вы не выполнили шаги 1 и 2 в серверной программе."
            self.failed_signal.emit(msg)
        except Exception as e:
            msg = str(e)
            if "10061" in msg or "refused" in msg.lower():
                msg = f"Подключение не удалось. Сервер выключен или указан неверный порт ({self.port})."
            self.failed_signal.emit(msg)


class ScanWorker(QThread):
    port_found = pyqtSignal(object)
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, target, ps, pe, timeout=0.3, deep=False):
        super().__init__()
        self.target = target
        self.ps = ps
        self.pe = pe
        self.timeout = timeout
        self.deep = deep
        self._cancel = False
        
    def cancel(self): 
        self._cancel = True
    
    def run(self):
        try:
            ports = []
            total = self.pe - self.ps + 1
            scanned = 0
            sc = PortScanner(self.target, self.ps, self.pe, timeout=self.timeout)
            
            logger.info(f"Начало сканирования {self.target} (Порты: {self.ps}-{self.pe})")
            
            with ThreadPoolExecutor(max_workers=100) as ex:
                futs = {ex.submit(sc._check_port, p): p for p in range(self.ps, self.pe + 1)}
                for f in as_completed(futs):
                    if self._cancel: 
                        logger.warning("Сканирование прервано пользователем.")
                        return
                        
                    scanned += 1
                    if scanned % 100 == 0 or scanned == total: 
                        self.progress.emit(scanned, total)
                        
                    r = f.result()
                    if r:
                        if self.deep: 
                            r = self._df(r)
                        ports.append(r)
                        self.port_found.emit(r)
                        logger.info(f"Найден открытый порт: {r.port} ({r.service})")
                        
            ports.sort(key=lambda x: x.port)
            logger.info(f"Сканирование завершено. Найдено {len(ports)} портов.")
            self.finished.emit(ports)
        except Exception as e: 
            logger.error(f"Ошибка сканирования: {e}", exc_info=True)
            self.error.emit(str(e))

    def _df(self, pi):
        port = pi.port
        try:
            if port in (80, 443, 8080, 8443, 8000, 8888):
                scheme = "https" if port in (443, 8443) else "http"
                try:
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(f"{scheme}://{self.target}:{port}/", headers={"User-Agent":"SecurityScanner/1.0"}, method="HEAD")
                    with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                        sv = resp.headers.get("Server", "")
                        pw = resp.headers.get("X-Powered-By", "")
                        parts = []
                        if sv: parts.append(f"Server: {sv}")
                        if pw: parts.append(f"X-Powered-By: {pw}")
                        if parts: pi.banner = " | ".join(parts)
                except Exception: 
                    pass
            elif port in (21, 22, 25, 110, 143):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((self.target, port))
                    b = s.recv(1024).decode("utf-8", errors="replace").strip()
                    s.close()
                    if b: pi.banner = b[:200]
                except Exception: 
                    pass
        except Exception: 
            pass
        return pi


class SendWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, url, data): 
        super().__init__()
        self.url = url
        self.data = data
        
    def run(self):
        try:
            jd = json.dumps(self.data, ensure_ascii=False).encode("utf-8")
            logger.info(f"Отправка отчета на сервер: {self.url} (Размер: {len(jd)} байт)")
            req = urllib.request.Request(self.url, data=jd, headers={"Content-Type":"application/json; charset=utf-8"}, method="POST")
            
            with urllib.request.urlopen(req, timeout=120) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))
                logger.info("Отчет успешно принят сервером.")
                self.finished.emit(response_data)
        except Exception as e: 
            logger.error(f"Ошибка при отправке на сервер: {e}")
            self.error.emit(str(e))


class NucleiWorker(QThread):
    progress = pyqtSignal(str, int) 
    log_msg = pyqtSignal(str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, target, open_ports):
        super().__init__()
        self.target = target
        self.open_ports = open_ports
        self.nuclei_path = r"C:\BOS\tools\nuclei.exe"
        
    def run(self):
        vectors = []
        if not os.path.exists(self.nuclei_path):
            msg = f"Nuclei не найден: {self.nuclei_path}"
            self.error.emit(msg)
            self.finished.emit([])
            return

        urls = [f"{self.target}:{p.port}" for p in self.open_ports] if self.open_ports else [self.target]
        self.progress.emit("Запуск ядра Nuclei...", 0)
        logger.info(f"Запуск Nuclei. Цели: {', '.join(urls)}")
        
        fd, temp_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        fd_url, url_list_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd_url)
        
        with open(url_list_path, "w", encoding="utf-8") as f: 
            f.write("\n".join(urls))
        
        try:
            cmd = [
                self.nuclei_path, 
                "-l", url_list_path, 
                "-json-export", temp_path, 
                "-ni", 
                "-disable-update-check", 
                "-mhe", "100000", 
                "-c", "50", 
                "-timeout", "2", 
                "-retries", "0", 
                "-stats", 
                "-si", "2"
            ]
            
            startupinfo = subprocess.STARTUPINFO() if os.name == 'nt' else None
            if startupinfo: 
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                bufsize=1, 
                universal_newlines=True, 
                startupinfo=startupinfo
            )
            
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line: continue
                
                stat_match = re.search(r'(?:reqs?|Requests):\s*(\d+)/(\d+)', clean_line, re.IGNORECASE)
                if stat_match:
                    tot = int(stat_match.group(2))
                    pct = int((int(stat_match.group(1)) / tot) * 100) if tot > 0 else 0
                    self.progress.emit(f"Анализ Nuclei: {stat_match.group(1)} из {tot} запросов...", pct)
                    continue 
                    
                self.log_msg.emit(clean_line)
            
            process.wait()
            logger.info("Процесс Nuclei завершен.")
            
            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                with open(temp_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            parsed = json.loads(line)
                            for item in (parsed if isinstance(parsed, list) else [parsed]):
                                if not isinstance(item, dict): continue
                                info = item.get("info", {})
                                if isinstance(info, list) and len(info) > 0: info = info[0]
                                elif not isinstance(info, dict): info = {}
                                
                                name = f"[NUCLEI] {info.get('name', item.get('template-id', 'Unknown'))}"
                                sev = str(info.get("severity", "MEDIUM")).upper()
                                pt = item.get("port", "")
                                
                                vectors.append(AttackVector(
                                    id=str(item.get("template-id", "nuclei-vuln"))[:50],
                                    name=name[:100],
                                    description=str(info.get("description", "Обнаружено Nuclei."))[:500],
                                    severity=sev if sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] else "MEDIUM",
                                    target_port=int(pt) if str(pt).isdigit() else None
                                ))
                        except Exception: 
                            pass
        except Exception as e: 
            logger.error(f"Ошибка выполнения Nuclei: {e}", exc_info=True)
            self.error.emit(str(e))
        finally:
            for p in [temp_path, url_list_path]:
                if os.path.exists(p): 
                    try: os.remove(p)
                    except: pass
                    
        self.finished.emit(vectors)


class NmapWorker(QThread):
    progress = pyqtSignal(str, int) 
    log_msg = pyqtSignal(str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, target, open_ports):
        super().__init__()
        self.target = target
        self.open_ports = open_ports
        
        # Поиск портативного или установленного Nmap
        portable_nmap = os.path.join(PROJECT_DIR, "tools", "nmap.exe")
        system_nmap_1 = r"C:\Program Files (x86)\Nmap\nmap.exe"
        system_nmap_2 = r"C:\Program Files\Nmap\nmap.exe"
        
        if os.path.exists(portable_nmap):
            self.nmap_path = portable_nmap
        elif os.path.exists(system_nmap_1):
            self.nmap_path = system_nmap_1
        else:
            self.nmap_path = system_nmap_2
        
    def run(self):
        vectors = []
        if not os.path.exists(self.nmap_path):
            msg = f"Nmap не найден по пути: {self.nmap_path}. Убедитесь, что nmap.exe находится в папке tools."
            self.log_msg.emit(f"❌ {msg}")
            self.error.emit(msg)
            self.finished.emit([])
            return

        if not self.open_ports:
            self.log_msg.emit("⚠️ Нет открытых портов для сканирования Nmap.")
            self.finished.emit([])
            return

        ports_str = ",".join(str(p.port) for p in self.open_ports)
        self.progress.emit("Запуск сканера Nmap...", 0)
        self.log_msg.emit(f"🚀 Инициализация Nmap. Цель: {self.target}, Порты: {ports_str}")
        logger.info(f"Запуск Nmap (NSE) на порты: {ports_str}")
        
        fd, temp_xml = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        
        try:
            # Агрессивные настройки для предотвращения зависания Nmap
            cmd = [
                self.nmap_path, 
                "-sV", 
                "--script", "vuln", 
                "-T4", 
                "--min-rate", "300",         # Отправлять пакеты быстро
                "--max-retries", "2",        # Не стучаться в мертвые порты вечно
                "--script-timeout", "2m",    # Убивать зависшие скрипты через 2 минуты
                "-p", ports_str, 
                "-oX", temp_xml, 
                "--stats-every", "5s",
                self.target
            ]
            
            self.log_msg.emit(f"💻 Команда: {' '.join(cmd)}")
            
            startupinfo = subprocess.STARTUPINFO() if os.name == 'nt' else None
            if startupinfo: 
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                bufsize=1, 
                universal_newlines=True, 
                startupinfo=startupinfo
            )
            
            for line in process.stdout:
                clean_line = line.strip()
                if not clean_line: continue
                
                # Поиск процента выполнения
                stat_match = re.search(r'About (\d+\.\d+)% done', clean_line)
                if stat_match:
                    pct = int(float(stat_match.group(1)))
                    self.progress.emit(f"Анализ протоколов Nmap: {pct}%...", pct)
                elif "undergoing" in clean_line:
                    # Nmap часто висит в статусе undergoing без процентов
                    action = clean_line.split(',')[-1].strip()
                    self.progress.emit(f"Nmap: {action}...", -1)
                else:
                    self.log_msg.emit(f"[NMAP] {clean_line}")
            
            process.wait()
            self.log_msg.emit(f"✅ Nmap завершил работу. Парсинг XML отчета...")
            logger.info("Процесс Nmap завершен, читаем XML.")
            
            if os.path.exists(temp_xml) and os.path.getsize(temp_xml) > 0:
                tree = ET.parse(temp_xml)
                root = tree.getroot()
                
                for host in root.findall('host'):
                    for port_elem in host.findall('.//port'):
                        port_id = port_elem.get('portid')
                        service_elem = port_elem.find('service')
                        service_name = service_elem.get('name') if service_elem is not None else "unknown"
                        
                        for script in port_elem.findall('.//script'):
                            script_id = script.get('id', 'nmap-script')
                            output = script.get('output', '')
                            
                            if "VULNERABLE" in output or "State: VULNERABLE" in output or "Likely vulnerable" in output:
                                name = f"[NMAP] Уязвимость протокола {service_name.upper()}"
                                cve_match = re.search(r'(CVE-\d{4}-\d+)', output)
                                cve = cve_match.group(1) if cve_match else script_id
                                sev = "HIGH"
                                if "cvss" in output.lower() and "10.0" in output: sev = "CRITICAL"
                                
                                desc = f"Nmap скрипт '{script_id}' выявил уязвимость:\n{output[:400]}..."
                                
                                vectors.append(AttackVector(
                                    id=cve,
                                    name=name,
                                    description=desc,
                                    severity=sev,
                                    target_port=int(port_id) if port_id.isdigit() else None
                                ))
                                self.log_msg.emit(f"🚨 Nmap нашел уязвимость: {cve} на порту {port_id}")
                
                self.log_msg.emit(f"✅ Обработка Nmap завершена. Найдено {len(vectors)} векторов.")
                logger.info(f"Nmap выявил {len(vectors)} уязвимостей.")
            else:
                self.log_msg.emit("⚠️ XML отчет Nmap пуст.")
                            
        except Exception as e:
            self.error.emit(f"Сбой выполнения Nmap: {str(e)}")
            self.log_msg.emit(f"❌ Ошибка Nmap: {str(e)}")
            logger.error(f"Сбой Nmap: {e}", exc_info=True)
        finally:
            if os.path.exists(temp_xml):
                try: os.remove(temp_xml)
                except: pass
                
        self.finished.emit(vectors)


class AttackerGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Assessment — Атакующий агент")
        self.setMinimumSize(1150, 750)
        self.open_ports = []
        self.attack_vectors = []
        self.scan_worker = None
        self.connected_to_server = False
        
        self._build_ui()
        self.setStyleSheet(STYLE)
        
        # Восстановление Системного лога
        gh = GUILogHandler(self._on_log_message)
        gh.setLevel(10)
        logger.addHandler(gh)
        self.log_signal.connect(self._append_log)
        
        self._load_history_list()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        ml = QHBoxLayout(central)
        ml.setSpacing(8)
        ml.setContentsMargins(8, 8, 8, 8)
        
        left = QWidget()
        left.setFixedWidth(290)
        ll = QVBoxLayout(left)
        ll.setSpacing(6)
        ll.setContentsMargins(0, 0, 0, 0)
        
        t = QLabel("АТАКУЮЩИЙ АГЕНТ")
        t.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        t.setStyleSheet("color:#888;padding:6px 0;letter-spacing:2px;")
        ll.addWidget(t)

        self.conn_frame = QFrame()
        self.conn_frame.setStyleSheet("background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        cf = QVBoxLayout(self.conn_frame)
        cf.setSpacing(4)
        
        self.conn_icon = QLabel("●  Нет связи с сервером")
        self.conn_icon.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.conn_icon.setStyleSheet("color:#666;")
        cf.addWidget(self.conn_icon)
        
        self.conn_detail = QLabel("")
        self.conn_detail.setStyleSheet("color:#555;font-size:10px;")
        self.conn_detail.setWordWrap(True)
        cf.addWidget(self.conn_detail)
        ll.addWidget(self.conn_frame)

        tg = QGroupBox("Параметры цели")
        tl = QVBoxLayout(tg)
        tl.setSpacing(4)
        tl.addWidget(QLabel("IP-адрес сервера:"))
        
        self.target_input = QLineEdit(TARGET_SERVER_HOST)
        self.target_input.setFont(QFont("Consolas", 12))
        tl.addWidget(self.target_input)
        
        tl.addWidget(QLabel("Порт API сервера:"))
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(TARGET_SERVER_PORT)
        tl.addWidget(self.port_spin)
        
        r = QHBoxLayout()
        r.addWidget(QLabel("Порты от:"))
        self.ps_spin = QSpinBox()
        self.ps_spin.setRange(1, 65535)
        self.ps_spin.setValue(1)
        r.addWidget(self.ps_spin)
        r.addWidget(QLabel("до:"))
        self.pe_spin = QSpinBox()
        self.pe_spin.setRange(1, 65535)
        self.pe_spin.setValue(10000)
        r.addWidget(self.pe_spin)
        tl.addLayout(r)
        
        self.chk_deep = QCheckBox("Глубокий фингерпринтинг")
        self.chk_deep.setChecked(True)
        tl.addWidget(self.chk_deep)
        ll.addWidget(tg)

        ag = QGroupBox("Действия")
        al = QVBoxLayout(ag)
        al.setSpacing(6)
        
        self.btn_check = QPushButton("1. Проверить связь с сервером")
        self.btn_check.clicked.connect(self._check_connection)
        al.addWidget(self.btn_check)
        
        self.btn_scan = QPushButton("2. Сканировать порты")
        self.btn_scan.clicked.connect(self._start_scan)
        al.addWidget(self.btn_scan)
        
        self.btn_nuclei = QPushButton("3. Веб-уязвимости (Nuclei)")
        self.btn_nuclei.setEnabled(False)
        self.btn_nuclei.clicked.connect(self._start_nuclei)
        al.addWidget(self.btn_nuclei)
        
        self.btn_nmap = QPushButton("4. Сетевые протоколы (Nmap)")
        self.btn_nmap.setEnabled(False)
        self.btn_nmap.clicked.connect(self._start_nmap)
        al.addWidget(self.btn_nmap)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(18)
        self.progress_bar.setVisible(False)
        al.addWidget(self.progress_bar)
        
        self.btn_send = QPushButton("5. Отправить на сервер для анализа")
        self.btn_send.setEnabled(False)
        self.btn_send.clicked.connect(self._send_results)
        al.addWidget(self.btn_send)
        
        self.btn_export = QPushButton("Экспорт лога")
        self.btn_export.clicked.connect(self._export_log)
        al.addWidget(self.btn_export)
        
        ll.addWidget(ag)
        ll.addStretch()

        sf = QFrame()
        sf.setStyleSheet("background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:8px;")
        sl = QVBoxLayout(sf)
        self.lbl_stats = QLabel("Ожидание сканирования")
        self.lbl_stats.setStyleSheet("color:#666;font-size:10px;")
        self.lbl_stats.setWordWrap(True)
        sl.addWidget(self.lbl_stats)
        ll.addWidget(sf)
        ml.addWidget(left)

        self.tabs = QTabWidget()
        
        # Вкладка 0: Порты
        pt = QWidget()
        ptl = QVBoxLayout(pt)
        self.ports_table = QTableWidget(0, 4)
        self.ports_table.setHorizontalHeaderLabels(["Порт", "Протокол", "Сервис", "Баннер"])
        self.ports_table.horizontalHeader().setStretchLastSection(True)
        self.ports_table.setColumnWidth(0, 70)
        self.ports_table.setColumnWidth(1, 70)
        self.ports_table.setColumnWidth(2, 120)
        self.ports_table.verticalHeader().setVisible(False)
        self.ports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        ptl.addWidget(self.ports_table)
        self.tabs.addTab(pt, "Порты")

        # Вкладка 1: Векторы атак
        at = QWidget()
        atl = QVBoxLayout(at)
        self.attacks_table = QTableWidget(0, 5)
        self.attacks_table.setHorizontalHeaderLabels(["ID", "Серьёзность", "Порт", "Название", "Описание"])
        self.attacks_table.horizontalHeader().setStretchLastSection(True)
        self.attacks_table.setColumnWidth(0, 120)
        self.attacks_table.setColumnWidth(1, 85)
        self.attacks_table.setColumnWidth(2, 60)
        self.attacks_table.setColumnWidth(3, 200)
        self.attacks_table.verticalHeader().setVisible(False)
        self.attacks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        atl.addWidget(self.attacks_table)
        self.tabs.addTab(at, "Векторы атак")

        # Вкладка 2: Ответ сервера
        rpt = QWidget()
        rtl = QVBoxLayout(rpt)
        self.response_table = QTableWidget(0, 5)
        self.response_table.setHorizontalHeaderLabels(["CVE", "Серьёзность", "Реализуемость", "Атака", "Рекомендация"])
        self.response_table.horizontalHeader().setStretchLastSection(True)
        self.response_table.setColumnWidth(0, 130)
        self.response_table.setColumnWidth(1, 85)
        self.response_table.setColumnWidth(2, 130)
        self.response_table.setColumnWidth(3, 180)
        self.response_table.verticalHeader().setVisible(False)
        self.response_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        rtl.addWidget(self.response_table)
        
        self.response_summary = QLabel("")
        self.response_summary.setStyleSheet("color:#888;font-size:11px;padding:4px;")
        rtl.addWidget(self.response_summary)
        self.tabs.addTab(rpt, "Ответ сервера")

        # Вкладка 3: История
        ht = QWidget()
        htl = QVBoxLayout(ht)
        self.history_list = QListWidget()
        self.history_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.btn_load_history = QPushButton("Загрузить выбранный отчёт")
        self.btn_load_history.clicked.connect(self._load_selected_history)
        htl.addWidget(QLabel("Сохраненные сканирования:"))
        htl.addWidget(self.history_list)
        htl.addWidget(self.btn_load_history)
        self.tabs.addTab(ht, "История")

        # Вкладка 4: Сканеры Лог
        nt = QWidget()
        ntl = QVBoxLayout(nt)
        self.scanner_output = QTextEdit()
        self.scanner_output.setReadOnly(True)
        self.scanner_output.setStyleSheet("background: #000; color: #0f0; font-family: 'Consolas'; font-size: 11px;")
        ntl.addWidget(self.scanner_output)
        self.tabs.addTab(nt, "Сканеры Лог")

        # Вкладка 5: Системный Лог
        lt = QWidget()
        ltl = QVBoxLayout(lt)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        ltl.addWidget(self.log_output)
        self.tabs.addTab(lt, "Системный Лог")
        
        ml.addWidget(self.tabs, 1)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Готов к работе")

    def _on_log_message(self, msg, level): 
        self.log_signal.emit(msg, level)
        
    def _append_log(self, msg, level):
        c = {"ERROR": "#b55", "WARNING": "#a85", "CRITICAL": "#c44"}.get(level, "#888")
        self.log_output.append(f'<span style="color:{c};">{msg}</span>')
        self.log_output.moveCursor(QTextCursor.MoveOperation.End)
        
    def _append_scanner_log(self, msg):
        self.scanner_output.append(msg)
        self.scanner_output.moveCursor(QTextCursor.MoveOperation.End)

    def _check_connection(self):
        logger.info("Проверка связи с сервером...")
        self.btn_check.setEnabled(False)
        self.btn_check.setText("Проверка...")
        self.conn_icon.setText("●  Проверка связи...")
        self.conn_icon.setStyleSheet("color:#888;")
        
        self.check_worker = CheckConnectionWorker(self.target_input.text(), self.port_spin.value())
        self.check_worker.connected_signal.connect(self._on_connected)
        self.check_worker.failed_signal.connect(self._on_connection_failed)
        self.check_worker.start()

    def _on_connected(self, hostname, ready, server_port):
        self.connected_to_server = True
        self.conn_icon.setText("●  Связь установлена")
        self.conn_icon.setStyleSheet("color:#8a8;")
        self.conn_detail.setText(f"Сервер: {hostname}\n{'Готов к приёму' if ready else 'НЕ ГОТОВ'}\nПорт: {server_port}")
        self.conn_frame.setStyleSheet("background:#1a1a1a;border:1px solid #3a5a3a;border-radius:4px;padding:8px;")
        self.btn_check.setText("1. Связь установлена")
        self.btn_check.setEnabled(True)
        logger.info(f"Связь успешно установлена: {hostname}")

    def _on_connection_failed(self, error):
        self.connected_to_server = False
        self.conn_icon.setText("●  Нет связи")
        self.conn_icon.setStyleSheet("color:#866;")
        self.conn_detail.setText(error[:300])
        self.conn_frame.setStyleSheet("background:#1a1a1a;border:1px solid #5a3a3a;border-radius:4px;padding:8px;")
        self.btn_check.setText("1. Повторить проверку")
        self.btn_check.setEnabled(True)
        logger.error(f"Сбой подключения: {error}")

    def _start_scan(self):
        if self.scan_worker and self.scan_worker.isRunning(): 
            self.scan_worker.cancel()
            self.btn_scan.setText("2. Сканировать порты")
            return
            
        self.open_ports = []
        self.attack_vectors = []
        self.ports_table.setRowCount(0)
        self.attacks_table.setRowCount(0)
        
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.btn_nuclei.setEnabled(False)
        self.btn_nmap.setEnabled(False)
        self.btn_send.setEnabled(False)
        self.btn_scan.setText("Остановить")
        
        self.scan_worker = ScanWorker(self.target_input.text(), self.ps_spin.value(), self.pe_spin.value(), 0.3, self.chk_deep.isChecked())
        self.scan_worker.port_found.connect(self._on_port_found)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished.connect(self._on_scan_done)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.start()

    def _on_port_found(self, p):
        r = self.ports_table.rowCount()
        self.ports_table.insertRow(r)
        self.ports_table.setItem(r, 0, QTableWidgetItem(str(p.port)))
        self.ports_table.setItem(r, 1, QTableWidgetItem(p.protocol))
        self.ports_table.setItem(r, 2, QTableWidgetItem(p.service))
        self.ports_table.setItem(r, 3, QTableWidgetItem(p.banner or ""))

    def _on_scan_progress(self, s, t): 
        self.progress_bar.setValue(int(s/t*100) if t else 0)
        self.progress_bar.setFormat(f"Сканирование портов: {s}/{t}")

    def _update_attacks_table(self):
        self.attacks_table.setRowCount(0)
        so = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        
        # Удаление полных дубликатов по ID
        unique_vectors = {av.id: av for av in self.attack_vectors}
        self.attack_vectors = list(unique_vectors.values())
        
        for av in sorted(self.attack_vectors, key=lambda v: so.get(v.severity, 5)):
            r = self.attacks_table.rowCount()
            self.attacks_table.insertRow(r)
            self.attacks_table.setItem(r, 0, QTableWidgetItem(str(av.id)))
            
            si = QTableWidgetItem(str(av.severity))
            si.setForeground(QColor({"CRITICAL":"#c44","HIGH":"#a85","MEDIUM":"#997","LOW":"#696","INFO":"#668"}.get(av.severity,"#888")))
            self.attacks_table.setItem(r, 1, si)
            
            self.attacks_table.setItem(r, 2, QTableWidgetItem(str(av.target_port or "-")))
            
            ni = QTableWidgetItem(str(av.name))
            if "[NUCLEI]" in str(av.name): 
                ni.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
                ni.setForeground(QColor("#8a8"))
            if "[NMAP]" in str(av.name): 
                ni.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
                ni.setForeground(QColor("#58a6ff"))
            self.attacks_table.setItem(r, 3, ni)
            
            self.attacks_table.setItem(r, 4, QTableWidgetItem(str(av.description)))
            
        cr = sum(1 for v in self.attack_vectors if v.severity=="CRITICAL")
        hi = sum(1 for v in self.attack_vectors if v.severity=="HIGH")
        self.lbl_stats.setText(f"Порты: {len(self.open_ports)}\nВсего векторов: {len(self.attack_vectors)}\nCRITICAL: {cr} | HIGH: {hi}")

    def _on_scan_done(self, ports):
        self.open_ports = ports
        self.progress_bar.setVisible(False)
        self.btn_scan.setText("2. Сканировать порты")
        
        self.attack_vectors = AttackVectorGenerator().generate(ports)
        self._update_attacks_table()
        
        if ports: 
            self.btn_nuclei.setEnabled(True)
            self.btn_nmap.setEnabled(True)
            self.btn_send.setEnabled(True)
            
        self._save_history_file("PortScan")
        self.tabs.setCurrentIndex(1)

    def _start_nuclei(self):
        logger.info("Пользователь инициировал запуск Nuclei")
        self._lock_scanners()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.scanner_output.clear()
        self.tabs.setCurrentIndex(4)
        
        self.nuclei_worker = NucleiWorker(self.target_input.text(), self.open_ports)
        self.nuclei_worker.progress.connect(self._on_scanner_progress)
        self.nuclei_worker.log_msg.connect(self._append_scanner_log)
        self.nuclei_worker.finished.connect(lambda v: self._on_scanner_done(v, "NucleiScan"))
        self.nuclei_worker.error.connect(self._on_scanner_error)
        self.nuclei_worker.start()

    def _start_nmap(self):
        logger.info("Пользователь инициировал запуск Nmap")
        self._lock_scanners()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.scanner_output.clear()
        self.tabs.setCurrentIndex(4)
        
        self.nmap_worker = NmapWorker(self.target_input.text(), self.open_ports)
        self.nmap_worker.progress.connect(self._on_scanner_progress)
        self.nmap_worker.log_msg.connect(self._append_scanner_log)
        self.nmap_worker.finished.connect(lambda v: self._on_scanner_done(v, "NmapScan"))
        self.nmap_worker.error.connect(self._on_scanner_error)
        self.nmap_worker.start()

    def _lock_scanners(self):
        self.btn_nuclei.setEnabled(False)
        self.btn_nmap.setEnabled(False)
        self.btn_scan.setEnabled(False)
        self.btn_send.setEnabled(False)

    def _on_scanner_progress(self, msg, val):
        self.progress_bar.setFormat(msg)
        if val >= 0:
            self.progress_bar.setValue(val)

    def _on_scanner_error(self, e):
        QMessageBox.warning(self, "Ошибка сканера", e)

    def _on_scanner_done(self, new_vectors, scan_type):
        self.progress_bar.setVisible(False)
        self.btn_nuclei.setEnabled(True)
        self.btn_nmap.setEnabled(True)
        self.btn_scan.setEnabled(True)
        self.btn_send.setEnabled(True)
        
        if new_vectors:
            self.attack_vectors.extend(new_vectors)
            self._update_attacks_table()
            self.tabs.setCurrentIndex(1)
            logger.info(f"Добавлено новых векторов: {len(new_vectors)}")
            
        self._save_history_file(scan_type)

    def _save_history_file(self, scan_type):
        if not self.open_ports and not self.attack_vectors: return
        t = self.target_input.text()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(HISTORY_DIR, f"{t}_{scan_type}_{ts}.json")
        
        sr = ScanResult(
            scanner_ip="127.0.0.1", 
            target_ip=t, 
            open_ports=self.open_ports, 
            discovered_services=[f"{x.service} (:{x.port})" for x in self.open_ports], 
            attack_vectors=self.attack_vectors, 
            os_detection="Windows", 
            scan_timestamp=datetime.now().isoformat()
        )
        try:
            with open(filepath, "w", encoding="utf-8") as f: 
                json.dump(asdict(sr), f, ensure_ascii=False, indent=2)
            self._load_history_list()
        except Exception as e: 
            logger.error(f"Ошибка сохранения истории: {e}")

    def _load_history_list(self):
        self.history_list.clear()
        try:
            for f in sorted(os.listdir(HISTORY_DIR), reverse=True):
                if f.endswith(".json"): 
                    self.history_list.addItem(f)
        except Exception: 
            pass

    def _load_selected_history(self):
        items = self.history_list.selectedItems()
        if not items: return
        try:
            with open(os.path.join(HISTORY_DIR, items[0].text()), "r", encoding="utf-8") as f: 
                data = json.load(f)
                
            self.target_input.setText(data.get("target_ip", TARGET_SERVER_HOST))
            self.open_ports = []
            self.ports_table.setRowCount(0)
            
            for p_dict in data.get("open_ports", []):
                p = OpenPort(**p_dict)
                self.open_ports.append(p)
                r = self.ports_table.rowCount()
                self.ports_table.insertRow(r)
                self.ports_table.setItem(r, 0, QTableWidgetItem(str(p.port)))
                self.ports_table.setItem(r, 1, QTableWidgetItem(p.protocol))
                self.ports_table.setItem(r, 2, QTableWidgetItem(p.service))
                self.ports_table.setItem(r, 3, QTableWidgetItem(p.banner or ""))
                
            self.attack_vectors = [AttackVector(**av_dict) for av_dict in data.get("attack_vectors", [])]
            self._update_attacks_table()
            
            self.btn_nuclei.setEnabled(True)
            self.btn_nmap.setEnabled(True)
            self.btn_send.setEnabled(True)
            self.tabs.setCurrentIndex(1)
            logger.info(f"Успешно загружена история: {items[0].text()}")
        except Exception as e: 
            QMessageBox.critical(self, "Ошибка", str(e))
            logger.error(f"Ошибка загрузки истории: {e}")

    def _on_scan_error(self, e): 
        self.progress_bar.setVisible(False)
        self.btn_scan.setText("2. Сканировать порты")
        QMessageBox.critical(self, "Ошибка", e)

    def _send_results(self):
        if not self.open_ports and not self.attack_vectors: return
        t = self.target_input.text()
        p = self.port_spin.value()
        
        sr = ScanResult(
            scanner_ip="127.0.0.1",
            target_ip=t,
            open_ports=self.open_ports,
            discovered_services=[],
            attack_vectors=self.attack_vectors, 
            os_detection="Windows", 
            scan_timestamp=datetime.now().isoformat()
        )
        
        self.btn_send.setEnabled(False)
        self.btn_send.setText("Отправка...")
        
        self.send_worker = SendWorker(f"http://{t}:{p}/analyze", asdict(sr))
        self.send_worker.finished.connect(self._on_send_done)
        self.send_worker.error.connect(self._on_send_error)
        self.send_worker.start()

    def _on_send_done(self, result):
        self.btn_send.setText("5. Отправить на сервер для анализа")
        self.btn_send.setEnabled(True)
        
        if result.get("status") == "success":
            sm = result.get("summary", {})
            details = result.get("details", [])
            self.response_table.setRowCount(0)
            
            for it in details:
                r = self.response_table.rowCount()
                self.response_table.insertRow(r)
                
                self.response_table.setItem(r, 0, QTableWidgetItem(str(it.get("cve_id", ""))))
                
                sev = str(it.get("severity", ""))
                si = QTableWidgetItem(sev)
                si.setForeground(QColor({"CRITICAL":"#c44","HIGH":"#a85","MEDIUM":"#997","LOW":"#696"}.get(sev,"#888")))
                self.response_table.setItem(r, 1, si)
                
                fi = QTableWidgetItem(str(it.get("feasibility", "")))
                fi.setForeground(QColor("#b55" if fi.text()=="РЕАЛИЗУЕМА" else "#696" if fi.text()=="НЕ РЕАЛИЗУЕМА" else "#d29922"))
                self.response_table.setItem(r, 2, fi)
                
                self.response_table.setItem(r, 3, QTableWidgetItem(str(it.get("attack_name", ""))))
                self.response_table.setItem(r, 4, QTableWidgetItem(str(it.get("recommendation", ""))[:150]))
                
            self.tabs.setCurrentIndex(2)
        else: 
            QMessageBox.warning(self, "Ответ", f"Ошибка: {result.get('error','?')}")

    def _on_send_error(self, error):
        self.btn_send.setText("5. Отправить на сервер для анализа")
        self.btn_send.setEnabled(True)
        if "503" in error: 
            QMessageBox.warning(self, "Сервер не готов", error)
        else: 
            QMessageBox.critical(self, "Ошибка отправки", error)

    def _export_log(self):
        t = self.log_output.toPlainText()
        if not t: return
        p, _ = QFileDialog.getSaveFileName(self, "Сохранить", f"attacker_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "Text (*.txt)")
        if p: 
            with open(p, "w", encoding="utf-8") as f:
                f.write(t)

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = AttackerGUI()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__": 
    main()