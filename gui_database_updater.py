import sys
import json
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QComboBox, 
                             QSpinBox, QPushButton, QTextEdit, QMessageBox, 
                             QGroupBox, QFormLayout, QTabWidget)
from PyQt6.QtCore import QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QFont
from openai import OpenAI

# Пути к базам данных
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "databases")
CAPEC_FILE = os.path.join(DB_DIR, "capec_database.json")
TOOLS_FILE = os.path.join(DB_DIR, "tools_database.json")
DEFENSE_FILE = os.path.join(DB_DIR, "defense_database.json")

# ==========================================
# Поток для работы с нейросетью
# ==========================================
class LLMWorker(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)
    finished_signal = pyqtSignal(bool)
    data_generated_signal = pyqtSignal(str, str)
    key_failed_signal = pyqtSignal(int, str) # Сигнал, что ключ сломался (индекс, причина)

    def __init__(self, api_keys, base_url, model, limit):
        super().__init__()
        self.api_keys = api_keys # Список рабочих ключей (очищенных от пометок)
        self.base_url = base_url
        self.model = model
        self.limit = limit
        self.is_running = True
        self.current_key_idx = 0

    def _load_json_safe(self, filepath):
        if not os.path.exists(filepath):
            return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            filename = os.path.basename(filepath)
            raise ValueError(f"Файл {filename} сломан! Ошибка формата JSON: {e}. Проверьте конец файла.")

    def run(self):
        self.log_signal.emit("🚀 Запуск процесса обогащения баз данных...")
        
        # 1. Безопасная загрузка баз
        try:
            capec_db = self._load_json_safe(CAPEC_FILE)
            tools_db = self._load_json_safe(TOOLS_FILE)
            defense_db = self._load_json_safe(DEFENSE_FILE)
        except ValueError as e:
            self.log_signal.emit(f"❌ {e}")
            self.finished_signal.emit(False)
            return
        except Exception as e:
            self.log_signal.emit(f"❌ Системная ошибка чтения: {e}")
            self.finished_signal.emit(False)
            return

        # Если старые базы были в виде списка (массива), превращаем их в словарь для работы скрипта
        if isinstance(tools_db, list):
            tools_db = {}
        if isinstance(defense_db, list):
            defense_db = {}

        # 2. Умный поиск CAPEC, которых еще нет (поддержка и словарей, и списков)
        all_capecs = []
        if isinstance(capec_db, dict):
            for c_id, c_data in capec_db.items():
                name = c_data.get("name", "Неизвестная атака") if isinstance(c_data, dict) else str(c_data)
                all_capecs.append((c_id, name))
        elif isinstance(capec_db, list):
            for c_data in capec_db:
                c_id = c_data.get("id") or c_data.get("ID")
                name = c_data.get("name", "Неизвестная атака")
                if c_id:
                    all_capecs.append((c_id, name))

        missing_capecs = []
        for c_id, name in all_capecs:
            if c_id not in tools_db or c_id not in defense_db:
                missing_capecs.append((c_id, name))

        if not missing_capecs:
            self.log_signal.emit("✅ Все векторы CAPEC уже есть в базах защиты и атаки.")
            self.finished_signal.emit(True)
            return

        self.log_signal.emit(f"🔍 Найдено {len(missing_capecs)} векторов без инструментов. Будет обработано: {min(self.limit, len(missing_capecs))}.")

        processed_count = 0

        # 3. Запрос к LLM с поддержкой ротации ключей
        for capec_id, name in missing_capecs:
            if not self.is_running or processed_count >= self.limit:
                break

            self.log_signal.emit(f"⏳ Генерируем данные для {capec_id} ({name})...")
            
            prompt = f"""
Ты эксперт по кибербезопасности. Расставь практические шаги для вектора: {capec_id} - {name}
Сгенерируй конкретные инструменты и bash/терминальные команды для эксплуатации (Red Team) и защиты (Blue Team).
Верни ответ СТРОГО в формате JSON без markdown:
{{
  "attack_tools": [
    {{
      "name": "Название (Nmap, SQLMap)",
      "skill": "Low/Medium/High",
      "url": "https://ссылка",
      "desc": "Что мы делаем",
      "commands": ["команда 1"],
      "cmd_explanations": {{"команда 1": "пояснение"}}
    }}
  ],
  "defense_tools": [
    {{
      "name": "Название (iptables, nginx)",
      "priority": "High/Medium/Low",
      "desc": "Как защищает",
      "commands": ["команда защиты"]
    }}
  ]
}}
"""
            success = False
            
            while not success and self.current_key_idx < len(self.api_keys) and self.is_running:
                current_key = self.api_keys[self.current_key_idx]
                client = OpenAI(api_key=current_key if current_key else "dummy", base_url=self.base_url)
                
                try:
                    response = client.chat.completions.create(
                        model=self.model,
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.2,
                        response_format={ "type": "json_object" }
                    )
                    
                    result_json = json.loads(response.choices[0].message.content)
                    tools_db[capec_id] = result_json.get("attack_tools", [])
                    defense_db[capec_id] = result_json.get("defense_tools", [])
                    
                    self.log_signal.emit(f"   ✅ Успешно: {capec_id}")
                    
                    formatted_json = json.dumps(result_json, indent=4, ensure_ascii=False)
                    self.data_generated_signal.emit(f"{capec_id} - {name}", formatted_json)
                    
                    processed_count += 1
                    self.progress_signal.emit(processed_count, self.limit)
                    success = True

                except Exception as e:
                    error_str = str(e).lower()
                    if "429" in error_str or "rate limit" in error_str or "quota" in error_str or "401" in error_str or "unauthorized" in error_str:
                        reason = "Лимит исчерпан" if "429" in error_str else "Неверный ключ"
                        self.log_signal.emit(f"   ⚠️ Ключ #{self.current_key_idx + 1} заблокирован ({reason}).")
                        
                        # Сообщаем GUI, что ключ сломался, чтобы он пометил его текстом
                        self.key_failed_signal.emit(self.current_key_idx, reason)
                        
                        self.current_key_idx += 1
                        if self.current_key_idx < len(self.api_keys):
                            self.log_signal.emit(f"   🔄 Переключаюсь на ключ #{self.current_key_idx + 1}...")
                        else:
                            self.log_signal.emit("   🚨 Все доступные API ключи исчерпаны!")
                    else:
                        self.log_signal.emit(f"   ❌ Сбой при генерации {capec_id}: {e}")
                        break

            if not success and self.current_key_idx >= len(self.api_keys):
                self.log_signal.emit("🛑 Процесс остановлен: рабочие ключи закончились.")
                break

        # 4. Сохраняем обновленные базы
        if processed_count > 0:
            self.log_signal.emit("💾 Сохранение баз данных...")
            try:
                with open(TOOLS_FILE, "w", encoding="utf-8") as f:
                    json.dump(tools_db, f, indent=4, ensure_ascii=False)
                with open(DEFENSE_FILE, "w", encoding="utf-8") as f:
                    json.dump(defense_db, f, indent=4, ensure_ascii=False)
                self.log_signal.emit(f"🎉 Готово! Добавлено новых записей: {processed_count}")
            except Exception as e:
                self.log_signal.emit(f"❌ Ошибка при сохранении: {e}")
        else:
            self.log_signal.emit("ℹ️ Новых записей не добавлено.")
            
        self.finished_signal.emit(True)

    def stop(self):
        self.is_running = False

# ==========================================
# Главное окно графического интерфейса
# ==========================================
class DatabaseUpdaterGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Обогащение Баз Данных (Мульти-Ключ)")
        self.resize(800, 700)
        self.setStyleSheet("background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI';")
        self.settings = QSettings("BOS_CyberPolygon", "DatabaseUpdater")
        self.worker = None
        self.key_mapping = [] # Хранит связь между очищенным ключом и его строкой в UI
        self._init_ui()
        self._load_settings()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        title = QLabel("🤖 Генератор команд атак и защиты")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        main_layout.addWidget(title)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #333; border-radius: 5px; }
            QTabBar::tab { background: #1e1e1e; border: 1px solid #333; padding: 8px 15px; margin-right: 2px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
            QTabBar::tab:selected { background: #2a4b6e; color: #fff; font-weight: bold; }
        """)
        main_layout.addWidget(self.tabs)

        # --- ВКЛАДКА 1: НАСТРОЙКИ И ЛОГИ ---
        self.tab_settings = QWidget()
        tab1_layout = QVBoxLayout(self.tab_settings)

        conn_group = QGroupBox("Настройки LLM Провайдера")
        conn_group.setStyleSheet("QGroupBox { border: 1px solid #333; border-radius: 5px; margin-top: 1ex; padding: 10px; } QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #58a6ff; }")
        conn_layout = QFormLayout(conn_group)

        self.provider_combo = QComboBox()
        self.provider_combo.addItems([
            "Groq (Сверхбыстрый Llama 3 - Бесплатно)", 
            "OpenRouter (Агрегатор - Бесплатные модели)", 
            "Mistral API (Free Tier)", 
            "9router (Прокси API)", 
            "Локальная сеть (Ollama - Полностью бесплатно)"
        ])
        self.provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        self.provider_combo.setStyleSheet("background: #1e1e1e; border: 1px solid #444; padding: 5px;")
        
        self.url_input = QLineEdit()
        self.url_input.setStyleSheet("background: #1e1e1e; border: 1px solid #444; padding: 5px;")
        
        self.keys_input = QTextEdit()
        self.keys_input.setPlaceholderText("Вставьте API ключи здесь (КАЖДЫЙ КЛЮЧ С НОВОЙ СТРОКИ).\nЕсли ключ сломается, он будет помечен текстом (не работает).")
        self.keys_input.setMaximumHeight(90)
        self.keys_input.setStyleSheet("background: #1e1e1e; border: 1px solid #444; padding: 5px;")
        self.keys_input.textChanged.connect(self._save_settings)
        
        self.model_combo = QComboBox()
        self.model_combo.setEditable(True) 
        self.model_combo.setStyleSheet("background: #1e1e1e; border: 1px solid #444; padding: 5px;")

        conn_layout.addRow("Провайдер:", self.provider_combo)
        conn_layout.addRow("Base URL:", self.url_input)
        conn_layout.addRow("Имя Модели:", self.model_combo)
        conn_layout.addRow("API Ключи:\n(с новой строки)", self.keys_input)
        
        self.btn_check = QPushButton("🔌 Проверить связь (по первому рабочему ключу)")
        self.btn_check.setStyleSheet("background: #2a4b6e; font-weight: bold; padding: 8px; border-radius: 4px;")
        self.btn_check.clicked.connect(self._test_connection)
        conn_layout.addRow("", self.btn_check)

        tab1_layout.addWidget(conn_group)

        gen_group = QGroupBox("Параметры обновления")
        gen_group.setStyleSheet("QGroupBox { border: 1px solid #333; border-radius: 5px; margin-top: 1ex; padding: 10px; } QGroupBox::title { color: #58a6ff; }")
        gen_layout = QHBoxLayout(gen_group)
        
        gen_layout.addWidget(QLabel("Сколько новых векторов сгенерировать:"))
        self.limit_spin = QSpinBox()
        self.limit_spin.setRange(1, 500)
        self.limit_spin.setValue(5)
        self.limit_spin.setStyleSheet("background: #1e1e1e; border: 1px solid #444; padding: 5px;")
        self.limit_spin.valueChanged.connect(self._save_settings)
        gen_layout.addWidget(self.limit_spin)
        
        self.btn_start = QPushButton("▶ Запустить генерацию баз")
        self.btn_start.setStyleSheet("background: #238636; font-weight: bold; padding: 10px; border-radius: 4px; color: white;")
        self.btn_start.clicked.connect(self._start_generation)
        gen_layout.addWidget(self.btn_start)
        
        tab1_layout.addWidget(gen_group)

        tab1_layout.addWidget(QLabel("Журнал событий:"))
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet("background: #0d1117; color: #c9d1d9; font-family: 'Consolas'; border: 1px solid #30363d;")
        tab1_layout.addWidget(self.log_box)

        self.tabs.addTab(self.tab_settings, "⚙️ Управление и Логи")

        # --- ВКЛАДКА 2: СГЕНЕРИРОВАННЫЕ ДАННЫЕ ---
        self.tab_data = QWidget()
        tab2_layout = QVBoxLayout(self.tab_data)
        
        info_label = QLabel("Здесь отображаются данные в реальном времени.\nОни автоматически сохраняются в tools_database.json и defense_database.json.")
        info_label.setStyleSheet("color: #8b949e; padding-bottom: 5px;")
        tab2_layout.addWidget(info_label)

        self.generated_data_box = QTextEdit()
        self.generated_data_box.setReadOnly(True)
        self.generated_data_box.setStyleSheet("background: #050f05; color: #58a6ff; font-family: 'Consolas'; border: 1px solid #30363d;")
        tab2_layout.addWidget(self.generated_data_box)

        self.tabs.addTab(self.tab_data, "📄 Сгенерированные данные")

    def _load_settings(self):
        """Загружает сохраненные ключи и настройки при старте"""
        saved_provider = self.settings.value("provider_idx", 0, type=int)
        saved_keys = self.settings.value("api_keys", "")
        saved_limit = self.settings.value("limit", 5, type=int)
        
        self.provider_combo.setCurrentIndex(saved_provider)
        if saved_keys:
            self.keys_input.setPlainText(saved_keys)
        self.limit_spin.setValue(saved_limit)

    def _save_settings(self):
        """Сохраняет настройки в систему"""
        self.settings.setValue("provider_idx", self.provider_combo.currentIndex())
        self.settings.setValue("api_keys", self.keys_input.toPlainText())
        self.settings.setValue("limit", self.limit_spin.value())

    def _on_provider_changed(self, index):
        self.model_combo.clear()
        if index == 0: # Groq
            self.url_input.setText("https://api.groq.com/openai/v1")
            self.model_combo.addItems(["llama3-70b-8192", "llama3-8b-8192", "mixtral-8x7b-32768", "gemma2-9b-it"])
        elif index == 1: # OpenRouter
            self.url_input.setText("https://openrouter.ai/api/v1")
            self.model_combo.addItems(["meta-llama/llama-3-8b-instruct:free", "google/gemma-2-9b-it:free", "mistralai/mistral-7b-instruct:free"])
        elif index == 2: # Mistral
            self.url_input.setText("https://api.mistral.ai/v1")
            self.model_combo.addItems(["open-mixtral-8x22b", "open-mixtral-8x7b", "open-mistral-7b"])
        elif index == 3: # 9router
            self.url_input.setText("https://api.9router.com/v1")
            self.model_combo.addItems(["gpt-4o-mini", "llama-3-70b", "mistral-large"])
        elif index == 4: # Ollama
            self.url_input.setText("http://localhost:11434/v1")
            self.model_combo.addItems(["llama3", "mistral", "qwen2"])
        
        self._save_settings()

    def _get_clean_api_keys(self):
        """Парсит текстовое поле, убирает сломанные ключи и возвращает список чистых"""
        lines = self.keys_input.toPlainText().split('\n')
        clean_keys = []
        self.key_mapping = [] # Сбрасываем маппинг
        
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            # Отделяем чистый ключ от пометки "(не работает...)"
            clean_key = line.split(' (не работает')[0].strip()
            clean_keys.append(clean_key)
            self.key_mapping.append(idx) # Запоминаем, на какой строке в UI находится этот ключ
            
        return clean_keys

    def _mark_key_as_failed(self, worker_idx, reason):
        """Добавляет к ключу пометку, что он сломан"""
        ui_idx = self.key_mapping[worker_idx]
        lines = self.keys_input.toPlainText().split('\n')
        
        clean_key = lines[ui_idx].split(' (не работает')[0].strip()
        lines[ui_idx] = f"{clean_key} (не работает: {reason})"
        
        # Обновляем UI и сохраняем
        self.keys_input.blockSignals(True) # чтобы не вызывать сохранение дважды
        self.keys_input.setPlainText('\n'.join(lines))
        self.keys_input.blockSignals(False)
        self._save_settings()

    def log(self, message):
        self.log_box.append(message)
        scrollbar = self.log_box.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def append_generated_data(self, title, json_data):
        separator = "=" * 60
        self.generated_data_box.append(f"<span style='color: #da3633;'><b>{separator}</b></span>")
        self.generated_data_box.append(f"<span style='color: #ffffff;'><b>🎯 Результат для: {title}</b></span>")
        self.generated_data_box.append(f"<span style='color: #da3633;'><b>{separator}</b></span><br>")
        self.generated_data_box.append(json_data)
        self.generated_data_box.append("<br>")
        scrollbar = self.generated_data_box.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _test_connection(self):
        api_keys = self._get_clean_api_keys()
        base_url = self.url_input.text().strip()
        model = self.model_combo.currentText().strip()

        if not base_url or not model:
            QMessageBox.warning(self, "Ошибка", "Укажите URL и название модели!")
            return

        test_key = api_keys[0] if api_keys else "dummy_key"

        self.log(f"🔌 Проверка связи (используем 1-й ключ)... Отправляем тестовый запрос.")
        self.btn_check.setEnabled(False)
        QApplication.processEvents()

        try:
            client = OpenAI(api_key=test_key, base_url=base_url)
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Скажи только одно слово: Привет"}],
                max_tokens=10
            )
            answer = response.choices[0].message.content.strip()
            self.log(f"✅ Успех! Ответ модели: {answer}")
            QMessageBox.information(self, "Успех", f"Связь установлена!\nОтвет модели: {answer}")
        except Exception as e:
            self.log(f"❌ Ошибка подключения: {e}")
            self._mark_key_as_failed(0, "Ошибка связи")
            QMessageBox.critical(self, "Ошибка", f"Не удалось подключиться к API:\n{e}")
        finally:
            self.btn_check.setEnabled(True)

    def _start_generation(self):
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.btn_start.setText("▶ Запустить генерацию баз")
            self.btn_start.setStyleSheet("background: #238636; font-weight: bold; padding: 10px; border-radius: 4px; color: white;")
            return

        api_keys = self._get_clean_api_keys()
        if not api_keys and "localhost" not in self.url_input.text():
            reply = QMessageBox.question(self, "Предупреждение", "Вы не ввели ни одного API ключа. Продолжить?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.No:
                return
                
        base_url = self.url_input.text().strip()
        model = self.model_combo.currentText().strip() 
        limit = self.limit_spin.value()

        self.log_box.clear()
        self.generated_data_box.clear() 
        self.btn_start.setText("⏹ Остановить генерацию")
        self.btn_start.setStyleSheet("background: #da3633; font-weight: bold; padding: 10px; border-radius: 4px; color: white;")
        self.btn_check.setEnabled(False)

        self.worker = LLMWorker(api_keys if api_keys else ["dummy_key"], base_url, model, limit)
        self.worker.log_signal.connect(self.log)
        self.worker.data_generated_signal.connect(self.append_generated_data)
        self.worker.key_failed_signal.connect(self._mark_key_as_failed) # Связываем сигнал сломанного ключа с функцией
        self.worker.finished_signal.connect(self._on_generation_finished)
        self.worker.start()

    def _on_generation_finished(self, success):
        self.btn_start.setText("▶ Запустить генерацию баз")
        self.btn_start.setStyleSheet("background: #238636; font-weight: bold; padding: 10px; border-radius: 4px; color: white;")
        self.btn_check.setEnabled(True)
        if success:
            QMessageBox.information(self, "Завершено", "Процесс обогащения баз завершён или остановлен!\nПерейдите на вкладку 'Сгенерированные данные', чтобы посмотреть результаты.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DatabaseUpdaterGUI()
    window.show()
    sys.exit(app.exec())