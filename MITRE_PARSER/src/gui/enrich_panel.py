"""Enrichment panel: LLM-powered generation of new tools/defense records."""
from __future__ import annotations

import json
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QSpinBox, QPushButton, QProgressBar, QTextEdit, QComboBox,
    QMessageBox,
)

from config import Config
from enrichment.llm_enricher import LlmEnricher
from translation.providers.base import BaseProvider
from db_writer import write_database


class _EnrichWorker(QThread):
    """Background worker for LLM enrichment."""

    progress = pyqtSignal(int, int, str)  # current, total, type
    log_message = pyqtSignal(str)
    finished_ok = pyqtSignal(int, int)  # tools_added, defense_added
    finished_error = pyqtSignal(str)

    def __init__(
        self,
        provider: BaseProvider,
        tools_count: int,
        defense_count: int,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.provider = provider
        self.tools_count = tools_count
        self.defense_count = defense_count

    def run(self):
        try:
            enricher = LlmEnricher(
                provider=self.provider,
                progress_callback=self._on_progress,
            )

            tools_added = 0
            defense_added = 0
            db_dir = Config.PROJECT_DATABASES_DIR

            # Generate tools
            if self.tools_count > 0:
                self.log_message.emit(
                    f"  [Enrich] Генерируем {self.tools_count} новых инструментов..."
                )
                existing_tools = self._load_db(db_dir / Config.DB_FILES["tools"])
                new_tools = enricher.generate_tools(self.tools_count, existing_tools)
                if new_tools:
                    write_database(
                        db_dir / Config.DB_FILES["tools"],
                        new_tools,
                        name="Tools (LLM)",
                        append=True,
                    )
                    tools_added = len(new_tools)
                    self.log_message.emit(
                        f"  [Enrich] Добавлено инструментов: {tools_added}"
                    )
                else:
                    self.log_message.emit("  [Enrich] Не удалось сгенерировать инструменты")

            # Generate defense
            if self.defense_count > 0:
                self.log_message.emit(
                    f"  [Enrich] Генерируем {self.defense_count} новых мер защиты..."
                )
                existing_defense = self._load_db(db_dir / Config.DB_FILES["defense"])
                new_defense = enricher.generate_defense(self.defense_count, existing_defense)
                if new_defense:
                    write_database(
                        db_dir / Config.DB_FILES["defense"],
                        new_defense,
                        name="Defense (LLM)",
                        append=True,
                    )
                    defense_added = len(new_defense)
                    self.log_message.emit(
                        f"  [Enrich] Добавлено мер защиты: {defense_added}"
                    )
                else:
                    self.log_message.emit("  [Enrich] Не удалось сгенерировать меры защиты")

            self.finished_ok.emit(tools_added, defense_added)

        except Exception as e:
            self.finished_error.emit(str(e))

    def _on_progress(self, current: int, total: int, label: str):
        self.progress.emit(current, total, label)

    @staticmethod
    def _load_db(path: Path) -> list[dict]:
        if not path.exists():
            return []
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []


class EnrichPanel(QWidget):
    """Panel for LLM-powered database enrichment."""

    def __init__(self, get_providers_fn, parent=None):
        super().__init__(parent)
        self._get_providers = get_providers_fn
        self._worker: _EnrichWorker | None = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Description
        desc = QLabel(
            "Использует LLM для генерации новых уникальных записей инструментов атаки\n"
            "и мер защиты. Модель генерирует записи на основе своих знаний о кибербезопасности.\n"
            "Записи автоматически дозаписываются в базы без дублирования."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("margin-bottom: 10px;")
        layout.addWidget(desc)

        # Settings
        settings_group = QGroupBox("Сколько записей сгенерировать")
        settings_layout = QHBoxLayout()

        settings_layout.addWidget(QLabel("Инструменты (tools):"))
        self.spin_tools = QSpinBox()
        self.spin_tools.setRange(0, 100)
        self.spin_tools.setValue(10)
        settings_layout.addWidget(self.spin_tools)

        settings_layout.addWidget(QLabel("Меры защиты (defense):"))
        self.spin_defense = QSpinBox()
        self.spin_defense.setRange(0, 100)
        self.spin_defense.setValue(10)
        settings_layout.addWidget(self.spin_defense)

        settings_layout.addStretch()
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # Provider selection for enrichment
        provider_group = QGroupBox("Провайдер для генерации")
        provider_layout = QHBoxLayout()
        provider_layout.addWidget(QLabel("Использовать:"))
        self.combo_provider = QComboBox()
        self.combo_provider.setMinimumWidth(250)
        provider_layout.addWidget(self.combo_provider, 1)
        self.btn_refresh_providers = QPushButton("Обновить список")
        self.btn_refresh_providers.clicked.connect(self._refresh_providers)
        provider_layout.addWidget(self.btn_refresh_providers)
        provider_group.setLayout(provider_layout)
        layout.addWidget(provider_group)

        # Action button
        self.btn_generate = QPushButton("Сгенерировать новые записи")
        self.btn_generate.setStyleSheet(
            "QPushButton { background-color: #FF9800; color: white; "
            "font-size: 14px; padding: 10px 20px; border-radius: 5px; }"
            "QPushButton:hover { background-color: #F57C00; }"
            "QPushButton:disabled { background-color: #888; }"
        )
        self.btn_generate.clicked.connect(self._start_generation)
        layout.addWidget(self.btn_generate)

        # Progress
        progress_group = QGroupBox("Прогресс")
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet("font-weight: bold;")
        progress_layout.addWidget(self.lbl_status)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        # Results counter
        results_group = QGroupBox("Результат")
        results_layout = QHBoxLayout()

        self.lbl_tools_added = QLabel("Инструментов добавлено: 0")
        self.lbl_tools_added.setStyleSheet("font-size: 14px; color: #4CAF50;")
        results_layout.addWidget(self.lbl_tools_added)

        self.lbl_defense_added = QLabel("Мер защиты добавлено: 0")
        self.lbl_defense_added.setStyleSheet("font-size: 14px; color: #2196F3;")
        results_layout.addWidget(self.lbl_defense_added)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        # Log
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        self.log_text.setStyleSheet(
            "font-family: Consolas, monospace; font-size: 11px;"
        )
        layout.addWidget(self.log_text)

        layout.addStretch()
        self._refresh_providers()

    def _refresh_providers(self) -> None:
        """Populate provider combo from settings panel."""
        self.combo_provider.clear()
        providers = self._get_providers()
        for i, p in enumerate(providers):
            self.combo_provider.addItem(p.name, i)
        if not providers:
            self.combo_provider.addItem("(нет доступных провайдеров)", -1)

    def _start_generation(self) -> None:
        """Start LLM enrichment."""
        providers = self._get_providers()
        idx = self.combo_provider.currentData()
        if idx is None or idx < 0 or idx >= len(providers):
            QMessageBox.warning(
                self, "Ошибка",
                "Выберите провайдер для генерации.\n"
                "Добавьте провайдер на вкладке «Настройки и запуск»."
            )
            return

        tools_count = self.spin_tools.value()
        defense_count = self.spin_defense.value()
        if tools_count == 0 and defense_count == 0:
            QMessageBox.information(self, "Инфо", "Укажите количество записей > 0")
            return

        provider = providers[idx]
        self.btn_generate.setEnabled(False)
        self.progress_bar.setValue(0)
        self.lbl_status.setText("Генерация...")
        self.log_text.clear()

        self._worker = _EnrichWorker(
            provider=provider,
            tools_count=tools_count,
            defense_count=defense_count,
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.log_message.connect(self._on_log)
        self._worker.finished_ok.connect(self._on_finished_ok)
        self._worker.finished_error.connect(self._on_finished_error)
        self._worker.start()

    def _on_progress(self, current: int, total: int, label: str) -> None:
        if total > 0:
            pct = int(current / total * 100)
            self.progress_bar.setValue(pct)
            self.lbl_status.setText(f"Генерация {label}: {current}/{total}")

    def _on_log(self, msg: str) -> None:
        self.log_text.append(msg)

    def _on_finished_ok(self, tools_added: int, defense_added: int) -> None:
        self.btn_generate.setEnabled(True)
        self.progress_bar.setValue(100)
        self.lbl_status.setText("Готово!")
        self.lbl_tools_added.setText(f"Инструментов добавлено: {tools_added}")
        self.lbl_defense_added.setText(f"Мер защиты добавлено: {defense_added}")
        total = tools_added + defense_added
        QMessageBox.information(
            self, "Генерация завершена",
            f"Добавлено {total} новых записей:\n"
            f"  - Инструментов: {tools_added}\n"
            f"  - Мер защиты: {defense_added}",
        )

    def _on_finished_error(self, error: str) -> None:
        self.btn_generate.setEnabled(True)
        self.lbl_status.setText(f"Ошибка: {error[:80]}")
        QMessageBox.warning(self, "Ошибка генерации", error)
