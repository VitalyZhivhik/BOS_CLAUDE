"""Main application window with tabs."""
from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QMessageBox, QStatusBar,
)

from gui.settings_panel import SettingsPanel
from gui.progress_panel import ProgressPanel
from gui.file_viewer import FileViewer
from gui.history_panel import HistoryPanel
from gui.enrich_panel import EnrichPanel
from gui.worker import PipelineWorker


class MainWindow(QMainWindow):
    """Main GUI window for MITRE Parser."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("MITRE Parser 2.0")
        self.setMinimumSize(900, 700)
        self._worker: PipelineWorker | None = None
        self._init_ui()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # Tab widget
        self.tabs = QTabWidget()

        # Tab 1: Settings + Launch
        self.settings_tab = QWidget()
        settings_layout = QVBoxLayout(self.settings_tab)
        self.settings_panel = SettingsPanel()
        settings_layout.addWidget(self.settings_panel)

        # Start/Stop buttons
        btn_layout = QHBoxLayout()
        self.btn_start = QPushButton("▶  Запустить парсер")
        self.btn_start.setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white; "
            "font-size: 14px; padding: 10px 20px; border-radius: 5px; }"
            "QPushButton:hover { background-color: #45a049; }"
            "QPushButton:disabled { background-color: #888; }"
        )
        self.btn_start.clicked.connect(self._start_pipeline)

        self.btn_stop = QPushButton("⏹  Остановить")
        self.btn_stop.setStyleSheet(
            "QPushButton { background-color: #f44336; color: white; "
            "font-size: 14px; padding: 10px 20px; border-radius: 5px; }"
            "QPushButton:hover { background-color: #d32f2f; }"
            "QPushButton:disabled { background-color: #888; }"
        )
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop_pipeline)

        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addStretch()
        settings_layout.addLayout(btn_layout)

        self.tabs.addTab(self.settings_tab, "Настройки и запуск")

        # Tab 2: Progress
        self.progress_panel = ProgressPanel()
        self.tabs.addTab(self.progress_panel, "Прогресс")

        # Tab 3: LLM Enrichment
        self.enrich_panel = EnrichPanel(
            get_providers_fn=self.settings_panel.get_providers
        )
        self.tabs.addTab(self.enrich_panel, "LLM-обогащение")

        # Tab 4: File viewer
        self.file_viewer = FileViewer()
        self.tabs.addTab(self.file_viewer, "Просмотр баз")

        # Tab 5: History
        self.history_panel = HistoryPanel()
        self.tabs.addTab(self.history_panel, "История")

        main_layout.addWidget(self.tabs)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Готов к работе")

    def _start_pipeline(self) -> None:
        """Collect settings and start the pipeline worker."""
        providers = self.settings_panel.get_providers()
        skip_translate = self.settings_panel.get_skip_translate()

        if not providers and not skip_translate:
            reply = QMessageBox.question(
                self,
                "Нет провайдеров",
                "Не выбран ни один провайдер перевода.\n"
                "Продолжить без перевода?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.No:
                return
            skip_translate = True

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_panel.reset()
        self.tabs.setCurrentWidget(self.progress_panel)
        self.status_bar.showMessage("Парсер запущен...")

        self._worker = PipelineWorker(
            providers=providers,
            limits=self.settings_panel.get_limits(),
            append_mode=self.settings_panel.get_append_mode(),
            resume=self.settings_panel.get_resume(),
            skip_translate=skip_translate,
        )
        self._worker.progress.connect(self.progress_panel.update_progress)
        self._worker.log_message.connect(self.progress_panel.append_log)
        self._worker.finished_ok.connect(self._on_finished_ok)
        self._worker.finished_error.connect(self._on_finished_error)
        self._worker.start()

    def _stop_pipeline(self) -> None:
        """Abort the running pipeline."""
        if self._worker:
            self._worker.abort()
            self.status_bar.showMessage("Останавливаем... (ждём текущую запись)")
            self.btn_stop.setEnabled(False)

    def _on_finished_ok(self) -> None:
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status_bar.showMessage("Парсер завершён успешно!")
        self.file_viewer._refresh_files()
        self.history_panel.refresh()
        QMessageBox.information(self, "Готово", "Парсер завершил работу успешно.")

    def _on_finished_error(self, error: str) -> None:
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status_bar.showMessage(f"Ошибка: {error[:80]}")
        self.history_panel.refresh()
        QMessageBox.warning(
            self, "Ошибка",
            f"Парсер завершился с ошибкой:\n\n{error}\n\n"
            "Промежуточные результаты сохранены. "
            "Отметьте 'Продолжить прерванный запуск' для resume.",
        )
