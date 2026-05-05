"""History panel: display past parser runs."""
from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QPushButton, QHeaderView,
)

from state_manager import StateManager


class HistoryPanel(QWidget):
    """Shows a table of past pipeline runs with stats."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.state = StateManager()
        self._init_ui()
        self.refresh()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Header
        header = QHBoxLayout()
        header.addWidget(QLabel("История запусков парсера"))
        header.addStretch()
        self.btn_refresh = QPushButton("Обновить")
        self.btn_refresh.clicked.connect(self.refresh)
        header.addWidget(self.btn_refresh)
        layout.addLayout(header)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Дата", "Статус", "Режим", "Записей", "Провайдеры", "Время",
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)

        # Checkpoint info
        self.lbl_checkpoint = QLabel("")
        self.lbl_checkpoint.setStyleSheet("color: #FFA726; font-weight: bold;")
        layout.addWidget(self.lbl_checkpoint)

    def refresh(self) -> None:
        """Reload history from disk."""
        history = self.state.get_history()
        self.table.setRowCount(0)

        for entry in reversed(history):
            row = self.table.rowCount()
            self.table.insertRow(row)

            started = entry.get("started_at", "")[:19].replace("T", " ")
            status = entry.get("status", "?")
            mode = entry.get("mode", "?")
            records = entry.get("records", {})
            rec_str = ", ".join(f"{k}={v}" for k, v in records.items() if v)
            providers = ", ".join(entry.get("providers_used", []))

            status_icon = {"completed": "✅", "aborted": "⚠️", "running": "⏳"}.get(
                status, "❓"
            )

            self.table.setItem(row, 0, QTableWidgetItem(started))
            self.table.setItem(row, 1, QTableWidgetItem(f"{status_icon} {status}"))
            self.table.setItem(row, 2, QTableWidgetItem(mode))
            self.table.setItem(row, 3, QTableWidgetItem(rec_str[:60]))
            self.table.setItem(row, 4, QTableWidgetItem(providers[:40]))
            self.table.setItem(row, 5, QTableWidgetItem(""))

        # Checkpoint status
        if self.state.has_checkpoint():
            cp = self.state.load_checkpoint()
            if cp:
                self.lbl_checkpoint.setText(
                    f"⚠️ Есть незавершённый запуск: {cp.run_id} "
                    f"(этап: {cp.stage}/{cp.sub_stage}, прогресс: {cp.progress})"
                )
            else:
                self.lbl_checkpoint.setText("")
        else:
            self.lbl_checkpoint.setText("")
