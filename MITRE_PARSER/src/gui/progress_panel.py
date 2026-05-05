"""Progress panel: real-time progress bars and log output."""
from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QProgressBar, QTextEdit, QGroupBox, QGridLayout,
)


class ProgressPanel(QWidget):
    """Displays real-time progress for each pipeline stage."""

    STAGES = [
        ("fetch", "Загрузка"),
        ("parse", "Парсинг"),
        ("link", "Связывание"),
        ("translate", "Перевод"),
        ("write", "Запись"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # ── Stage progress bars ──
        stages_group = QGroupBox("Этапы")
        grid = QGridLayout()

        self._bars: dict[str, QProgressBar] = {}
        self._labels: dict[str, QLabel] = {}

        for row, (key, name) in enumerate(self.STAGES):
            label = QLabel(f"{name}:")
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setTextVisible(True)
            status_label = QLabel("")

            grid.addWidget(label, row, 0)
            grid.addWidget(bar, row, 1)
            grid.addWidget(status_label, row, 2)

            self._bars[key] = bar
            self._labels[key] = status_label

        stages_group.setLayout(grid)
        layout.addWidget(stages_group)

        # ── Translation detail ──
        self.translate_detail = QLabel("")
        self.translate_detail.setStyleSheet("font-weight: bold; color: #2196F3;")
        layout.addWidget(self.translate_detail)

        # ── Log output ──
        log_group = QGroupBox("Лог")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(300)
        self.log_text.setStyleSheet(
            "font-family: Consolas, monospace; font-size: 11px;"
        )
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        layout.addStretch()

    def update_progress(self, stage: str, current: int, total: int, label: str) -> None:
        """Update progress bar for a given stage."""
        if stage not in self._bars:
            return

        bar = self._bars[stage]
        lbl = self._labels[stage]

        if total > 0:
            pct = int(current / total * 100)
            bar.setRange(0, total)
            bar.setValue(current)
            bar.setFormat(f"{current}/{total} ({pct}%)")
            lbl.setText(label)
        else:
            bar.setRange(0, 0)
            lbl.setText(label)

        if stage == "translate" and total > 0:
            self.translate_detail.setText(
                f"Перевод [{label}]: {current}/{total}"
            )

    def append_log(self, msg: str) -> None:
        """Append a message to the log output."""
        self.log_text.append(msg)
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def reset(self) -> None:
        """Reset all progress bars."""
        for bar in self._bars.values():
            bar.setValue(0)
            bar.setRange(0, 100)
            bar.setFormat("")
        for lbl in self._labels.values():
            lbl.setText("")
        self.translate_detail.setText("")
        self.log_text.clear()
