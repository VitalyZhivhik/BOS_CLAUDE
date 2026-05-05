"""File viewer: browse and search JSON database files."""
from __future__ import annotations

import json
from pathlib import Path

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLineEdit,
    QPushButton, QSplitter, QComboBox, QMessageBox,
)

from config import Config


class FileViewer(QWidget):
    """Browse JSON databases with search functionality."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_data: list[dict] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Top bar: file selection + refresh
        top = QHBoxLayout()
        top.addWidget(QLabel("База:"))
        self.combo_file = QComboBox()
        self.combo_file.currentTextChanged.connect(self._load_file)
        top.addWidget(self.combo_file, 1)

        self.btn_refresh = QPushButton("Обновить")
        self.btn_refresh.clicked.connect(self._refresh_files)
        top.addWidget(self.btn_refresh)
        layout.addLayout(top)

        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Поиск:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("ID, название или текст...")
        self.search_input.returnPressed.connect(self._search)
        search_layout.addWidget(self.search_input, 1)
        self.btn_search = QPushButton("Найти")
        self.btn_search.clicked.connect(self._search)
        search_layout.addWidget(self.btn_search)
        self.lbl_count = QLabel("")
        search_layout.addWidget(self.lbl_count)
        layout.addLayout(search_layout)

        # Splitter: tree + detail
        splitter = QSplitter(Qt.Horizontal)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["ID", "Название", "Severity"])
        self.tree.setColumnWidth(0, 120)
        self.tree.setColumnWidth(1, 300)
        self.tree.currentItemChanged.connect(self._on_item_selected)
        splitter.addWidget(self.tree)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setStyleSheet(
            "font-family: Consolas, monospace; font-size: 11px;"
        )
        splitter.addWidget(self.detail_text)

        splitter.setSizes([400, 500])
        layout.addWidget(splitter)

        self._refresh_files()

    def _refresh_files(self) -> None:
        """Scan databases directory and populate file list."""
        self.combo_file.clear()
        db_dir = Config.PROJECT_DATABASES_DIR
        if not db_dir.exists():
            return
        json_files = sorted(db_dir.glob("*.json"))
        for f in json_files:
            self.combo_file.addItem(f.name, str(f))

    def _load_file(self, filename: str) -> None:
        """Load selected JSON file into the tree."""
        if not filename:
            return
        idx = self.combo_file.currentIndex()
        if idx < 0:
            return
        filepath = self.combo_file.itemData(idx)
        if not filepath:
            return

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось прочитать:\n{e}")
            return

        if not isinstance(data, list):
            data = [data] if isinstance(data, dict) else []

        self._current_data = data
        self._populate_tree(data)
        self.lbl_count.setText(f"Записей: {len(data)}")

    def _populate_tree(self, records: list[dict]) -> None:
        """Fill tree with record summaries."""
        self.tree.clear()
        for rec in records[:5000]:  # limit for UI performance
            if not isinstance(rec, dict):
                continue
            item = QTreeWidgetItem([
                rec.get("id", "?"),
                rec.get("name", rec.get("description", "")[:80]),
                rec.get("severity", rec.get("base_severity", "")),
            ])
            item.setData(0, Qt.UserRole, rec)
            self.tree.addTopLevelItem(item)

    def _on_item_selected(self, current: QTreeWidgetItem | None, _prev) -> None:
        if current is None:
            self.detail_text.clear()
            return
        rec = current.data(0, Qt.UserRole)
        if rec:
            formatted = json.dumps(rec, ensure_ascii=False, indent=2)
            self.detail_text.setPlainText(formatted)

    def _search(self) -> None:
        """Filter tree items by search query."""
        query = self.search_input.text().strip().lower()
        if not query:
            self._populate_tree(self._current_data)
            self.lbl_count.setText(f"Записей: {len(self._current_data)}")
            return

        filtered = []
        for rec in self._current_data:
            if not isinstance(rec, dict):
                continue
            searchable = json.dumps(rec, ensure_ascii=False).lower()
            if query in searchable:
                filtered.append(rec)

        self._populate_tree(filtered)
        self.lbl_count.setText(f"Найдено: {len(filtered)} из {len(self._current_data)}")
