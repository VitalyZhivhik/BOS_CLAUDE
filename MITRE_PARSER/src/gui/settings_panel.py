"""Settings panel: limits, provider selection with custom API keys, availability check."""
from __future__ import annotations

import json
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QLabel,
    QSpinBox, QCheckBox, QPushButton, QRadioButton, QButtonGroup,
    QGridLayout, QLineEdit, QComboBox, QScrollArea, QFrame,
    QDialog, QDialogButtonBox, QFormLayout, QMessageBox,
)

from config import Config
from translation.providers.base import BaseProvider, ProviderStatus
from translation.providers.google_provider import GoogleProvider
from translation.providers.groq_provider import GroqProvider
from translation.providers.mistral_provider import MistralProvider
from translation.providers.openrouter_provider import OpenRouterProvider, FREE_MODELS


_SETTINGS_FILE = Config.OUTPUT_DIR / "provider_settings.json"


class _CheckWorker(QThread):
    """Background thread to check provider availability."""
    result = pyqtSignal(int, bool, float, str)  # row_index, available, latency, error

    def __init__(self, row_index: int, provider: BaseProvider, parent=None):
        super().__init__(parent)
        self.row_index = row_index
        self.provider = provider

    def run(self):
        status = self.provider.check_availability()
        self.result.emit(self.row_index, status.available, status.latency_ms, status.error)


class _AddProviderDialog(QDialog):
    """Dialog to add a custom provider."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Добавить провайдер")
        self.setMinimumWidth(450)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.combo_type = QComboBox()
        self.combo_type.addItems(["Groq", "Mistral", "OpenRouter"])
        self.combo_type.currentTextChanged.connect(self._on_type_changed)
        form.addRow("Тип:", self.combo_type)

        self.edit_label = QLineEdit()
        self.edit_label.setPlaceholderText("Метка (необязательно)")
        form.addRow("Метка:", self.edit_label)

        self.edit_api_key = QLineEdit()
        self.edit_api_key.setPlaceholderText("Вставьте API ключ...")
        self.edit_api_key.setEchoMode(QLineEdit.Password)
        form.addRow("API ключ:", self.edit_api_key)

        self.combo_model = QComboBox()
        self.combo_model.setEditable(True)
        self.combo_model.hide()
        self.lbl_model = QLabel("Модель:")
        self.lbl_model.hide()
        form.addRow(self.lbl_model, self.combo_model)

        layout.addLayout(form)

        # Hint
        self.lbl_hint = QLabel(
            "Groq: бесплатно на groq.com/keys\n"
            "Mistral: бесплатно на console.mistral.ai\n"
            "OpenRouter: бесплатно на openrouter.ai/keys"
        )
        self.lbl_hint.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(self.lbl_hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._on_type_changed("Groq")

    def _on_type_changed(self, ptype: str):
        if ptype == "OpenRouter":
            self.combo_model.clear()
            self.combo_model.addItems(FREE_MODELS)
            self.combo_model.show()
            self.lbl_model.show()
        else:
            self.combo_model.hide()
            self.lbl_model.hide()

    def get_provider_config(self) -> dict | None:
        api_key = self.edit_api_key.text().strip()
        if not api_key:
            return None
        return {
            "type": self.combo_type.currentText().lower(),
            "label": self.edit_label.text().strip(),
            "api_key": api_key,
            "model": self.combo_model.currentText() if self.combo_model.isVisible() else "",
        }


class ProviderRow(QWidget):
    """A single provider row with checkbox, label, status, and remove button."""

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self.config = config
        self._init_ui()

    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)

        self.checkbox = QCheckBox()
        self.checkbox.setChecked(True)
        layout.addWidget(self.checkbox)

        ptype = self.config.get("type", "")
        label = self.config.get("label", "")
        display = f"{ptype.capitalize()}"
        if label:
            display += f" ({label})"
        if self.config.get("model"):
            short_model = self.config["model"].split("/")[-1].split(":")[0]
            display += f" [{short_model}]"

        self.lbl_name = QLabel(display)
        layout.addWidget(self.lbl_name, 1)

        self.lbl_status = QLabel("⚪")
        self.lbl_status.setMinimumWidth(180)
        layout.addWidget(self.lbl_status)

        self.btn_remove = QPushButton("✕")
        self.btn_remove.setFixedWidth(30)
        self.btn_remove.setStyleSheet("color: #f44336;")
        layout.addWidget(self.btn_remove)

    def build_provider(self) -> BaseProvider | None:
        """Build a provider instance from config."""
        ptype = self.config.get("type", "")
        api_key = self.config.get("api_key", "")
        label = self.config.get("label", "")
        model = self.config.get("model", "")

        if ptype == "google":
            return GoogleProvider()
        elif ptype == "groq":
            if not api_key:
                return None
            return GroqProvider(api_key=api_key, key_label=label)
        elif ptype == "mistral":
            if not api_key:
                return None
            return MistralProvider(api_key=api_key)
        elif ptype == "openrouter":
            if not api_key:
                return None
            return OpenRouterProvider(api_key=api_key, model=model, label=label)
        return None

    def is_selected(self) -> bool:
        return self.checkbox.isChecked()


class SettingsPanel(QWidget):
    """Panel for configuring parser limits, translation providers, and run mode."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._check_workers: list[_CheckWorker] = []
        self._provider_rows: list[ProviderRow] = []
        self._init_ui()
        self._load_saved_providers()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # ── Limits ──
        limits_group = QGroupBox("Лимиты записей (0 = все)")
        limits_layout = QGridLayout()

        self.spin_capec = QSpinBox()
        self.spin_capec.setRange(0, 50000)
        self.spin_capec.setValue(600)
        self.spin_capec.setSpecialValueText("Все")

        self.spin_cwe = QSpinBox()
        self.spin_cwe.setRange(0, 50000)
        self.spin_cwe.setValue(1500)
        self.spin_cwe.setSpecialValueText("Все")

        self.spin_cve = QSpinBox()
        self.spin_cve.setRange(0, 50000)
        self.spin_cve.setValue(800)
        self.spin_cve.setSpecialValueText("Все")

        self.spin_attack = QSpinBox()
        self.spin_attack.setRange(0, 50000)
        self.spin_attack.setValue(600)
        self.spin_attack.setSpecialValueText("Все")

        limits_layout.addWidget(QLabel("CAPEC:"), 0, 0)
        limits_layout.addWidget(self.spin_capec, 0, 1)
        limits_layout.addWidget(QLabel("CWE:"), 0, 2)
        limits_layout.addWidget(self.spin_cwe, 0, 3)
        limits_layout.addWidget(QLabel("CVE:"), 1, 0)
        limits_layout.addWidget(self.spin_cve, 1, 1)
        limits_layout.addWidget(QLabel("ATT&CK:"), 1, 2)
        limits_layout.addWidget(self.spin_attack, 1, 3)

        limits_group.setLayout(limits_layout)
        layout.addWidget(limits_group)

        # ── Run mode ──
        mode_group = QGroupBox("Режим записи")
        mode_layout = QHBoxLayout()
        self.mode_group = QButtonGroup(self)
        self.radio_new = QRadioButton("Новый прогон (перезапись)")
        self.radio_append = QRadioButton("Дозапись (уникальные)")
        self.radio_new.setChecked(True)
        self.mode_group.addButton(self.radio_new, 0)
        self.mode_group.addButton(self.radio_append, 1)
        mode_layout.addWidget(self.radio_new)
        mode_layout.addWidget(self.radio_append)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)

        # ── Translation providers ──
        providers_group = QGroupBox("Провайдеры перевода (выберите несколько для параллельного перевода)")
        providers_layout = QVBoxLayout()

        # Provider list area
        self.providers_container = QVBoxLayout()
        providers_layout.addLayout(self.providers_container)

        # Buttons row
        btn_row = QHBoxLayout()
        self.btn_add_provider = QPushButton("+ Добавить провайдер")
        self.btn_add_provider.clicked.connect(self._add_provider_dialog)
        btn_row.addWidget(self.btn_add_provider)

        self.btn_add_google = QPushButton("+ Google (бесплатно)")
        self.btn_add_google.clicked.connect(self._add_google)
        btn_row.addWidget(self.btn_add_google)

        btn_row.addStretch()

        self.btn_check_api = QPushButton("Проверить доступность")
        self.btn_check_api.clicked.connect(self.check_all_providers)
        btn_row.addWidget(self.btn_check_api)

        providers_layout.addLayout(btn_row)

        self.chk_skip_translate = QCheckBox("Пропустить перевод (быстрый режим)")
        providers_layout.addWidget(self.chk_skip_translate)

        self.lbl_parallel_hint = QLabel(
            "Все отмеченные провайдеры разделят записи между собой и будут переводить параллельно."
        )
        self.lbl_parallel_hint.setStyleSheet("color: #888; font-size: 11px; margin-top: 5px;")
        providers_layout.addWidget(self.lbl_parallel_hint)

        providers_group.setLayout(providers_layout)
        layout.addWidget(providers_group)

        # ── Resume ──
        self.chk_resume = QCheckBox("Продолжить прерванный запуск (если есть checkpoint)")
        layout.addWidget(self.chk_resume)

        layout.addStretch()

    # ── Provider management ──────────────────────────────

    def _add_provider_row(self, config: dict) -> None:
        row = ProviderRow(config)
        row.btn_remove.clicked.connect(lambda: self._remove_provider_row(row))
        self._provider_rows.append(row)
        self.providers_container.addWidget(row)
        self._save_providers()

    def _remove_provider_row(self, row: ProviderRow) -> None:
        self.providers_container.removeWidget(row)
        self._provider_rows.remove(row)
        row.deleteLater()
        self._save_providers()

    def _add_google(self) -> None:
        self._add_provider_row({"type": "google", "label": "", "api_key": "", "model": ""})

    def _add_provider_dialog(self) -> None:
        dlg = _AddProviderDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            config = dlg.get_provider_config()
            if config:
                self._add_provider_row(config)
            else:
                QMessageBox.warning(self, "Ошибка", "API ключ не может быть пустым.")

    # ── Persistence ──────────────────────────────────────

    def _save_providers(self) -> None:
        """Save provider configs to disk (keys stored locally)."""
        configs = [row.config for row in self._provider_rows]
        try:
            _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with _SETTINGS_FILE.open("w", encoding="utf-8") as f:
                json.dump(configs, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _load_saved_providers(self) -> None:
        """Load saved provider configs from disk."""
        if not _SETTINGS_FILE.exists():
            # Add defaults
            self._add_provider_row({"type": "google", "label": "", "api_key": "", "model": ""})
            self._add_provider_row({
                "type": "groq", "label": "ключ 1",
                "api_key": "",
                "model": "",
            })
            self._add_provider_row({
                "type": "groq", "label": "ключ 2",
                "api_key": "",
                "model": "",
            })
            self._add_provider_row({
                "type": "mistral", "label": "",
                "api_key": "",
                "model": "",
            })
            return

        try:
            with _SETTINGS_FILE.open("r", encoding="utf-8") as f:
                configs = json.load(f)
            if isinstance(configs, list):
                for cfg in configs:
                    if isinstance(cfg, dict):
                        self._add_provider_row(cfg)
        except (OSError, json.JSONDecodeError):
            self._add_provider_row({"type": "google", "label": "", "api_key": "", "model": ""})

    # ── Public getters ───────────────────────────────────

    def get_limits(self) -> dict[str, int]:
        return {
            "capec": self.spin_capec.value(),
            "cwe": self.spin_cwe.value(),
            "cve": self.spin_cve.value(),
            "attack": self.spin_attack.value(),
        }

    def get_append_mode(self) -> bool:
        return self.radio_append.isChecked()

    def get_resume(self) -> bool:
        return self.chk_resume.isChecked()

    def get_skip_translate(self) -> bool:
        return self.chk_skip_translate.isChecked()

    def get_providers(self) -> list[BaseProvider]:
        """Build list of selected providers."""
        providers: list[BaseProvider] = []
        for row in self._provider_rows:
            if row.is_selected():
                p = row.build_provider()
                if p:
                    providers.append(p)
        return providers

    # ── API check ────────────────────────────────────────

    def check_all_providers(self) -> None:
        """Check availability of all selected providers."""
        self.btn_check_api.setEnabled(False)
        self.btn_check_api.setText("Проверяем...")
        self._check_workers.clear()
        self._pending_checks = 0

        for i, row in enumerate(self._provider_rows):
            if not row.is_selected():
                row.lbl_status.setText("⚪ (не выбран)")
                continue
            provider = row.build_provider()
            if not provider:
                row.lbl_status.setText("⚪ (нет ключа)")
                continue

            row.lbl_status.setText("⏳ ...")
            self._pending_checks += 1
            worker = _CheckWorker(i, provider)
            worker.result.connect(self._on_check_result)
            self._check_workers.append(worker)
            worker.start()

        if self._pending_checks == 0:
            self.btn_check_api.setEnabled(True)
            self.btn_check_api.setText("Проверить доступность")

    def _on_check_result(self, row_idx: int, available: bool,
                         latency: float, error: str) -> None:
        if row_idx < len(self._provider_rows):
            row = self._provider_rows[row_idx]
            if available:
                row.lbl_status.setText(f"✅ Доступен ({latency:.0f}ms)")
            else:
                short_err = error[:50] if error else "нет ответа"
                row.lbl_status.setText(f"❌ {short_err}")

        self._pending_checks -= 1
        if self._pending_checks <= 0:
            self.btn_check_api.setEnabled(True)
            self.btn_check_api.setText("Проверить доступность")
