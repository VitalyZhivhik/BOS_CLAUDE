"""QThread worker for running the pipeline without blocking the GUI."""
from __future__ import annotations

from PyQt5.QtCore import QThread, pyqtSignal

from pipeline import Pipeline
from translation.providers.base import BaseProvider


class PipelineWorker(QThread):
    """Runs pipeline in a background thread, emitting progress signals."""

    progress = pyqtSignal(str, int, int, str)  # stage, current, total, label
    log_message = pyqtSignal(str)
    finished_ok = pyqtSignal()
    finished_error = pyqtSignal(str)

    def __init__(
        self,
        providers: list[BaseProvider],
        limits: dict[str, int],
        append_mode: bool = False,
        resume: bool = False,
        skip_translate: bool = False,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.providers = providers
        self.limits = limits
        self.append_mode = append_mode
        self.resume = resume
        self.skip_translate = skip_translate
        self._pipeline: Pipeline | None = None

    def run(self) -> None:
        try:
            self._pipeline = Pipeline(
                skip_translate=self.skip_translate,
                providers=self.providers,
                limits=self.limits,
                append_mode=self.append_mode,
                resume=self.resume,
                progress_callback=self._on_progress,
                log_callback=self._on_log,
            )
            self._pipeline.run()
            self.finished_ok.emit()
        except KeyboardInterrupt:
            self.finished_error.emit("Прервано пользователем")
        except Exception as e:
            self.finished_error.emit(str(e))

    def abort(self) -> None:
        if self._pipeline:
            self._pipeline.abort()

    def _on_progress(self, stage: str, current: int, total: int, label: str) -> None:
        self.progress.emit(stage, current, total, label)

    def _on_log(self, msg: str) -> None:
        self.log_message.emit(msg)
