"""
Checkpoint / Resume manager for pipeline runs.

Saves intermediate state to disk so interrupted runs can be continued
without losing progress. Also maintains run history.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from config import Config


@dataclass
class Checkpoint:
    run_id: str = ""
    stage: str = ""
    sub_stage: str = ""
    progress: int = 0
    total: int = 0
    completed_stages: list[str] = field(default_factory=list)
    partial_files: dict[str, str] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    updated_at: str = ""


@dataclass
class RunHistoryEntry:
    run_id: str
    started_at: str
    finished_at: str = ""
    status: str = "running"
    records: dict[str, int] = field(default_factory=dict)
    providers_used: list[str] = field(default_factory=list)
    duration_sec: float = 0.0
    mode: str = "new"


class StateManager:
    """Manages checkpoints and run history for the pipeline."""

    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or Config.OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._checkpoint_path = self.output_dir / "checkpoint.json"
        self._history_path = self.output_dir / "run_history.json"
        self._partial_dir = self.output_dir / "_partial"
        self._partial_dir.mkdir(parents=True, exist_ok=True)
        self._checkpoint: Checkpoint | None = None

    # ── Checkpoint ────────────────────────────────────────

    def has_checkpoint(self) -> bool:
        return self._checkpoint_path.exists()

    def load_checkpoint(self) -> Checkpoint | None:
        if not self._checkpoint_path.exists():
            return None
        try:
            with self._checkpoint_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            self._checkpoint = Checkpoint(**{
                k: v for k, v in data.items()
                if k in Checkpoint.__dataclass_fields__
            })
            return self._checkpoint
        except (OSError, json.JSONDecodeError, TypeError) as e:
            print(f"  [State] Не удалось загрузить checkpoint: {e}")
            return None

    def start_run(self, settings: dict[str, Any] | None = None) -> str:
        """Start a new run, returning the run_id."""
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._checkpoint = Checkpoint(
            run_id=run_id,
            started_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            settings=settings or {},
        )
        self._save_checkpoint()
        return run_id

    def update_stage(self, stage: str, sub_stage: str = "",
                     progress: int = 0, total: int = 0) -> None:
        if not self._checkpoint:
            return
        self._checkpoint.stage = stage
        self._checkpoint.sub_stage = sub_stage
        self._checkpoint.progress = progress
        self._checkpoint.total = total
        self._checkpoint.updated_at = datetime.now().isoformat()
        self._save_checkpoint()

    def complete_stage(self, stage: str) -> None:
        if not self._checkpoint:
            return
        if stage not in self._checkpoint.completed_stages:
            self._checkpoint.completed_stages.append(stage)
        self._checkpoint.stage = ""
        self._checkpoint.sub_stage = ""
        self._checkpoint.progress = 0
        self._checkpoint.updated_at = datetime.now().isoformat()
        self._save_checkpoint()

    def save_partial(self, name: str, records: list[dict]) -> None:
        """Save partial results for a specific database."""
        path = self._partial_dir / f"{name}_partial.json"
        try:
            with path.open("w", encoding="utf-8") as f:
                json.dump(records, f, ensure_ascii=False)
            if self._checkpoint:
                self._checkpoint.partial_files[name] = str(path)
                self._save_checkpoint()
        except OSError as e:
            print(f"  [State] Ошибка сохранения partial {name}: {e}")

    def load_partial(self, name: str) -> list[dict] | None:
        """Load partial results if available."""
        if not self._checkpoint:
            return None
        path_str = self._checkpoint.partial_files.get(name)
        if not path_str:
            return None
        path = Path(path_str)
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else None
        except (OSError, json.JSONDecodeError):
            return None

    def finish_run(self, records: dict[str, int],
                   providers: list[str], mode: str = "new") -> None:
        """Mark run as completed, save to history, remove checkpoint."""
        if self._checkpoint:
            entry = RunHistoryEntry(
                run_id=self._checkpoint.run_id,
                started_at=self._checkpoint.started_at,
                finished_at=datetime.now().isoformat(),
                status="completed",
                records=records,
                providers_used=providers,
                duration_sec=time.time(),
                mode=mode,
            )
            self._append_history(entry)
        self._cleanup()

    def abort_run(self) -> None:
        """Mark run as aborted in history but keep checkpoint for resume."""
        if self._checkpoint:
            entry = RunHistoryEntry(
                run_id=self._checkpoint.run_id,
                started_at=self._checkpoint.started_at,
                finished_at=datetime.now().isoformat(),
                status="aborted",
            )
            self._append_history(entry)

    def clear_checkpoint(self) -> None:
        self._cleanup()

    # ── History ───────────────────────────────────────────

    def get_history(self) -> list[dict]:
        if not self._history_path.exists():
            return []
        try:
            with self._history_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    # ── Private ───────────────────────────────────────────

    def _save_checkpoint(self) -> None:
        if not self._checkpoint:
            return
        try:
            with self._checkpoint_path.open("w", encoding="utf-8") as f:
                json.dump(asdict(self._checkpoint), f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _append_history(self, entry: RunHistoryEntry) -> None:
        history = self.get_history()
        history.append(asdict(entry))
        if len(history) > 100:
            history = history[-100:]
        try:
            with self._history_path.open("w", encoding="utf-8") as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _cleanup(self) -> None:
        self._checkpoint = None
        try:
            self._checkpoint_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            for f in self._partial_dir.glob("*_partial.json"):
                f.unlink(missing_ok=True)
        except OSError:
            pass


__all__ = ["StateManager", "Checkpoint"]
