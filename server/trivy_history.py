import json
import os
from dataclasses import dataclass
from typing import Optional


TRIVY_HISTORY_DIR = "data"
TRIVY_HISTORY_PREFIX = "trivy_scan_"
TRIVY_HISTORY_SUFFIX = ".json"


@dataclass
class TrivyHistoryRecord:
    record_id: str
    filename: str
    filepath: str
    timestamp: str
    total_vulns: int
    critical: int


class TrivyHistory:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _data_dir(self) -> str:
        return os.path.join(self.base_dir, TRIVY_HISTORY_DIR)

    def list_records(self) -> list[TrivyHistoryRecord]:
        out: list[TrivyHistoryRecord] = []
        data_dir = self._data_dir()
        if not os.path.isdir(data_dir):
            return out
        for fname in sorted(os.listdir(data_dir), reverse=True):
            if not (fname.startswith(TRIVY_HISTORY_PREFIX) and fname.endswith(TRIVY_HISTORY_SUFFIX)):
                continue
            fpath = os.path.join(data_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                summary = data.get("summary", {}) if isinstance(data, dict) else {}
                total = int(summary.get("total_vulns", 0) or 0)
                crit = int(summary.get("critical", 0) or 0)
                ts = fname[len(TRIVY_HISTORY_PREFIX) : -len(TRIVY_HISTORY_SUFFIX)]
                out.append(
                    TrivyHistoryRecord(
                        record_id=fname,
                        filename=fname,
                        filepath=fpath,
                        timestamp=ts,
                        total_vulns=total,
                        critical=crit,
                    )
                )
            except Exception:
                continue
        return out

    def get_record_path(self, record_id: str) -> Optional[str]:
        rid = str(record_id or "").strip()
        if not rid:
            return None
        if "/" in rid or "\\" in rid:
            return None
        if not (rid.startswith(TRIVY_HISTORY_PREFIX) and rid.endswith(TRIVY_HISTORY_SUFFIX)):
            return None
        fpath = os.path.join(self._data_dir(), rid)
        if not os.path.exists(fpath):
            return None
        return fpath

    def delete_record(self, record_id: str) -> bool:
        fpath = self.get_record_path(record_id)
        if not fpath:
            return False
        os.remove(fpath)
        return True

