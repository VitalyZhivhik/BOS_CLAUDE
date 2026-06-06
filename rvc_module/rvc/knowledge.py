"""Доступ к локальному срезу баз MITRE (CVE/CWE/CAPEC/ATT&CK)."""

from __future__ import annotations

import json
import os

_KB_PATH = os.path.join(os.path.dirname(__file__), "mitre_kb.json")


class Knowledge:
    """Только чтение: lookup по CVE/CWE/CAPEC/ATT&CK из mitre_kb.json."""

    def __init__(self, path: str = _KB_PATH):
        with open(path, encoding="utf-8") as fh:
            self._kb = json.load(fh)
        self.snapshot = self._kb.get("_meta", {}).get("snapshot", "unknown")
        self.sources = self._kb.get("_meta", {}).get("sources", [])

    def cve(self, cve_id: str) -> dict | None:
        return self._kb.get("cve", {}).get(cve_id.upper())

    def cwe(self, cwe_id: str) -> dict:
        info = self._kb.get("cwe", {}).get(cwe_id.upper(), {})
        return {"id": cwe_id.upper(), "name": info.get("name", ""), "description": info.get("description", "")}

    def capec(self, capec_id: str) -> dict:
        info = self._kb.get("capec", {}).get(capec_id.upper(), {})
        return {"id": capec_id.upper(), "name": info.get("name", ""), "description": info.get("description", "")}

    def technique(self, tech_id: str) -> dict:
        info = self._kb.get("attack", {}).get(tech_id.upper(), {})
        return {
            "id": tech_id.upper(),
            "name": info.get("name", ""),
            "tactic": info.get("tactic", ""),
            "description": info.get("description", ""),
        }

    def technique_for_attack_type(self, attack_type: str) -> str | None:
        return self._kb.get("attack_type_to_technique", {}).get((attack_type or "").lower())
