"""
Сборщик databases/defense_database.json.

Источники:
  • существующие записи defense_database.json (DEF-001..009) — сохраняются;
  • catalog/defense_tools_seed.json — расширенный курируемый каталог защит;
  • MITRE ATT&CK course-of-action (M-коды) — автогенерация;
  • techniques + cve (для расчёта attack_type / cve_ids у MITRE-записей).

Схема выхода соответствует ожиданиям server/attack_toolkit.py:
  id, attack_type, cve_ids, name, description,
  tools=[{name, description, commands}],
  priority, effort, effectiveness.
Дополнительно: mitre_mitigation_id, related_techniques, references, language="ru".
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from config import Config


def _load_json(path: Path) -> list:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except (OSError, json.JSONDecodeError) as e:
        print(f"  [DefenseDB] Не удалось прочитать {path.name}: {e}")
    return []


_TACTIC_TO_ATTACK_TYPE = {
    "Initial Access": "initial_access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege_escalation",
    "Defense Evasion": "defense_evasion",
    "Credential Access": "credential_access",
    "Discovery": "reconnaissance",
    "Lateral Movement": "lateral_movement",
    "Collection": "data_collection",
    "Command And Control": "command_and_control",
    "Exfiltration": "data_exfiltration",
    "Impact": "denial_of_service",
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource_development",
}


def _priority_from_score(max_cvss: float) -> str:
    if max_cvss >= 9.0:
        return "CRITICAL"
    if max_cvss >= 7.0:
        return "HIGH"
    if max_cvss >= 4.0:
        return "MEDIUM"
    if max_cvss > 0:
        return "LOW"
    return "MEDIUM"


class DefenseDbBuilder:
    """Собирает defense_database.json из ручных + seed + MITRE-mitigations."""

    MITRE_PREFIX = "DEF-MITRE-"

    def build(
        self,
        techniques: list[dict],
        mitre_mitigations: list[dict],
        cve: list[dict],
        existing_defense: list[dict] | None = None,
    ) -> list[dict]:
        existing = list(existing_defense or [])
        seed = _load_json(Config.CATALOG_DIR / "defense_tools_seed.json")

        techs_by_id = {t["id"]: t for t in techniques if t.get("id")}
        cve_by_id = {c["id"]: c for c in cve if c.get("id")}

        result: list[dict] = []
        seen_ids: set[str] = set()

        def _push(rec: dict) -> None:
            if not rec or not rec.get("id"):
                return
            if rec["id"] in seen_ids:
                return
            result.append(rec)
            seen_ids.add(rec["id"])

        for d in existing:
            _push(self._normalize_existing(d))

        for d in seed:
            _push(self._normalize_existing(d))

        for rec in self._mitre_mitigations_to_defense(
            mitre_mitigations, techs_by_id, cve_by_id
        ):
            _push(rec)

        # Сортировка: сначала ручные DEF-NNN, затем SEED, затем MITRE
        def _sort_key(r: dict) -> tuple:
            rid = r.get("id", "")
            if rid.startswith(self.MITRE_PREFIX):
                return (3, rid)
            if rid.startswith("DEF-SEED-"):
                return (2, rid)
            return (1, rid)

        result.sort(key=_sort_key)
        return result

    # ── Helpers ────────────────────────────────────────
    def _normalize_existing(self, d: dict) -> dict:
        rec = dict(d)
        rec.setdefault("id", "")
        rec.setdefault("attack_type", "")
        rec.setdefault("cve_ids", [])
        rec.setdefault("name", "")
        rec.setdefault("description", "")
        rec.setdefault("tools", [])
        rec.setdefault("priority", "MEDIUM")
        rec.setdefault("effort", "Medium")
        rec.setdefault("effectiveness", "Medium")
        rec.setdefault("language", "ru")
        # Tools — список словарей
        norm_tools = []
        for t in rec.get("tools") or []:
            if isinstance(t, dict):
                tool = dict(t)
                tool.setdefault("name", "")
                tool.setdefault("description", "")
                tool.setdefault("commands", [])
                if isinstance(tool["commands"], str):
                    tool["commands"] = [tool["commands"]]
                norm_tools.append(tool)
        rec["tools"] = norm_tools
        return rec

    def _mitre_mitigations_to_defense(
        self,
        mitre_mitigations: list[dict],
        techs_by_id: dict[str, dict],
        cve_by_id: dict[str, dict],
    ) -> list[dict]:
        out: list[dict] = []
        for mit in mitre_mitigations:
            m_id = mit.get("id") or ""
            if not m_id:
                continue
            related_techs = list(mit.get("related_techniques") or [])

            # Определяем attack_type по тактикам связанных техник
            tactic_counter: dict[str, int] = defaultdict(int)
            cve_set: set[str] = set()
            max_cvss = 0.0
            for tid in related_techs:
                t = techs_by_id.get(tid)
                if not t:
                    continue
                for tac in t.get("tactics") or []:
                    tactic_counter[tac] += 1
                for cve_id in t.get("related_cve") or []:
                    cve_set.add(cve_id)
                    cv = cve_by_id.get(cve_id)
                    if cv and cv.get("cvss_score"):
                        try:
                            max_cvss = max(max_cvss, float(cv["cvss_score"]))
                        except (TypeError, ValueError):
                            pass

            if tactic_counter:
                top_tactic = max(tactic_counter.items(), key=lambda x: x[1])[0]
                attack_type = _TACTIC_TO_ATTACK_TYPE.get(top_tactic, "general_security")
            else:
                attack_type = "general_security"

            commands = [
                f"# Рекомендация MITRE ATT&CK: {mit.get('name', m_id)}",
                f"# Подробнее: {mit.get('url', '')}".rstrip(),
                "",
                "# Применимые техники атак (Txxxx):",
                ", ".join(related_techs[:15]) or "—",
                "",
                "# Ниже — текст рекомендации (на русском, после автоматического перевода):",
                (mit.get("description") or "").strip(),
            ]

            rec = {
                "id": f"{self.MITRE_PREFIX}{m_id}",
                "mitre_mitigation_id": m_id,
                "attack_type": attack_type,
                "cve_ids": sorted(cve_set)[:30],
                "name": mit.get("name", m_id),
                "description": (mit.get("description") or "").strip(),
                "tools": [
                    {
                        "name": "Рекомендуемая практика безопасности (MITRE M-код)",
                        "description": mit.get("name", "") or "Меры защиты по MITRE ATT&CK",
                        "commands": commands,
                    }
                ],
                "priority": _priority_from_score(max_cvss),
                "effort": "Medium",
                "effectiveness": "High",
                "related_techniques": related_techs[:50],
                "references": [r.get("url", "") for r in (mit.get("references") or []) if r.get("url")][:10],
                "language": "ru",
                "source": "MITRE ATT&CK",
            }
            out.append(rec)
        return out


__all__ = ["DefenseDbBuilder"]
