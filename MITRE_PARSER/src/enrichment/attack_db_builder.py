"""
Сборщик databases/tools_database.json.

На вход получает:
  • существующие записи tools_database.json (ручные TOOL-001..020) — сохраняются;
  • catalog/attack_tools_seed.json — ручные расширенные записи (на русском);
  • MITRE software (S-коды) — автогенерация;
  • catalog/attack_type_to_tools.json — маппинг типов атак к инструментам;
  • techniques (для расчёта applicable_attack_types/applicable_cve у MITRE-записей).

На выходе — единый список dict-ов в схеме, совместимой с
server/attack_toolkit.py (поля: id, name, type, description, url,
applicable_attack_types, applicable_cve, commands{}, phases, skill_level, os),
с дополнительными полями (mitre_software_id, related_techniques, aliases,
groups_using, language="ru").
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
        print(f"  [AttackDB] Не удалось прочитать {path.name}: {e}")
    return []


def _normalize_tactic_to_attack_type(tactic: str) -> list[str]:
    """Грубое сопоставление тактики ATT&CK к нашим internal attack_type."""
    if not tactic:
        return []
    t = tactic.lower()
    table = {
        "initial access": ["initial_access"],
        "execution": ["execution", "remote_code_execution"],
        "persistence": ["persistence"],
        "privilege escalation": ["privilege_escalation"],
        "defense evasion": ["defense_evasion"],
        "credential access": ["credential_access", "brute_force"],
        "discovery": ["reconnaissance", "discovery"],
        "lateral movement": ["lateral_movement"],
        "collection": ["data_collection"],
        "command and control": ["command_and_control"],
        "exfiltration": ["data_exfiltration"],
        "impact": ["denial_of_service", "data_destruction"],
        "reconnaissance": ["reconnaissance"],
        "resource development": ["resource_development"],
    }
    return table.get(t, [t.replace(" ", "_")])


def _phase_for_tactic(tactic: str) -> str:
    """Перевод тактики ATT&CK в русское название фазы."""
    table = {
        "Initial Access": "Первоначальный доступ",
        "Execution": "Выполнение",
        "Persistence": "Закрепление",
        "Privilege Escalation": "Повышение привилегий",
        "Defense Evasion": "Обход защиты",
        "Credential Access": "Получение учётных данных",
        "Discovery": "Разведка",
        "Lateral Movement": "Горизонтальное перемещение",
        "Collection": "Сбор информации",
        "Command And Control": "Командное управление",
        "Exfiltration": "Эксфильтрация",
        "Impact": "Воздействие",
        "Reconnaissance": "Разведка",
        "Resource Development": "Развитие ресурсов",
    }
    return table.get(tactic, tactic)


class AttackDbBuilder:
    """
    Собирает финальный tools_database.json из трёх источников.
    Идентификаторы:
      • TOOL-XXX (ручные, существующие) — оставляем как есть;
      • TOOL-SEED-XXX (расширенный seed) — оставляем как есть;
      • TOOL-MITRE-Sxxxx (автогенерация из MITRE) — новый префикс.
    """

    MITRE_PREFIX = "TOOL-MITRE-"

    def __init__(self) -> None:
        self.attack_type_map: dict[str, list[str]] = self._load_type_map()

    def _load_type_map(self) -> dict[str, list[str]]:
        path = Config.CATALOG_DIR / "attack_type_to_tools.json"
        if not path.exists():
            return {}
        try:
            with path.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}
        # Инвертируем: имя тула → список типов атак
        inv: dict[str, list[str]] = defaultdict(list)
        for atk_type, tools in raw.items():
            if atk_type.startswith("_"):
                continue
            for tool_name in tools:
                inv[tool_name.lower()].append(atk_type)
        return {k: sorted(set(v)) for k, v in inv.items()}

    # ── Public ─────────────────────────────────────────
    def build(
        self,
        techniques: list[dict],
        software: list[dict],
        existing_tools: list[dict] | None = None,
    ) -> list[dict]:
        existing = list(existing_tools or [])
        seed = _load_json(Config.CATALOG_DIR / "attack_tools_seed.json")

        result: list[dict] = []
        seen_ids: set[str] = set()
        seen_names: set[str] = set()

        def _push(rec: dict) -> None:
            if not rec or not rec.get("id"):
                return
            if rec["id"] in seen_ids:
                return
            name_key = (rec.get("name") or "").lower()
            if name_key and name_key in seen_names:
                # Если по имени уже есть — обогащаем существующий новыми полями
                for prev in result:
                    if (prev.get("name") or "").lower() == name_key:
                        self._merge(prev, rec)
                        return
                return
            self._enrich_attack_types(rec)
            result.append(rec)
            seen_ids.add(rec["id"])
            if name_key:
                seen_names.add(name_key)

        # 1) Существующие ручные (приоритет)
        for tool in existing:
            _push(self._normalize_existing(tool))

        # 2) Seed-каталог
        for tool in seed:
            _push(self._normalize_existing(tool))

        # 3) MITRE software → автогенерация
        techs_by_id = {t["id"]: t for t in techniques if t.get("id")}
        mitre_records = self._mitre_software_to_tools(software, techs_by_id)
        for rec in mitre_records:
            _push(rec)

        # Сортировка: ручные TOOL-NNN, затем SEED, затем MITRE
        def _sort_key(r: dict) -> tuple:
            rid = r.get("id", "")
            if rid.startswith("TOOL-MITRE-"):
                return (3, rid)
            if rid.startswith("TOOL-SEED-"):
                return (2, rid)
            return (1, rid)

        result.sort(key=_sort_key)
        return result

    # ── Helpers ────────────────────────────────────────
    def _normalize_existing(self, tool: dict) -> dict:
        """Приводит существующую/seed-запись к строгой схеме (без потерь)."""
        rec = dict(tool)
        rec.setdefault("id", "")
        rec.setdefault("name", "")
        rec.setdefault("type", "exploitation")
        rec.setdefault("description", "")
        rec.setdefault("url", "")
        rec.setdefault("applicable_attack_types", [])
        rec.setdefault("applicable_cve", [])
        rec.setdefault("commands", {})
        rec.setdefault("phases", [])
        rec.setdefault("skill_level", "Intermediate")
        rec.setdefault("os", [])
        rec.setdefault("language", "ru")
        # Если commands — список (старый формат), оборачиваем в "default"
        if isinstance(rec.get("commands"), list):
            rec["commands"] = {"default": rec["commands"]}
        return rec

    def _enrich_attack_types(self, rec: dict) -> None:
        """Добавляет attack_type из общего маппинга (по имени)."""
        name = (rec.get("name") or "").lower()
        if not name:
            return
        # Берём по точному совпадению или по подстроке
        extra = list(self.attack_type_map.get(name, []))
        if not extra:
            for k, v in self.attack_type_map.items():
                if k in name or name in k:
                    extra.extend(v)
        if extra:
            current = list(rec.get("applicable_attack_types") or [])
            rec["applicable_attack_types"] = sorted(set(current) | set(extra))

    def _merge(self, dst: dict, src: dict) -> None:
        """Дозаливает поля src в dst, не затирая значимое."""
        for key in (
            "applicable_attack_types", "applicable_cve",
            "phases", "os", "aliases", "related_techniques", "groups_using",
        ):
            if key in src and isinstance(src[key], list) and src[key]:
                cur = list(dst.get(key) or [])
                merged = []
                seen = set()
                for x in cur + list(src[key]):
                    k = json.dumps(x, sort_keys=True, ensure_ascii=False) if isinstance(x, dict) else x
                    if k in seen:
                        continue
                    seen.add(k)
                    merged.append(x)
                dst[key] = merged
        if not dst.get("description") and src.get("description"):
            dst["description"] = src["description"]
        if not dst.get("url") and src.get("url"):
            dst["url"] = src["url"]
        for k in ("mitre_software_id", "language", "type"):
            if k in src and not dst.get(k):
                dst[k] = src[k]

    def _mitre_software_to_tools(
        self,
        software: list[dict],
        techs_by_id: dict[str, dict],
    ) -> list[dict]:
        out: list[dict] = []
        for sw in software:
            sw_id = sw.get("id") or ""
            if not sw_id:
                continue
            tool_id = f"{self.MITRE_PREFIX}{sw_id}"
            related_techs = list(sw.get("related_techniques") or [])

            # Тактики и фазы из связанных техник
            tactics_set: set[str] = set()
            attack_types_set: set[str] = set()
            cve_set: set[str] = set()
            for tid in related_techs:
                t = techs_by_id.get(tid)
                if not t:
                    continue
                for tac in t.get("tactics") or []:
                    tactics_set.add(tac)
                    for at in _normalize_tactic_to_attack_type(tac):
                        attack_types_set.add(at)
                for cve_id in (t.get("related_cve") or []):
                    cve_set.add(cve_id)

            phases = [_phase_for_tactic(t) for t in sorted(tactics_set)]

            sw_type = sw.get("type", "tool")
            type_label = "mitre_tool" if sw_type == "tool" else "mitre_malware"
            skill = "Advanced" if sw_type == "malware" else "Intermediate"

            commands_default = [
                f"# {sw.get('name', sw_id)} — обзор и техники применения",
                f"# Подробности и матрица техник: {sw.get('url', '')}".rstrip(),
                "",
                "# Найти конкретные техники, в которых используется это ПО, можно",
                "# по списку related_techniques в данной записи (Txxxx коды).",
            ]

            rec = {
                "id": tool_id,
                "mitre_software_id": sw_id,
                "name": sw.get("name", sw_id),
                "type": type_label,
                "description": sw.get("description", ""),
                "url": sw.get("url", ""),
                "applicable_attack_types": sorted(attack_types_set),
                "applicable_cve": sorted(cve_set)[:30],
                "commands": {"default": commands_default},
                "phases": phases or ["Эксплуатация"],
                "skill_level": skill,
                "os": list(sw.get("platforms") or []),
                "aliases": list(sw.get("aliases") or []),
                "related_techniques": related_techs[:50],
                "groups_using": list(sw.get("groups_using") or []),
                "language": "ru",
                "source": "MITRE ATT&CK",
                "version": sw.get("version", ""),
            }
            out.append(rec)
        return out


__all__ = ["AttackDbBuilder"]
