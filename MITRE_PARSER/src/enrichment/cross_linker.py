"""
Многопроходное идемпотентное связывание всех знаний:

  CVE  ──► CWE     (через related_cwe)
  CWE  ──► CAPEC   (через related_capec)
  CAPEC ↔  ATT&CK  (через related_mitre / related_capec)
  CWE  ──► CVE     (через observed_examples)
  CVE  ──► CAPEC   (через CWE)
  CVE  ──► ATT&CK  (через CWE→CAPEC)
  CVE/ATT&CK ──► tools / defense (после построения каталогов)
  ATT&CK ──► CWE   (через CAPEC.related_cwe)

Также:
  - распространение mitigations по цепочке;
  - наследование от MITRE-софта (software_used) → cve.related_tools и т.п.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable


def _to_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value] if value else []
    return [value]


def _uniq(seq: Iterable, limit: int = 50) -> list:
    seen = set()
    out = []
    for x in seq:
        key = x if not isinstance(x, dict) else tuple(sorted(x.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(x)
        if len(out) >= limit:
            break
    return out


def _add_unique(target: list, items: Iterable) -> int:
    """Добавляет items в target без дубликатов; возвращает кол-во новых."""
    if target is None:
        return 0
    seen = set(target)
    added = 0
    for x in items:
        if x not in seen:
            target.append(x)
            seen.add(x)
            added += 1
    return added


class CrossLinker:
    """
    Получает на вход все наборы dict-списков и выполняет связывание in-place.
    После работы у каждого объекта будут максимально полные списки related_*.
    """

    def __init__(
        self,
        capec: list[dict],
        cwe: list[dict],
        cve: list[dict],
        techniques: list[dict],
        software: list[dict] | None = None,
        mitre_mitigations: list[dict] | None = None,
    ) -> None:
        self.capec = capec
        self.cwe = cwe
        self.cve = cve
        self.techniques = techniques
        self.software = software or []
        self.mitre_mitigations = mitre_mitigations or []

        self.capec_by_id: dict[str, dict] = {x["id"]: x for x in self.capec if x.get("id")}
        self.cwe_by_id: dict[str, dict] = {x["id"]: x for x in self.cwe if x.get("id")}
        self.cve_by_id: dict[str, dict] = {x["id"]: x for x in self.cve if x.get("id")}
        self.tech_by_id: dict[str, dict] = {x["id"]: x for x in self.techniques if x.get("id")}
        self.software_by_id: dict[str, dict] = {x["id"]: x for x in self.software if x.get("id")}
        self.mit_by_id: dict[str, dict] = {x["id"]: x for x in self.mitre_mitigations if x.get("id")}

        self.stats: dict[str, int] = defaultdict(int)

    # ── Утилиты ───────────────────────────────────────────
    def _ensure_list(self, obj: dict, field: str) -> list:
        if field not in obj or not isinstance(obj[field], list):
            obj[field] = _to_list(obj.get(field))
        return obj[field]

    # ── Этапы связывания ──────────────────────────────────
    def _link_cve_to_cwe_chain(self) -> None:
        """CVE → CWE → CAPEC → ATT&CK + перенос mitigations."""
        for cve_id, cve_rec in self.cve_by_id.items():
            cwe_ids = list(cve_rec.get("related_cwe") or [])
            related_capec: set[str] = set()
            related_mitre: set[str] = set()
            mitigations: list = []
            cwe_existed = self._ensure_list(cve_rec, "related_cwe")
            for cwe_id in cwe_ids:
                cwe_rec = self.cwe_by_id.get(cwe_id)
                if not cwe_rec:
                    continue
                # Из CWE собираем CAPEC
                for cap in cwe_rec.get("related_capec", []) or []:
                    related_capec.add(cap)
                # Из mitigation
                if cwe_rec.get("mitigation"):
                    mitigations.append(cwe_rec["mitigation"])
                # И детальные
                for m in cwe_rec.get("mitigations_detailed", []) or []:
                    if m.get("description"):
                        mitigations.append(m["description"])
                # Обратно в CWE: запомним CVE
                cve_list = self._ensure_list(cwe_rec, "related_cve")
                self.stats["cwe.related_cve"] += _add_unique(cve_list, [cve_id])

            # CAPEC → ATT&CK
            for cap_id in list(related_capec):
                cap = self.capec_by_id.get(cap_id)
                if not cap:
                    continue
                for tid in cap.get("related_mitre", []) or []:
                    related_mitre.add(tid)
                for m in cap.get("mitigations", []) or []:
                    mitigations.append(m)
                # Обратно: capec.related_cve
                self.stats["capec.related_cve"] += _add_unique(
                    self._ensure_list(cap, "related_cve"), [cve_id]
                )

            # ATT&CK
            for tid in list(related_mitre):
                t = self.tech_by_id.get(tid)
                if t:
                    for m in t.get("mitigations", []) or []:
                        mitigations.append(m)
                    self.stats["tech.related_cve"] += _add_unique(
                        self._ensure_list(t, "related_cve"), [cve_id]
                    )

            # Записываем
            cap_field = self._ensure_list(cve_rec, "related_capec")
            mit_field = self._ensure_list(cve_rec, "related_mitre")
            mitg_field = self._ensure_list(cve_rec, "mitigations")
            self.stats["cve.related_capec"] += _add_unique(cap_field, sorted(related_capec))
            self.stats["cve.related_mitre"] += _add_unique(mit_field, sorted(related_mitre))
            self.stats["cve.mitigations"] += _add_unique(mitg_field, mitigations)

    def _link_cwe_observed_examples_to_cve(self) -> None:
        """CWE.observed_examples → cve.related_cwe / mitigation enrichment."""
        for cwe_id, cwe_rec in self.cwe_by_id.items():
            for ex in cwe_rec.get("observed_examples", []) or []:
                cve_id = (ex.get("cve_id") or "").upper()
                if not cve_id:
                    continue
                cve_rec = self.cve_by_id.get(cve_id)
                if not cve_rec:
                    continue
                self.stats["cve.related_cwe(observed)"] += _add_unique(
                    self._ensure_list(cve_rec, "related_cwe"), [cwe_id]
                )

    def _link_capec_attck_bidirectional(self) -> None:
        """ATT&CK.related_capec ↔ CAPEC.related_mitre (двунаправленно)."""
        for tech_id, t in self.tech_by_id.items():
            for cap_id in t.get("related_capec", []) or []:
                cap = self.capec_by_id.get(cap_id)
                if not cap:
                    continue
                self.stats["capec.related_mitre"] += _add_unique(
                    self._ensure_list(cap, "related_mitre"), [tech_id]
                )
        for cap_id, cap in self.capec_by_id.items():
            for tech_id in cap.get("related_mitre", []) or []:
                t = self.tech_by_id.get(tech_id)
                if not t:
                    continue
                self.stats["tech.related_capec"] += _add_unique(
                    self._ensure_list(t, "related_capec"), [cap_id]
                )

    def _link_cwe_capec_bidirectional(self) -> None:
        """CWE.related_capec ↔ CAPEC.related_cwe."""
        for cwe_id, cwe in self.cwe_by_id.items():
            for cap_id in cwe.get("related_capec", []) or []:
                cap = self.capec_by_id.get(cap_id)
                if not cap:
                    continue
                self.stats["capec.related_cwe"] += _add_unique(
                    self._ensure_list(cap, "related_cwe"), [cwe_id]
                )
        for cap_id, cap in self.capec_by_id.items():
            for cwe_id in cap.get("related_cwe", []) or []:
                cwe = self.cwe_by_id.get(cwe_id)
                if not cwe:
                    continue
                self.stats["cwe.related_capec"] += _add_unique(
                    self._ensure_list(cwe, "related_capec"), [cap_id]
                )

    def _link_attck_to_cwe_via_capec(self) -> None:
        """ATT&CK ← CWE через CAPEC."""
        for tech_id, t in self.tech_by_id.items():
            cwe_ids: set[str] = set(t.get("related_cwe") or [])
            for cap_id in t.get("related_capec", []) or []:
                cap = self.capec_by_id.get(cap_id)
                if not cap:
                    continue
                for cwe_id in cap.get("related_cwe", []) or []:
                    cwe_ids.add(cwe_id)
            new = sorted(cwe_ids - set(t.get("related_cwe") or []))
            if new:
                self.stats["tech.related_cwe"] += _add_unique(
                    self._ensure_list(t, "related_cwe"), new
                )

    def _link_software_techniques(self) -> None:
        """Sync software.related_techniques ↔ technique.software_used."""
        for sw_id, sw in self.software_by_id.items():
            for tid in sw.get("related_techniques", []) or []:
                t = self.tech_by_id.get(tid)
                if not t:
                    continue
                # Добавим в software_used, если ещё нет
                cur_ids = {x.get("id") for x in t.get("software_used", []) if isinstance(x, dict)}
                if sw_id not in cur_ids:
                    t.setdefault("software_used", []).append({
                        "id": sw_id, "name": sw.get("name", ""), "type": sw.get("type", ""),
                    })
                    self.stats["tech.software_used"] += 1

    def _link_mitigations_to_techniques(self) -> None:
        """Sync mitigation.related_techniques → technique.mitigations_detailed."""
        for m_id, mit in self.mit_by_id.items():
            for tid in mit.get("related_techniques", []) or []:
                t = self.tech_by_id.get(tid)
                if not t:
                    continue
                cur_ids = {
                    x.get("id") for x in t.get("mitigations_detailed", [])
                    if isinstance(x, dict)
                }
                if m_id not in cur_ids:
                    t.setdefault("mitigations_detailed", []).append({
                        "id": m_id, "name": mit.get("name", ""),
                        "description": mit.get("description", ""),
                    })
                    self.stats["tech.mitigations_detailed"] += 1

    def _propagate_cve_to_software_and_mitigations(self) -> None:
        """
        Распространяем связи через ATT&CK:
          - cve.related_mitre + technique.software_used → cve.related_tools (S-коды)
          - cve.related_mitre + technique.mitigations_detailed → cve.related_defense (M-коды)
        """
        for cve_id, cve_rec in self.cve_by_id.items():
            tools = self._ensure_list(cve_rec, "related_tools")
            defense = self._ensure_list(cve_rec, "related_defense")
            for tid in cve_rec.get("related_mitre", []) or []:
                t = self.tech_by_id.get(tid)
                if not t:
                    continue
                for sw in t.get("software_used", []) or []:
                    if isinstance(sw, dict) and sw.get("id"):
                        if sw["id"] not in tools:
                            tools.append(sw["id"])
                            self.stats["cve.related_tools"] += 1
                for m in t.get("mitigations_detailed", []) or []:
                    if isinstance(m, dict) and m.get("id"):
                        if m["id"] not in defense:
                            defense.append(m["id"])
                            self.stats["cve.related_defense"] += 1

    # ── Главный запуск ────────────────────────────────────
    def run(self, passes: int = 2) -> dict:
        print(f"  [Linker] Запуск связывания ({passes} прохода)...")
        for i in range(passes):
            self._link_cwe_capec_bidirectional()
            self._link_capec_attck_bidirectional()
            self._link_cwe_observed_examples_to_cve()
            self._link_cve_to_cwe_chain()
            self._link_attck_to_cwe_via_capec()
            self._link_software_techniques()
            self._link_mitigations_to_techniques()
            self._propagate_cve_to_software_and_mitigations()
            print(f"    проход {i + 1}: добавлено связей всего = {sum(self.stats.values())}")
        result = dict(self.stats)
        print(f"  [Linker] Готово. Сводка: {result}")
        return result


__all__ = ["CrossLinker"]
