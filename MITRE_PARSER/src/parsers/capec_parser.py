"""
Парсер CAPEC v3.x (XML).

Извлекает все ключевые поля: Description, Extended_Description, Likelihood_Of_Attack,
Typical_Severity, Execution_Flow (с шагами), Prerequisites, Skills_Required,
Resources_Required, Indicators, Consequences, Example_Instances,
Related_Weaknesses (CWE), Related_Attack_Patterns (CAPEC),
Taxonomy_Mappings (включая ATT&CK), Mitigations, Abstraction.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from config import Config
from parsers.base import clean_html, find_all, find_one, text_of


class CapecParser:
    NAMESPACE = "http://capec.mitre.org/capec-3"

    def parse(self, xml_content: bytes, offset: int = 0) -> list[dict]:
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            print(f"  [CAPEC] Ошибка XML: {e}")
            return []

        ns = self.NAMESPACE
        patterns = root.findall(f".//{{{ns}}}Attack_Pattern")
        print(f"  [CAPEC] Найдено Attack_Pattern: {len(patterns)}")

        if offset > 0:
            patterns = patterns[offset:]
            print(f"  [CAPEC] Смещение: {offset}, осталось: {len(patterns)}")

        if Config.MAX_CAPEC_RECORDS > 0 and len(patterns) > Config.MAX_CAPEC_RECORDS:
            patterns = patterns[: Config.MAX_CAPEC_RECORDS]
            print(f"  [CAPEC] Лимит: {Config.MAX_CAPEC_RECORDS}")

        results: list[dict] = []
        for elem in patterns:
            item = self._parse_pattern(elem, ns)
            if item:
                results.append(item)
        print(f"  [CAPEC] Готово: {len(results)} записей")
        return results

    def _parse_pattern(self, elem: ET.Element, ns: str) -> dict | None:
        capec_id = elem.get("ID", "").strip()
        if not capec_id:
            return None
        status = (elem.get("Status") or "").strip()
        if status.lower() in ("deprecated",):
            return None

        item: dict = {
            "id": f"CAPEC-{capec_id}",
            "name": (elem.get("Name") or "").strip(),
            "abstraction": (elem.get("Abstraction") or "").strip(),
            "status": status,
            "description": "",
            "extended_description": "",
            "severity": "UNKNOWN",
            "likelihood_of_attack": "",
            "typical_likelihood_of_exploit": "",
            "prerequisites": [],
            "skills_required": [],
            "resources_required": [],
            "indicators": [],
            "consequences": [],
            "execution_flow": [],
            "example_instances": [],
            "related_cwe": [],
            "related_attack_patterns": [],
            "related_mitre": [],  # заполняется через cross_linker
            "taxonomy_mappings": [],
            "mitigations": [],
        }

        # Description / Extended_Description
        desc = find_one(elem, ns, "Description")
        if desc is not None:
            item["description"] = text_of(desc)
        ext = find_one(elem, ns, "Extended_Description")
        if ext is not None:
            item["extended_description"] = text_of(ext)

        # Severity / Likelihood
        sev = find_one(elem, ns, "Typical_Severity")
        if sev is not None and sev.text:
            item["severity"] = sev.text.strip().upper()
        lh = find_one(elem, ns, "Likelihood_Of_Attack")
        if lh is not None and lh.text:
            item["likelihood_of_attack"] = lh.text.strip()
        lh2 = find_one(elem, ns, "Typical_Likelihood_Of_Exploit")
        if lh2 is not None and lh2.text:
            item["typical_likelihood_of_exploit"] = lh2.text.strip()

        # Prerequisites
        for pr in find_all(elem, ns, "Prerequisite"):
            t = text_of(pr)
            if t:
                item["prerequisites"].append(t)

        # Skills_Required
        for sk in find_all(elem, ns, "Skill"):
            level = (sk.get("Level") or "").strip()
            note = text_of(sk)
            if level or note:
                item["skills_required"].append({"level": level, "description": note})

        # Resources_Required
        for rs in find_all(elem, ns, "Resource"):
            t = text_of(rs)
            if t:
                item["resources_required"].append(t)

        # Indicators
        for ind in find_all(elem, ns, "Indicator"):
            t = text_of(ind)
            if t:
                item["indicators"].append(t)

        # Consequences
        for cons in find_all(elem, ns, "Consequence"):
            scopes = [text_of(s) for s in find_all(cons, ns, "Scope")]
            impacts = [text_of(s) for s in find_all(cons, ns, "Impact")]
            note = text_of(find_one(cons, ns, "Note"))
            entry = {
                "scope": [s for s in scopes if s],
                "impact": [s for s in impacts if s],
                "note": note,
            }
            if entry["scope"] or entry["impact"] or entry["note"]:
                item["consequences"].append(entry)

        # Execution_Flow (Attack_Step)
        for step in find_all(elem, ns, "Attack_Step"):
            step_no = text_of(find_one(step, ns, "Step"))
            phase = text_of(find_one(step, ns, "Phase"))
            description = text_of(find_one(step, ns, "Description"))
            techs = [text_of(t) for t in find_all(step, ns, "Technique")]
            entry = {
                "step": step_no,
                "phase": phase,
                "description": description,
                "techniques": [t for t in techs if t],
            }
            if any(entry.values()):
                item["execution_flow"].append(entry)

        # Related_Weaknesses
        for rw in find_all(elem, ns, "Related_Weakness"):
            cwe_id = rw.get("CWE_ID")
            if cwe_id:
                item["related_cwe"].append(f"CWE-{cwe_id}")

        # Related_Attack_Patterns
        for rap in find_all(elem, ns, "Related_Attack_Pattern"):
            other = rap.get("CAPEC_ID")
            nature = rap.get("Nature", "")
            if other:
                item["related_attack_patterns"].append({
                    "nature": nature,
                    "id": f"CAPEC-{other}",
                })

        # Taxonomy_Mappings (ATT&CK + другие)
        for tm in find_all(elem, ns, "Taxonomy_Mapping"):
            taxo = tm.get("Taxonomy_Name", "")
            entry_id = text_of(find_one(tm, ns, "Entry_ID"))
            entry_name = text_of(find_one(tm, ns, "Entry_Name"))
            mapping_fit = text_of(find_one(tm, ns, "Mapping_Fit"))
            obj = {
                "taxonomy": taxo,
                "entry_id": entry_id,
                "entry_name": entry_name,
                "mapping_fit": mapping_fit,
            }
            item["taxonomy_mappings"].append(obj)
            # Если это ATT&CK — копируем в related_mitre сразу
            if taxo.upper() == "ATTACK" and entry_id:
                tid = entry_id.strip()
                if re.fullmatch(r"\d{4}(\.\d{3})?", tid):
                    item["related_mitre"].append(f"T{tid}")
                elif tid.upper().startswith("T"):
                    item["related_mitre"].append(tid.upper())

        # Example_Instances
        for ex in find_all(elem, ns, "Example"):
            t = text_of(ex)
            if t:
                item["example_instances"].append(t)

        # Mitigations
        mitigations_container = elem.find(f"{{{ns}}}Mitigations")
        if mitigations_container is not None:
            for m in mitigations_container.findall(f"{{{ns}}}Mitigation"):
                t = text_of(m)
                if t:
                    item["mitigations"].append(t)

        # Уникализация
        item["related_cwe"] = sorted(set(item["related_cwe"]))
        item["related_mitre"] = sorted(set(item["related_mitre"]))

        return item


__all__ = ["CapecParser"]
