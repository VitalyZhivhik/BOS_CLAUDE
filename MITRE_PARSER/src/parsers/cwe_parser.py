"""
Парсер CWE v4.x (XML).

Извлекает: Description, Extended_Description, Common_Consequences,
Modes_Of_Introduction, Applicable_Platforms (Languages/OSes/Architectures/
Technologies), Likelihood_Of_Exploit, Demonstrative_Examples (краткие),
Observed_Examples (с CVE), Detection_Methods (с описанием/эффективностью),
Potential_Mitigations (Phase/Strategy/Description/Effectiveness),
Related_Weaknesses, Related_Attack_Patterns (CAPEC).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from config import Config
from parsers.base import clean_html, find_all, find_one, text_of, trunc


class CweParser:
    NAMESPACE = "http://cwe.mitre.org/cwe-7"

    def parse(self, xml_content: bytes, offset: int = 0) -> list[dict]:
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            print(f"  [CWE] Ошибка XML: {e}")
            return []

        ns = self.NAMESPACE
        weaknesses = root.findall(f".//{{{ns}}}Weakness")
        print(f"  [CWE] Найдено Weakness: {len(weaknesses)}")

        if offset > 0:
            weaknesses = weaknesses[offset:]
            print(f"  [CWE] Смещение: {offset}, осталось: {len(weaknesses)}")

        if Config.MAX_CWE_RECORDS > 0 and len(weaknesses) > Config.MAX_CWE_RECORDS:
            weaknesses = weaknesses[: Config.MAX_CWE_RECORDS]
            print(f"  [CWE] Лимит: {Config.MAX_CWE_RECORDS}")

        results: list[dict] = []
        for w in weaknesses:
            item = self._parse_weakness(w, ns)
            if item:
                results.append(item)
        print(f"  [CWE] Готово: {len(results)} записей")
        return results

    def _parse_weakness(self, elem: ET.Element, ns: str) -> dict | None:
        wid = (elem.get("ID") or "").strip()
        if not wid:
            return None
        status = (elem.get("Status") or "").strip()
        if status.lower() in ("deprecated", "obsolete"):
            return None

        item: dict = {
            "id": f"CWE-{wid}",
            "name": (elem.get("Name") or "").strip(),
            "abstraction": (elem.get("Abstraction") or "").strip(),
            "structure": (elem.get("Structure") or "").strip(),
            "status": status,
            "category": (elem.get("Abstraction") or elem.get("Structure") or "unknown").strip().lower(),
            "description": "",
            "extended_description": "",
            "likelihood_of_exploit": "",
            "common_consequences": [],
            "modes_of_introduction": [],
            "applicable_platforms": {
                "languages": [],
                "operating_systems": [],
                "architectures": [],
                "technologies": [],
            },
            "demonstrative_examples": [],
            "observed_examples": [],  # → также копируется в related_cve
            "related_cve": [],
            "related_capec": [],
            "related_weaknesses": [],
            "detection_methods": [],
            "detection_methods_detailed": [],
            "mitigation": "",
            "mitigations_detailed": [],
            "requires_technology": [],
        }

        # Description / Extended
        desc = find_one(elem, ns, "Description")
        if desc is not None:
            item["description"] = text_of(desc)
        ext = find_one(elem, ns, "Extended_Description")
        if ext is not None:
            item["extended_description"] = text_of(ext)

        # Likelihood
        lo = find_one(elem, ns, "Likelihood_Of_Exploit")
        if lo is not None and lo.text:
            item["likelihood_of_exploit"] = lo.text.strip()

        # Common_Consequences
        for cons in find_all(elem, ns, "Consequence"):
            scopes = [text_of(s) for s in find_all(cons, ns, "Scope")]
            impacts = [text_of(s) for s in find_all(cons, ns, "Impact")]
            note = text_of(find_one(cons, ns, "Note"))
            entry = {
                "scope": [s for s in scopes if s],
                "impact": [s for s in impacts if s],
                "note": note,
            }
            if any(entry.values()):
                item["common_consequences"].append(entry)

        # Modes_Of_Introduction
        moi_container = elem.find(f"{{{ns}}}Modes_Of_Introduction")
        if moi_container is not None:
            for intr in moi_container.findall(f"{{{ns}}}Introduction"):
                phase = text_of(find_one(intr, ns, "Phase"))
                note = text_of(find_one(intr, ns, "Note"))
                if phase or note:
                    item["modes_of_introduction"].append({"phase": phase, "note": note})

        # Applicable_Platforms
        ap_container = elem.find(f"{{{ns}}}Applicable_Platforms")
        if ap_container is not None:
            for ch in ap_container:
                tag = ch.tag.split("}", 1)[-1]  # без namespace
                name = (ch.get("Name") or ch.get("Class") or "").strip()
                if not name:
                    continue
                key_map = {
                    "Language": "languages",
                    "Operating_System": "operating_systems",
                    "Architecture": "architectures",
                    "Technology": "technologies",
                }
                key = key_map.get(tag)
                if key:
                    item["applicable_platforms"][key].append(name)
                    if key == "technologies":
                        item["requires_technology"].append(name.lower())

        # Demonstrative_Examples (берём краткие фрагменты Intro_Text)
        for ex in find_all(elem, ns, "Demonstrative_Example"):
            intro = find_one(ex, ns, "Intro_Text")
            if intro is not None:
                t = text_of(intro)
                if t:
                    item["demonstrative_examples"].append(trunc(t, 400))

        # Observed_Examples
        for ox in find_all(elem, ns, "Observed_Example"):
            ref = text_of(find_one(ox, ns, "Reference"))
            description = text_of(find_one(ox, ns, "Description"))
            link = text_of(find_one(ox, ns, "Link"))
            if ref:
                cve = ref.upper()
                if not cve.startswith("CVE-"):
                    cve = f"CVE-{cve}"
                item["observed_examples"].append({
                    "cve_id": cve,
                    "description": description,
                    "link": link,
                })
                item["related_cve"].append(cve)

        # Related_Attack_Patterns (CAPEC)
        for rap_container in find_all(elem, ns, "Related_Attack_Patterns"):
            for rap in find_all(rap_container, ns, "Related_Attack_Pattern"):
                cap = rap.get("CAPEC_ID")
                if cap:
                    item["related_capec"].append(f"CAPEC-{cap}")

        # Related_Weaknesses
        for rw_container in find_all(elem, ns, "Related_Weaknesses"):
            for rw in find_all(rw_container, ns, "Related_Weakness"):
                other = rw.get("CWE_ID")
                nature = rw.get("Nature", "")
                if other:
                    item["related_weaknesses"].append({
                        "nature": nature,
                        "id": f"CWE-{other}",
                    })

        # Detection_Methods (детально)
        det_container = elem.find(f"{{{ns}}}Detection_Methods")
        if det_container is not None:
            for det in det_container.findall(f"{{{ns}}}Detection_Method"):
                method = text_of(find_one(det, ns, "Method"))
                description = text_of(find_one(det, ns, "Description"))
                effectiveness = text_of(find_one(det, ns, "Effectiveness"))
                if method or description:
                    item["detection_methods_detailed"].append({
                        "method": method,
                        "description": description,
                        "effectiveness": effectiveness,
                    })
                    if method:
                        item["detection_methods"].append(method.lower().replace(" ", "_"))

        # Potential_Mitigations
        mit_container = elem.find(f"{{{ns}}}Potential_Mitigations")
        mit_texts: list[str] = []
        if mit_container is not None:
            for m in mit_container.findall(f"{{{ns}}}Mitigation"):
                phases = [text_of(p) for p in find_all(m, ns, "Phase")]
                strategy = text_of(find_one(m, ns, "Strategy"))
                description = text_of(find_one(m, ns, "Description"))
                effectiveness = text_of(find_one(m, ns, "Effectiveness"))
                effectiveness_notes = text_of(find_one(m, ns, "Effectiveness_Notes"))
                if description or strategy:
                    item["mitigations_detailed"].append({
                        "phase": [p for p in phases if p],
                        "strategy": strategy,
                        "description": description,
                        "effectiveness": effectiveness,
                        "effectiveness_notes": effectiveness_notes,
                    })
                    if description:
                        mit_texts.append(description)
        if mit_texts:
            item["mitigation"] = "; ".join(mit_texts[:3])

        # Уникализация
        item["related_capec"] = sorted(set(item["related_capec"]))
        item["related_cve"] = sorted(set(item["related_cve"]))
        item["requires_technology"] = sorted(set(item["requires_technology"]))

        return item


__all__ = ["CweParser"]
