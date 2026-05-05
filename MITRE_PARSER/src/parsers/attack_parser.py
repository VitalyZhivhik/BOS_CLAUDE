"""
Парсер MITRE ATT&CK STIX 2.1 (enterprise-attack.json).

Извлекает:
  • techniques (attack-pattern) — со всеми «x_mitre_*» полями, тактиками,
    подтехниками, source/target relationships, software_used, groups_using,
    mitigations_detailed, examples (procedures), references.
  • software (tool / malware) — S-коды.
  • mitigations (course-of-action) — M-коды.
  • groups (intrusion-set) — G-коды.

Возвращает четыре списка: techniques, software, mitigations, groups —
все с подробной структурой и ВСЕ ID в каноническом виде (Txxxx, Sxxxx, Mxxxx, Gxxxx).
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from config import Config
from parsers.base import clean_html


_REVOKED_KEYS = ("revoked", "x_mitre_deprecated")


def _is_dropped(obj: dict) -> bool:
    return any(bool(obj.get(k)) for k in _REVOKED_KEYS)


def _mitre_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if ext:
                return ext
    return None


def _attack_url(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return ""


def _all_external_refs(obj: dict) -> list[dict]:
    out: list[dict] = []
    for ref in obj.get("external_references", []) or []:
        out.append({
            "source_name": ref.get("source_name", ""),
            "external_id": ref.get("external_id", ""),
            "url": ref.get("url", ""),
            "description": clean_html(ref.get("description", "")),
        })
    return out


class AttackStixParser:
    """Полный парсер enterprise-attack STIX bundle."""

    def parse(self, content: bytes | str | dict, offset: int = 0) -> dict[str, list[dict]]:
        data = self._load(content)
        objects: list[dict] = data.get("objects", []) or []
        print(f"  [ATT&CK] Загружено объектов STIX: {len(objects)}")

        # Индексы
        by_stix_id: dict[str, dict] = {o["id"]: o for o in objects if "id" in o}

        techniques_raw: list[dict] = []
        software_raw: list[dict] = []
        mitigations_raw: list[dict] = []
        groups_raw: list[dict] = []

        for obj in objects:
            if _is_dropped(obj):
                continue
            t = obj.get("type")
            if t == "attack-pattern":
                techniques_raw.append(obj)
            elif t in ("tool", "malware"):
                software_raw.append(obj)
            elif t == "course-of-action":
                mitigations_raw.append(obj)
            elif t == "intrusion-set":
                groups_raw.append(obj)

        # Карта родительских техник
        parent_by_mid: dict[str, dict] = {}
        for tech in techniques_raw:
            mid = _mitre_id(tech)
            if mid and "." not in mid:
                parent_by_mid[mid] = tech

        # Связи
        uses_software_to_tech: dict[str, list[str]] = defaultdict(list)
        uses_group_to_tech: dict[str, list[str]] = defaultdict(list)
        uses_group_to_software: dict[str, list[str]] = defaultdict(list)
        mitigates_mit_to_tech: dict[str, list[str]] = defaultdict(list)
        subtechnique_of: dict[str, str] = {}  # child_stix_id -> parent_stix_id
        revoked_to: dict[str, str] = {}

        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            rt = obj.get("relationship_type")
            src = obj.get("source_ref", "")
            tgt = obj.get("target_ref", "")
            if not src or not tgt:
                continue
            if rt == "uses":
                src_obj = by_stix_id.get(src) or {}
                tgt_obj = by_stix_id.get(tgt) or {}
                if tgt_obj.get("type") == "attack-pattern":
                    if src_obj.get("type") in ("tool", "malware"):
                        uses_software_to_tech[src].append(tgt)
                    elif src_obj.get("type") == "intrusion-set":
                        uses_group_to_tech[src].append(tgt)
                elif tgt_obj.get("type") in ("tool", "malware") and src_obj.get("type") == "intrusion-set":
                    uses_group_to_software[src].append(tgt)
            elif rt == "mitigates":
                mitigates_mit_to_tech[src].append(tgt)
            elif rt == "subtechnique-of":
                subtechnique_of[src] = tgt
            elif rt == "revoked-by":
                revoked_to[src] = tgt

        # Обратные индексы
        tech_to_software: dict[str, list[str]] = defaultdict(list)
        tech_to_groups: dict[str, list[str]] = defaultdict(list)
        tech_to_mitigations: dict[str, list[str]] = defaultdict(list)
        tech_to_subs: dict[str, list[str]] = defaultdict(list)
        software_to_groups: dict[str, list[str]] = defaultdict(list)

        for sw_id, techs in uses_software_to_tech.items():
            for t in techs:
                tech_to_software[t].append(sw_id)
        for grp_id, techs in uses_group_to_tech.items():
            for t in techs:
                tech_to_groups[t].append(grp_id)
        for mit_id, techs in mitigates_mit_to_tech.items():
            for t in techs:
                tech_to_mitigations[t].append(mit_id)
        for child, parent in subtechnique_of.items():
            tech_to_subs[parent].append(child)
        for grp_id, sws in uses_group_to_software.items():
            for sw in sws:
                software_to_groups[sw].append(grp_id)

        # Парсинг
        techniques = self._parse_techniques(
            techniques_raw,
            by_stix_id,
            parent_by_mid,
            tech_to_software,
            tech_to_groups,
            tech_to_mitigations,
            tech_to_subs,
        )
        software = self._parse_software(
            software_raw,
            by_stix_id,
            uses_software_to_tech,
            software_to_groups,
        )
        mitigations = self._parse_mitigations(
            mitigations_raw,
            by_stix_id,
            mitigates_mit_to_tech,
        )
        groups = self._parse_groups(
            groups_raw,
            by_stix_id,
            uses_group_to_tech,
            uses_group_to_software,
        )

        if offset > 0:
            techniques = techniques[offset:]
            print(f"  [ATT&CK] Смещение: {offset}, осталось techniques: {len(techniques)}")

        if Config.MAX_ATTACK_RECORDS > 0 and len(techniques) > Config.MAX_ATTACK_RECORDS:
            techniques = techniques[: Config.MAX_ATTACK_RECORDS]

        if Config.MAX_MITRE_SOFTWARE > 0 and len(software) > Config.MAX_MITRE_SOFTWARE:
            software = software[: Config.MAX_MITRE_SOFTWARE]
        if Config.MAX_MITRE_MITIGATIONS > 0 and len(mitigations) > Config.MAX_MITRE_MITIGATIONS:
            mitigations = mitigations[: Config.MAX_MITRE_MITIGATIONS]

        print(
            f"  [ATT&CK] Получено: techniques={len(techniques)}, "
            f"software={len(software)}, mitigations={len(mitigations)}, groups={len(groups)}"
        )
        return {
            "techniques": techniques,
            "software": software,
            "mitigations": mitigations,
            "groups": groups,
        }

    # ── Загрузка JSON ─────────────────────────────────────
    def _load(self, content: bytes | str | dict) -> dict[str, Any]:
        if isinstance(content, dict):
            return content
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            print(f"  [ATT&CK] Ошибка JSON: {e}")
            return {}

    # ── Техники ───────────────────────────────────────────
    def _parse_techniques(
        self,
        techniques_raw: list[dict],
        by_stix_id: dict[str, dict],
        parent_by_mid: dict[str, dict],
        tech_to_software: dict[str, list[str]],
        tech_to_groups: dict[str, list[str]],
        tech_to_mitigations: dict[str, list[str]],
        tech_to_subs: dict[str, list[str]],
    ) -> list[dict]:
        results: list[dict] = []
        for tech in techniques_raw:
            mid = _mitre_id(tech)
            if not mid:
                continue
            stix_id = tech.get("id")
            parent_tech = None
            if "." in mid:
                parent_tech = parent_by_mid.get(mid.split(".", 1)[0])

            # CWE / CAPEC из external_references
            related_cwe: list[str] = []
            related_capec: list[str] = []
            for ref in tech.get("external_references", []) or []:
                src = (ref.get("source_name") or "").lower()
                ext = ref.get("external_id") or ""
                if not ext:
                    continue
                if "cwe" in src:
                    related_cwe.append(ext if ext.startswith("CWE-") else f"CWE-{ext}")
                elif "capec" in src:
                    related_capec.append(ext if ext.startswith("CAPEC-") else f"CAPEC-{ext}")

            # Тактики (kill_chain_phases) — список
            tactics: list[str] = []
            for phase in tech.get("kill_chain_phases", []) or []:
                name = (phase.get("phase_name") or "").replace("-", " ").strip()
                if name:
                    tactics.append(name.title())
            if not tactics and parent_tech:
                for phase in parent_tech.get("kill_chain_phases", []) or []:
                    name = (phase.get("phase_name") or "").replace("-", " ").strip()
                    if name:
                        tactics.append(name.title())

            description = clean_html(tech.get("description") or (parent_tech or {}).get("description", ""))
            detection = clean_html(
                tech.get("x_mitre_detection") or (parent_tech or {}).get("x_mitre_detection", "")
            )
            platforms = tech.get("x_mitre_platforms") or (parent_tech or {}).get("x_mitre_platforms") or []
            data_sources = tech.get("x_mitre_data_sources") or (parent_tech or {}).get("x_mitre_data_sources") or []
            permissions = tech.get("x_mitre_permissions_required") or (parent_tech or {}).get("x_mitre_permissions_required") or []
            defense_bypassed = tech.get("x_mitre_defense_bypassed") or (parent_tech or {}).get("x_mitre_defense_bypassed") or []
            system_reqs = tech.get("x_mitre_system_requirements") or (parent_tech or {}).get("x_mitre_system_requirements") or []

            # Связанные объекты
            software_stix_ids = tech_to_software.get(stix_id, [])
            if not software_stix_ids and parent_tech:
                software_stix_ids = tech_to_software.get(parent_tech.get("id", ""), [])
            software_used = []
            for sid in software_stix_ids:
                so = by_stix_id.get(sid)
                if not so:
                    continue
                sm_id = _mitre_id(so)
                if sm_id:
                    software_used.append({
                        "id": sm_id,
                        "name": so.get("name", ""),
                        "type": so.get("type", ""),
                    })

            group_stix_ids = tech_to_groups.get(stix_id, [])
            if not group_stix_ids and parent_tech:
                group_stix_ids = tech_to_groups.get(parent_tech.get("id", ""), [])
            groups_using = []
            for gid in group_stix_ids:
                go = by_stix_id.get(gid)
                if not go:
                    continue
                gm_id = _mitre_id(go)
                if gm_id:
                    groups_using.append({"id": gm_id, "name": go.get("name", "")})

            mit_stix_ids = tech_to_mitigations.get(stix_id, [])
            if not mit_stix_ids and parent_tech:
                mit_stix_ids = tech_to_mitigations.get(parent_tech.get("id", ""), [])
            mitigations_detailed = []
            mitigations_flat: list[str] = []
            for mid_stix in mit_stix_ids:
                mo = by_stix_id.get(mid_stix)
                if not mo:
                    continue
                m_mid = _mitre_id(mo)
                m_name = mo.get("name", "")
                m_desc = clean_html(mo.get("description", ""))
                if m_mid:
                    mitigations_detailed.append({
                        "id": m_mid,
                        "name": m_name,
                        "description": m_desc,
                    })
                if m_name:
                    mitigations_flat.append(m_name)
                if m_desc:
                    mitigations_flat.extend(
                        [p.strip() for p in m_desc.split("\n\n") if p.strip()]
                    )

            # Подтехники
            sub_stix_ids = tech_to_subs.get(stix_id, [])
            subtechniques = []
            for sub_sid in sub_stix_ids:
                so = by_stix_id.get(sub_sid)
                if so:
                    sm = _mitre_id(so)
                    if sm:
                        subtechniques.append(sm)

            parent_mid = mid.split(".", 1)[0] if "." in mid else None

            # Простой эвристический extractor: какие сервисы упоминаются
            requires_service = self._extract_services(platforms, description)

            results.append({
                "id": mid,
                "name": tech.get("name", "").strip(),
                "tactic": tactics[0] if tactics else "",
                "tactics": tactics,
                "description": description,
                "platforms": list(platforms),
                "data_sources": list(data_sources),
                "permissions_required": list(permissions),
                "defense_bypassed": list(defense_bypassed),
                "system_requirements": list(system_reqs),
                "related_cwe": sorted(set(related_cwe)),
                "related_capec": sorted(set(related_capec)),
                "requires_service": requires_service,
                "detection": detection,
                "mitigations": list(dict.fromkeys(mitigations_flat))[:20],
                "mitigations_detailed": mitigations_detailed,
                "software_used": software_used,
                "groups_using": groups_using,
                "subtechniques": subtechniques,
                "parent_technique": parent_mid,
                "is_subtechnique": bool(parent_mid),
                "url": _attack_url(tech),
                "references": _all_external_refs(tech),
                "version": tech.get("x_mitre_version", ""),
                "created": tech.get("created", ""),
                "modified": tech.get("modified", ""),
            })
        return results

    def _extract_services(self, platforms: list, description: str) -> list[str]:
        services: set[str] = set()
        plat_map = {
            "windows": "windows_os",
            "linux": "linux_os",
            "macos": "macos_os",
            "azure": "cloud_identity",
            "office 365": "office365",
            "containers": "container_runtime",
            "google workspace": "google_workspace",
        }
        for p in platforms or []:
            pl = (p or "").lower()
            for k, v in plat_map.items():
                if k in pl:
                    services.add(v)
        svc_map = {
            "web server": "web_server",
            "database": "database",
            "active directory": "active_directory",
            "ssh": "ssh",
            "rdp": "rdp",
            "smb": "smb",
            "powershell": "powershell",
            "api": "api_service",
            "kerberos": "kerberos",
            "ldap": "ldap",
            "dns": "dns",
            "smtp": "smtp",
            "ftp": "ftp",
        }
        desc_l = (description or "").lower()
        for k, v in svc_map.items():
            if k in desc_l:
                services.add(v)
        return sorted(services)

    # ── Software ──────────────────────────────────────────
    def _parse_software(
        self,
        software_raw: list[dict],
        by_stix_id: dict[str, dict],
        uses_software_to_tech: dict[str, list[str]],
        software_to_groups: dict[str, list[str]],
    ) -> list[dict]:
        results: list[dict] = []
        for so in software_raw:
            sm_id = _mitre_id(so)
            if not sm_id:
                continue
            stix_id = so.get("id", "")
            tech_stix_ids = uses_software_to_tech.get(stix_id, [])
            related_techniques = []
            for t_sid in tech_stix_ids:
                to = by_stix_id.get(t_sid)
                if not to:
                    continue
                tm = _mitre_id(to)
                if tm:
                    related_techniques.append(tm)

            group_stix_ids = software_to_groups.get(stix_id, [])
            groups_using = []
            for g_sid in group_stix_ids:
                go = by_stix_id.get(g_sid)
                if not go:
                    continue
                gm = _mitre_id(go)
                if gm:
                    groups_using.append({"id": gm, "name": go.get("name", "")})

            results.append({
                "id": sm_id,  # S0002, S0029...
                "name": so.get("name", "").strip(),
                "type": so.get("type", ""),  # tool / malware
                "labels": list(so.get("labels") or []),
                "aliases": list(so.get("x_mitre_aliases") or so.get("aliases") or []),
                "description": clean_html(so.get("description", "")),
                "platforms": list(so.get("x_mitre_platforms") or []),
                "related_techniques": sorted(set(related_techniques)),
                "groups_using": groups_using,
                "url": _attack_url(so),
                "references": _all_external_refs(so),
                "version": so.get("x_mitre_version", ""),
            })
        return results

    # ── Mitigations ──────────────────────────────────────
    def _parse_mitigations(
        self,
        mitigations_raw: list[dict],
        by_stix_id: dict[str, dict],
        mitigates_mit_to_tech: dict[str, list[str]],
    ) -> list[dict]:
        results: list[dict] = []
        for mo in mitigations_raw:
            mm_id = _mitre_id(mo)
            if not mm_id:
                continue
            stix_id = mo.get("id", "")
            tech_stix_ids = mitigates_mit_to_tech.get(stix_id, [])
            related_techniques = []
            for t_sid in tech_stix_ids:
                to = by_stix_id.get(t_sid)
                if not to:
                    continue
                tm = _mitre_id(to)
                if tm:
                    related_techniques.append(tm)
            results.append({
                "id": mm_id,
                "name": mo.get("name", "").strip(),
                "description": clean_html(mo.get("description", "")),
                "related_techniques": sorted(set(related_techniques)),
                "url": _attack_url(mo),
                "references": _all_external_refs(mo),
                "version": mo.get("x_mitre_version", ""),
            })
        return results

    # ── Groups ───────────────────────────────────────────
    def _parse_groups(
        self,
        groups_raw: list[dict],
        by_stix_id: dict[str, dict],
        uses_group_to_tech: dict[str, list[str]],
        uses_group_to_software: dict[str, list[str]],
    ) -> list[dict]:
        results: list[dict] = []
        for go in groups_raw:
            gm_id = _mitre_id(go)
            if not gm_id:
                continue
            stix_id = go.get("id", "")
            tech_ids = []
            for t_sid in uses_group_to_tech.get(stix_id, []):
                to = by_stix_id.get(t_sid)
                if not to:
                    continue
                tm = _mitre_id(to)
                if tm:
                    tech_ids.append(tm)
            software_ids = []
            for s_sid in uses_group_to_software.get(stix_id, []):
                so = by_stix_id.get(s_sid)
                if not so:
                    continue
                sm = _mitre_id(so)
                if sm:
                    software_ids.append(sm)
            results.append({
                "id": gm_id,
                "name": go.get("name", "").strip(),
                "aliases": list(go.get("aliases") or []),
                "description": clean_html(go.get("description", "")),
                "related_techniques": sorted(set(tech_ids)),
                "related_software": sorted(set(software_ids)),
                "url": _attack_url(go),
                "references": _all_external_refs(go),
            })
        return results


__all__ = ["AttackStixParser"]
