"""
Парсер NVD CVE 2.0 JSON фида.

Извлекает: id, опубликовано/изменено, описание (EN+RU), CVSS v2 и v3 раздельно
со всеми компонентами вектора, related_cwe, references с категоризацией
(exploit/patch/advisory/vendor/third-party), exploit_available, exploit_db_ids,
affected_software (краткий список) и affected_versions (детальный),
attack_type / requires_service / requires_port (эвристики).
"""
from __future__ import annotations

import re
from typing import Any

from config import Config
from parsers.base import clean_html


_EXPLOIT_TAGS = {"Exploit", "Issue Tracking", "Third Party Advisory"}
_PATCH_TAGS = {"Patch", "Vendor Advisory", "Mitigation"}


class CveParser:
    def parse(self, nvd_data: dict, offset: int = 0) -> list[dict]:
        vulns = nvd_data.get("vulnerabilities", []) or []
        print(f"  [CVE] CVE в фиде: {len(vulns)}")

        if offset > 0:
            vulns = vulns[offset:]
            print(f"  [CVE] Смещение: {offset}, осталось: {len(vulns)}")

        if Config.MAX_CVE_RECORDS > 0 and len(vulns) > Config.MAX_CVE_RECORDS:
            vulns = vulns[: Config.MAX_CVE_RECORDS]
            print(f"  [CVE] Лимит: {Config.MAX_CVE_RECORDS}")

        results: list[dict] = []
        for wrapper in vulns:
            cve_obj = wrapper.get("cve") or {}
            item = self._parse(cve_obj)
            if item:
                results.append(item)
        print(f"  [CVE] Готово: {len(results)} записей")
        return results

    def _parse(self, cve: dict) -> dict | None:
        cve_id = cve.get("id") or ""
        if not cve_id:
            return None

        # ── Описание ──
        description = ""
        for d in cve.get("descriptions", []) or []:
            if (d.get("lang") or "").startswith("en"):
                description = (d.get("value") or "").strip()
                break
        if not description and cve.get("descriptions"):
            description = (cve["descriptions"][0].get("value") or "").strip()

        # ── CVSS v2/v3 ──
        cvss_v2 = self._extract_cvss(cve, "cvssMetricV2")
        cvss_v3 = (
            self._extract_cvss(cve, "cvssMetricV31")
            or self._extract_cvss(cve, "cvssMetricV30")
        )

        # Сводные поля (для совместимости)
        if cvss_v3:
            cvss_score = float(cvss_v3.get("score") or 0.0)
            severity = (cvss_v3.get("severity") or "UNKNOWN").upper()
        elif cvss_v2:
            cvss_score = float(cvss_v2.get("score") or 0.0)
            severity = (cvss_v2.get("severity") or "UNKNOWN").upper()
        else:
            cvss_score = 0.0
            severity = "UNKNOWN"

        # ── CWE ──
        related_cwe: list[str] = []
        for w in cve.get("weaknesses", []) or []:
            for desc_w in w.get("description", []) or []:
                val = (desc_w.get("value") or "").strip().upper()
                if val.startswith("CWE-"):
                    related_cwe.append(val)
        related_cwe = sorted(set(related_cwe))

        # ── Affected software / versions ──
        affected_software: set[str] = set()
        affected_versions: list[dict] = []
        for conf in cve.get("configurations", []) or []:
            for node in conf.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    if not match.get("vulnerable"):
                        continue
                    cpe = match.get("criteria") or ""
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        ver = parts[5] if len(parts) > 5 else "*"
                        affected_software.add(f"{vendor} {product}".strip())
                        affected_versions.append({
                            "vendor": vendor,
                            "product": product,
                            "version": ver if ver != "*" else "",
                            "version_start_including": match.get("versionStartIncluding", ""),
                            "version_start_excluding": match.get("versionStartExcluding", ""),
                            "version_end_including": match.get("versionEndIncluding", ""),
                            "version_end_excluding": match.get("versionEndExcluding", ""),
                        })

        # ── References (категоризация) ──
        refs_categorized = {
            "exploit": [], "patch": [], "advisory": [],
            "vendor": [], "third_party": [], "other": [],
        }
        exploit_db_ids: list[str] = []
        for ref in cve.get("references", []) or []:
            url = ref.get("url") or ""
            tags = set(ref.get("tags") or [])
            entry = {"url": url, "tags": sorted(tags), "source": ref.get("source", "")}
            if "Exploit" in tags or "exploit-db.com" in url:
                refs_categorized["exploit"].append(entry)
                m = re.search(r"exploit-db\.com/exploits/(\d+)", url)
                if m:
                    exploit_db_ids.append(m.group(1))
            if "Patch" in tags:
                refs_categorized["patch"].append(entry)
            if "Vendor Advisory" in tags:
                refs_categorized["vendor"].append(entry)
                refs_categorized["advisory"].append(entry)
            if "Third Party Advisory" in tags:
                refs_categorized["third_party"].append(entry)
                refs_categorized["advisory"].append(entry)
            if not (tags & (_EXPLOIT_TAGS | _PATCH_TAGS)):
                refs_categorized["other"].append(entry)

        exploit_available = bool(refs_categorized["exploit"]) or bool(exploit_db_ids)

        # Эвристики
        desc_lower = description.lower()
        attack_type = self._detect_attack_type(desc_lower)
        services, ports = self._extract_services_ports(desc_lower)

        item = {
            "id": cve_id,
            "description": description,
            "description_en": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_v2": cvss_v2 or {},
            "cvss_v3": cvss_v3 or {},
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "vuln_status": cve.get("vulnStatus", ""),
            "affected_software": list(sorted(affected_software))[:10],
            "affected_versions": affected_versions[:25],
            "attack_type": attack_type,
            "related_cwe": related_cwe,
            "related_capec": [],
            "related_mitre": [],
            "related_tools": [],
            "related_defense": [],
            "mitigations": [],
            "requires_service": services,
            "requires_port": ports,
            "prerequisites": [],
            "references_categorized": refs_categorized,
            "exploit_available": exploit_available,
            "exploit_db_ids": exploit_db_ids,
        }
        return item

    def _extract_cvss(self, cve: dict, key: str) -> dict | None:
        metrics = (cve.get("metrics") or {}).get(key) or []
        if not metrics:
            return None
        first = metrics[0]
        data = first.get("cvssData") or {}
        return {
            "version": data.get("version", ""),
            "vector": data.get("vectorString", ""),
            "score": data.get("baseScore", 0.0),
            "severity": (data.get("baseSeverity")
                         or first.get("baseSeverity")
                         or "").upper() or "UNKNOWN",
            "attack_vector": data.get("attackVector", ""),
            "attack_complexity": data.get("attackComplexity", ""),
            "privileges_required": data.get("privilegesRequired", ""),
            "user_interaction": data.get("userInteraction", ""),
            "scope": data.get("scope", ""),
            "confidentiality_impact": data.get("confidentialityImpact", ""),
            "integrity_impact": data.get("integrityImpact", ""),
            "availability_impact": data.get("availabilityImpact", ""),
            "exploitability_score": first.get("exploitabilityScore", 0.0),
            "impact_score": first.get("impactScore", 0.0),
        }

    def _detect_attack_type(self, desc: str) -> str:
        rules = [
            (("sql injection", "sqli", "blind sql"), "sql_injection"),
            (("xss", "cross-site scripting", "cross site scripting"), "cross_site_scripting"),
            (("csrf", "cross-site request forgery"), "cross_site_request_forgery"),
            (("ssrf", "server-side request forgery"), "server_side_request_forgery"),
            (("xxe",), "xxe_injection"),
            (("path traversal", "directory traversal", "..\\", "../"), "directory_traversal"),
            (("command injection", "os command injection", "shell injection"), "command_injection"),
            (("remote code execution", "rce", "arbitrary code execution"), "remote_code_execution"),
            (("privilege escalation", "elevation of privilege"), "privilege_escalation"),
            (("buffer overflow", "stack overflow", "heap overflow"), "buffer_overflow"),
            (("use after free",), "use_after_free"),
            (("denial of service", "dos attack", "ddos", "crash"), "denial_of_service"),
            (("brute force", "password guessing"), "brute_force"),
            (("authentication bypass", "auth bypass"), "authentication_bypass"),
            (("information disclosure", "information leak"), "information_disclosure"),
            (("deserialization", "untrusted deserialization"), "deserialization_attack"),
            (("file upload",), "unrestricted_file_upload"),
            (("race condition",), "race_condition"),
        ]
        for keywords, label in rules:
            if any(k in desc for k in keywords):
                return label
        return "unknown"

    def _extract_services_ports(self, desc: str) -> tuple[list[str], list[int]]:
        services: set[str] = set()
        ports: set[int] = set()
        for m in re.finditer(r"\b(?:port|порт)\s*(\d{1,5})\b", desc):
            try:
                p = int(m.group(1))
            except ValueError:
                continue
            if 1 <= p <= 65535:
                ports.add(p)
        svc_map = {
            "apache": "web_server", "nginx": "web_server", "iis": "web_server",
            "tomcat": "web_server", "mysql": "database", "postgres": "database",
            "mariadb": "database", "mssql": "database", "oracle": "database",
            "mongodb": "database", "redis": "database",
            "ssh": "ssh", "rdp": "rdp", "smb": "smb", "ftp": "ftp",
            "telnet": "telnet", "snmp": "snmp", "kerberos": "kerberos",
            "ldap": "ldap", "active directory": "active_directory",
            "exchange": "exchange_server", "sharepoint": "sharepoint",
            "jenkins": "jenkins", "gitlab": "gitlab", "wordpress": "wordpress",
            "drupal": "drupal", "joomla": "joomla", "vmware": "vmware",
            "hyper-v": "hyperv", "kubernetes": "kubernetes", "docker": "docker",
        }
        for k, v in svc_map.items():
            if k in desc:
                services.add(v)
        return sorted(services), sorted(ports)


__all__ = ["CveParser"]
