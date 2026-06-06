"""Загрузка и нормализация входных JSON в единый ScanContext.

Источники:
  - history/**/*.json        — внешние сканы атакующего (PortScan/Nmap/Nuclei/Parallel)
  - data/trivy_scan_*.json   — уязвимости пакетов (Trivy)
  - data/scan_history/scan_*.json — инвентаризация ПО на стенде
"""

from __future__ import annotations

import glob
import json
import os
import re

from .models import AttackVector, OpenPort, ScanContext, ServerConfig, TrivyVuln

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def _read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def parse_banner(service: str, banner: str) -> dict:
    """Извлекает продукт и версию из баннера/имени сервиса."""
    info: dict = {}
    text = f"{service} {banner}".lower()

    if "vmware authentication daemon" in text or "vmware-authd" in text:
        info["product"] = "vmware-authd"
        m = re.search(r"version\s+(\d+\.\d+(?:\.\d+)?)", text)
        if m:
            info["version"] = m.group(1)
    elif "mysql" in text or "caching_sha2_password" in text or "mysql_native_password" in text:
        info["product"] = "mysql"
    elif "ssh" in text:
        info["product"] = "ssh"
    elif "smb" in text:
        info["product"] = "smb"
    elif "rpc" in text:
        info["product"] = "rpc"

    if "version" not in info and banner:
        m = VERSION_RE.search(banner)
        if m:
            info["version"] = m.group(1)
    return info


def _extract_cves(*parts: str) -> list[str]:
    found: list[str] = []
    for part in parts:
        if part:
            found.extend(m.upper() for m in CVE_RE.findall(part))
    seen, out = set(), []
    for cve in found:
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def load_attacker(history_dir: str) -> tuple[dict[int, OpenPort], list[AttackVector], str]:
    """Объединяет все внешние сканы: union открытых портов и dedup векторов атак."""
    external: dict[int, OpenPort] = {}
    vectors: dict[tuple, AttackVector] = {}
    target_ip = ""

    for path in sorted(glob.glob(os.path.join(history_dir, "**", "*.json"), recursive=True)):
        try:
            data = _read_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        target_ip = target_ip or data.get("target_ip", "")

        for p in data.get("open_ports", []):
            port = p.get("port")
            if not port:
                continue
            existing = external.get(port)
            banner = p.get("banner", "") or ""
            service = p.get("service", "") or ""
            if existing is None:
                external[port] = OpenPort(port, service, banner, p.get("protocol", "TCP"))
            else:
                if not existing.banner and banner:
                    existing.banner = banner
                if (not existing.service or existing.service.lower() == "unknown") and service:
                    existing.service = service

        for av in data.get("attack_vectors", []):
            cves = _extract_cves(
                " ".join(av.get("representative_cve_ids", []) or []),
                av.get("name", ""),
                av.get("description", ""),
            )
            key = (av.get("name", ""), av.get("target_port"))
            if key in vectors:
                merged = vectors[key]
                for c in cves:
                    if c not in merged.cve_ids:
                        merged.cve_ids.append(c)
                if not merged.tools_used and av.get("tools_used"):
                    merged.tools_used = av.get("tools_used")
                continue
            vectors[key] = AttackVector(
                id=av.get("id", ""),
                name=av.get("name", ""),
                target_port=av.get("target_port"),
                target_service=av.get("target_service", ""),
                attack_type=av.get("attack_type", "") or "",
                severity=(av.get("severity") or "UNKNOWN").upper(),
                tools_used=av.get("tools_used", "") or "",
                description=av.get("description", "") or "",
                cve_ids=cves,
                inferred_product=av.get("inferred_product", "") or "",
            )

    return external, list(vectors.values()), target_ip


def load_trivy(data_dir: str) -> list[TrivyVuln]:
    """Загружает самый свежий отчёт Trivy."""
    files = sorted(glob.glob(os.path.join(data_dir, "trivy_scan_*.json")))
    if not files:
        return []
    data = _read_json(files[-1])
    out: list[TrivyVuln] = []
    for v in data.get("vulnerabilities", []):
        out.append(
            TrivyVuln(
                vuln_id=v.get("vuln_id", ""),
                pkg_name=v.get("pkg_name", ""),
                installed_version=v.get("installed_version", ""),
                fixed_version=v.get("fixed_version", ""),
                severity=(v.get("severity") or "UNKNOWN").upper(),
                title=v.get("title", ""),
                description=v.get("description", ""),
                cwe_ids=v.get("cwe_ids", []) or [],
                capec_ids=v.get("capec_ids", []) or [],
            )
        )
    return out


def load_server(scan_history_dir: str) -> ServerConfig:
    """Загружает самую свежую инвентаризацию стенда."""
    files = sorted(glob.glob(os.path.join(scan_history_dir, "scan_*.json")))
    if not files:
        return ServerConfig()
    data = _read_json(files[-1])

    ports = [
        OpenPort(p.get("port"), p.get("service", ""), p.get("banner", ""), p.get("protocol", "TCP"))
        for p in data.get("open_ports", [])
        if p.get("port")
    ]
    services = [s.get("name") if isinstance(s, dict) else s for s in data.get("running_services", [])]

    return ServerConfig(
        hostname=data.get("hostname", ""),
        os_name=data.get("os_name", ""),
        os_version=data.get("os_version", ""),
        open_ports=ports,
        installed_software=data.get("installed_software", []),
        running_services=[s for s in services if s],
        security_measures=data.get("security_measures", []),
        flags={
            "has_database": data.get("has_database", False),
            "has_web_server": data.get("has_web_server", False),
            "has_rdp": data.get("has_rdp_enabled", False),
            "has_smb": data.get("has_smb_enabled", False),
            "has_ftp": data.get("has_ftp_enabled", False),
        },
    )


def load_context(base_dir: str) -> ScanContext:
    """Собирает ScanContext из стандартного расположения файлов стенда."""
    external, vectors, target_ip = load_attacker(os.path.join(base_dir, "history"))
    trivy = load_trivy(os.path.join(base_dir, "data"))
    server = load_server(os.path.join(base_dir, "data", "scan_history"))

    for port, op in external.items():
        op_info = parse_banner(op.service, op.banner)
        if op_info.get("product") and (not op.service or op.service.lower() == "unknown"):
            op.service = op_info["product"]

    return ScanContext(
        server=server,
        trivy=trivy,
        attack_vectors=vectors,
        external_ports=external,
        target_ip=target_ip,
    )
