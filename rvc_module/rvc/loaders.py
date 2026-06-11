"""Загрузка и нормализация входных JSON в единый ScanContext.

Источники (исторический контракт):
  - history/**/*.json        — внешние сканы атакующего (PortScan/Nmap/Nuclei/Parallel)
  - data/trivy_scan_*.json   — уязвимости пакетов (Trivy)
  - data/scan_history/scan_*.json — инвентаризация ПО на стенде

Новый контракт сканеров (репозиторий, ветка final):
  - tools/history/**/*.json  — единый формат отчётов (PortScan/Parallel/analyze):
        { scanner_ip, target_ip, open_ports[], discovered_services[],
          attack_vectors[], os_detection, scan_timestamp }
    Отдельной инвентаризации хоста и Trivy в этом контракте нет, поэтому
    представление о сервере СИНТЕЗИРУЕТСЯ из наблюдаемых открытых портов
    (см. _synthesize_server): достижимым считается то, что реально увидел
    сканер. Никакие факты при этом не выдумываются — синтез опирается только
    на то, что присутствует во входных данных.
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


def _text(x) -> str:
    """Безопасно приводит любое значение к строке (защита от мусорных типов во входе)."""
    if x is None:
        return ""
    return x if isinstance(x, str) else str(x)


def _port(x) -> int | None:
    """Приводит порт к int или None (строка 'abc', float, bool -> None)."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, str) and x.strip().isdigit():
        return int(x.strip())
    return None


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
            found.extend(m.upper() for m in CVE_RE.findall(str(part)))
    seen, out = set(), []
    for cve in found:
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def _os_detection_text(data: dict) -> str:
    """os_detection бывает строкой ('Windows') или объектом — приводим к строке."""
    od = data.get("os_detection")
    if isinstance(od, str):
        return od.strip()
    if isinstance(od, dict):
        for key in ("name", "os", "os_name", "product", "value"):
            v = od.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def load_attacker(history_dir: str) -> tuple[dict[int, OpenPort], list[AttackVector], str, str]:
    """Объединяет все внешние сканы: union открытых портов и dedup векторов атак.

    Возвращает (external_ports, attack_vectors, target_ip, os_detection).
    """
    external: dict[int, OpenPort] = {}
    vectors: dict[tuple, AttackVector] = {}
    target_ip = ""
    os_detection = ""

    for path in sorted(glob.glob(os.path.join(history_dir, "**", "*.json"), recursive=True)):
        try:
            data = _read_json(path)
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        target_ip = target_ip or _text(data.get("target_ip"))
        os_detection = os_detection or _os_detection_text(data)

        for p in (data.get("open_ports") or []):
            if not isinstance(p, dict):
                continue
            port = _port(p.get("port"))
            if not port:
                continue
            existing = external.get(port)
            banner = _text(p.get("banner"))
            service = _text(p.get("service"))
            if existing is None:
                external[port] = OpenPort(port, service, banner, _text(p.get("protocol")) or "TCP")
            else:
                if not existing.banner and banner:
                    existing.banner = banner
                if (not existing.service or existing.service.lower() == "unknown") and service:
                    existing.service = service

        for av in (data.get("attack_vectors") or []):
            if not isinstance(av, dict):
                continue
            cves = _extract_cves(
                " ".join(_text(x) for x in (av.get("representative_cve_ids") or [])),
                _text(av.get("name")),
                _text(av.get("description")),
            )
            key = (_text(av.get("name")), _port(av.get("target_port")))
            if key in vectors:
                merged = vectors[key]
                for c in cves:
                    if c not in merged.cve_ids:
                        merged.cve_ids.append(c)
                if not merged.tools_used and av.get("tools_used"):
                    merged.tools_used = _text(av.get("tools_used"))
                continue
            vectors[key] = AttackVector(
                id=_text(av.get("id")),
                name=_text(av.get("name")),
                target_port=_port(av.get("target_port")),
                target_service=_text(av.get("target_service")),
                attack_type=_text(av.get("attack_type")),
                severity=(_text(av.get("severity")) or "UNKNOWN").upper(),
                tools_used=_text(av.get("tools_used")),
                description=_text(av.get("description")),
                cve_ids=cves,
                inferred_product=_text(av.get("inferred_product")),
            )

    return external, list(vectors.values()), target_ip, os_detection


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


# Порт -> флаг наличия сервиса (для синтеза представления о хосте по портам).
_PORT_TO_FLAG = {
    21: "has_ftp",
    139: "has_smb",
    445: "has_smb",
    3306: "has_database",
    3307: "has_database",
    3389: "has_rdp",
    80: "has_web_server",
    443: "has_web_server",
    8080: "has_web_server",
    8443: "has_web_server",
}


def _synthesize_server(external: dict[int, OpenPort], os_detection: str) -> ServerConfig:
    """Строит ServerConfig из наблюдаемых открытых портов, когда отдельной
    инвентаризации хоста нет (новый контракт сканеров).

    Достижимым считается ровно то, что увидел сканер. Флаги сервисов выводятся
    из номеров портов. Версии/ПО/средства защиты НЕ домысливаются: их
    отсутствие означает «неизвестно», а не «отсутствует».
    """
    ports = [OpenPort(op.port, op.service, op.banner, op.protocol) for op in external.values()]
    flags: dict = {
        "has_database": False,
        "has_web_server": False,
        "has_rdp": False,
        "has_smb": False,
        "has_ftp": False,
    }
    for op in external.values():
        flag = _PORT_TO_FLAG.get(op.port)
        if flag:
            flags[flag] = True
    return ServerConfig(
        hostname="",
        os_name=os_detection,
        os_version="",          # билд ОС в новом контракте недоступен -> проверка версии = «вручную»
        open_ports=ports,
        installed_software=[],
        running_services=[],
        security_measures=[],   # средства защиты неизвестны (не наблюдались), не считаем их отсутствующими по умолчанию
        flags=flags,
        synthesized=True,
    )


def load_context(base_dir: str) -> ScanContext:
    """Собирает ScanContext из стандартного расположения файлов стенда.

    Поддерживает оба контракта: классический (data/ + history/) и новый
    (tools/history/** без инвентаризации). Если инвентаризации нет, но есть
    сканы атакующего — представление о сервере синтезируется из портов.
    """
    external, vectors, target_ip, os_detection = load_attacker(os.path.join(base_dir, "history"))
    trivy = load_trivy(os.path.join(base_dir, "data"))
    server = load_server(os.path.join(base_dir, "data", "scan_history"))

    for port, op in external.items():
        op_info = parse_banner(op.service, op.banner)
        if op_info.get("product") and (not op.service or op.service.lower() == "unknown"):
            op.service = op_info["product"]

    if not server.open_ports and external:
        server = _synthesize_server(external, os_detection)

    return ScanContext(
        server=server,
        trivy=trivy,
        attack_vectors=vectors,
        external_ports=external,
        target_ip=target_ip,
    )
