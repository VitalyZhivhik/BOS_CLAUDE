"""Движок реализуемости: пять детерминированных проверок и вердикт.

Принятие решения не использует ML и не обращается в сеть — результат
является чистой функцией от входных данных и среза базы MITRE.
"""

from __future__ import annotations

from .knowledge import Knowledge
from .models import AttackVector, CheckResult, ScanContext

VERDICT_REALIZABLE = "realizable"
VERDICT_PARTIALLY = "partially"
VERDICT_NOT = "not_realizable"

_SERVICE_FLAG = {"smb": "has_smb", "rdp": "has_rdp", "ftp": "has_ftp"}
_PRODUCT_ROOTS = ("vmware", "vcenter", "apache", "httpd", "nginx", "iis", "tomcat", "mysql")


def _port_detail(av: AttackVector, ctx: ScanContext):
    port = av.target_port
    return ctx.external_ports.get(port), port


def _observed_product_hints(ctx: ScanContext) -> list[str]:
    hints = []
    for name, ver in ctx.server.software_index():
        if any(root in name for root in _PRODUCT_ROOTS):
            hints.append(f"{name} {ver}".strip())
    return hints


def check_reachable(av: AttackVector, ctx: ScanContext) -> CheckResult:
    """№1: порт подтверждён и снаружи (атакующим), и внутри (сервером)."""
    port = av.target_port
    if port is None:
        return CheckResult("reachable", "unknown", "Вектор не привязан к конкретному порту")
    ext = port in ctx.external_ports
    srv = port in ctx.server.port_numbers()
    if ext and srv:
        return CheckResult("reachable", "pass", f"Порт {port} открыт снаружи и подтверждён в конфигурации сервера")
    if ext and not srv:
        return CheckResult("reachable", "warn", f"Порт {port} виден атакующему, но не подтверждён инвентаризацией сервера")
    if srv and not ext:
        return CheckResult("reachable", "fail", f"Порт {port} есть на сервере, но недоступен снаружи")
    return CheckResult("reachable", "fail", f"Порт {port} не наблюдался открытым снаружи")


def check_service(av: AttackVector, ctx: ScanContext) -> CheckResult:
    """№2: сервис на порту реально работает."""
    op, port = _port_detail(av, ctx)
    banner = (op.banner if op else "") or ""
    svc = (av.target_service or (op.service if op else "")).lower()

    if banner.strip():
        return CheckResult("service_enabled", "pass", f"Сервис на порту {port} ответил баннером (живой сервис)")

    for key, flag in _SERVICE_FLAG.items():
        if key in svc:
            if ctx.server.flags.get(flag):
                return CheckResult("service_enabled", "pass", f"Сервис {key.upper()} включён в конфигурации ({flag}=true)")
            return CheckResult("service_enabled", "warn", f"Порт открыт, но {flag}=false — нужна ручная проверка")

    if any(k in svc for k in ("mysql", "sql", "database")):
        if ctx.server.flags.get("has_database"):
            return CheckResult("service_enabled", "pass", "СУБД включена в конфигурации (has_database=true)")
        return CheckResult("service_enabled", "warn", "Порт СУБД открыт, но has_database=false — проверить наличие БД")

    if "rpc" in svc or port == 135:
        return CheckResult("service_enabled", "pass", "RPC (порт 135) — штатный сетевой сервис Windows")

    return CheckResult("service_enabled", "warn", f"Сервис на порту {port} напрямую не подтверждён")


def check_version(av: AttackVector, ctx: ScanContext, kb: Knowledge) -> CheckResult:
    """№3: версия/продукт попадают в уязвимый диапазон CVE."""
    if not av.cve_ids:
        return CheckResult("version_vulnerable", "na", "Вектор без CVE — проверка версии не применяется")

    info = None
    used_cve = None
    for cve in av.cve_ids:
        data = kb.cve(cve)
        if data and data.get("match"):
            info, used_cve = data, cve
            break

    if info is None:
        return CheckResult("version_vulnerable", "unknown", f"Нет данных о версии для {', '.join(av.cve_ids)} — нужна ручная проверка")

    match = info["match"]

    if "os" in match:
        build = ctx.server.os_build()
        patch = match.get("patch", "патч производителя")
        if build is None:
            return CheckResult("version_vulnerable", "unknown", f"Сборку ОС определить не удалось — проверить применимость {used_cve}")
        rng = match.get("vulnerable_build_range")
        if rng:
            if rng[0] <= build <= rng[1]:
                return CheckResult("version_vulnerable", "pass", f"Сборка ОС {build} в диапазоне, уязвимом к {used_cve} ({patch})")
            return CheckResult("version_vulnerable", "fail", f"Сборка ОС {build} вне диапазона, уязвимого к {used_cve} ({patch}) — не уязвима")
        threshold = match.get("vulnerable_if_build_lt")
        if threshold:
            if build >= threshold:
                return CheckResult("version_vulnerable", "fail", f"Сборка ОС {build} новее уязвимых к {used_cve} ({patch}) — не уязвима")
            return CheckResult("version_vulnerable", "pass", f"Сборка ОС {build} попадает в диапазон, уязвимый к {used_cve}")
        return CheckResult("version_vulnerable", "unknown", f"Правило версии ОС для {used_cve} не задано")

    requires = [r.lower() for r in match.get("requires_product", [])]
    if requires:
        software = [name for name, _ in ctx.server.software_index()]
        present = any(req in name for req in requires for name in software)
        present = present or any(req in (av.inferred_product or "").lower() for req in requires)
        if present:
            return CheckResult("version_vulnerable", "pass", f"Целевой продукт ({info.get('affected_product')}) присутствует на стенде")
        hints = _observed_product_hints(ctx)
        instead = f"; обнаружено вместо него: {', '.join(hints[:2])}" if hints else ""
        return CheckResult(
            "version_vulnerable",
            "fail",
            f"{used_cve} относится к «{info.get('affected_product')}», но этот продукт на стенде не найден{instead} — продукт не совпадает",
        )

    return CheckResult("version_vulnerable", "unknown", f"Правило версии для {used_cve} не задано")


def check_mitigation(av: AttackVector, ctx: ScanContext) -> CheckResult:
    """№4: наличие компенсирующих контролей."""
    active = []
    if ctx.server.has_measure("firewall"):
        active.append("брандмауэр")
    if ctx.server.has_measure("antivirus"):
        active.append("антивирус")

    if "smb signing" in av.name.lower() and ctx.server.flags.get("has_smb"):
        return CheckResult("no_mitigation", "warn", "Требует подтверждения, что SMB signing действительно отключён")

    if active:
        return CheckResult("no_mitigation", "warn", f"Активны: {', '.join(active)} — возможна детекция/ограничение атаки")
    return CheckResult("no_mitigation", "pass", "Компенсирующие контроли не обнаружены")


def _severity_of(av: AttackVector, kb: Knowledge) -> str:
    best = av.severity if av.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else None
    for cve in av.cve_ids:
        data = kb.cve(cve)
        if data:
            cvss = data.get("cvss", 0)
            sev = "CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
            order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            if best is None or order[sev] > order.get(best, 0):
                best = sev
    return best or "UNKNOWN"


def _decide(reachable: CheckResult, service: CheckResult, version: CheckResult) -> tuple[str, str]:
    if reachable.status == "fail":
        return VERDICT_NOT, reachable.evidence
    if service.status == "fail":
        return VERDICT_NOT, service.evidence
    if version.status == "fail":
        return VERDICT_NOT, version.evidence
    if reachable.status == "warn":
        return VERDICT_PARTIALLY, reachable.evidence
    if version.status == "unknown":
        return VERDICT_PARTIALLY, version.evidence
    if service.status == "warn":
        return VERDICT_PARTIALLY, service.evidence
    return VERDICT_REALIZABLE, "Достижим снаружи, сервис активен, версия уязвима либо не опровергнута"


def _confidence(verdict: str, service: CheckResult, version: CheckResult, mitigation: CheckResult) -> float:
    if verdict == VERDICT_REALIZABLE:
        c = 0.7
        if service.status == "pass":
            c += 0.1
        if version.status == "pass":
            c += 0.1
        if mitigation.status == "warn":
            c -= 0.1
    elif verdict == VERDICT_PARTIALLY:
        c = 0.5
        if mitigation.status == "warn":
            c -= 0.05
    else:
        c = 0.12
    return round(min(0.97, max(0.05, c)), 2)


def assess_vector(av: AttackVector, ctx: ScanContext, kb: Knowledge) -> dict:
    """Прогоняет вектор атаки через пять проверок и возвращает вердикт с трассой."""
    reachable = check_reachable(av, ctx)
    service = check_service(av, ctx)
    version = check_version(av, ctx, kb)
    mitigation = check_mitigation(av, ctx)

    verdict, reason = _decide(reachable, service, version)
    confidence = _confidence(verdict, service, version, mitigation)

    return {
        "verdict": verdict,
        "reason": reason,
        "confidence": confidence,
        "severity": _severity_of(av, kb),
        "trace": [reachable, service, version, mitigation],
    }
