"""Структуры данных модуля RVC."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OpenPort:
    """Открытый порт с баннером и распознанным сервисом."""

    port: int
    service: str = ""
    banner: str = ""
    protocol: str = "TCP"


@dataclass
class AttackVector:
    """Вектор атаки, найденный внешним сканером (атакующим)."""

    id: str
    name: str
    target_port: int | None = None
    target_service: str = ""
    attack_type: str = ""
    severity: str = "UNKNOWN"
    tools_used: str = ""
    description: str = ""
    cve_ids: list[str] = field(default_factory=list)
    inferred_product: str = ""


@dataclass
class TrivyVuln:
    """Уязвимость пакета, найденная Trivy на сервере."""

    vuln_id: str
    pkg_name: str
    installed_version: str = ""
    fixed_version: str = ""
    severity: str = "UNKNOWN"
    title: str = ""
    description: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    capec_ids: list[str] = field(default_factory=list)


@dataclass
class ServerConfig:
    """Внутренняя конфигурация стенда (инвентаризация ПО)."""

    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    open_ports: list[OpenPort] = field(default_factory=list)
    installed_software: list[dict] = field(default_factory=list)
    running_services: list[str] = field(default_factory=list)
    security_measures: list[dict] = field(default_factory=list)
    flags: dict = field(default_factory=dict)
    synthesized: bool = False  # True, если конфиг выведен из портов (инвентаризации хоста не было)

    def port_numbers(self) -> set[int]:
        return {p.port for p in self.open_ports}

    def software_index(self) -> list[tuple[str, str]]:
        """Список (имя_в_нижнем_регистре, версия) установленного ПО."""
        out = []
        for item in self.installed_software:
            name = (item.get("name") or "").lower()
            if name:
                out.append((name, item.get("version") or ""))
        return out

    def os_build(self) -> int | None:
        """Числовой build из os_version (например, 10.0.26200 -> 26200)."""
        parts = (self.os_version or "").split(".")
        if len(parts) >= 3 and parts[-1].isdigit():
            return int(parts[-1])
        return None

    def has_measure(self, category: str) -> bool:
        for m in self.security_measures:
            if (m.get("category") or "").lower() == category.lower():
                return (m.get("status") or "").lower() in ("active", "enabled", "on")
        return False


@dataclass
class ScanContext:
    """Полный контекст одного стенда после загрузки всех источников."""

    server: ServerConfig
    trivy: list[TrivyVuln] = field(default_factory=list)
    attack_vectors: list[AttackVector] = field(default_factory=list)
    external_ports: dict[int, OpenPort] = field(default_factory=dict)
    target_ip: str = ""

    def reachable_ports(self) -> set[int]:
        """Порты, подтверждённые и снаружи (атакующим), и внутри (сервером)."""
        return set(self.external_ports) & self.server.port_numbers()


@dataclass
class CheckResult:
    """Результат одной проверки реализуемости."""

    name: str
    status: str  # pass | fail | unknown | warn
    evidence: str


@dataclass
class Finding:
    """Итоговая карточка уязвимости в отчёте."""

    attack_name: str
    attack_vector_id: str
    attack_type: str
    severity: str
    port: int | None
    service: str
    verdict: str  # realizable | partially | not_realizable
    confidence: float
    reason: str
    trace: list[CheckResult] = field(default_factory=list)
    references: dict = field(default_factory=dict)
    target_software: dict = field(default_factory=dict)
    playbook: dict = field(default_factory=dict)
    source: str = "attacker"
