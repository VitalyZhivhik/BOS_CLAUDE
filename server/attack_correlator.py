"""
Модуль корреляции атак.
Сопоставляет обнаруженные атакующим агентом векторы атак
с реальной конфигурацией сервера и базами CVE/CWE/CAPEC/MITRE ATT&CK.
Определяет реализуемость каждой атаки.
ИСПРАВЛЕНИЯ:
  - Строгая дедупликация по ключу (cve_id, attack_name) на всех этапах
  - Дополнительные проверки: Java, Exchange, Active Directory
  - Метод get_summary() с расширенной статистикой
"""
import os
import sys
from dataclasses import asdict
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.models import (
    SystemInfo, ScanResult, VulnerabilityMatch,
    AttackFeasibility, Severity, AttackVector
)
from server.vulnerability_db import VulnerabilityDatabase
class AttackCorrelator:
    """Движок корреляции атак с конфигурацией сервера."""
    def __init__(self, system_info: SystemInfo, vuln_db: VulnerabilityDatabase):
        self.system_info = system_info
        self.vuln_db = vuln_db
        self.results: list[VulnerabilityMatch] = []
        self._scan_result: ScanResult = None
    def correlate(self, scan_result: ScanResult) -> list[VulnerabilityMatch]:
        """Основной метод корреляции."""
        print("\n[*] Начинаем корреляцию атак с конфигурацией сервера...")
        self._scan_result = scan_result
        self.results = []
        # 1. Анализ каждого вектора атаки от атакующего агента
        for av in scan_result.attack_vectors:
            if isinstance(av, dict):
                try:
                    av = AttackVector(**av)
                except TypeError:
                    # Если поля не совпадают, создаём с базовыми полями
                    av = AttackVector(
                        id=av.get("id", ""),
                        name=av.get("name", ""),
                        description=av.get("description", ""),
                        target_port=av.get("target_port"),
                        target_service=av.get("target_service", ""),
                        attack_type=av.get("attack_type", ""),
                        severity=av.get("severity", Severity.MEDIUM.value),
                    )
            matches = self._analyze_attack_vector(av)
            self.results.extend(matches)
        # 2. Дополнительно: анализ на основе открытых портов и CVE
        port_based = self._analyze_port_based_vulnerabilities(scan_result)
        self.results.extend(port_based)
        # 3. Анализ на основе установленного ПО и известных CVE
        sw_based = self._analyze_software_vulnerabilities()
        self.results.extend(sw_based)
        # Строгая дедупликация по (cve_id + attack_name)
        self.results = self._deduplicate(self.results)
        print(f"[+] Корреляция завершена. Уникальных результатов: {len(self.results)}")
        return self.results
    # ──────────────────────────────────────────────
    #  Анализ векторов атаки
    # ──────────────────────────────────────────────
    def _analyze_attack_vector(self, av: AttackVector) -> list[VulnerabilityMatch]:
        """Анализ одного вектора атаки."""
        matches = []
        # Поиск соответствующих CVE по типу атаки и сервису
        related_cves = []
        if av.target_service:
            related_cves.extend(self.vuln_db.find_cves_by_service(av.target_service))
        if av.target_port:
            related_cves.extend(self.vuln_db.find_cves_by_port(av.target_port))
        # Дедупликация CVE внутри вектора атаки
        seen_ids = set()
        unique_cves = []
        for cve in related_cves:
            if cve["id"] not in seen_ids:
                seen_ids.add(cve["id"])
                unique_cves.append(cve)
        for cve in unique_cves:
            feasibility, reason = self._evaluate_feasibility(cve, av)
            mitigations = self.vuln_db.get_all_mitigations(cve)
            cwe_ids = ", ".join(cve.get("related_cwe", []))
            capec_ids = ", ".join(cve.get("related_capec", []))
            mitre_ids = ", ".join(cve.get("related_mitre", []))
            recommendation = self._generate_recommendation(cve, feasibility, mitigations)
            match = VulnerabilityMatch(
                cve_id=cve["id"],
                cwe_id=cwe_ids,
                capec_id=capec_ids,
                mitre_technique=mitre_ids,
                attack_vector_id=av.id,
                attack_name=av.name,
                description=cve["description"],
                severity=cve.get("severity", Severity.MEDIUM.value),
                feasibility=feasibility.value,
                reason=reason,
                recommendation=recommendation,
            )
            matches.append(match)
        return matches
    # ──────────────────────────────────────────────
    #  Оценка реализуемости
    # ──────────────────────────────────────────────
    def _evaluate_feasibility(self, cve: dict, av: AttackVector) -> tuple:
        """
        Оценка реализуемости атаки на основе конфигурации сервера.
        Сопоставление «что нашёл атакующий» с «что реально есть на сервере».
        """
        required_services = cve.get("requires_service", [])
        attack_type = cve.get("attack_type", "")
        # Собираем информацию о сервере
        open_port_nums = self._get_open_ports()
        running_svc_lower = set(s.lower() for s in self.system_info.running_services)
        sw_names_lower = self._get_software_names()
        reasons = []
        # === Проверка SQL-инъекций ===
        if attack_type == "sql_injection":
            if not self.system_info.has_database:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "На сервере не обнаружено ни одной СУБД. "
                    "SQL-инъекция невозможна при отсутствии базы данных."
                )
            if not self.system_info.has_web_server:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "На сервере нет веб-сервера. SQL-инъекция через веб-интерфейс невозможна."
                )
        # === Проверка XSS ===
        if attack_type == "cross_site_scripting":
            if not self.system_info.has_web_server:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "На сервере нет веб-сервера. XSS-атака невозможна."
                )
        # === Проверка RDP-атак ===
        if "rdp" in required_services:
            if not self.system_info.has_rdp_enabled:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "RDP отключён на сервере. Атаки через RDP невозможны."
                )
            if 3389 not in open_port_nums:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Порт 3389 (RDP) закрыт. Удалённый доступ по RDP недоступен."
                )
            reasons.append("RDP включён и порт 3389 открыт")
        # === Проверка SMB-атак ===
        if "smb" in required_services:
            if not self.system_info.has_smb_enabled:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "SMB не обнаружен (порт 445 закрыт). Атаки через SMB невозможны."
                )
            reasons.append("SMB активен (порт 445 открыт)")
        # === Проверка FTP-атак ===
        if "ftp" in required_services:
            if not self.system_info.has_ftp_enabled:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "FTP-сервер не обнаружен (порт 21 закрыт). Атаки через FTP невозможны."
                )
            reasons.append("FTP-сервер активен")
        # === Проверка SSH-атак ===
        if "ssh" in required_services:
            if 22 not in open_port_nums:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "SSH-сервер не обнаружен (порт 22 закрыт). Атаки через SSH невозможны."
                )
            reasons.append("SSH-сервер активен")
        # === Проверка веб-атак ===
        if "web_server" in required_services or "web_application" in required_services:
            if not self.system_info.has_web_server:
                web_ports = {80, 443, 8080, 8443}
                if not web_ports.intersection(open_port_nums):
                    return (
                        AttackFeasibility.NOT_FEASIBLE,
                        "Веб-сервер не обнаружен. Веб-атаки невозможны."
                    )
            reasons.append("Веб-сервер обнаружен")
        # === Проверка Java-приложений ===
        if "java_application" in required_services:
            java_found = any("java" in sw for sw in sw_names_lower)
            if not java_found:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Java не установлена. Атаки, требующие Java-окружения, невозможны."
                )
            reasons.append("Java обнаружена")
        # === Проверка Exchange Server ===
        if "exchange_server" in required_services:
            exchange_found = any("exchange" in sw for sw in sw_names_lower)
            if not exchange_found:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Microsoft Exchange Server не установлен. Атаки через Exchange невозможны."
                )
            reasons.append("Exchange Server обнаружен")
        # === Проверка Active Directory / Netlogon ===
        if "active_directory" in required_services or "netlogon" in required_services:
            is_dc = any("netlogon" in s for s in running_svc_lower)
            if not is_dc:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Сервер не является контроллером домена (служба Netlogon не активна). "
                    "Атаки на AD невозможны."
                )
            reasons.append("Active Directory / Netlogon активен")
        # === Проверка Print Spooler ===
        if "print_spooler" in required_services:
            spooler_found = any("spooler" in s for s in running_svc_lower)
            if not spooler_found:
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    "Служба Print Spooler не запущена. PrintNightmare невозможен."
                )
            reasons.append("Print Spooler активен")
        # === Проверка требуемых портов ===
        required_ports = cve.get("requires_port", [])
        if required_ports:
            missing = [p for p in required_ports if p not in open_port_nums]
            # Достаточно хотя бы одного порта из списка
            if missing and len(missing) == len(required_ports):
                return (
                    AttackFeasibility.NOT_FEASIBLE,
                    f"Ни один из требуемых портов ({', '.join(str(p) for p in required_ports)}) не открыт."
                )
            open_req = [p for p in required_ports if p in open_port_nums]
            if open_req:
                reasons.append(f"Открытые требуемые порты: {', '.join(str(p) for p in open_req)}")
        # Если все проверки пройдены — атака реализуема
        reason_text = "; ".join(reasons) if reasons else "Условия для атаки выполнены"
        return AttackFeasibility.FEASIBLE, reason_text
    # ──────────────────────────────────────────────
    #  Анализ на основе портов
    # ──────────────────────────────────────────────
    def _analyze_port_based_vulnerabilities(
        self, scan_result: ScanResult
    ) -> list[VulnerabilityMatch]:
        """Анализ уязвимостей на основе открытых портов от атакующего."""
        matches = []
        seen = set()
        attacker_ports = set()
        for p in scan_result.open_ports:
            if hasattr(p, "port"):
                attacker_ports.add(p.port)
            elif isinstance(p, dict):
                attacker_ports.add(p.get("port", 0))
        for port in attacker_ports:
            for cve in self.vuln_db.find_cves_by_port(port):
                key = (cve["id"], f"Port-{port}")
                if key in seen:
                    continue
                seen.add(key)
                av = AttackVector(
                    id=f"PORT-{port}",
                    name=f"Port {port} Attack",
                    description=f"Атака через открытый порт {port}",
                    target_port=port,
                    target_service=cve.get("requires_service", [""])[0] if cve.get("requires_service") else "",
                )
                feasibility, reason = self._evaluate_feasibility(cve, av)
                mitigations = self.vuln_db.get_all_mitigations(cve)
                recommendation = self._generate_recommendation(cve, feasibility, mitigations)
                matches.append(VulnerabilityMatch(
                    cve_id=cve["id"],
                    cwe_id=", ".join(cve.get("related_cwe", [])),
                    capec_id=", ".join(cve.get("related_capec", [])),
                    mitre_technique=", ".join(cve.get("related_mitre", [])),
                    attack_vector_id=f"PORT-{port}",
                    attack_name=f"Атака через порт {port} ({cve.get('attack_type', 'unknown')})",
                    description=cve["description"],
                    severity=cve.get("severity", Severity.MEDIUM.value),
                    feasibility=feasibility.value,
                    reason=reason,
                    recommendation=recommendation,
                ))
        return matches
    # ──────────────────────────────────────────────
    #  Анализ на основе ПО
    # ──────────────────────────────────────────────
    def _analyze_software_vulnerabilities(self) -> list[VulnerabilityMatch]:
        """Анализ уязвимостей установленного ПО."""
        matches = []
        seen = set()
        sw_list = self.system_info.installed_software or []
        for sw in sw_list:
            name = sw.name if hasattr(sw, "name") else sw.get("name", "")
            if not name:
                continue
            for cve in self.vuln_db.find_cves_by_software(name):
                key = (cve["id"], name)
                if key in seen:
                    continue
                seen.add(key)
                av = AttackVector(
                    id=f"SW-{name[:20]}",
                    name=f"Software Attack: {name}",
                    description=f"Уязвимость в ПО: {name}",
                    target_service=name,
                )
                feasibility, reason = self._evaluate_feasibility(cve, av)
                mitigations = self.vuln_db.get_all_mitigations(cve)
                recommendation = self._generate_recommendation(cve, feasibility, mitigations)
                matches.append(VulnerabilityMatch(
                    cve_id=cve["id"],
                    cwe_id=", ".join(cve.get("related_cwe", [])),
                    capec_id=", ".join(cve.get("related_capec", [])),
                    mitre_technique=", ".join(cve.get("related_mitre", [])),
                    attack_vector_id=f"SW-{name[:20]}",
                    attack_name=f"Уязвимость ПО: {name}",
                    description=cve["description"],
                    severity=cve.get("severity", Severity.MEDIUM.value),
                    feasibility=feasibility.value,
                    reason=reason,
                    recommendation=recommendation,
                ))
        return matches
    # ──────────────────────────────────────────────
    #  Дедупликация
    # ──────────────────────────────────────────────
    def _deduplicate(self, results: list[VulnerabilityMatch]) -> list[VulnerabilityMatch]:
        """
        Строгая дедупликация по ключу (cve_id, attack_name).
        Оставляем первое вхождение — наиболее точное (от вектора атаки).
        """
        seen = set()
        unique = []
        for r in results:
            cve = str(r.cve_id or "")
            name = str(r.attack_name or "")
            key = f"{cve}||{name}"
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique
    # ──────────────────────────────────────────────
    #  Вспомогательные методы
    # ──────────────────────────────────────────────
    def _get_open_ports(self) -> set:
        open_port_nums = set()
        if isinstance(self.system_info.open_ports, list):
            for p in self.system_info.open_ports:
                if hasattr(p, "port"):
                    open_port_nums.add(p.port)
                elif isinstance(p, dict):
                    open_port_nums.add(p.get("port", 0))
        return open_port_nums
    def _get_software_names(self) -> set:
        sw_names_lower = set()
        if isinstance(self.system_info.installed_software, list):
            for sw in self.system_info.installed_software:
                if hasattr(sw, "name"):
                    sw_names_lower.add(sw.name.lower())
                elif isinstance(sw, dict):
                    sw_names_lower.add(sw.get("name", "").lower())
        return sw_names_lower
    def _generate_recommendation(
        self, cve: dict, feasibility: AttackFeasibility, mitigations: list
    ) -> str:
        """Генерация рекомендации по защите."""
        if feasibility == AttackFeasibility.NOT_FEASIBLE:
            return "Текущая конфигурация защищена от данной атаки. Поддерживайте защитные меры в актуальном состоянии."
        base_recs = []
        attack_type = cve.get("attack_type", "")
        if attack_type == "sql_injection":
            base_recs.append("Использовать параметризованные запросы и ORM-фреймворки.")
        elif attack_type == "cross_site_scripting":
            base_recs.append("Экранировать выходные данные, применить Content Security Policy.")
        elif attack_type == "remote_code_execution":
            base_recs.append("Применить критические обновления безопасности немедленно.")
        elif attack_type == "brute_force":
            base_recs.append("Включить блокировку учётных записей, добавить MFA.")
        elif attack_type == "privilege_escalation":
            base_recs.append("Применить принцип наименьших привилегий, обновить систему.")
        if mitigations:
            base_recs.extend(mitigations[:2])
        cve_id = cve.get("id", "")
        if cve_id:
            base_recs.append(f"Изучить официальный патч для {cve_id} на сайте вендора.")
        return " ".join(base_recs) if base_recs else "Применить доступные обновления безопасности."
    # ──────────────────────────────────────────────
    #  Сводка результатов
    # ──────────────────────────────────────────────
    def get_summary(self) -> dict:
        """Получение сводки результатов корреляции."""
        feasible = [r for r in self.results if AttackFeasibility.FEASIBLE.value in str(r.feasibility)
                    and AttackFeasibility.NOT_FEASIBLE.value not in str(r.feasibility)]
        not_feasible = [r for r in self.results if AttackFeasibility.NOT_FEASIBLE.value in str(r.feasibility)]
        by_severity = {}
        for r in self.results:
            sev = r.severity or "INFO"
            by_severity[sev] = by_severity.get(sev, 0) + 1
        target_ip = ""
        scanner_ip = ""
        if self._scan_result:
            target_ip = self._scan_result.target_ip or ""
            scanner_ip = self._scan_result.scanner_ip or ""
        return {
            "total_results": len(self.results),
            "feasible_attacks": len(feasible),
            "not_feasible_attacks": len(not_feasible),
            "by_severity": by_severity,
            "critical_count": by_severity.get("CRITICAL", 0),
            "high_count": by_severity.get("HIGH", 0),
            "medium_count": by_severity.get("MEDIUM", 0),
            "low_count": by_severity.get("LOW", 0),
            "target_ip": target_ip,
            "scanner_ip": scanner_ip,
            "risk_level": self._calculate_risk_level(feasible, by_severity),
        }
    def _calculate_risk_level(self, feasible: list, by_severity: dict) -> str:
        """Определение общего уровня риска."""
        crit = by_severity.get("CRITICAL", 0)
        high = by_severity.get("HIGH", 0)
        feasible_crit = sum(1 for r in feasible if r.severity == "CRITICAL")
        feasible_high = sum(1 for r in feasible if r.severity == "HIGH")
        if feasible_crit > 0:
            return "КРИТИЧЕСКИЙ"
        elif feasible_high > 0 or crit > 0:
            return "ВЫСОКИЙ"
        elif high > 0:
            return "СРЕДНИЙ"
        elif len(feasible) > 0:
            return "НИЗКИЙ"
        return "ИНФОРМАЦИОННЫЙ"
