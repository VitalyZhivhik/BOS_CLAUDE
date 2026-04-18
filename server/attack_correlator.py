"""
Модуль корреляции атак.
Сопоставляет обнаруженные атакующим агентом векторы атак
с реальной конфигурацией сервера и базами CVE/CWE/CAPEC/MITRE ATT&CK.
Определяет реализуемость каждой атаки.
НОВИНКА: Интеграция с Trivy для подтверждения уязвимостей.
"""

import os
import sys
import time
from dataclasses import asdict
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.models import (
    SystemInfo, ScanResult, VulnerabilityMatch,
    AttackFeasibility, Severity, AttackVector
)
from server.vulnerability_db import VulnerabilityDatabase
from server.trivy_correlator import TrivyCorrelator
from server.trivy_scanner import TrivyScanResult
from common.logger import get_server_logger

logger = get_server_logger()


class AttackCorrelator:
    """Движок корреляции атак с конфигурацией сервера."""

    def __init__(self, system_info: SystemInfo, vuln_db: VulnerabilityDatabase, trivy_result=None):
        self.system_info = system_info
        self.vuln_db = vuln_db
        self.trivy_result = trivy_result  # Результаты сканирования Trivy
        self.results: list[VulnerabilityMatch] = []
        self.progress_callback = None  # Callback для прогресса

    def set_progress_callback(self, callback):
        """Устанавливает callback для отслеживания прогресса."""
        self.progress_callback = callback
    
    def _report_progress(self, percent: int, message: str):
        """Отправляет прогресс через callback."""
        if self.progress_callback:
            self.progress_callback(percent, message)

    def correlate(self, scan_result: ScanResult) -> list[VulnerabilityMatch]:
        """Основной метод корреляции."""
        start_time = time.time()
        logger.info("=" * 70)
        logger.info(" НАЧАЛО КОРРЕЛЯЦИИ АТАК С КОНФИГУРАЦИЕЙ СЕРВЕРА")
        logger.info("=" * 70)
        
        self._report_progress(0, "Начало корреляции атак...")
        self.results = []

        # 1. Анализ каждого вектора атаки от атакующего агента
        total_vectors = len(scan_result.attack_vectors)
        logger.info(f"[1/3] Векторов атак для анализа: {total_vectors}")
        self._report_progress(5, f"Анализ {total_vectors} векторов атак...")
        
        vector_start = time.time()
        for i, av in enumerate(scan_result.attack_vectors, 1):
            if isinstance(av, dict):
                av = AttackVector(**av)
            
            # Прогресс: 5-50% для анализа векторов
            percent = 5 + int((i / total_vectors) * 45) if total_vectors > 0 else 5
            self._report_progress(percent, f"Анализ вектора {i}/{total_vectors}...")
            
            # Логируем каждые 10 векторов для отслеживания прогресса
            if i % 10 == 0 or i == total_vectors:
                elapsed = time.time() - vector_start
                logger.info(f"  [{i}/{total_vectors}] Векторов обработано ({elapsed:.2f}s)...")
            
            matches = self._analyze_attack_vector(av)
            # ВАЖНО: Даже если нет CVE, добавляем вектор как "не реализуемый"
            if not matches:
                # Создаем заглушку для вектора без CVE
                match = VulnerabilityMatch(
                    cve_id="N/A",
                    cwe_id="N/A",
                    capec_id="N/A",
                    mitre_technique="N/A",
                    attack_vector_id=av.id,
                    attack_name=av.name,
                    description=f"Вектор атаки '{av.name}' не имеет известных CVE уязвимостей",
                    severity="INFO",
                    feasibility=AttackFeasibility.NOT_FEASIBLE.value,
                    reason="Не найдено соответствующих CVE уязвимостей в базе данных",
                    recommendation="Требуется ручной анализ вектора атаки",
                )
                matches = [match]
            
            self.results.extend(matches)
        
        vector_elapsed = time.time() - vector_start
        logger.info(f"[1/3] Завершено: {len(self.results)} результатов за {vector_elapsed:.2f}s")

        # 2. Дополнительно: анализ на основе открытых портов и CVE
        logger.info("[2/3] Анализ уязвимостей по портам...")
        self._report_progress(55, "Анализ уязвимостей по портам...")
        port_start = time.time()
        port_based = self._analyze_port_based_vulnerabilities(scan_result)
        self.results.extend(port_based)
        port_elapsed = time.time() - port_start
        logger.info(f"[2/3] Завершено: +{len(port_based)} результатов за {port_elapsed:.2f}s")

        # 3. Анализ на основе установленного ПО и известных CVE
        logger.info("[3/3] Анализ уязвимостей установленного ПО...")
        self._report_progress(75, "Анализ уязвимостей установленного ПО...")
        sw_start = time.time()
        sw_based = self._analyze_software_vulnerabilities()
        self.results.extend(sw_based)
        sw_elapsed = time.time() - sw_start
        logger.info(f"[3/3] Завершено: +{len(sw_based)} результатов за {sw_elapsed:.2f}s")

        # Убираем дубликаты (Умная агрегация)
        logger.info("Дедупликация результатов...")
        self._report_progress(90, "Дедупликация результатов...")
        dedup_start = time.time()
        before_count = len(self.results)
        self.results = self._deduplicate(self.results)
        dedup_elapsed = time.time() - dedup_start
        logger.info(f"Дедупликация: {before_count} -> {len(self.results)} за {dedup_elapsed:.2f}s")

        # 4. КОРРЕЛЯЦИЯ С TRIVY (если есть данные)
        if self.trivy_result:
            logger.info("[4/4] Корреляция с данными Trivy...")
            self._report_progress(92, "Корреляция с Trivy...")
            trivy_start = time.time()
            trivy_enhanced = self._correlate_with_trivy(scan_result)
            self.results = trivy_enhanced
            trivy_elapsed = time.time() - trivy_start
            logger.info(f"[4/4] Корреляция с Trivy завершена за {trivy_elapsed:.2f}s")
        else:
            logger.warning("[4/4] Данные Trivy отсутствуют - корреляция без подтверждения уязвимостей")
            self._report_progress(92, "ВНИМАНИЕ: Trivy не запущен - корреляция без подтверждения")

        # Присвоение обнаруженного ПО к уязвимостям (Умная корреляция)
        logger.info("Присвоение целевого ПО к уязвимостям...")
        self._report_progress(95, "Присвоение целевого ПО к уязвимостям...")
        
        # Шаг 1: Строим карту CVE -> ПО из всех доступных источников
        software_map = self._build_software_map(scan_result)
        
        # Шаг 2: Применяем карту к результатам
        for match in self.results:
            if match.target_software:  # Уже установлено из предыдущих шагов
                continue
            
            # Пробуем найти ПО для каждого CVE в списке
            if match.cve_id:
                for cve in match.cve_id.split(","):
                    cve = cve.strip()
                    if cve in software_map:
                        match.target_software = software_map[cve]
                        break
                
                # Если не нашли по CVE, пробуем по attack_vector_id
                if not match.target_software and match.attack_vector_id:
                    # Ищем ПО по имени атаки/вектора
                    for key, sw in software_map.items():
                        if match.attack_name.lower() in sw.lower() or sw.lower() in match.attack_name.lower():
                            match.target_software = sw
                            break
            
            # Фоллбэк: если всё ещё нет ПО, используем эвристику по порту
            if not match.target_software:
                match.target_software = self._guess_software_from_port(match, scan_result)
        
        logger.info(f"Присвоено ПО: {sum(1 for m in self.results if m.target_software)}/{len(self.results)} результатов")

        total_elapsed = time.time() - start_time
        self._report_progress(100, f"Корреляция завершена. Найдено {len(self.results)} уникальных результатов")
        logger.info("=" * 70)
        logger.info(f" КОРРЕЛЯЦИЯ ЗАВЕРШЕНА ЗА {total_elapsed:.2f} СЕК")
        logger.info(f" Уникальных результатов: {len(self.results)}")
        if self.trivy_result:
            logger.info(f" ✅ Trivy подтвердил уязвимости")
        else:
            logger.warning(f" ⚠️ Trivy НЕ запущен - реализуемость атак НЕ подтверждена!")
        logger.info("=" * 70)
        return self.results

    def _analyze_attack_vector(self, av: AttackVector) -> list[VulnerabilityMatch]:
        """Анализ одного вектора атаки."""
        matches = []

        # Поиск соответствующих CVE по типу атаки и сервису
        related_cves = []
        if av.target_service:
            related_cves.extend(self.vuln_db.find_cves_by_service(av.target_service))
        if av.target_port:
            related_cves.extend(self.vuln_db.find_cves_by_port(av.target_port))

        # Убираем дубликаты CVE
        seen_ids = set()
        unique_cves = []
        for cve in related_cves:
            if cve["id"] not in seen_ids:
                seen_ids.add(cve["id"])
                unique_cves.append(cve)

        for cve in unique_cves:
            feasibility, reason = self._evaluate_feasibility(cve, av)
            chain = self.vuln_db.get_full_chain(cve)
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

    def _check_trivy_vulnerability(self, cve_id: str) -> tuple:
        """
        Проверяет уязвимость через данные Trivy.
        Возвращает (confirmed: bool, details: str, severity: str).
        """
        if not self.trivy_result:
            return False, "Trivy не запущен - подтверждение уязвимости недоступно", "UNKNOWN"
        
        # Преобразуем trivy_result в список уязвимостей
        vulns = []
        if isinstance(self.trivy_result, dict):
            vulns = self.trivy_result.get("vulnerabilities", [])
        elif hasattr(self.trivy_result, "vulnerabilities"):
            vulns = self.trivy_result.vulnerabilities
        
        for vuln in vulns:
            vuln_id = vuln.get("vuln_id") if isinstance(vuln, dict) else getattr(vuln, "vuln_id", "")
            
            if vuln_id and vuln_id.upper() == cve_id.upper():
                severity = vuln.get("severity", "UNKNOWN") if isinstance(vuln, dict) else getattr(vuln, "severity", "UNKNOWN")
                pkg_name = vuln.get("pkg_name", "") if isinstance(vuln, dict) else getattr(vuln, "pkg_name", "")
                installed_version = vuln.get("installed_version", "") if isinstance(vuln, dict) else getattr(vuln, "installed_version", "")
                fixed_version = vuln.get("fixed_version", "") if isinstance(vuln, dict) else getattr(vuln, "fixed_version", "")
                
                details = (
                    f"✅ Trivy ПОДТВЕРДИЛ уязвимость {cve_id} в ПО '{pkg_name}' "
                    f"(версия {installed_version})."
                )
                if fixed_version:
                    details += f" Доступно исправление: {fixed_version}."
                
                return True, details, severity
        
        return False, f"Trivy не обнаружил уязвимость {cve_id} в установленном ПО", "UNKNOWN"

    def _calculate_feasibility_score(self, cve: dict, av: AttackVector, reasons: list, protection_notes: list) -> tuple:
        """
        Многофакторная оценка реализуемости атаки.
        Возвращает (score: int, max_score: int, feasibility: AttackFeasibility, reason: str).
        
        Факторы:
        - Сетевая доступность (30 баллов)
        - Подтверждение Trivy (35 баллов)
        - Уязвимая версия ПО (20 баллов)
        - Отсутствие патчей (10 баллов)
        - Слабые средства защиты (5 баллов)
        
        УЛУЧШЕННАЯ ВЕРСИЯ:
        - Повышены пороги для большей реалистичности
        - Больше баллов за сетевую доступность
        - Больше баллов за подтверждение Trivy
        - Снижены требования к средствам защиты
        """
        score = 0
        max_score = 100
        score_details = []
        
        # Фактор 1: Сетевая доступность (30 баллов)
        required_ports = cve.get("requires_port", [])
        open_port_nums = set()
        if isinstance(self.system_info.open_ports, list):
            for p in self.system_info.open_ports:
                if hasattr(p, 'port'):
                    open_port_nums.add(p.port)
                elif isinstance(p, dict):
                    open_port_nums.add(p.get("port", 0))
        
        if required_ports:
            # Если есть конкретные требуемые порты - проверяем их
            matched_ports = [p for p in required_ports if p in open_port_nums]
            if matched_ports:
                port_score = min(30, len(matched_ports) / len(required_ports) * 30)
                score += port_score
                score_details.append(f"Порты открыты: {matched_ports}")
            else:
                # Если порты требуются но не открыты - снижаем баллы
                score -= 10
                score_details.append(f"Требуемые порты закрыты: {required_ports}")
        else:
            # Если нет специфичных портов, но атака требует сетевого доступа
            attack_type = cve.get("attack_type", "")
            if attack_type in ["sql_injection", "cross_site_scripting", "remote_code_execution"]:
                # Проверяем наличие веб-портов
                web_ports = {80, 443, 8080, 8443}
                if web_ports.intersection(open_port_nums):
                    score += 25
                    score_details.append("Веб-порты открыты")
                else:
                    score += 10
                    score_details.append("Веб-порты частично открыты")
            else:
                # Для других атак считаем что сеть доступна
                score += 15
                score_details.append("Сетевой доступ предполагается")
        
        # Фактор 2: Подтверждение Trivy (35 баллов)
        cve_id = cve.get("id", "")
        trivy_confirmed, trivy_details, trivy_severity = self._check_trivy_vulnerability(cve_id)
        
        if trivy_confirmed:
            if trivy_severity in ["CRITICAL", "HIGH"]:
                score += 35
                score_details.append("Trivy подтвердил (критично)")
            elif trivy_severity == "MEDIUM":
                score += 25
                score_details.append("Trivy подтвердил (средне)")
            else:
                score += 15
                score_details.append("Trivy подтвердил (низко)")
        else:
            # Если Trivy не подтвердил, но есть другие признаки
            score += 5
            score_details.append("Trivy не подтвердил, но есть другие признаки")
        
        # Фактор 3: Уязвимое ПО обнаружено (20 баллов)
        sw_names_lower = set()
        if isinstance(self.system_info.installed_software, list):
            for sw in self.system_info.installed_software:
                if hasattr(sw, 'name'):
                    sw_names_lower.add(sw.name.lower())
                elif isinstance(sw, dict):
                    sw_names_lower.add(sw.get("name", "").lower())
        
        affected_software = cve.get("affected_software", [])
        vulnerable_sw_found = False
        for sw_name in affected_software:
            sw_lower = sw_name.lower()
            if any(sw_lower in installed for installed in sw_names_lower):
                vulnerable_sw_found = True
                break
        
        if vulnerable_sw_found:
            score += 20
            score_details.append("Уязвимое ПО обнаружено")
        else:
            # Проверяем по target_service из вектора атаки
            if av.target_service:
                av_svc_lower = av.target_service.lower()
                if any(av_svc_lower in installed for installed in sw_names_lower):
                    score += 10
                    score_details.append("ПО по вектору атаки обнаружено")
        
        # Фактор 4: Отсутствие патчей/обновлений (10 баллов)
        if not self.system_info.updates_installed:
            score += 10
            score_details.append("Обновления не установлены")
        else:
            score += 5
            score_details.append("Обновления установлены")
        
        # Фактор 5: Слабые средства защиты (5 баллов)
        # Снижаем требования к средствам защиты
        if not self.system_info.firewall_active:
            score += 3
            score_details.append("Брандмауэр отключён")
        if not self.system_info.antivirus_active:
            score += 2
            score_details.append("Антивирус отключён")
        
        # Определяем реализуемость на основе score (ПОВЫШЕННЫЕ ПОРОГИ)
        if score >= 60:
            feasibility = AttackFeasibility.FEASIBLE
        elif score >= 30:
            feasibility = AttackFeasibility.PARTIALLY_FEASIBLE
        elif score >= 10:
            feasibility = AttackFeasibility.REQUIRES_ANALYSIS
        else:
            feasibility = AttackFeasibility.NOT_FEASIBLE
        
        reason_text = ". ".join(score_details)
        if protection_notes:
            reason_text += ". Защита: " + "; ".join(protection_notes)
        if trivy_confirmed:
            reason_text += ". " + trivy_details
        
        return score, max_score, feasibility, reason_text

    def _evaluate_feasibility(self, cve: dict, av: AttackVector) -> tuple:
        """
        Оценка реализуемости атаки на основе конфигурации сервера.
        ВАЖНО: ВСЕ векторы атаки сохраняются в отчёте, но с разной оценкой реализуемости.
        Это позволяет показать полную картину угроз, а не скрывать "не реализуемые" атаки.
        
        УЛУЧШЕННАЯ ВЕРСИЯ: Использует многофакторную оценку с учётом:
        - Сетевой доступности
        - Подтверждения Trivy
        - Версий ПО
        - Средств защиты
        """
        prerequisites = cve.get("prerequisites", [])
        required_services = cve.get("requires_service", [])
        required_ports = cve.get("requires_port", [])
        attack_type = cve.get("attack_type", "")

        # Собираем информацию о сервере
        open_port_nums = set()
        if isinstance(self.system_info.open_ports, list):
            for p in self.system_info.open_ports:
                if hasattr(p, 'port'):
                    open_port_nums.add(p.port)
                elif isinstance(p, dict):
                    open_port_nums.add(p.get("port", 0))

        running_svc_lower = set(s.lower() for s in self.system_info.running_services)
        sw_names_lower = set()
        if isinstance(self.system_info.installed_software, list):
            for sw in self.system_info.installed_software:
                if hasattr(sw, 'name'):
                    sw_names_lower.add(sw.name.lower())
                elif isinstance(sw, dict):
                    sw_names_lower.add(sw.get("name", "").lower())

        reasons = []
        protection_notes = []

        # === Проверка сетевой доступности ===
        network_accessible = False
        
        # Проверка портов
        if required_ports:
            matched_ports = [p for p in required_ports if p in open_port_nums]
            if matched_ports:
                network_accessible = True
                reasons.append(f"Требуемые порты открыты: {matched_ports}")
            else:
                reasons.append(f"Требуемые порты закрыты: {required_ports}")
        else:
            # Если нет специфичных портов, но атака требует сетевого доступа
            if attack_type in ["sql_injection", "cross_site_scripting", "remote_code_execution"]:
                web_ports = {80, 443, 8080, 8443}
                if web_ports.intersection(open_port_nums):
                    network_accessible = True
                    reasons.append("Веб-порты открыты")
                else:
                    reasons.append("Веб-порты закрыты")
            else:
                network_accessible = True
                reasons.append("Сетевой доступ предполагается")

        # === Проверка сервисов ===
        services_available = False
        
        # Проверка RDP
        if "rdp" in required_services:
            if self.system_info.has_rdp_enabled and 3389 in open_port_nums:
                services_available = True
                reasons.append("RDP включён и порт 3389 открыт")
            else:
                reasons.append("RDP недоступен")

        # Проверка SMB
        if "smb" in required_services:
            if self.system_info.has_smb_enabled:
                services_available = True
                reasons.append("SMB активен (порт 445 открыт)")
            else:
                reasons.append("SMB не обнаружен")

        # Проверка FTP
        if "ftp" in required_services:
            if self.system_info.has_ftp_enabled:
                services_available = True
                reasons.append("FTP-сервер активен")
            else:
                reasons.append("FTP-сервер не обнаружен")

        # Проверка SSH
        if "ssh" in required_services:
            if 22 in open_port_nums:
                services_available = True
                reasons.append("SSH-сервер активен")
            else:
                reasons.append("SSH-сервер не обнаружен")

        # Проверка веб-сервера
        if "web_server" in required_services or "web_application" in required_services:
            if self.system_info.has_web_server:
                services_available = True
                reasons.append("Веб-сервер обнаружен")
            else:
                reasons.append("Веб-сервер не обнаружен")

        # Проверка специфичного ПО
        software_found = False
        for sw_name in cve.get("affected_software", []):
            sw_lower = sw_name.lower()
            found = any(sw_lower in installed for installed in sw_names_lower)
            if found:
                software_found = True
                reasons.append(f"Обнаружено уязвимое ПО: {sw_name}")

        # Проверка по target_service из вектора атаки
        if av.target_service:
            av_svc_lower = av.target_service.lower()
            if any(av_svc_lower in installed for installed in sw_names_lower):
                software_found = True
                reasons.append(f"ПО по вектору атаки обнаружено: {av.target_service}")

        # === Учёт средств защиты ===
        if self.system_info.firewall_active:
            protection_notes.append("Брандмауэр активен (может блокировать часть атак)")
        if self.system_info.antivirus_active:
            protection_notes.append("Антивирус активен (может обнаружить эксплоит)")

        # === МНОГОФАКТОРНАЯ ОЦЕНКА (улучшенная логика) ===
        score, max_score, feasibility, detailed_reason = self._calculate_feasibility_score(
            cve, av, reasons, protection_notes
        )

        # Добавляем числовую оценку в reason
        final_reason = f"Оценка реализуемости: {score}/{max_score}. {detailed_reason}"

        return (feasibility, final_reason)

    def _analyze_port_based_vulnerabilities(self, scan_result: ScanResult) -> list[VulnerabilityMatch]:
        """Анализ уязвимостей на основе обнаруженных открытых портов."""
        matches = []
        seen_cves = set(m.cve_id for m in self.results)

        for port_info in scan_result.open_ports:
            port = port_info.port if hasattr(port_info, 'port') else port_info.get("port", 0)
            cves = self.vuln_db.find_cves_by_port(port)
            for cve in cves:
                if cve["id"] in seen_cves:
                    continue
                seen_cves.add(cve["id"])

                dummy_av = AttackVector(
                    id=f"port-{port}",
                    name=f"Атака через порт {port}",
                    description=f"Вектор атаки через открытый порт {port}",
                    target_port=port,
                )
                feasibility, reason = self._evaluate_feasibility(cve, dummy_av)
                mitigations = self.vuln_db.get_all_mitigations(cve)
                recommendation = self._generate_recommendation(cve, feasibility, mitigations)

                match = VulnerabilityMatch(
                    cve_id=cve["id"],
                    cwe_id=", ".join(cve.get("related_cwe", [])),
                    capec_id=", ".join(cve.get("related_capec", [])),
                    mitre_technique=", ".join(cve.get("related_mitre", [])),
                    attack_vector_id=dummy_av.id,
                    attack_name=dummy_av.name,
                    description=cve["description"],
                    severity=cve.get("severity", "MEDIUM"),
                    feasibility=feasibility.value,
                    reason=reason,
                    recommendation=recommendation,
                )
                matches.append(match)

        return matches

    def _analyze_software_vulnerabilities(self) -> list[VulnerabilityMatch]:
        """Анализ уязвимостей установленного ПО."""
        matches = []
        seen_cves = set(m.cve_id for m in self.results)

        for sw in self.system_info.installed_software:
            sw_name = sw.name if hasattr(sw, 'name') else sw.get("name", "")
            cves = self.vuln_db.find_cves_by_software(sw_name)
            for cve in cves:
                if cve["id"] in seen_cves:
                    continue
                seen_cves.add(cve["id"])

                dummy_av = AttackVector(
                    id=f"sw-{sw_name[:20]}",
                    name=f"Атака на {sw_name}",
                    description=f"Эксплуатация уязвимости в {sw_name}",
                    target_service=sw_name,
                )
                feasibility, reason = self._evaluate_feasibility(cve, dummy_av)
                mitigations = self.vuln_db.get_all_mitigations(cve)
                recommendation = self._generate_recommendation(cve, feasibility, mitigations)

                match = VulnerabilityMatch(
                    cve_id=cve["id"],
                    cwe_id=", ".join(cve.get("related_cwe", [])),
                    capec_id=", ".join(cve.get("related_capec", [])),
                    mitre_technique=", ".join(cve.get("related_mitre", [])),
                    attack_vector_id=dummy_av.id,
                    attack_name=dummy_av.name,
                    description=cve["description"],
                    severity=cve.get("severity", "MEDIUM"),
                    feasibility=feasibility.value,
                    reason=reason,
                    recommendation=recommendation,
                )
                matches.append(match)

        return matches

    def _generate_recommendation(self, cve: dict, feasibility: AttackFeasibility, mitigations: list) -> str:
        """Генерация рекомендации по защите."""
        if feasibility == AttackFeasibility.NOT_FEASIBLE:
            return (
                "✅ Атака не реализуема в текущей конфигурации. "
                "Рекомендуется поддерживать текущие настройки безопасности.\n"
                "💡 Рекомендации: Регулярно обновляйте ПО и проводите аудит безопасности."
            )

        recommendations = []
        if feasibility in (AttackFeasibility.FEASIBLE, AttackFeasibility.PARTIALLY_FEASIBLE):
            recommendations.append("⚠️ ВНИМАНИЕ: Атака потенциально реализуема!")
            recommendations.append("")

        # Добавляем конкретные рекомендации в зависимости от типа атаки
        attack_type = cve.get("attack_type", "")
        if attack_type == "sql_injection":
            recommendations.extend([
                "🛡️ Рекомендации по защите от SQL-инъекций:",
                "  1. Используйте параметризованные запросы (prepared statements)",
                "  2. Валидируйте и экранируйте все входные данные",
                "  3. Ограничьте права доступа к базе данных",
                "  4. Установите WAF (Web Application Firewall)",
                "  5. Регулярно обновляйте СУБД и веб-приложения"
            ])
        elif attack_type == "cross_site_scripting":
            recommendations.extend([
                "🛡️ Рекомендации по защите от XSS:",
                "  1. Экранируйте вывод пользовательских данных",
                "  2. Используйте Content Security Policy (CSP)",
                "  3. Валидируйте входные данные на сервере",
                "  4. Устанавливайте HttpOnly флаги для cookies",
                "  5. Обновляйте браузеры и фреймворки"
            ])
        elif attack_type == "remote_code_execution":
            recommendations.extend([
                "🛡️ Рекомендации по защите от RCE:",
                "  1. Обновите ПО до последних версий",
                "  2. Ограничьте права выполнения команд",
                "  3. Используйте sandbox для выполнения кода",
                "  4. Валидируйте все входные данные",
                "  5. Отключите ненужные функции и сервисы"
            ])
        elif "brute_force" in attack_type:
            recommendations.extend([
                "🛡️ Рекомендации по защите от брутфорса:",
                "  1. Включите двухфакторную аутентификацию",
                "  2. Ограничьте количество попыток входа",
                "  3. Используйте сложные пароли",
                "  4. Включите блокировку IP после неудачных попыток",
                "  5. Мониторьте подозрительную активность"
            ])

        if mitigations:
            recommendations.append("📋 Специфичные меры защиты:")
            for i, mit in enumerate(mitigations, 1):
                recommendations.append(f"  {i}. {mit}")

        # Добавляем общие рекомендации
        if cve.get("severity") in ("CRITICAL", "HIGH"):
            recommendations.extend([
                "",
                "🚨 ПРИОРИТЕТ: Высокий. Требуется немедленное внимание!",
                "   - Установите патчи в течение 24-48 часов",
                "   - Рассмотрите временное отключение уязвимого сервиса",
                "   - Усильте мониторинг и логирование"
            ])
        elif cve.get("severity") == "MEDIUM":
            recommendations.extend([
                "",
                "⚠️ ПРИОРИТЕТ: Средний. Рекомендуется устранение в течение недели"
            ])
        else:
            recommendations.extend([
                "",
                "ℹ️ ПРИОРИТЕТ: Низкий. Рекомендуется устранение при плановом обновлении"
            ])

        # Добавляем рекомендации по мониторингу
        recommendations.extend([
            "",
            "🔍 Рекомендации по мониторингу:",
            "  - Настройте алерты на подозрительную активность",
            "  - Регулярно проверяйте логи безопасности",
            "  - Проводите периодическое сканирование уязвимостей"
        ])

        return "\n".join(recommendations) if recommendations else "Требуется ручной анализ."


    # =========================================================================
    # НОВЫЙ БЛОК: УМНАЯ АГРЕГАЦИЯ ДУБЛИКАТОВ
    # =========================================================================

    def _get_max_severity(self, sev1: str, sev2: str) -> str:
        """Сравнение критичности (возвращает наивысшую)."""
        weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        w1 = weights.get(str(sev1).upper(), 0)
        w2 = weights.get(str(sev2).upper(), 0)
        return sev1 if w1 >= w2 else sev2

    def _get_worst_feasibility(self, feas1: str, feas2: str) -> str:
        """Сравнение реализуемости (возвращает наихудший/самый опасный статус)."""
        weights = {
            AttackFeasibility.FEASIBLE.value: 4,
            AttackFeasibility.PARTIALLY_FEASIBLE.value: 3,
            AttackFeasibility.REQUIRES_ANALYSIS.value: 2,
            AttackFeasibility.NOT_FEASIBLE.value: 1
        }
        w1 = weights.get(feas1, 0)
        w2 = weights.get(feas2, 0)
        return feas1 if w1 >= w2 else feas2

    def _deduplicate(self, results: list[VulnerabilityMatch]) -> list[VulnerabilityMatch]:
        """
        Удаление дубликатов с умной агрегацией.
        Вместо создания 100 записей для одного порта/вектора, этот метод
        схлопывает их в 1 запись, объединяя все CVE через запятую
        и выбирая максимальный уровень угрозы.
        """
        groups = {}
        for r in results:
            # Схлопываем по Названию атаки + CAPEC (чтобы объединить одинаковые векторы)
            key = f"{r.attack_name}_{r.capec_id}"
            
            if key not in groups:
                groups[key] = {
                    'match': r, 
                    'cves': set([r.cve_id]) if r.cve_id and r.cve_id != "N/A" else set(),
                    'count': 1
                }
            else:
                groups[key]['count'] += 1
                if r.cve_id and r.cve_id != "N/A":
                    groups[key]['cves'].add(r.cve_id)
                
                existing_match = groups[key]['match']
                # Берем наивысшую критичность и реализуемость из всех дубликатов
                existing_match.severity = self._get_max_severity(existing_match.severity, r.severity)
                existing_match.feasibility = self._get_worst_feasibility(existing_match.feasibility, r.feasibility)
                
                # Если у нового дубликата критичность выше, забираем его описание, так как оно важнее
                w_existing = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}.get(str(existing_match.severity).upper(), 0)
                w_new = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}.get(str(r.severity).upper(), 0)
                if w_new > w_existing:
                    existing_match.description = r.description
                    existing_match.reason = r.reason
                    existing_match.recommendation = r.recommendation
            if hasattr(r, 'target_software') and r.target_software:
                existing_match.target_software = r.target_software

        unique = []
        for g in groups.values():
            match = g['match']
            cves = sorted(list(g['cves']))
            
            if cves:
                # Если CVE очень много, обрезаем строку, чтобы не сломать таблицы в UI
                if len(cves) > 10:
                    match.cve_id = ", ".join(cves[:10]) + f" ... (+ ещё {len(cves)-10})"
                else:
                    match.cve_id = ", ".join(cves)
            else:
                match.cve_id = "N/A"
                
            unique.append(match)
            
        return unique

    def _correlate_with_trivy(self, scan_result: ScanResult) -> list[VulnerabilityMatch]:
        """
        Корреляция результатов с данными Trivy.
        Усиливает реализуемость атак если Trivy подтвердил уязвимость.
        """
        if not self.trivy_result:
            return self.results
        
        logger.info("[TRIVY] Запуск корреляции с данными Trivy...")
        
        correlator = TrivyCorrelator()
        
        # Коррелируем Trivy с атаками атакующего
        corr_result = correlator.correlate(
            trivy_result=self.trivy_result,
            attacker_vectors=scan_result.attack_vectors,
            open_ports=self.system_info.open_ports,
            existing_matches=self.results
        )
        
        # Объединяем результаты
        trivy_matches = correlator.get_enhanced_matches()
        merged = correlator.merge_with_existing(self.results, trivy_matches)
        
        logger.info(f"[TRIVY] Корреляция завершена:")
        logger.info(f"  - Совпадений с атаками: {corr_result.matched_with_attacks}")
        logger.info(f"  - Усилено атак: {corr_result.enhanced_attacks}")
        logger.info(f"  - Новых критических находок: {len(corr_result.new_critical_findings)}")
        
        return merged

    def _build_software_map(self, scan_result: ScanResult) -> dict:
        """
        Строит карту CVE -> ПО из всех доступных источников.
        
        Приоритеты:
        1. Trivy (самый надежный источник - реальные уязвимости в ПО)
        2. CVE база данных (affected_software из описания CVE)
        3. Установленное ПО на сервере
        4. Сопоставление по портам
        """
        software_map = {}
        
        # 1. Приоритет: Данные из Trivy (самый надежный источник)
        if self.trivy_result:
            trivy_vulns = []
            if isinstance(self.trivy_result, dict):
                trivy_vulns = self.trivy_result.get("vulnerabilities", [])
            elif hasattr(self.trivy_result, "vulnerabilities"):
                trivy_vulns = self.trivy_result.vulnerabilities
            
            for v in trivy_vulns:
                v_id = v.get("vuln_id") if isinstance(v, dict) else getattr(v, "vuln_id", "")
                pkg = v.get("pkg_name") if isinstance(v, dict) else getattr(v, "pkg_name", "")
                ver = v.get("installed_version") if isinstance(v, dict) else getattr(v, "installed_version", "")
                
                if v_id and pkg:
                    software_name = f"{pkg} v.{ver}" if ver else pkg
                    software_map[v_id] = software_name
                    
                    # Также добавляем варианты без версии для гибкого поиска
                    if ver:
                        software_map[f"{v_id}_base"] = pkg
            
            logger.info(f"[SOFTWARE_MAP] Из Trivy добавлено {len(software_map)} записей")
        
        # 2. CVE база данных (affected_software)
        if hasattr(self.vuln_db, 'cve_db'):
            cve_list = self.vuln_db.cve_db if isinstance(self.vuln_db.cve_db, list) else []
            for cve_info in cve_list:
                cve_id = cve_info.get("id", "")
                if cve_id in software_map:
                    continue  # Уже есть из Trivy
                
                affected = cve_info.get("affected_software", [])
                if affected:
                    # Берем первое affected ПО как наиболее вероятное
                    software_map[cve_id] = affected[0]
        
        # 3. Сопоставление по установленному ПО
        for sw in self.system_info.installed_software:
            sw_name = sw.name if hasattr(sw, 'name') else sw.get("name", "")
            sw_version = sw.version if hasattr(sw, 'version') else sw.get("version", "")
            
            if not sw_name:
                continue
            
            # Ищем CVE для этого ПО
            cves = self.vuln_db.find_cves_by_software(sw_name)
            for cve in cves:
                cve_id = cve.get("id", "")
                if cve_id and cve_id not in software_map:
                    software_name = f"{sw_name} v.{sw_version}" if sw_version else sw_name
                    software_map[cve_id] = software_name
        
        # 4. Сопоставление по портам из scan_result
        if hasattr(scan_result, 'open_ports'):
            ports = scan_result.open_ports
        elif isinstance(scan_result, dict):
            ports = scan_result.get("open_ports", [])
        else:
            ports = []
        
        port_service_map = {
            21: "FTP Server",
            22: "OpenSSH",
            25: "SMTP Server",
            53: "DNS Server",
            80: "HTTP Server (Apache/Nginx/IIS)",
            110: "POP3 Server",
            143: "IMAP Server",
            443: "HTTPS Server (Apache/Nginx/IIS)",
            445: "Windows SMB",
            993: "IMAPS Server",
            995: "POP3S Server",
            1433: "Microsoft SQL Server",
            1521: "Oracle Database",
            3306: "MySQL",
            3389: "Microsoft RDP",
            5432: "PostgreSQL",
            5900: "VNC Server",
            6379: "Redis",
            8080: "HTTP Proxy (Tomcat/Jenkins)",
            8443: "HTTPS Alt (Tomcat)",
            27017: "MongoDB",
        }
        
        for port_info in ports:
            port_num = port_info.port if hasattr(port_info, 'port') else port_info.get("port", 0)
            service = port_info.service if hasattr(port_info, 'service') else port_info.get("service", "")
            
            # Если есть конкретный сервис от сканера
            if service and service.lower() not in ["unknown", ""]:
                # Находим CVE для этого порта
                cves = self.vuln_db.find_cves_by_port(port_num)
                for cve in cves:
                    cve_id = cve.get("id", "")
                    if cve_id and cve_id not in software_map:
                        software_map[cve_id] = service
            
            # Если есть стандартный сервис для порта
            elif port_num in port_service_map:
                cves = self.vuln_db.find_cves_by_port(port_num)
                for cve in cves:
                    cve_id = cve.get("id", "")
                    if cve_id and cve_id not in software_map:
                        software_map[cve_id] = port_service_map[port_num]
        
        logger.info(f"[SOFTWARE_MAP] Всего записей в карте ПО: {len(software_map)}")
        return software_map

    def _guess_software_from_port(self, match: VulnerabilityMatch, scan_result: ScanResult) -> str:
        """
        Эвристическое определение ПО по порту из scan_result.
        Используется как фоллбэк когда нет точных данных.
        """
        # Стандартные маппинги портов
        port_service_map = {
            21: "FTP Server",
            22: "OpenSSH",
            25: "SMTP Server",
            53: "DNS Server",
            80: "HTTP Server (Apache/Nginx/IIS)",
            110: "POP3 Server",
            143: "IMAP Server",
            443: "HTTPS Server (Apache/Nginx/IIS)",
            445: "Windows SMB",
            993: "IMAPS Server",
            995: "POP3S Server",
            1433: "Microsoft SQL Server",
            1521: "Oracle Database",
            3306: "MySQL",
            3389: "Microsoft RDP",
            5432: "PostgreSQL",
            5900: "VNC Server",
            6379: "Redis",
            8080: "HTTP Proxy (Tomcat/Jenkins)",
            8443: "HTTPS Alt (Tomcat)",
            27017: "MongoDB",
        }
        
        # Получаем порт из match
        target_port = match.cve_id  # Может быть в CVE_ID если формат особый
        port = None
        
        # Пробуем извлечь порт из attack_vector_id
        if match.attack_vector_id:
            av_id = match.attack_vector_id
            if av_id.startswith("port-"):
                try:
                    port = int(av_id.replace("port-", ""))
                except ValueError:
                    pass
        
        # Если не нашли, пробуем из target_port в CVE базе
        if port is None:
            cve_id = match.cve_id.split(",")[0].strip()
            # Ищем CVE в списке
            if hasattr(self.vuln_db, 'cve_db') and isinstance(self.vuln_db.cve_db, list):
                for cve in self.vuln_db.cve_db:
                    if cve.get("id") == cve_id:
                        requires_port = cve.get("requires_port", [])
                        if requires_port:
                            port = requires_port[0]
                        break
        
        if port and port in port_service_map:
            return port_service_map[port]
        
        # Последняя попытка: используем информацию из имени атаки
        attack_name_lower = match.attack_name.lower() if match.attack_name else ""
        
        if "веб" in attack_name_lower or "http" in attack_name_lower:
            return "Web Server (Apache/Nginx/IIS)"
        elif "ssh" in attack_name_lower:
            return "OpenSSH"
        elif "rdp" in attack_name_lower or "удаленный рабочий стол" in attack_name_lower:
            return "Microsoft RDP"
        elif "smb" in attack_name_lower:
            return "Windows SMB"
        elif "ftp" in attack_name_lower:
            return "FTP Server"
        elif "sql" in attack_name_lower or "база данных" in attack_name_lower:
            return "Database Server"
        elif "почт" in attack_name_lower or "smtp" in attack_name_lower:
            return "Mail Server"
        
        return "Неидентифицированное ПО"

    def validate_results(self) -> dict:
        """
        Валидация результатов корреляции.
        Обнаруживает противоречия и аномалии в данных.
        
        Возвращает отчёт о валидации с флагами проблем.
        """
        validation_report = {
            "total_results": len(self.results),
            "discrepancies": [],
            "warnings": [],
            "quality_score": 100,  # 0-100
        }
        
        trivy_cve_set = set()
        if self.trivy_result:
            # Собираем CVE из Trivy
            vulns = []
            if isinstance(self.trivy_result, dict):
                vulns = self.trivy_result.get("vulnerabilities", [])
            elif hasattr(self.trivy_result, "vulnerabilities"):
                vulns = self.trivy_result.vulnerabilities
            
            for v in vulns:
                v_id = v.get("vuln_id") if isinstance(v, dict) else getattr(v, "vuln_id", "")
                if v_id:
                    trivy_cve_set.add(v_id.upper())
        
        for match in self.results:
            cve_id = match.cve_id.split(",")[0].strip().upper() if match.cve_id else ""
            
            # Проверка 1: Trivy подтвердил, но мы сказали "НЕ РЕАЛИЗУЕМА"
            if cve_id in trivy_cve_set and match.feasibility == AttackFeasibility.NOT_FEASIBLE.value:
                validation_report["discrepancies"].append({
                    "type": "TRIVY_CONTRADICTION",
                    "cve_id": cve_id,
                    "description": f"Trivy подтвердил уязвимость {cve_id}, но система оценила как 'НЕ РЕАЛИЗУЕМА'",
                    "severity": "HIGH",
                    "recommendation": "Требуется ручной анализ - возможно ошибка в оценке конфигурации"
                })
                validation_report["quality_score"] -= 10
            
            # Проверка 2: Система сказала "РЕАЛИЗУЕМА", но Trivy не нашёл
            if (match.feasibility == AttackFeasibility.FEASIBLE.value and 
                cve_id and cve_id not in trivy_cve_set and trivy_cve_set):
                validation_report["warnings"].append({
                    "type": "UNCONFIRMED_FEASIBLE",
                    "cve_id": cve_id,
                    "description": f"Атака оценена как 'РЕАЛИЗУЕМА', но Trivy не обнаружил уязвимость",
                    "severity": "MEDIUM",
                    "recommendation": "Проверить версии ПО - возможно требуется обновление баз Trivy"
                })
                validation_report["quality_score"] -= 5
            
            # Проверка 3: Критичная уязвимость без целевого ПО
            if match.severity in ["CRITICAL", "HIGH"] and not match.target_software:
                validation_report["warnings"].append({
                    "type": "MISSING_TARGET_SOFTWARE",
                    "cve_id": cve_id,
                    "description": f"Критичная уязвимость {cve_id} без определённого целевого ПО",
                    "severity": "MEDIUM",
                    "recommendation": "Уточнить привязку ПО через дополнительные источники"
                })
                validation_report["quality_score"] -= 3
            
            # Проверка 4: Отсутствие описания CWE
            if not match.cwe_id or match.cwe_id == "N/A":
                validation_report["warnings"].append({
                    "type": "MISSING_CWE",
                    "cve_id": cve_id,
                    "description": f"Уязвимость {cve_id} без классификации CWE",
                    "severity": "LOW",
                    "recommendation": "Обогатить базу CVE данными о CWE"
                })
                validation_report["quality_score"] -= 1
        
        # Проверка 5: Статистика по реализуемости
        feasible_count = sum(1 for m in self.results if m.feasibility == AttackFeasibility.FEASIBLE.value)
        total_count = len(self.results)
        
        if total_count > 0:
            feasible_ratio = feasible_count / total_count
            # Если более 80% атак реализуемы - это может быть аномалией
            if feasible_ratio > 0.8:
                validation_report["warnings"].append({
                    "type": "HIGH_FEASIBILITY_RATIO",
                    "description": f"{feasible_ratio:.0%} атак оценены как реализуемые",
                    "severity": "MEDIUM",
                    "recommendation": "Проверить корректность оценки конфигурации защиты"
                })
                validation_report["quality_score"] -= 5
            
            # Если менее 5% атак реализуемы - возможно система слишком консервативна
            elif feasible_ratio < 0.05 and total_count > 10:
                validation_report["warnings"].append({
                    "type": "LOW_FEASIBILITY_RATIO",
                    "description": f"Только {feasible_ratio:.0%} атак оценены как реализуемые",
                    "severity": "LOW",
                    "recommendation": "Проверить полноту данных о системе"
                })
                validation_report["quality_score"] -= 3
        
        # Ограничиваем quality_score минимум 0
        validation_report["quality_score"] = max(0, validation_report["quality_score"])
        
        return validation_report

    def get_summary(self) -> dict:
        """Сводка результатов корреляции с метриками качества."""
        total = len(self.results)
        feasible = sum(1 for r in self.results if r.feasibility == AttackFeasibility.FEASIBLE.value)
        not_feasible = sum(1 for r in self.results if r.feasibility == AttackFeasibility.NOT_FEASIBLE.value)
        partial = sum(1 for r in self.results if r.feasibility == AttackFeasibility.PARTIALLY_FEASIBLE.value)
        unknown = sum(1 for r in self.results if r.feasibility == AttackFeasibility.REQUIRES_ANALYSIS.value)

        critical = sum(1 for r in self.results if str(r.severity).upper() == "CRITICAL" and r.feasibility != AttackFeasibility.NOT_FEASIBLE.value)
        high = sum(1 for r in self.results if str(r.severity).upper() == "HIGH" and r.feasibility != AttackFeasibility.NOT_FEASIBLE.value)
        
        # Рассчитываем contextual severity для критичных уязвимостей
        contextual_critical = 0
        for r in self.results:
            if str(r.severity).upper() == "CRITICAL" and r.feasibility != AttackFeasibility.NOT_FEASIBLE.value:
                # Учитываем только те, где реализуемость высокая
                if r.feasibility == AttackFeasibility.FEASIBLE.value:
                    contextual_critical += 1
        
        # Получаем отчёт валидации
        validation = self.validate_results()

        return {
            "total_vulnerabilities_analyzed": total,
            "feasible_attacks": feasible,
            "not_feasible_attacks": not_feasible,
            "partially_feasible": partial,
            "requires_analysis": unknown,
            "critical_actionable": contextual_critical,  # Только реально реализуемые критичные
            "high_actionable": high,
            "validation_quality_score": validation["quality_score"],
            "validation_discrepancies": len(validation["discrepancies"]),
            "validation_warnings": len(validation["warnings"]),
        }
    
    def get_validation_report(self) -> dict:
        """Полный отчёт валидации результатов."""
        return self.validate_results()
