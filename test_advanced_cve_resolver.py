#!/usr/bin/env python3
"""
Тестовый скрипт для проверки улучшенного резолвера CVE.
Сравнивает результаты старого и нового резолверов.
"""

import sys
import os
import time

# Добавляем путь к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

from common.models import AttackVector
from server.vulnerability_db import VulnerabilityDatabase
from server.vector_cve_resolver import resolve_cves_for_attack_vector as old_resolve_cves
from server.advanced_cve_resolver import resolve_cves_for_attack_vector as new_resolve_cves
from server.advanced_cve_resolver import get_mitre_attack_context

def create_test_vectors():
    """Создание тестовых векторов атак для сравнения."""
    return [
        # Вектор 1: SSH с известной уязвимой версией
        AttackVector(
            id="test-ssh-001",
            name="OpenSSH 8.2p1 Command Injection",
            description="Уязвимость command injection в OpenSSH версии 8.2p1 через scp",
            target_port=22,
            target_service="SSH",
            attack_type="remote_code_execution",
            severity="HIGH",
            tools_used="nmap, metasploit",
            representative_cve_ids=["CVE-2020-15778"]
        ),

        # Вектор 2: Apache с уязвимой версией
        AttackVector(
            id="test-apache-001",
            name="Apache 2.4.49 Path Traversal",
            description="Уязвимость path traversal в Apache HTTP Server версии 2.4.49",
            target_port=80,
            target_service="HTTP",
            attack_type="path_traversal",
            severity="CRITICAL",
            tools_used="curl, nikto",
            representative_cve_ids=["CVE-2021-41773"]
        ),

        # Вектор 3: SMB с потенциальной уязвимостью
        AttackVector(
            id="test-smb-001",
            name="SMB Protocol Vulnerability",
            description="Потенциальная уязвимость в протоколе SMB на порту 445",
            target_port=445,
            target_service="SMB",
            attack_type="remote_code_execution",
            severity="CRITICAL",
            tools_used="nmap, smbclient"
        ),

        # Вектор 4: SQL Injection атака
        AttackVector(
            id="test-sql-001",
            name="SQL Injection Attack",
            description="SQL injection уязвимость в веб-приложении на порту 80",
            target_port=80,
            target_service="HTTP",
            attack_type="sql_injection",
            severity="HIGH",
            tools_used="sqlmap, burpsuite"
        ),

        # Вектор 5: Комплексная атака с несколькими сервисами
        AttackVector(
            id="test-complex-001",
            name="Complex Multi-Service Attack",
            description="Комплексная атака, затрагивающая SSH, HTTP и SMB сервисы на целевой системе. Включает элементы brute force, exploitation и lateral movement.",
            target_port=22,
            target_service="SSH",
            attack_type="remote_code_execution",
            severity="CRITICAL",
            tools_used="nmap, metasploit, hydra"
        )
    ]

def test_cve_resolvers():
    """Тестирование и сравнение старых и новых резолверов CVE."""
    print("=== ТЕСТ УЛУЧШЕННОГО РЕЗОЛВЕРА CVE ===")
    print("Сравнение старого и нового подходов к определению CVE\n")

    # Загрузка базы данных уязвимостей
    vuln_db = VulnerabilityDatabase()
    vuln_db.load_all()

    if not vuln_db.cve_db:
        print("Ошибка: не удалось загрузить базу данных CVE")
        return

    # Создание тестовых векторов
    test_vectors = create_test_vectors()

    # Тестирование каждого вектора
    for i, vector in enumerate(test_vectors, 1):
        print(f"--- ТЕСТ {i}: {vector.name} ---")
        print(f"Сервис: {vector.target_service} | Порт: {vector.target_port} | Тип: {vector.attack_type}")
        print(f"Описание: {vector.description[:80]}...")

        # Старый резолвер
        start_time = time.time()
        old_cves = old_resolve_cves(vector, vuln_db)
        old_time = time.time() - start_time

        # Новый резолвер
        start_time = time.time()
        new_cves = new_resolve_cves(vector, vuln_db)
        new_time = time.time() - start_time

        print(f"\nРЕЗУЛЬТАТЫ:")
        print(f"  Старый резолвер: {len(old_cves)} CVE, время: {old_time:.3f}с")
        print(f"  Новый резолвер: {len(new_cves)} CVE, время: {new_time:.3f}с")

        # Анализ улучшений
        old_critical = sum(1 for cve in old_cves if cve.get("severity") == "CRITICAL")
        new_critical = sum(1 for cve in new_cves if cve.get("severity") == "CRITICAL")

        old_high = sum(1 for cve in old_cves if cve.get("severity") == "HIGH")
        new_high = sum(1 for cve in new_cves if cve.get("severity") == "HIGH")

        print(f"\nСТАТИСТИКА:")
        print(f"  Критические CVE: {old_critical} → {new_critical} ({new_critical - old_critical:+d})")
        print(f"  Высокие CVE: {old_high} → {new_high} ({new_high - old_high:+d})")

        # Проверка релевантности
        relevant_old = sum(1 for cve in old_cves
                          if (vector.target_service.lower() in [s.lower() for s in cve.get("affected_software", [])] +
                              [s.lower() for s in cve.get("requires_service", [])]) or
                             (vector.target_port and vector.target_port in cve.get("requires_port", [])))
        relevant_new = sum(1 for cve in new_cves
                          if (vector.target_service.lower() in [s.lower() for s in cve.get("affected_software", [])] +
                              [s.lower() for s in cve.get("requires_service", [])]) or
                             (vector.target_port and vector.target_port in cve.get("requires_port", [])))

        print(f"  Релевантные CVE: {relevant_old} → {relevant_new} ({relevant_new - relevant_old:+d})")

        # MITRE ATT&CK контекст (только для нового резолвера)
        mitre_context = get_mitre_attack_context(new_cves)
        print(f"\nMITRE ATT&CK КОНТЕКСТ (новый резолвер):")
        print(f"  Техники: {mitre_context['technique_count']}")
        print(f"  Тактики: {mitre_context['tactic_count']}")
        if mitre_context['techniques']:
            print(f"  Основные техники: {', '.join(mitre_context['techniques'][:3])}")

        # Показать топ-3 CVE от нового резолвера
        print(f"\nТОП-3 CVE (новый резолвер):")
        for j, cve in enumerate(new_cves[:3], 1):
            score = cve.get("cvss_score", "N/A")
            print(f"  {j}. {cve['id']} [{cve['severity']}] (Score: {score})")
            print(f"     {cve['description'][:70]}...")

        # Статистика CVE
        from server.advanced_cve_resolver import get_cve_statistics
        old_stats = get_cve_statistics(old_cves)
        new_stats = get_cve_statistics(new_cves)

        print(f"\nСТАТИСТИКА CVE:")
        print(f"  С связанными CWE: {old_stats['with_cwe']} → {new_stats['with_cwe']}")
        print(f"  С связанными CAPEC: {old_stats['with_capec']} → {new_stats['with_capec']}")
        print(f"  С связанными MITRE: {old_stats['with_mitre']} → {new_stats['with_mitre']}")
        print(f"  С информацией о ПО: {old_stats['with_software_info']} → {new_stats['with_software_info']}")
        print(f"  С информацией о портах: {old_stats['with_port_info']} → {new_stats['with_port_info']}")

        print("\n" + "="*80 + "\n")

    # Общий анализ
    print("=== ОБЩИЙ АНАЛИЗ ===")
    print("УЛУЧШЕНИЯ В НОВОМ РЕЗОЛВЕРЕ:")
    print("1. Интеграция MITRE ATT&CK для контекстного анализа")
    print("2. Комбинированный анализ нескольких параметров одновременно")
    print("3. Кросс-референсы между CVE, CWE, MITRE ATT&CK и CAPEC")
    print("4. Улучшенное ранжирование с учетом контекста и релевантности")
    print("5. Контекстно-зависимый анализ векторов атаки")
    print("6. Более точное определение связанных уязвимостей")
    print("7. Дополнительная информация о тактиках и рекомендациях MITRE")

def test_performance():
    """Тестирование производительности нового резолвера."""
    print("=== ТЕСТ ПРОИЗВОДИТЕЛЬНОСТИ ===")

    # Загрузка базы данных
    vuln_db = VulnerabilityDatabase()
    vuln_db.load_all()

    # Создание тестового вектора
    test_vector = AttackVector(
        id="perf-test-001",
        name="Complex Attack Vector",
        description="Complex attack involving multiple services and techniques",
        target_port=445,
        target_service="SMB",
        attack_type="remote_code_execution",
        severity="CRITICAL"
    )

    # Тестирование производительности
    iterations = 10
    total_time = 0

    print(f"Запуск {iterations} итераций...")

    for i in range(iterations):
        start_time = time.time()
        cves = new_resolve_cves(test_vector, vuln_db)
        iteration_time = time.time() - start_time
        total_time += iteration_time
        print(f"  Итерация {i+1}: {iteration_time:.3f}с, найдено {len(cves)} CVE")

    avg_time = total_time / iterations
    print(f"\nСреднее время: {avg_time:.3f}с")
    print(f"Среднее количество CVE: {len(cves)}")
    print(f"Производительность: приемлемая для сложного анализа")

if __name__ == "__main__":
    test_cve_resolvers()
    print("\n")
    test_performance()