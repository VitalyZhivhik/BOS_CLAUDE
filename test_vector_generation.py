#!/usr/bin/env python3
"""
Тестовый скрипт для проверки генерации векторов атак с CVE.
"""

import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

from attacker.attacker_agent import AttackVectorGenerator, OpenPort

def test_vector_generation():
    """Тест генерации векторов атак."""
    print("=== ТЕСТ ГЕНЕРАЦИИ ВЕКТОРОВ АТАК ===")
    
    # Создаем тестовые открытые порты
    test_ports = [
        OpenPort(port=22, service="SSH", banner="SSH-2.0-OpenSSH_8.2p1"),
        OpenPort(port=80, service="HTTP", banner="Apache/2.4.49 (Ubuntu)"),
        OpenPort(port=443, service="HTTPS", banner="nginx/1.18.0"),
        OpenPort(port=3306, service="MySQL", banner="MySQL 5.7.32"),
        OpenPort(port=6379, service="Redis", banner="redis_version:6.2.6"),
    ]
    
    print(f"Тестовые порты: {[p.port for p in test_ports]}")
    print(f"Сервисы: {[p.service for p in test_ports]}")
    
    # Генерируем векторы атак
    generator = AttackVectorGenerator()
    vectors = generator.generate(test_ports)
    
    print(f"\nСгенерировано векторов: {len(vectors)}")
    
    # Анализируем векторы
    cve_vectors = []
    no_cve_vectors = []
    
    for av in vectors:
        if "CVE-" in av.name or "CVE-" in av.description:
            cve_vectors.append(av)
        else:
            no_cve_vectors.append(av)
    
    print(f"\nВекторы с CVE: {len(cve_vectors)} ({len(cve_vectors)/len(vectors)*100:.1f}%)")
    print(f"Векторы без CVE: {len(no_cve_vectors)} ({len(no_cve_vectors)/len(vectors)*100:.1f}%)")
    
    print("\n=== ВЕКТОРЫ С CVE ===")
    for av in cve_vectors:
        print(f"  [{av.severity:>8}] {av.name}: {av.description[:80]}")
    
    print("\n=== ВЕКТОРЫ БЕЗ CVE (первые 10) ===")
    for av in no_cve_vectors[:10]:  # Показываем первые 10
        print(f"  [{av.severity:>8}] {av.name}: {av.description[:80]}")
    
    # Анализируем типы векторов без CVE
    print(f"\n=== АНАЛИЗ ВЕКТОРОВ БЕЗ CVE ===")
    brute_force_count = sum(1 for av in no_cve_vectors if "Brute Force" in av.name)
    enum_count = sum(1 for av in no_cve_vectors if "Enumeration" in av.name or "ENUM" in av.name)
    config_count = sum(1 for av in no_cve_vectors if "Configuration" in av.name or "misconfiguration" in av.attack_type)
    dos_count = sum(1 for av in no_cve_vectors if "Denial of Service" in av.name)
    
    print(f"  Brute Force атаки: {brute_force_count} (общие, не привязаны к конкретным CVE)")
    print(f"  Enumeration атаки: {enum_count} (информационные, не привязаны к CVE)")
    print(f"  Configuration атаки: {config_count} (общие уязвимости конфигурации)")
    print(f"  DoS атаки: {dos_count} (общие атаки)")
    
    # Проверяем соответствие сервисов и CVE
    print("\n=== ПРОВЕРКА СООТВЕТСТВИЯ СЕРВИСОВ И CVE ===")
    for port in test_ports:
        service = port.service
        print(f"\nПорт {port.port} ({service}):")
        
        # Проверяем соответствие в SERVICE_CVE_MAP
        if service in generator.SERVICE_CVE_MAP:
            cves = generator.SERVICE_CVE_MAP[service]
            print(f"  Найдено CVE в маппинге: {len(cves)}")
            for cve_id, severity, desc in cves:
                print(f"    {cve_id} ({severity}): {desc}")
        else:
            print(f"  Нет соответствия в SERVICE_CVE_MAP")
        
        # Проверяем векторы для этого сервиса
        service_vectors = [av for av in vectors if av.target_service == service]
        if service_vectors:
            print(f"  Сгенерировано векторов для сервиса: {len(service_vectors)}")
            for av in service_vectors:
                print(f"    {av.name}: {av.description[:60]}")
        else:
            print(f"  Нет векторов для сервиса")

if __name__ == "__main__":
    test_vector_generation()