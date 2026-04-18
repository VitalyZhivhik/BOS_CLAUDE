"""
Скрипт для обновления баз данных CVE, CWE, CAPEC, MITRE ATT&CK
реальными данными из официальных источников с переводом на русский язык.
"""

import json
import urllib.request
import urllib.error
import time
import os
from datetime import datetime

class DatabaseUpdater:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_dir = os.path.join(self.base_dir, "databases")
        
    def translate_text(self, text, max_length=500):
        """
        Простой перевод ключевых терминов безопасности.
        Для полноценного перевода рекомендуется использовать API переводчика.
        """
        translations = {
            # Типы атак
            "sql_injection": "SQL-инъекция",
            "cross_site_scripting": "Межсайтовый скриптинг (XSS)",
            "remote_code_execution": "Удаленное выполнение кода",
            "privilege_escalation": "Повышение привилегий",
            "buffer_overflow": "Переполнение буфера",
            "denial_of_service": "Отказ в обслуживании",
            "authentication_bypass": "Обход аутентификации",
            "directory_traversal": "Обход каталогов",
            "command_injection": "Инъекция команд",
            "deserialization_attack": "Атака десериализации",
            "unknown": "Неизвестно",
            
            # Уровни серьезности
            "CRITICAL": "КРИТИЧЕСКИЙ",
            "HIGH": "ВЫСОКИЙ",
            "MEDIUM": "СРЕДНИЙ",
            "LOW": "НИЗКИЙ",
            "UNKNOWN": "НЕИЗВЕСТНО",
            
            # Общие термины
            "The product": "Продукт",
            "The software": "Программное обеспечение",
            "The application": "Приложение",
            "allows": "позволяет",
            "attacker": "атакующий",
            "vulnerability": "уязвимость",
            "exploit": "эксплойт",
            "malicious": "вредоносный",
        }
        
        result = text
        for eng, rus in translations.items():
            result = result.replace(eng, rus)
        
        return result
    
    def fetch_nvd_cve_data(self, cve_id):
        """
        Получение данных CVE из NVD API.
        """
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln = data['vulnerabilities'][0]['cve']
                    
                    # Извлечение описания
                    description = ""
                    if 'descriptions' in vuln:
                        for desc in vuln['descriptions']:
                            if desc['lang'] == 'en':
                                description = desc['value']
                                break
                    
                    # Извлечение CVSS
                    cvss_score = 0.0
                    severity = "UNKNOWN"
                    if 'metrics' in vuln:
                        if 'cvssMetricV31' in vuln['metrics']:
                            cvss_data = vuln['metrics']['cvssMetricV31'][0]
                            cvss_score = cvss_data['cvssData']['baseScore']
                            severity = cvss_data['cvssData']['baseSeverity']
                        elif 'cvssMetricV2' in vuln['metrics']:
                            cvss_data = vuln['metrics']['cvssMetricV2'][0]
                            cvss_score = cvss_data['cvssData']['baseScore']
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    
                    return {
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': severity
                    }
            
            time.sleep(1)  # Задержка для соблюдения лимитов API
            return None
            
        except Exception as e:
            print(f"Ошибка при получении {cve_id}: {e}")
            return None
    
    def update_cve_database(self, limit=10):
        """
        Обновление базы CVE реальными данными.
        """
        print("=" * 60)
        print("ОБНОВЛЕНИЕ БАЗЫ CVE")
        print("=" * 60)
        
        cve_path = os.path.join(self.db_dir, "cve_database.json")
        
        try:
            with open(cve_path, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
        except Exception as e:
            print(f"Ошибка чтения базы CVE: {e}")
            return
        
        updated_count = 0
        
        for i, entry in enumerate(cve_data[:limit]):
            cve_id = entry.get('id', '')
            
            if not cve_id.startswith('CVE-'):
                continue
            
            print(f"\n[{i+1}/{limit}] Обновление {cve_id}...")
            
            # Получение данных из NVD
            nvd_data = self.fetch_nvd_cve_data(cve_id)
            
            if nvd_data:
                # Обновление описания
                if nvd_data['description']:
                    entry['description'] = nvd_data['description']
                    entry['description_ru'] = self.translate_text(nvd_data['description'][:500])
                
                # Обновление CVSS и серьезности
                entry['cvss_score'] = nvd_data['cvss_score']
                entry['severity'] = nvd_data['severity']
                entry['severity_ru'] = self.translate_text(nvd_data['severity'])
                
                # Перевод типа атаки
                if 'attack_type' in entry:
                    entry['attack_type_ru'] = self.translate_text(entry['attack_type'])
                
                updated_count += 1
                print(f"✓ Обновлено: {cve_id}")
            else:
                print(f"✗ Не удалось обновить: {cve_id}")
        
        # Сохранение обновленной базы
        try:
            backup_path = cve_path + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(cve_data, f, ensure_ascii=False, indent=2)
            print(f"\n✓ Создана резервная копия: {backup_path}")
            
            with open(cve_path, 'w', encoding='utf-8') as f:
                json.dump(cve_data, f, ensure_ascii=False, indent=2)
            
            print(f"\n✓ База CVE обновлена: {updated_count} записей")
            
        except Exception as e:
            print(f"✗ Ошибка сохранения: {e}")
    
    def update_cwe_database(self):
        """
        Обновление базы CWE с переводом на русский.
        """
        print("\n" + "=" * 60)
        print("ОБНОВЛЕНИЕ БАЗЫ CWE")
        print("=" * 60)
        
        cwe_path = os.path.join(self.db_dir, "cwe_database.json")
        
        try:
            with open(cwe_path, 'r', encoding='utf-8') as f:
                cwe_data = json.load(f)
        except Exception as e:
            print(f"Ошибка чтения базы CWE: {e}")
            return
        
        updated_count = 0
        
        for i, entry in enumerate(cwe_data[:20]):  # Обновляем первые 20
            cwe_id = entry.get('id', '')
            
            print(f"\n[{i+1}] Обработка {cwe_id}...")
            
            # Перевод названия
            if 'name' in entry and entry['name']:
                entry['name_ru'] = self.translate_text(entry['name'])
            
            # Перевод описания
            if 'description' in entry and entry['description']:
                entry['description_ru'] = self.translate_text(entry['description'][:500])
            
            # Перевод мер защиты
            if 'mitigation' in entry and entry['mitigation']:
                entry['mitigation_ru'] = self.translate_text(entry['mitigation'][:500])
            
            # Перевод категории
            if 'category' in entry:
                entry['category_ru'] = self.translate_text(entry['category'])
            
            updated_count += 1
            print(f"✓ Обновлено: {cwe_id}")
        
        # Сохранение
        try:
            backup_path = cwe_path + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(cwe_data, f, ensure_ascii=False, indent=2)
            
            with open(cwe_path, 'w', encoding='utf-8') as f:
                json.dump(cwe_data, f, ensure_ascii=False, indent=2)
            
            print(f"\n✓ База CWE обновлена: {updated_count} записей")
            
        except Exception as e:
            print(f"✗ Ошибка сохранения: {e}")
    
    def fill_empty_fields(self):
        """
        Заполнение пустых полей значениями по умолчанию.
        """
        print("\n" + "=" * 60)
        print("ЗАПОЛНЕНИЕ ПУСТЫХ ПОЛЕЙ")
        print("=" * 60)
        
        databases = {
            'cve_database.json': {
                'mitigations': ['Обновите программное обеспечение до последней версии',
                               'Примените рекомендованные патчи безопасности',
                               'Следуйте рекомендациям производителя'],
                'related_cwe': [],
                'related_capec': [],
                'related_mitre': [],
                'requires_service': [],
                'requires_port': [],
                'prerequisites': []
            },
            'cwe_database.json': {
                'mitigation': 'Следуйте лучшим практикам безопасной разработки',
                'related_capec': [],
                'requires_technology': [],
                'detection_methods': []
            }
        }
        
        for db_name, defaults in databases.items():
            db_path = os.path.join(self.db_dir, db_name)
            
            try:
                with open(db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                filled_count = 0
                
                for entry in data:
                    for field, default_value in defaults.items():
                        if field not in entry or not entry[field]:
                            entry[field] = default_value
                            filled_count += 1
                
                # Сохранение
                with open(db_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                
                print(f"✓ {db_name}: заполнено {filled_count} пустых полей")
                
            except Exception as e:
                print(f"✗ Ошибка обработки {db_name}: {e}")

def main():
    print("=" * 60)
    print(" ОБНОВЛЕНИЕ БАЗ ДАННЫХ СИСТЕМЫ БЕЗОПАСНОСТИ")
    print("=" * 60)
    print()
    print("ВНИМАНИЕ: Этот скрипт обновит базы данных реальными данными")
    print("из официальных источников. Будут созданы резервные копии.")
    print()
    
    choice = input("Продолжить? (y/n): ").lower()
    
    if choice != 'y':
        print("Отменено пользователем.")
        return
    
    updater = DatabaseUpdater()
    
    print("\n1. Обновление базы CVE (первые 10 записей)...")
    updater.update_cve_database(limit=10)
    
    print("\n2. Обновление базы CWE (первые 20 записей)...")
    updater.update_cwe_database()
    
    print("\n3. Заполнение пустых полей...")
    updater.fill_empty_fields()
    
    print("\n" + "=" * 60)
    print("ОБНОВЛЕНИЕ ЗАВЕРШЕНО")
    print("=" * 60)
    print("\nРекомендации:")
    print("1. Проверьте обновленные базы данных")
    print("2. Для полного обновления увеличьте лимиты в коде")
    print("3. Для качественного перевода используйте API переводчика")
    print("4. Резервные копии сохранены с расширением .backup_*")

if __name__ == "__main__":
    main()
