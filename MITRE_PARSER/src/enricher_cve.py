import json
import re

# ----------------------------------------------------------------------
# 1. Ручные маппинги для конкретных CVE (можно расширять)
# ----------------------------------------------------------------------
manual_mapping = {
    "CVE-2012-4550": {
        "related_capec": ["CAPEC-1", "CAPEC-180"],
        "related_mitre": ["T1190", "T1068"],
        "requires_service": ["JBoss Application Server", "EJB Container", "JACC (Java Authorization Contract for Containers)"],
        "requires_port": [8080, 1099, 4447],
        "prerequisites": [
            "Целевая система использует платформу JBoss с включённой авторизацией на основе ролей для EJB.",
            "Авторизация настроена с использованием JACC, но реализация вызова модулей авторизации некорректна.",
            "Злоумышленник имеет сетевой доступ к JBoss-серверу (обычно через порты 8080, 1099 или 4447)."
        ]
    }
}

# ----------------------------------------------------------------------
# 2. Маппинг CWE -> CAPEC (на основе предыдущего скрипта)
# ----------------------------------------------------------------------
cwe_to_capec = {
    "CWE-280": ["CAPEC-1", "CAPEC-180"],
    "CWE-264": ["CAPEC-1", "CAPEC-180"],
    "CWE-89": ["CAPEC-66", "CAPEC-108", "CAPEC-110"],
    "CWE-79": ["CAPEC-18", "CAPEC-32", "CAPEC-63"],
    "CWE-78": ["CAPEC-15", "CAPEC-248"],
    "CWE-119": ["CAPEC-100", "CAPEC-123"],
    "CWE-22": ["CAPEC-126", "CAPEC-139"],
    "CWE-287": ["CAPEC-114", "CAPEC-115"],
    "CWE-522": ["CAPEC-102", "CAPEC-157"],
    "CWE-200": ["CAPEC-116", "CAPEC-169"],
    "CWE-284": ["CAPEC-3", "CAPEC-43"],
    "CWE-269": ["CAPEC-233", "CAPEC-234"],
    "CWE-400": ["CAPEC-125", "CAPEC-130"],
    "CWE-611": ["CAPEC-221", "CAPEC-228"],
    "CWE-94": ["CAPEC-242"],
    "CWE-732": ["CAPEC-1", "CAPEC-180"],
    "CWE-426": ["CAPEC-38", "CAPEC-159"],
    "CWE-427": ["CAPEC-38", "CAPEC-159"],
    "CWE-451": ["CAPEC-173", "CAPEC-103"],
    "CWE-345": ["CAPEC-148", "CAPEC-149"],
    "CWE-319": ["CAPEC-102", "CAPEC-117"],
}

# ----------------------------------------------------------------------
# 3. Определение MITRE ATT&CK по ключевым словам в описании и CWE
# ----------------------------------------------------------------------
def map_to_mitre(desc, cwe_list, software):
    text = desc.lower()
    mitre = []
    # Уязвимости авторизации/доступа
    if any(k in text for k in ["authorization", "access", "permission", "role", "bypass"]):
        mitre.append("T1190")  # Exploit Public-Facing Application
        mitre.append("T1068")  # Exploitation for Privilege Escalation
    if any(k in text for k in ["ejb", "jboss", "jacc"]):
        mitre.append("T1190")  # Public-facing app
    if "cwe-280" in [c.lower() for c in cwe_list] or "cwe-264" in [c.lower() for c in cwe_list]:
        mitre.append("T1078")  # Valid Accounts (misuse of roles)
    if not mitre:
        mitre = ["T1190"]  # fallback
    return list(dict.fromkeys(mitre))

# ----------------------------------------------------------------------
# 4. Определение сервисов на основе ПО и описания
# ----------------------------------------------------------------------
def extract_services(desc, software):
    services = []
    text = desc.lower()
    for sw in software:
        services.append(sw)
    if "jboss" in text or any("jboss" in s.lower() for s in software):
        services.extend(["EJB Container", "JACC"])
    if "ejb" in text:
        services.append("Enterprise Java Beans")
    if "jacc" in text:
        services.append("Java Authorization Contract for Containers")
    # удаляем дубликаты
    return list(dict.fromkeys(services))

# ----------------------------------------------------------------------
# 5. Определение портов на основе ПО и описания
# ----------------------------------------------------------------------
def extract_ports(desc, software):
    text = desc.lower()
    ports = []
    if "jboss" in text or any("jboss" in s.lower() for s in software):
        ports = [8080, 1099, 4447]  # типовые порты JBoss
    # можно добавить другие порты по ключевым словам
    return ports

# ----------------------------------------------------------------------
# 6. Генерация предварительных условий (prerequisites)
# ----------------------------------------------------------------------
def generate_prerequisites(desc, software, cwe_list):
    prereq = []
    text = desc.lower()
    for sw in software:
        prereq.append(f"Целевая система использует {sw}.")
    if any(c in cwe_list for c in ["CWE-280", "CWE-264"]):
        prereq.append("Авторизация основана на ролях, но механизм вызова модулей авторизации реализован некорректно.")
    if "ejb" in text:
        prereq.append("Злоумышленник может отправлять запросы к EJB-компонентам.")
    prereq.append("Злоумышленник имеет сетевой доступ к уязвимому серверу.")
    return prereq

# ----------------------------------------------------------------------
# 7. Основная функция обработки
# ----------------------------------------------------------------------
def process_cve_list(cve_data):
    for item in cve_data:
        cve_id = item.get("id")
        if not cve_id:
            continue
        
        # Если есть ручной маппинг для этого CVE, используем его
        if cve_id in manual_mapping:
            mapping = manual_mapping[cve_id]
            if not item.get("related_capec"):
                item["related_capec"] = mapping["related_capec"]
            if not item.get("related_mitre"):
                item["related_mitre"] = mapping["related_mitre"]
            if not item.get("requires_service"):
                item["requires_service"] = mapping["requires_service"]
            if not item.get("requires_port"):
                item["requires_port"] = mapping["requires_port"]
            if not item.get("prerequisites"):
                item["prerequisites"] = mapping["prerequisites"]
            continue
        
        # Иначе автоматическое заполнение
        desc = item.get("description", "")
        software = item.get("affected_software", [])
        cwe_list = item.get("related_cwe", [])
        
        # ---- related_capec ----
        if not item.get("related_capec"):
            capec_set = set()
            for cwe in cwe_list:
                if cwe in cwe_to_capec:
                    capec_set.update(cwe_to_capec[cwe])
            if not capec_set:
                # эвристика по описанию
                if any(k in desc.lower() for k in ["authorization", "access", "permission", "bypass"]):
                    capec_set.update(["CAPEC-1", "CAPEC-180"])
                else:
                    capec_set.add("CAPEC-21")  # общий паттерн
            item["related_capec"] = sorted(capec_set)
        
        # ---- related_mitre ----
        if not item.get("related_mitre"):
            item["related_mitre"] = map_to_mitre(desc, cwe_list, software)
        
        # ---- requires_service ----
        if not item.get("requires_service"):
            item["requires_service"] = extract_services(desc, software)
        
        # ---- requires_port ----
        if not item.get("requires_port"):
            item["requires_port"] = extract_ports(desc, software)
        
        # ---- prerequisites ----
        if not item.get("prerequisites"):
            item["prerequisites"] = generate_prerequisites(desc, software, cwe_list)
    
    return cve_data

# ----------------------------------------------------------------------
# 8. Загрузка и сохранение JSON
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Чтение входного файла (предполагается, что он называется cve_list.json)
    with open("C:\projects\MITRE_PARSER\output\cve_database.json", "r", encoding="utf-8") as f:
        cve_data = json.load(f)
    
    processed_data = process_cve_list(cve_data)
    
    with open("C:\projects\MITRE_PARSER\output\cve_database_filled.json", "w", encoding="utf-8") as f:
        json.dump(processed_data, f, ensure_ascii=False, indent=2)
    
    print("Обработка завершена. Результат сохранён в cve_database_filled.json")