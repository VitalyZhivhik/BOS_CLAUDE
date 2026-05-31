import json
import re

# Загрузка данных
with open('C:\projects\MITRE_PARSER\output\cwe_database.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# ----------------------------------------------------------------------
# 1. Ручной маппинг CWE -> CAPEC (наиболее частые случаи)
# ----------------------------------------------------------------------
cwe_to_capec = {
    "CWE-1004": ["CAPEC-31"],
    "CWE-89": ["CAPEC-66", "CAPEC-108", "CAPEC-110"],
    "CWE-79": ["CAPEC-18", "CAPEC-32", "CAPEC-63"],
    "CWE-78": ["CAPEC-15", "CAPEC-248"],
    "CWE-77": ["CAPEC-15", "CAPEC-248"],
    "CWE-119": ["CAPEC-100", "CAPEC-123"],
    "CWE-120": ["CAPEC-100", "CAPEC-123"],
    "CWE-22": ["CAPEC-126", "CAPEC-139"],
    "CWE-276": ["CAPEC-1", "CAPEC-17"],
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
    "CWE-290": ["CAPEC-94", "CAPEC-102"],
    "CWE-294": ["CAPEC-102", "CAPEC-94"],
    "CWE-521": ["CAPEC-16", "CAPEC-112"],
    "CWE-307": ["CAPEC-2", "CAPEC-16"],
    "CWE-693": ["CAPEC-24", "CAPEC-199"],
    "CWE-268": ["CAPEC-268"],
    "CWE-264": ["CAPEC-126"],
    "CWE-829": ["CAPEC-175", "CAPEC-201"],
    "CWE-800": ["CAPEC-1583", "CAPEC-1584"],
    "CWE-799": ["CAPEC-1583"],
    "CWE-780": ["CAPEC-268"],
    "CWE-74": ["CAPEC-15", "CAPEC-33"],
    "CWE-20": ["CAPEC-153"],
    "CWE-94": ["CAPEC-242"],
    "CWE-347": ["CAPEC-1606"],
    "CWE-682": ["CAPEC-128"],
    "CWE-404": ["CAPEC-125", "CAPEC-131"],
    "CWE-770": ["CAPEC-125", "CAPEC-130"],
}

# ----------------------------------------------------------------------
# 2. Определение технологий (requires_technology) по ключевым словам
# ----------------------------------------------------------------------
def detect_technologies(entry):
    text = (entry.get("name", "") + " " + entry.get("description", "")).lower()
    tech = []
    if any(k in text for k in ["cookie", "http", "https", "web", "browser"]):
        tech.append("Web")
    if any(k in text for k in ["php", "asp", "jsp", "servlet", "cgi"]):
        tech.append("Web Server")
    if any(k in text for k in ["sql", "database", "db", "query"]):
        tech.append("Database")
    if any(k in text for k in ["buffer", "memory", "stack", "heap"]):
        tech.append("Native Code (C/C++)")
    if any(k in text for k in ["xml", "xslt", "soap"]):
        tech.append("XML Processor")
    if any(k in text for k in ["javascript", "script", "xss"]):
        tech.append("Client-side Scripting")
    if any(k in text for k in ["windows", "registry", "win32", "dll"]):
        tech.append("Windows OS")
    if any(k in text for k in ["linux", "unix", "posix"]):
        tech.append("Linux/Unix")
    if any(k in text for k in ["authentication", "password", "credential"]):
        tech.append("Authentication Mechanism")
    if any(k in text for k in ["network", "packet", "protocol"]):
        tech.append("Network Protocol")
    if any(k in text for k in ["file", "directory", "path"]):
        tech.append("File System")
    if any(k in text for k in ["permission", "acl", "access control"]):
        tech.append("Access Control")
    if not tech:
        tech.append("Multiple / Unspecified")
    return list(dict.fromkeys(tech))

# ----------------------------------------------------------------------
# 3. Генерация detection_methods (если пусто)
# ----------------------------------------------------------------------
def generate_detection_methods(entry):
    text = (entry.get("name", "") + " " + entry.get("description", "")).lower()
    methods = []
    if any(k in text for k in ["sql", "injection", "query"]):
        methods.append("Автоматический статический анализ (SAST) – поиск конкатенации строк в запросах.")
        methods.append("Динамическое тестирование безопасности (DAST) – отправка специальных payload'ов.")
        methods.append("Ручной код-ревью с акцентом на формирование SQL-запросов.")
    if any(k in text for k in ["xss", "script", "html", "javascript"]):
        methods.append("Автоматический статический анализ – поиск неэкранированного вывода пользовательских данных.")
        methods.append("Динамическое тестирование – внедрение тестовых скриптов в поля ввода.")
        methods.append("Ручной анализ шаблонов и механизмов кодирования вывода.")
    if any(k in text for k in ["buffer", "overflow", "memory"]):
        methods.append("Статический анализ – проверка границ буферов, использование опасных функций (strcpy, sprintf).")
        methods.append("Динамический анализ (фаззинг) с нестандартными входными данными.")
        methods.append("Использование инструментов защиты памяти (ASAN, Valgrind).")
    if any(k in text for k in ["path", "directory", "file", "traversal"]):
        methods.append("Статический анализ – поиск конкатенации путей с пользовательским вводом.")
        methods.append("Динамическое тестирование – попытки обхода каталогов (../, ..\\).")
    if any(k in text for k in ["authentication", "authorization", "access", "permission"]):
        methods.append("Анализ конфигураций ACL и проверок доступа.")
        methods.append("Пентест – попытки обойти аутентификацию/авторизацию.")
    if any(k in text for k in ["information", "disclosure", "exposure"]):
        methods.append("Анализ ответов сервера, проверка сообщений об ошибках.")
        methods.append("Сканирование на наличие скрытых каталогов/файлов.")
    if not methods:
        methods.append("Автоматический статический анализ (SAST) – выявление опасных паттернов.")
        methods.append("Динамическое тестирование безопасности (DAST) / фаззинг.")
        methods.append("Ручной анализ кода и конфигураций.")
    return methods

# ----------------------------------------------------------------------
# 4. Генерация mitigation (если поле пустое или слишком короткое)
# ----------------------------------------------------------------------
def generate_mitigation(entry):
    existing = entry.get("mitigation", "")
    if existing and len(existing.strip()) > 50:
        return existing   # не трогаем, если уже есть содержательная рекомендация
    
    text = (entry.get("name", "") + " " + entry.get("description", "")).lower()
    mitigations = []
    
    if any(k in text for k in ["sql", "injection"]):
        mitigations.append("Используйте параметризованные запросы (prepared statements) или безопасные ORM.")
        mitigations.append("Проводите валидацию вводимых данных по белому списку.")
    if any(k in text for k in ["xss", "script", "html"]):
        mitigations.append("Всегда кодируйте вывод (HTML escape) для контекста отображения.")
        mitigations.append("Используйте Content Security Policy (CSP) для ограничения выполнения скриптов.")
    if any(k in text for k in ["buffer", "overflow"]):
        mitigations.append("Перепишите код на языке с автоматическим управлением памятью (Java, Python, Rust).")
        mitigations.append("Используйте безопасные функции (strncpy, snprintf) и проверяйте границы.")
        mitigations.append("Включите защиты компилятора: ASLR, DEP, Stack Canaries.")
    if any(k in text for k in ["path", "directory", "traversal"]):
        mitigations.append("Избегайте конкатенации пользовательского ввода с путями к файлам.")
        mitigations.append("Используйте белый список допустимых файлов/каталогов.")
    if any(k in text for k in ["authentication", "authorization", "access"]):
        mitigations.append("Применяйте принцип наименьших привилегий.")
        mitigations.append("Настраивайте ACL и проверку доступа на каждом запросе.")
    if any(k in text for k in ["cookie", "httponly"]):
        mitigations.append("Устанавливайте флаг `HttpOnly` для всех файлов cookie, содержащих конфиденциальные данные.")
        mitigations.append("Дополнительно используйте флаг `Secure` и атрибут `SameSite`.")
    if not mitigations:
        mitigations.append("Проведите анализ рисков и внедрите стандартные средства защиты: валидацию ввода, санитизацию, безопасные API, принцип наименьших привилегий.")
    return "\n".join(mitigations)

# ----------------------------------------------------------------------
# 5. Основной цикл обработки
# ----------------------------------------------------------------------
for item in data:
    cwe_id = item["id"]
    
    # 1. requires_technology (если пусто)
    if not item.get("requires_technology"):
        item["requires_technology"] = detect_technologies(item)
    
    # 2. related_capec (если пусто)
    if not item.get("related_capec"):
        if cwe_id in cwe_to_capec:
            item["related_capec"] = cwe_to_capec[cwe_id]
        else:
            # Эвристика по ключевым словам
            text = (item.get("name", "") + " " + item.get("description", "")).lower()
            if "injection" in text:
                item["related_capec"] = ["CAPEC-242"]
            elif "xss" in text or "cross-site" in text:
                item["related_capec"] = ["CAPEC-63"]
            elif "buffer" in text or "overflow" in text:
                item["related_capec"] = ["CAPEC-100"]
            elif "path" in text or "directory" in text:
                item["related_capec"] = ["CAPEC-126"]
            elif "authentication" in text or "access" in text:
                item["related_capec"] = ["CAPEC-114"]
            else:
                item["related_capec"] = ["CAPEC-21", "CAPEC-176"]  # общие паттерны
    
    # 3. detection_methods (если пусто)
    if not item.get("detection_methods"):
        item["detection_methods"] = generate_detection_methods(item)
    
    # 4. mitigation (если пусто или слишком короткое)
    if not item.get("mitigation") or len(item["mitigation"].strip()) < 30:
        item["mitigation"] = generate_mitigation(item)

# Сохранение результата
with open('C:\projects\MITRE_PARSER\output\cwe_database_filled.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print("Обработка завершена. Результат сохранён в cwe_database_filled.json")