import json
import re

# Загружаем исходный файл
with open('C:\projects\MITRE_PARSER\output\capec_database.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Пример простого маппинга CAPEC -> MITRE ATT&CK (можно расширить)
mitre_mapping = {
    "CAPEC-1": ["T1078", "T1098"],  # Valid Accounts, Account Manipulation
    "CAPEC-10": ["T1203", "T1068"],  # Exploitation for Client Execution, Exploitation for Privilege Escalation
    "CAPEC-100": ["T1203", "T1068"],
    "CAPEC-101": ["T1190", "T1059"],  # Exploit Public-Facing Application, Command and Scripting Interpreter
    "CAPEC-102": ["T1040", "T1557"],  # Network Sniffing, Adversary-in-the-Middle
    "CAPEC-103": ["T1204", "T1566"],  # User Execution, Phishing
    "CAPEC-104": ["T1059", "T1068"],
    "CAPEC-105": ["T1203", "T1190"],
    "CAPEC-107": ["T1040", "T1557"],
    "CAPEC-108": ["T1190", "T1505"],  # Server Software Component
    "CAPEC-109": ["T1190", "T1505"],
    "CAPEC-11": ["T1595"],  # Active Scanning
    "CAPEC-110": ["T1190", "T1505"],
    "CAPEC-111": ["T1040", "T1557"],
    "CAPEC-112": ["T1110"],  # Brute Force
    "CAPEC-113": ["T1595", "T1526"],  # Cloud Service Discovery
    "CAPEC-114": ["T1078", "T1550"],  # Use Alternate Authentication Material
    "CAPEC-115": ["T1078", "T1550"],
    "CAPEC-116": ["T1592", "T1595"],
    "CAPEC-117": ["T1040", "T1557"],
    "CAPEC-12": ["T1565", "T1025"],  # Data Manipulation, Data from Removable Media
    "CAPEC-120": ["T1190", "T1059"],
    "CAPEC-121": ["T1592", "T1595"],
    "CAPEC-122": ["T1068", "T1078"],
    "CAPEC-123": ["T1068", "T1203"],
    "CAPEC-124": ["T1499", "T1565"],
    "CAPEC-125": ["T1499"],
    "CAPEC-126": ["T1006"],
    "CAPEC-127": ["T1083"],  # File and Directory Discovery
    "CAPEC-128": ["T1068", "T1203"],
    "CAPEC-129": ["T1068", "T1203"],
    "CAPEC-13": ["T1574", "T1098"],  # Hijack Execution Flow, Account Manipulation
    "CAPEC-130": ["T1499"],
    "CAPEC-131": ["T1499"],
    "CAPEC-132": ["T1222"],  # File and Directory Permissions Modification
    "CAPEC-133": ["T1595"],
    "CAPEC-134": ["T1190", "T1059"],
    "CAPEC-135": ["T1203", "T1068"],
    "CAPEC-136": ["T1190", "T1059"],
    "CAPEC-137": ["T1190", "T1059"],
    "CAPEC-138": ["T1068", "T1059"],
    "CAPEC-139": ["T1006"],
    "CAPEC-14": ["T1203", "T1068"],
    "CAPEC-140": ["T1078", "T1098"],
    "CAPEC-141": ["T1565", "T1499"],
    "CAPEC-142": ["T1565", "T1499"],
    "CAPEC-143": ["T1083"],
    "CAPEC-144": ["T1083"],
    "CAPEC-145": ["T1565"],
    "CAPEC-146": ["T1565", "T1499"],
    "CAPEC-147": ["T1499"],
    "CAPEC-148": ["T1565"],
    "CAPEC-149": ["T1083"],
    "CAPEC-15": ["T1059"],
    "CAPEC-150": ["T1083"],
    "CAPEC-151": ["T1078", "T1550"],
    "CAPEC-153": ["T1190", "T1059"],
    "CAPEC-154": ["T1565", "T1557"],
    "CAPEC-155": ["T1083"],
    "CAPEC-157": ["T1040"],
    "CAPEC-158": ["T1040"],
    "CAPEC-159": ["T1574"],
    "CAPEC-16": ["T1110"],
    "CAPEC-160": ["T1059"],
    "CAPEC-161": ["T1557"],
    "CAPEC-162": ["T1565"],
    "CAPEC-163": ["T1566"],
    "CAPEC-164": ["T1566"],
    "CAPEC-165": ["T1565"],
    "CAPEC-166": ["T1565", "T1499"],
    "CAPEC-167": ["T1595"],
    "CAPEC-168": ["T1565", "T1070"],  # Indicator Removal
    "CAPEC-169": ["T1595", "T1592"],
    "CAPEC-17": ["T1203", "T1068"],
    "CAPEC-170": ["T1595"],
    "CAPEC-173": ["T1566", "T1204"],
    "CAPEC-174": ["T1059"],
    "CAPEC-175": ["T1203", "T1068"],
    "CAPEC-176": ["T1574", "T1098"],
    "CAPEC-177": ["T1574"],
    "CAPEC-178": ["T1566", "T1204"],
    "CAPEC-179": ["T1595"],
    "CAPEC-18": ["T1059"],
    "CAPEC-180": ["T1078", "T1068"],
    "CAPEC-181": ["T1566"],
    "CAPEC-182": ["T1059"],
    "CAPEC-183": ["T1190", "T1059"],
    "CAPEC-184": ["T1499", "T1565"],
    "CAPEC-185": ["T1204", "T1566"],
    "CAPEC-186": ["T1204", "T1566"],
    "CAPEC-187": ["T1204", "T1566"],
    "CAPEC-188": ["T1595"],
    "CAPEC-189": ["T1595"],
    "CAPEC-19": ["T1059"],
    "CAPEC-190": ["T1595"],
    "CAPEC-191": ["T1595"],
    "CAPEC-192": ["T1595"],
    "CAPEC-193": ["T1190", "T1505"],
    "CAPEC-194": ["T1078", "T1550"],
    "CAPEC-195": ["T1566"],
    "CAPEC-196": ["T1078", "T1550"],
    "CAPEC-197": ["T1499"],
    "CAPEC-198": ["T1059"],
    "CAPEC-199": ["T1059"],
    "CAPEC-2": ["T1110"],
    "CAPEC-20": ["T1110"],
    "CAPEC-200": ["T1565", "T1499"],
    "CAPEC-201": ["T1190", "T1505"],
    "CAPEC-202": ["T1078", "T1550"],
    "CAPEC-203": ["T1565", "T1070"],
    "CAPEC-204": ["T1083"],
    "CAPEC-206": ["T1553"],  # Subvert Trust Controls
    "CAPEC-207": ["T1565", "T1499"],
    "CAPEC-208": ["T1565"],
    "CAPEC-209": ["T1059"],
    "CAPEC-21": ["T1078", "T1550"],
    "CAPEC-212": ["T1565", "T1499"],
    "CAPEC-215": ["T1595"],
    "CAPEC-216": ["T1557"],
    "CAPEC-217": ["T1557", "T1040"],
    "CAPEC-218": ["T1565"],
    "CAPEC-219": ["T1557"],
    "CAPEC-22": ["T1078", "T1550"],
    "CAPEC-220": ["T1557"],
    "CAPEC-221": ["T1499"],
    "CAPEC-222": ["T1566"],
    "CAPEC-224": ["T1595"],
    "CAPEC-226": ["T1078", "T1550"],
    "CAPEC-227": ["T1499"],
    "CAPEC-228": ["T1499"],
    "CAPEC-229": ["T1499"],
    "CAPEC-23": ["T1203", "T1068"],
    "CAPEC-230": ["T1499"],
    "CAPEC-231": ["T1499"],
    "CAPEC-233": ["T1068"],
    "CAPEC-234": ["T1068"],
    "CAPEC-237": ["T1068"],
    "CAPEC-24": ["T1203", "T1068"],
    "CAPEC-240": ["T1190"],
    "CAPEC-242": ["T1059"],
    "CAPEC-243": ["T1059"],
    "CAPEC-244": ["T1059"],
    "CAPEC-245": ["T1059"],
    "CAPEC-247": ["T1059"],
    "CAPEC-248": ["T1059"],
    "CAPEC-25": ["T1499"],
    "CAPEC-250": ["T1190"],
    "CAPEC-251": ["T1574"],
    "CAPEC-252": ["T1574"],
    "CAPEC-253": ["T1574"],
    "CAPEC-256": ["T1499"],
    "CAPEC-26": ["T1499", "T1068"],
    "CAPEC-260": ["T1040"],
    "CAPEC-261": ["T1595"],
    "CAPEC-263": ["T1499"],
    "CAPEC-267": ["T1190", "T1059"],
    "CAPEC-268": ["T1070", "T1565"],
    "CAPEC-27": ["T1499", "T1068"],
    "CAPEC-270": ["T1547"],  # Boot or Logon Autostart Execution
    "CAPEC-271": ["T1565", "T1499"],
    "CAPEC-272": ["T1557"],
    "CAPEC-273": ["T1557"],
    "CAPEC-274": ["T1078"],
    "CAPEC-275": ["T1557"],
    "CAPEC-276": ["T1557"],
    "CAPEC-277": ["T1557"],
    "CAPEC-278": ["T1557"],
    "CAPEC-279": ["T1190", "T1059"],
    "CAPEC-28": ["T1595"],
    "CAPEC-285": ["T1595"],
    "CAPEC-287": ["T1595"],
    "CAPEC-29": ["T1499", "T1068"],
    "CAPEC-290": ["T1595"],
    "CAPEC-291": ["T1595"],
    "CAPEC-292": ["T1595"],
    "CAPEC-293": ["T1595"],
    "CAPEC-294": ["T1595"],
    "CAPEC-295": ["T1595"],
    "CAPEC-296": ["T1595"],
    "CAPEC-297": ["T1595"],
    "CAPEC-298": ["T1595"],
    "CAPEC-299": ["T1595"],
    "CAPEC-3": ["T1190", "T1059"],
    "CAPEC-30": ["T1068"],
    "CAPEC-300": ["T1595"],
    "CAPEC-301": ["T1595"],
    "CAPEC-302": ["T1595"],
    "CAPEC-303": ["T1595"],
    "CAPEC-304": ["T1595"],
    "CAPEC-305": ["T1595"],
    "CAPEC-306": ["T1595"],
    "CAPEC-307": ["T1595"],
    "CAPEC-308": ["T1595"],
    "CAPEC-309": ["T1595"],
    "CAPEC-31": ["T1040", "T1557"],
    "CAPEC-310": ["T1595"],
    "CAPEC-312": ["T1595"],
    "CAPEC-313": ["T1595"],
    "CAPEC-317": ["T1595"],
    "CAPEC-318": ["T1595"],
    "CAPEC-319": ["T1595"],
    "CAPEC-32": ["T1059"],
    "CAPEC-320": ["T1595"],
    "CAPEC-321": ["T1595"],
    "CAPEC-322": ["T1595"],
    "CAPEC-323": ["T1595"],
    "CAPEC-324": ["T1595"],
    "CAPEC-325": ["T1595"],
    "CAPEC-326": ["T1595"],
    "CAPEC-327": ["T1595"],
    "CAPEC-328": ["T1595"],
    "CAPEC-329": ["T1595"],
    "CAPEC-33": ["T1190", "T1059"],
    "CAPEC-330": ["T1595"],
    "CAPEC-331": ["T1595"],
    "CAPEC-332": ["T1595"],
    "CAPEC-34": ["T1190", "T1059"],
    "CAPEC-35": ["T1203", "T1068"],
    "CAPEC-36": ["T1078", "T1550"],
    "CAPEC-37": ["T1083", "T1595"],
    "CAPEC-38": ["T1574"],
    "CAPEC-383": ["T1040"],
    "CAPEC-384": ["T1557"],
    "CAPEC-385": ["T1565", "T1557"],
    "CAPEC-386": ["T1565", "T1557"],
    "CAPEC-387": ["T1565", "T1557"],
    "CAPEC-388": ["T1565", "T1557"],
    "CAPEC-389": ["T1565", "T1557"],
    "CAPEC-39": ["T1565", "T1078"],
    "CAPEC-4": ["T1190", "T1059"],
    "CAPEC-40": ["T1059", "T1203"],
    "CAPEC-41": ["T1190", "T1059"],
    "CAPEC-42": ["T1203", "T1068"],
    "CAPEC-43": ["T1190", "T1059"],
    "CAPEC-44": ["T1203", "T1068"],
    "CAPEC-45": ["T1203", "T1068"],
}

# Генерация prerequisites и mitigations на основе описания (пример)
def generate_prerequisites(desc, name):
    if not desc:
        return ["Отсутствует информация. Обычно требуется знание внутреннего устройства приложения.", "Злоумышленник должен иметь возможность взаимодействовать с целевой системой."]
    # Простые эвристики
    if "буфер" in desc.lower() or "buffer" in desc.lower():
        return ["Приложение использует операции с буфером без проверки границ.", "Злоумышленник может контролировать входные данные, попадающие в буфер."]
    if "инъекц" in desc.lower() or "injection" in desc.lower():
        return ["Приложение использует пользовательский ввод для формирования команд или запросов без должной фильтрации.", "Злоумышленник может вставлять специальные символы в поля ввода."]
    if "аутентификац" in desc.lower() or "authentication" in desc.lower():
        return ["Система использует механизм аутентификации, который имеет недостатки в реализации или конфигурации.", "Злоумышленник может взаимодействовать с интерфейсом аутентификации."]
    # По умолчанию
    return ["Отсутствуют явные предварительные условия. Обычно требуется некоторый уровень доступа к целевой системе или сети.", "Злоумышленник должен иметь возможность отправлять запросы/сообщения цели."]

def generate_mitigations(desc, name, cwe_list):
    mit = []
    if "буфер" in desc.lower() or "buffer" in desc.lower():
        mit.append("Используйте языки или компиляторы с автоматической проверкой границ (например, Rust, Go).")
        mit.append("Применяйте безопасные функции (strncpy, snprintf) и проверяйте длину входных данных.")
        mit.append("Включите защиту ASLR, DEP, Stack Canaries.")
    if "инъекц" in desc.lower() or "injection" in desc.lower():
        mit.append("Всегда используйте параметризованные запросы (prepared statements) или безопасные API (например, ORM).")
        mit.append("Проводите строгую валидацию и санитизацию всех пользовательских входных данных (белый список).")
        mit.append("Применяйте принцип наименьших привилегий для учётных записей БД и приложений.")
    if "acl" in desc.lower() or "доступ" in desc.lower():
        mit.append("Настройте ACL таким образом, чтобы по умолчанию все ресурсы были запрещены, а доступ разрешён только явно.")
        mit.append("Регулярно проводите аудит прав доступа и удаляйте избыточные привилегии.")
    if not mit:
        mit.append("Проведите анализ угроз и моделирование для выявления конкретных уязвимостей.")
        mit.append("Внедрите многоуровневую защиту (logging, WAF, SIEM).")
    return mit

# Заполнение записей
for item in data:
    # 1. related_mitre
    if not item.get("related_mitre"):
        if item["id"] in mitre_mapping:
            item["related_mitre"] = mitre_mapping[item["id"]]
        else:
            # По умолчанию ставим технику разведки или эксплуатации
            item["related_mitre"] = ["T1595", "T1068"]  # Active Scanning, Exploitation for Privilege Escalation

    # 2. prerequisites
    if not item.get("prerequisites"):
        item["prerequisites"] = generate_prerequisites(item.get("description", ""), item["id"])

    # 3. mitigations
    if not item.get("mitigations"):
        item["mitigations"] = generate_mitigations(item.get("description", ""), item["id"], item.get("related_cwe", []))

    # 4. related_cwe – если пусто, попробуем найти по CAPEC (вручную не будем, оставим как есть или добавим общие)
    if not item.get("related_cwe"):
        # Общие CWE для многих атак
        if "инъекц" in item.get("description", "").lower():
            item["related_cwe"] = ["CWE-89", "CWE-74", "CWE-20"]
        elif "буфер" in item.get("description", "").lower():
            item["related_cwe"] = ["CWE-119", "CWE-120"]
        elif "обход" in item.get("description", "").lower() or "traversal" in item.get("description", "").lower():
            item["related_cwe"] = ["CWE-22"]
        else:
            item["related_cwe"] = ["CWE-284"]  # Improper Access Control

# Сохраняем результат
with open('C:\projects\MITRE_PARSER\output\capec_database_filled.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)