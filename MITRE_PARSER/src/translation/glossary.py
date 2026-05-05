"""
Глоссарий терминов кибербезопасности EN -> RU.

Применяется ДО обращения к сетевому переводчику для:
  1) единообразия терминологии;
  2) ускорения работы (короткие термины не уходят в сеть);
  3) корректного перевода аббревиатур (RCE, SQLi, XSS и т.п.),
     с которыми Google часто ошибается.

Замена идёт по «целым словам» (\\b...\\b), регистр сохраняется через
функциональную замену. Аббревиатуры в верхнем регистре не трогаем —
оставляем как есть, но пишем русский эквивалент в скобках при первом
обращении.
"""
from __future__ import annotations

import re
from typing import Iterable

# ── Базовый словарь (EN -> RU) ────────────────────────────────────
GLOSSARY: dict[str, str] = {
    # Атаки и техники
    "remote code execution": "удалённое выполнение кода",
    "arbitrary code execution": "выполнение произвольного кода",
    "command injection": "инъекция команд ОС",
    "sql injection": "SQL-инъекция",
    "cross-site scripting": "межсайтовый скриптинг",
    "cross site scripting": "межсайтовый скриптинг",
    "cross-site request forgery": "подделка межсайтовых запросов",
    "server-side request forgery": "подделка запросов на стороне сервера",
    "directory traversal": "обход каталогов",
    "path traversal": "обход путей файловой системы",
    "buffer overflow": "переполнение буфера",
    "stack overflow": "переполнение стека",
    "heap overflow": "переполнение кучи",
    "use after free": "использование после освобождения",
    "race condition": "состояние гонки",
    "denial of service": "отказ в обслуживании",
    "privilege escalation": "повышение привилегий",
    "lateral movement": "горизонтальное перемещение",
    "initial access": "первоначальный доступ",
    "credential access": "доступ к учётным данным",
    "credential dumping": "выгрузка учётных данных",
    "credential stuffing": "подстановка учётных данных",
    "brute force": "перебор",
    "password spraying": "распыление паролей",
    "phishing": "фишинг",
    "spear phishing": "целевой фишинг",
    "spearphishing": "целевой фишинг",
    "social engineering": "социальная инженерия",
    "man in the middle": "человек посередине",
    "man-in-the-middle": "человек посередине",
    "replay attack": "атака повторного воспроизведения",
    "deserialization": "десериализация",
    "race conditions": "состояния гонки",
    "memory corruption": "повреждение памяти",
    "out-of-bounds read": "чтение за границами буфера",
    "out-of-bounds write": "запись за границами буфера",
    "null pointer dereference": "разыменование нулевого указателя",
    "integer overflow": "целочисленное переполнение",
    "format string": "строка формата",
    "type confusion": "путаница типов",
    "improper input validation": "некорректная проверка входных данных",
    "improper authentication": "некорректная аутентификация",
    "improper authorization": "некорректная авторизация",
    "improper access control": "некорректное управление доступом",
    "improper neutralization": "некорректная нейтрализация",
    "information disclosure": "раскрытие информации",
    "information exposure": "раскрытие информации",
    "sensitive data exposure": "раскрытие конфиденциальных данных",
    "session hijacking": "перехват сессии",
    "session fixation": "фиксация сессии",
    "clickjacking": "кликджекинг",
    "tabnabbing": "табнаббинг",
    "code injection": "инъекция кода",
    "xml external entity": "внешняя XML-сущность",
    "xxe": "XXE-атака (внешняя XML-сущность)",
    # Защита и операции
    "patch management": "управление обновлениями",
    "vulnerability management": "управление уязвимостями",
    "vulnerability assessment": "оценка уязвимостей",
    "penetration testing": "тестирование на проникновение",
    "threat hunting": "поиск угроз",
    "threat intelligence": "разведка угроз",
    "incident response": "реагирование на инциденты",
    "intrusion detection": "обнаружение вторжений",
    "intrusion prevention": "предотвращение вторжений",
    "endpoint detection and response": "обнаружение и реагирование на конечных точках",
    "network segmentation": "сегментация сети",
    "network monitoring": "мониторинг сети",
    "traffic analysis": "анализ сетевого трафика",
    "log analysis": "анализ журналов",
    "log monitoring": "мониторинг журналов",
    "security audit": "аудит безопасности",
    "code review": "проверка кода",
    "static analysis": "статический анализ",
    "dynamic analysis": "динамический анализ",
    "fuzzing": "фаззинг",
    "sandboxing": "изоляция в песочнице",
    "input validation": "проверка входных данных",
    "output encoding": "кодирование вывода",
    "least privilege": "принцип наименьших привилегий",
    "principle of least privilege": "принцип наименьших привилегий",
    "defense in depth": "эшелонированная защита",
    "zero trust": "нулевое доверие",
    "multi-factor authentication": "многофакторная аутентификация",
    "multifactor authentication": "многофакторная аутентификация",
    "two-factor authentication": "двухфакторная аутентификация",
    "single sign-on": "единый вход",
    "encryption at rest": "шифрование данных в покое",
    "encryption in transit": "шифрование данных при передаче",
    "secure boot": "безопасная загрузка",
    "code signing": "подписание кода",
    "rate limiting": "ограничение частоты запросов",
    "account lockout": "блокировка учётной записи",
    "input sanitization": "очистка входных данных",
    "parameterized queries": "параметризованные запросы",
    "prepared statements": "подготовленные выражения",
    "content security policy": "политика безопасности содержимого",
    # Объекты и сущности
    "attacker": "атакующий",
    "adversary": "противник",
    "victim": "жертва",
    "vulnerability": "уязвимость",
    "vulnerabilities": "уязвимости",
    "weakness": "слабое место",
    "weaknesses": "слабые места",
    "exploit": "эксплойт",
    "exploitation": "эксплуатация",
    "payload": "полезная нагрузка",
    "shellcode": "шеллкод",
    "malware": "вредоносное ПО",
    "ransomware": "программа-вымогатель",
    "spyware": "шпионская программа",
    "rootkit": "руткит",
    "backdoor": "бэкдор",
    "trojan": "троян",
    "worm": "сетевой червь",
    "botnet": "ботнет",
    "implant": "имплант",
    "command-and-control": "командный сервер",
    "command and control": "командный сервер",
    "dropper": "дроппер",
    "loader": "загрузчик",
    "stager": "стейджер",
    # Технические термины
    "firewall": "межсетевой экран",
    "web application firewall": "межсетевой экран веб-приложений",
    "operating system": "операционная система",
    "kernel": "ядро",
    "process": "процесс",
    "thread": "поток",
    "service": "сервис",
    "daemon": "демон",
    "registry": "реестр",
    "scheduled task": "запланированное задание",
    "scheduled tasks": "запланированные задания",
    "powershell script": "PowerShell-скрипт",
    "command line": "командная строка",
    "package manager": "менеджер пакетов",
    "dependency": "зависимость",
    "library": "библиотека",
    "framework": "фреймворк",
    "container": "контейнер",
    "image": "образ",
    "snapshot": "снимок состояния",
    # Стандартные фразы из MITRE/CWE
    "the product": "продукт",
    "the software": "программное обеспечение",
    "the application": "приложение",
    "the attacker": "атакующий",
    "an attacker": "атакующий",
    "may allow": "может позволить",
    "could allow": "может позволить",
    "allows an attacker": "позволяет атакующему",
    "allows attackers": "позволяет атакующим",
    "is vulnerable to": "уязвим к",
    "is susceptible to": "подвержен",
    "via": "через",
    "by sending": "путём отправки",
    "by crafting": "путём формирования",
    "specially crafted": "специально сформированный",
    "as a result": "в результате",
    "due to": "из-за",
    # Уровни/Серьёзность
    "CRITICAL": "КРИТИЧЕСКИЙ",
    "HIGH": "ВЫСОКИЙ",
    "MEDIUM": "СРЕДНИЙ",
    "LOW": "НИЗКИЙ",
    "VERY HIGH": "ОЧЕНЬ ВЫСОКИЙ",
    "VERY LOW": "ОЧЕНЬ НИЗКИЙ",
    "UNKNOWN": "НЕИЗВЕСТНО",
    # Тактики ATT&CK
    "Initial Access": "Первоначальный доступ",
    "Execution": "Выполнение",
    "Persistence": "Закрепление",
    "Privilege Escalation": "Повышение привилегий",
    "Defense Evasion": "Обход защиты",
    "Credential Access": "Доступ к учётным данным",
    "Discovery": "Разведка",
    "Lateral Movement": "Горизонтальное перемещение",
    "Collection": "Сбор информации",
    "Command And Control": "Командное управление",
    "Exfiltration": "Эксфильтрация данных",
    "Impact": "Воздействие",
    "Reconnaissance": "Разведка",
    "Resource Development": "Развитие ресурсов",
    # Платформы
    "Windows": "Windows",
    "Linux": "Linux",
    "macOS": "macOS",
    "Network": "Сеть",
    "Containers": "Контейнеры",
    "Cloud": "Облако",
    "Office 365": "Office 365",
    "Azure AD": "Azure AD",
    "SaaS": "SaaS",
    "IaaS": "IaaS",
    # Фазы / kill chain
    "Reconnaissance": "Разведка",
    "Scanning": "Сканирование",
    "Exploitation": "Эксплуатация",
    "Post-Exploitation": "Пост-эксплуатация",
    "Weaponization": "Подготовка оружия",
    "Delivery": "Доставка",
    "Installation": "Установка",
    "Actions on Objectives": "Действия по достижению целей",
}


# Аббревиатуры — НЕ переводим, но при первом упоминании в тексте
# можем добавить расшифровку (опционально). Здесь просто список,
# чтобы переводчик их пропускал.
PROTECTED_TOKENS: set[str] = {
    "RCE", "LFI", "RFI", "SSRF", "CSRF", "XSS", "XXE", "SQLi", "NoSQLi",
    "DoS", "DDoS", "MITM", "APT", "C2", "C&C", "EDR", "XDR", "SIEM", "SOAR",
    "WAF", "IDS", "IPS", "SOC", "SOC2", "PCI", "PCI-DSS", "GDPR", "ISO",
    "DNS", "DHCP", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "TLS", "SSL",
    "SSH", "RDP", "SMB", "FTP", "SFTP", "LDAP", "AD", "DC", "PE", "ELF",
    "DLL", "PDB", "CLR", ".NET", "JVM", "JWT", "OAuth", "SAML", "OIDC",
    "API", "REST", "SOAP", "RPC", "gRPC", "JSON", "XML", "YAML", "CSV",
    "URL", "URI", "URN", "IP", "IPv4", "IPv6", "MAC", "VLAN", "VPN",
    "MFA", "2FA", "SSO", "OTP", "TOTP", "HOTP", "PKI", "CA", "CRL",
    "CVE", "CWE", "CAPEC", "ATT&CK", "TTP", "IoC", "IOA", "MISP",
    "STIX", "TAXII", "OWASP", "NIST", "CVSS", "EPSS", "KEV",
}


_GLOSSARY_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in sorted(GLOSSARY.keys(), key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


def apply_glossary(text: str) -> str:
    """
    Применяет словарь к тексту: заменяет EN-термины на RU-эквиваленты.
    Регистр совпадений учитывается частично (по варианту из словаря).
    """
    if not text:
        return text

    def _repl(match: re.Match) -> str:
        key = match.group(1)
        # Сначала ищем точное совпадение, потом по нижнему регистру
        if key in GLOSSARY:
            return GLOSSARY[key]
        return GLOSSARY.get(key.lower(), key)

    return _GLOSSARY_REGEX.sub(_repl, text)


def is_protected(text: str) -> bool:
    """True, если текст — техническая аббревиатура/идентификатор, переводить не нужно."""
    s = text.strip()
    if not s:
        return True
    if s in PROTECTED_TOKENS:
        return True
    # Идентификаторы вида CWE-89, T1190.001, CVE-2017-0144, CAPEC-66, S0002, M1027, G0006
    if re.fullmatch(
        r"(?:CWE|CVE|CAPEC|TOOL|DEF)-\d+(?:[\.-]\w+)?|T\d{4}(?:\.\d{3})?|[SMG]\d{4}",
        s,
    ):
        return True
    # Просто число / версия
    if re.fullmatch(r"[\d.,/]+", s):
        return True
    return False


def split_for_translation(text: str, max_len: int) -> Iterable[str]:
    """Разбивает длинный текст на куски не больше max_len (по предложениям)."""
    if len(text) <= max_len:
        yield text
        return
    parts: list[str] = []
    buf = ""
    for sentence in re.split(r"(?<=[\.\!\?])\s+", text):
        if len(buf) + len(sentence) + 1 > max_len:
            if buf:
                parts.append(buf)
            buf = sentence
        else:
            buf = (buf + " " + sentence).strip()
    if buf:
        parts.append(buf)
    yield from parts


__all__ = [
    "GLOSSARY",
    "PROTECTED_TOKENS",
    "apply_glossary",
    "is_protected",
    "split_for_translation",
]
