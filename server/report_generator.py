import json
import os
import re

from common.models import normalize_feasibility, normalize_severity, report_status_meta
from server.report_template import HTML_TEMPLATE

class SoftwareEnricher:
    """
    Продвинутый алгоритм сопоставления CVE/Вектора с реально установленным ПО на сервере.
    Использует данные Trivy для точной идентификации ПО + fuzzy matching для улучшения точности.
    
    УЛУЧШЕННАЯ ВЕРСИЯ:
    - Fuzzy matching имён ПО (расстояние Левенштейна)
    - Учёт версий ПО при сопоставлении
    - Многоуровневая приоритизация источников
    - Токенизация и семантическое сравнение
    """
    def __init__(self, system_info, cve_db, capec_db, trivy_result=None):
        # system_info может быть dict или SystemInfo объект
        if isinstance(system_info, dict):
            self.installed_software = system_info.get('installed_software', [])
            self.open_ports = system_info.get('open_ports', [])
        else:
            # Если это SystemInfo объект
            self.installed_software = getattr(system_info, 'installed_software', [])
            self.open_ports = getattr(system_info, 'open_ports', [])

        self.cve_db = cve_db if isinstance(cve_db, dict) else {}
        self.capec_db = capec_db if isinstance(capec_db, dict) else {}

        # Строим карту CVE -> ПО из данных Trivy
        self.trivy_cve_map = {}  # {CVE-ID: {pkg_name, installed_version, cwe_ids, capec_ids}}
        if trivy_result:
            self._build_trivy_map(trivy_result)

        # Отдельный список "пакеты из Trivy" (не смешиваем с установленным ПО реестра)
        self.trivy_packages = []  # [{name, version}]
        if trivy_result and isinstance(trivy_result, dict):
            pkgs = []
            seen = set()
            for v in trivy_result.get("vulnerabilities", []) or []:
                if not isinstance(v, dict):
                    continue
                pkg = (v.get("pkg_name") or "").strip()
                ver = (v.get("installed_version") or "").strip()
                if not pkg:
                    continue
                key = (pkg, ver)
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append({"name": pkg, "version": ver})
            self.trivy_packages = pkgs
    
    def _fuzzy_match_software(self, target_name: str, installed_list: list) -> tuple:
        """
        Нечёткое сопоставление имён ПО.
        Использует токенизацию, Jaccard similarity и эвристики.
        Возвращает (matched_name, confidence_score).
        """
        if not target_name or not installed_list:
            return None, 0.0
        
        target_lower = target_name.lower().strip()
        target_tokens = set(target_lower.split())
        
        best_match = None
        best_score = 0.0
        
        for sw in installed_list:
            sw_name = sw.name if hasattr(sw, 'name') else sw.get('name', '')
            if not sw_name:
                continue
            
            sw_lower = sw_name.lower().strip()
            sw_tokens = set(sw_lower.split())
            
            # Игнорируем короткие слова и служебные токены
            stop_words = {'the', 'a', 'an', 'for', 'of', 'in', 'on', 'and', 'or', 'to', 'v', 'ver', 'version'}
            target_filtered = target_tokens - stop_words
            sw_filtered = sw_tokens - stop_words
            
            if not target_filtered or not sw_filtered:
                continue
            
            # Jaccard similarity
            intersection = target_filtered & sw_filtered
            union = target_filtered | sw_filtered
            
            if union:
                jaccard = len(intersection) / len(union)
            else:
                jaccard = 0.0
            
            # Дополнительная проверка: содержится ли одно в другом
            contains_score = 0.0
            if target_lower in sw_lower or sw_lower in target_lower:
                contains_score = 0.8
            
            # Проверка по ключевым словам (длиной > 3 символов)
            keyword_matches = 0
            for word in target_filtered:
                if len(word) > 3:
                    if word in sw_filtered:
                        keyword_matches += 1
                    elif any(word in sw_word or sw_word in word for sw_word in sw_filtered if len(sw_word) > 3):
                        keyword_matches += 0.5
            
            keyword_score = keyword_matches / len(target_filtered) if target_filtered else 0
            
            # Итоговый score
            final_score = max(jaccard, contains_score, keyword_score)
            
            if final_score > best_score and final_score > 0.4:  # Порог уверенности
                best_score = final_score
                best_match = sw_name
        
        return best_match, best_score
    
    def _normalize_software_name(self, name: str) -> str:
        """
        Нормализация имени ПО: удаление версий, служебных слов, приведение к нижнему регистру.
        """
        if not name:
            return ""
        
        # Удаляем версии (например, "1.2.3", "v2.0")
        import re
        normalized = re.sub(r'\bv?\d+(\.\d+)*', '', name)
        
        # Удаляем служебные слова
        stop_words = ['the', 'a', 'an', 'for', 'of', 'in', 'on', 'and', 'or', 'to']
        words = normalized.lower().split()
        words = [w for w in words if w not in stop_words and len(w) > 1]
        
        return ' '.join(words).strip()
    
    def _check_version_vulnerable(self, pkg_name: str, installed_version: str, cve_id: str) -> bool:
        """
        Проверяет, уязвима ли конкретная версия ПО для данного CVE.
        Упрощённая проверка - в будущем можно использовать semver.
        """
        if not installed_version:
            return True  # Если версия неизвестна, считаем уязвимой
        
        # Получаем информацию о CVE
        cve_info = self.cve_db.get(cve_id, {})
        if isinstance(cve_info, dict):
            affected_versions = cve_info.get('affected_versions', [])
            if affected_versions:
                # Простая проверка: если версия есть в списке уязвимых
                for av in affected_versions:
                    if av in installed_version or installed_version in av:
                        return True
                return False
        
        return True  # По умолчанию считаем уязвимой

    def _build_trivy_map(self, trivy_result):
        """Строит карту CVE->ПО из данных Trivy (поддерживает dict и TrivyScanResult)."""
        vulns = []
        if isinstance(trivy_result, dict):
            vulns = trivy_result.get('vulnerabilities', [])
            # Поддержка сырого формата Trivy
            if not vulns and 'Results' in trivy_result:
                for res in trivy_result.get('Results', []):
                    for v in res.get('Vulnerabilities', []):
                        vulns.append({
                            'vuln_id': v.get('VulnerabilityID', ''),
                            'pkg_name': v.get('PkgName', ''),
                            'installed_version': v.get('InstalledVersion', ''),
                            'cwe_ids': v.get('CweIDs', []),
                            'capec_ids': v.get('CapecIDs', []),
                        })
        elif hasattr(trivy_result, 'vulnerabilities'):
            vulns = trivy_result.vulnerabilities

        for v in vulns:
            if isinstance(v, dict):
                vuln_id = v.get('vuln_id', '')
                pkg_name = v.get('pkg_name', '')
                inst_ver = v.get('installed_version', '')
                cwe_ids = v.get('cwe_ids', [])
                capec_ids = v.get('capec_ids', [])
            else:
                vuln_id = getattr(v, 'vuln_id', '')
                pkg_name = getattr(v, 'pkg_name', '')
                inst_ver = getattr(v, 'installed_version', '')
                cwe_ids = getattr(v, 'cwe_ids', [])
                capec_ids = getattr(v, 'capec_ids', [])

            if vuln_id and pkg_name:
                self.trivy_cve_map[vuln_id] = {
                    'pkg_name': pkg_name,
                    'installed_version': inst_ver,
                    'cwe_ids': cwe_ids or [],
                    'capec_ids': capec_ids or [],
                }

    def identify_real_software(self, record, port_str):
        cve_id = getattr(record, 'cve_id', '')
        capec_id = getattr(record, 'capec_id', '')
        fallback_sw = getattr(record, 'target_software', '').strip()

        # 0. ПЕРВЫЙ ПРИОРИТЕТ: Данные из Trivy (самый надежный источник)
        if cve_id and self.trivy_cve_map:
            for single_cve in cve_id.split(','):
                single_cve = single_cve.strip()
                if single_cve in self.trivy_cve_map:
                    trivy_info = self.trivy_cve_map[single_cve]
                    pkg = trivy_info['pkg_name']
                    ver = trivy_info.get('installed_version', '')
                    if pkg:
                        # Явно помечаем источник, чтобы не путать с установленным ПО Windows
                        base = f"{pkg} {ver}".strip() if ver else pkg
                        return f"{base} (Trivy)"

        # 1. Поиск точного совпадения по тексту CVE
        matched_sw = self._search_in_installed_software(cve_id, capec_id)
        if matched_sw:
            return matched_sw

        # 2. Если сканер передал явное имя и это не заглушка — верим ему
        ignore_list = ["", "unknown", "n/a", "none", "локальный", "служба ос", "os component"]
        if fallback_sw and fallback_sw.lower() not in ignore_list:
            if "microsoft" in fallback_sw.lower() and "windows" in fallback_sw.lower():
                return "Microsoft Windows OS"
            return fallback_sw.title() if len(fallback_sw) < 25 else fallback_sw

        # 3. Привязка к известному порту
        matched_port_service = self._search_in_open_ports(port_str)
        if matched_port_service:
            return matched_port_service

        # 4. Фоллбэк
        if "Локальный" not in str(port_str):
            return f"Неидентифицированная служба (Порт {port_str})"

        return "Неидентифицированный системный компонент"

    def _search_in_installed_software(self, cve_id, capec_id):
        cve_info = self.cve_db.get(cve_id, {})
        affected_sw_list = cve_info.get('affected_software', [])
        description = cve_info.get('description', '').lower()
        
        if not description and capec_id in self.capec_db:
            description = self.capec_db[capec_id].get('description', '').lower()

        for sw in self.installed_software:
            sw_name = sw.name if hasattr(sw, 'name') else sw.get('name', '')
            if not sw_name: continue
            
            sw_name_lower = sw_name.lower()

            for affected in affected_sw_list:
                if affected.lower() in sw_name_lower or sw_name_lower in affected.lower():
                    return sw_name

            keywords = [word for word in sw_name_lower.split() if len(word) > 3]
            
            for kw in keywords:
                if kw in ['windows', 'microsoft', 'update', 'security', 'linux']: 
                    continue
                if re.search(r'\b' + re.escape(kw) + r'\b', description):
                    return sw_name
        return None

    def _search_in_open_ports(self, port_str):
        if port_str in (None, "None", "", "Локальный вектор (без порта)"):
            return None
            
        target_port = str(port_str).strip()
        
        for port_obj in self.open_ports:
            p_num = str(port_obj.port if hasattr(port_obj, 'port') else port_obj.get('port', ''))
            
            if p_num == target_port:
                proc_name = port_obj.process_name if hasattr(port_obj, 'process_name') else port_obj.get('process_name', '')
                if proc_name:
                    return f"Сетевая служба ({proc_name})"
        
        # Эвристика, если процесс неизвестен
        port_map = {
            "80": "HTTP Server (Apache/Nginx)", "443": "HTTPS Server", 
            "22": "OpenSSH", "21": "FTP Server", "3389": "Microsoft RDP", 
            "445": "Windows SMB", "1433": "Microsoft SQL Server", "3306": "MySQL"
        }
        if target_port in port_map:
            return port_map[target_port]

        return None


class ReportGenerator:
    def __init__(self, system_summary, correlation_results, summary, toolkit=None, trivy_result=None, **kwargs):
        self.system_summary = system_summary
        self.summary = summary
        self.toolkit = toolkit
        self.trivy_result = trivy_result

        self.tools_db = self._load_local_db("databases/tools_database.json")
        self.cwe_db = self._load_local_db("databases/cwe_database.json")
        self.capec_db = self._load_local_db("databases/capec_database.json")
        self.cve_db = self._load_local_db("databases/cve_database.json")
        self.mitre_db = self._load_local_db("databases/mitre_attack.json")
        self.defense_db = self._load_local_db("databases/defense_database.json")

        self.raw_results = correlation_results

        # Инициализируем обогатитель ПО:
        # 1) предпочитаем реальный SystemInfo (реестр/сервисы/порты) если он передан
        # 2) Trivy используем как отдельный, самый точный источник (CVE->pkg)
        system_info_for_enricher = kwargs.get("system_info") or system_summary or {}
        self.sw_enricher = SoftwareEnricher(system_info_for_enricher, self.cve_db, self.capec_db, trivy_result=trivy_result)

        groups = {}
        for r in correlation_results:
            capec = getattr(r, 'capec_id', None) or 'Нет CAPEC'
            cwe = getattr(r, 'cwe_id', None) or 'Нет CWE'
            
            # ЧЕСТНАЯ работа с портами (без "Порт не найден")
            port_raw = getattr(r, 'target_port', None)
            if port_raw in (None, "None", "null", "", 0, "0"):
                port = "Локальный вектор (без порта)"
            else:
                port = str(port_raw)
            
            # ИСПОЛЬЗУЕМ НОВЫЙ АЛГОРИТМ ПО
            real_sw = self.sw_enricher.identify_real_software(r, port)
            
            key = f"{real_sw}_{port}_{capec}_{cwe}"
            
            if key not in groups:
                groups[key] = {
                    'base_record': r,
                    'records': [r],
                    'mapped_sw': real_sw,
                    'count': 1,
                    'cves': set([getattr(r, 'cve_id', 'Нет CVE')]),
                    'names': set([getattr(r, 'attack_name', 'Атака')]),
                    'sevs': [getattr(r, 'severity', 'INFO')],
                    'feas': [getattr(r, 'feasibility', 'UNKNOWN')],
                    'found_by': set([getattr(r, 'found_by', 'Сервер')]) if hasattr(r, 'found_by') else set(['Сервер'])
                }
            else:
                groups[key]['count'] += 1
                groups[key]['records'].append(r)
                groups[key]['cves'].add(getattr(r, 'cve_id', 'Нет CVE'))
                groups[key]['names'].add(getattr(r, 'attack_name', 'Атака'))
                groups[key]['sevs'].append(getattr(r, 'severity', 'INFO'))
                groups[key]['feas'].append(getattr(r, 'feasibility', 'UNKNOWN'))
                if hasattr(r, 'found_by'):
                    groups[key]['found_by'].add(getattr(r, 'found_by', 'Сервер'))

        self.aggregated_groups = groups

    def _load_local_db(self, path):
        try:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _canonical_cwe_list(self, raw) -> list:
        """
        Разбирает поле cwe_id: в данных CVE и Trivy часто приходит 'CWE-352, CWE-352'
        или несколько разных CWE через запятую. Возвращает уникальные идентификаторы CWE-NNN.
        """
        if raw is None:
            return []
        s = str(raw).strip()
        if not s or s.upper() in ("N/A", "НЕТ CWE") or s == "CWE-Неизвестно":
            return []
        out = []
        seen = set()
        for part in re.split(r"[,;|/]+", s):
            t = part.strip()
            if not t:
                continue
            up = re.sub(r"\s+", "", t.upper())
            m = re.fullmatch(r"CWE-(\d+)", up)
            if m:
                cid = f"CWE-{m.group(1)}"
            elif re.fullmatch(r"\d+", t.strip()):
                cid = f"CWE-{t.strip()}"
            else:
                continue
            if cid not in seen:
                seen.add(cid)
                out.append(cid)
        return out

    def _lookup_single_cwe_description(self, cwe_id: str):
        """Описание одного CWE из локальной JSON-базы или None."""
        if not cwe_id:
            return None
        db = self.cwe_db
        item = None
        uid = cwe_id.strip().upper()
        if isinstance(db, dict):
            if cwe_id in db:
                item = db[cwe_id]
            elif uid in db:
                item = db[uid]
            else:
                m = re.search(r"(\d+)$", uid)
                if m:
                    cid = f"CWE-{m.group(1)}"
                    if cid in db:
                        item = db[cid]
                    elif m.group(1) in db:
                        item = db[m.group(1)]
        elif isinstance(db, list):
            for row in db:
                rid = str(row.get("id") or row.get("cwe_id") or "").strip()
                if rid.upper() == uid:
                    item = row
                    break
        if not item:
            return None
        text = (item.get("description_ru") or item.get("description") or "").strip()
        return text or None

    def _get_cwe_description(self, cwe_id):
        """Подробное описание(я) CWE: поддерживает строку с несколькими CWE и дубликатами."""
        missing = "Детальное описание для данного CWE не найдено в локальной базе."
        ids = self._canonical_cwe_list(cwe_id)
        if not ids:
            s = str(cwe_id or "").strip()
            if not s or s == "Нет CWE":
                return "Описание отсутствует."
            return missing
        parts = []
        for cid in ids:
            txt = self._lookup_single_cwe_description(cid)
            if len(ids) == 1:
                parts.append(txt if txt else missing)
            else:
                block = (txt or missing)
                parts.append(f"【{cid}】\n{block}")
        return "\n\n".join(parts)

    def _calculate_contextual_cvss(self, base_cvss: float, feasibility: str, has_protection: bool) -> float:
        """
        Расчёт контекстного CVSS Score на основе реализуемости и средств защиты.
        
        Адаптирует базовый CVSS с учётом:
        - Реализуемости атаки в текущей конфигурации
        - Наличия средств защиты (брандмауэр, антивирус)
        
        Возвращает скорректированный CVSS (0.0 - 10.0).
        """
        # Базовые веса для реализуемости
        feasibility_modifiers = {
            'РЕАЛИЗУЕМА': 1.0,           # Полная реализуемость - оставляем как есть
            'ЧАСТИЧНО РЕАЛИЗУЕМА': 0.6,  # Частичная - снижаем на 40%
            'ТРЕБУЕТ АНАЛИЗА': 0.4,      # Неопределённость - снижаем на 60%
            'НЕ РЕАЛИЗУЕМА': 0.1,        # Нереализуема - минимальный риск
            'UNKNOWN': 0.5               # Неизвестно - средний modifier
        }
        
        # Получаем modifier для текущей реализуемости
        feas_upper = str(feasibility).upper()
        modifier = 1.0
        for key, val in feasibility_modifiers.items():
            if key in feas_upper:
                modifier = val
                break
        
        # Дополнительное снижение если есть средства защиты
        if has_protection:
            modifier *= 0.8  # Снижаем ещё на 20%
        
        # Применяем modifier к базовому CVSS
        contextual_cvss = base_cvss * modifier
        
        # Ограничиваем диапазон 0.0 - 10.0
        return max(0.0, min(10.0, contextual_cvss))
    
    def _cvss_from_severity(self, severity: str) -> float:
        """
        Преобразует текстовую критичность в приблизительный CVSS Score.
        Используется когда точный CVSS недоступен.
        """
        severity_cvss_map = {
            'CRITICAL': 9.0,  # 9.0-10.0
            'HIGH': 7.5,      # 7.0-8.9
            'MEDIUM': 5.0,    # 4.0-6.9
            'LOW': 2.5,       # 2.0-3.9
            'INFO': 0.5,      # 0.1-1.9
            'UNKNOWN': 5.0    # Среднее значение
        }
        return severity_cvss_map.get(str(severity).upper(), 5.0)
    
    def _get_max_sev(self, sevs):
        order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        valid_sevs = [s for s in sevs if s]
        if not valid_sevs: return 'INFO'
        return max(valid_sevs, key=lambda s: order.get(str(s).upper(), 0))
    
    def _get_contextual_severity(self, base_severity: str, feasibility: str, has_protection: bool = False) -> str:
        """
        Определяет контекстную критичность с учётом реализуемости и защиты.
        Возвращает скорректированный уровень критичности.
        """
        # Получаем базовый CVSS
        base_cvss = self._cvss_from_severity(base_severity)
        
        # Рассчитываем контекстный CVSS
        contextual_cvss = self._calculate_contextual_cvss(base_cvss, feasibility, has_protection)
        
        # Преобразуем обратно в текстовую критичность
        if contextual_cvss >= 9.0:
            return 'CRITICAL'
        elif contextual_cvss >= 7.0:
            return 'HIGH'
        elif contextual_cvss >= 4.0:
            return 'MEDIUM'
        elif contextual_cvss >= 2.0:
            return 'LOW'
        else:
            return 'INFO'

    def _get_worst_feas(self, feas_list):
        valid = [str(f).upper() for f in feas_list if f]
        # Поддерживаем разные представления статусов (RU/EN/legacy),
        # чтобы отчёт совпадал со сводкой корреляции.
        if any('РЕАЛИЗУЕМА' == f or f == 'FEASIBLE' for f in valid):
            return 'РЕАЛИЗУЕМА'
        if any('ЧАСТИЧНО' in f or 'PARTIALLY' in f for f in valid):
            return 'ЧАСТИЧНО РЕАЛИЗУЕМА'
        if any('ТРЕБУЕТ АНАЛИЗА' in f or 'REQUIRES_ANALYSIS' in f or 'REQUIRES ANALYSIS' in f for f in valid):
            return 'ТРЕБУЕТ АНАЛИЗА'
        if any('НЕ РЕАЛИЗУЕМА' == f or f == 'NOT_FEASIBLE' or f == 'NOT FEASIBLE' for f in valid):
            return 'НЕ РЕАЛИЗУЕМА'
        return 'UNKNOWN'

    def _get_feas_rank(self, feas: str) -> int:
        f = str(feas or "").upper()
        if f == "РЕАЛИЗУЕМА" or f == "FEASIBLE":
            return 4
        if "ЧАСТИЧНО" in f or "PARTIALLY" in f:
            return 3
        if "ТРЕБУЕТ АНАЛИЗА" in f or "REQUIRES_ANALYSIS" in f or "REQUIRES ANALYSIS" in f:
            return 2
        if f == "НЕ РЕАЛИЗУЕМА" or f == "NOT_FEASIBLE" or f == "NOT FEASIBLE":
            return 1
        return 0

    def _get_trace_score(self, record) -> int:
        trace = getattr(record, "feasibility_trace", None) or {}
        if isinstance(trace, dict):
            try:
                return int(trace.get("score", 0) or 0)
            except Exception:
                return 0
        return 0

    def _select_group_representative(self, records):
        """Выбор записи-представителя для группы: опаснее по статусу, при равенстве — выше score."""
        if not records:
            return None
        best = records[0]
        best_key = (
            self._get_feas_rank(getattr(best, "feasibility", "")),
            self._get_trace_score(best),
        )
        for rec in records[1:]:
            cur_key = (
                self._get_feas_rank(getattr(rec, "feasibility", "")),
                self._get_trace_score(rec),
            )
            if cur_key > best_key:
                best = rec
                best_key = cur_key
        return best

    def _build_software_context(self, sw_name: str, port: str, capec: str, cwe: str, vuln_desc: str) -> dict:
        """
        Формирует человеко-понятный контекст ПО для отчёта:
        что это за компонент, его роль и возможные последствия компрометации.
        """
        sw_l = (sw_name or "").lower()
        port_l = str(port or "").strip()
        desc_l = (vuln_desc or "").lower()
        capec_l = (capec or "").lower()
        cwe_l = (cwe or "").lower()

        category = "Системный/инфраструктурный компонент"
        purpose = "Обеспечивает базовые функции хоста или сетевого сервиса."
        impact = "Компрометация может привести к нарушению доступности или конфиденциальности."
        scope = "Локальный контур сервера"

        rules = [
            (("mysql", "postgres", "mssql", "oracle", "redis", "mongodb", "database"),
             "База данных",
             "Хранение и обработка бизнес-данных и учётных записей.",
             "Утечка/модификация данных, эскалация в приложениях, простои сервисов.",
             "Контур данных и приложений"),
            (("apache", "nginx", "iis", "http", "web", "tomcat", "news", "booking"),
             "Веб-приложение/веб-сервер",
             "Обработка пользовательских HTTP(S)-запросов и бизнес-логики.",
             "Доступ к пользовательским сессиям, дефейс, удалённое выполнение кода, компрометация backend.",
             "Публичный периметр"),
            (("smb", "rdp", "ssh", "ftp", "smtp", "imap", "pop3", "winrm"),
             "Сетевой сервис удалённого доступа/обмена",
             "Обеспечивает удалённый доступ, передачу файлов или администрирование.",
             "Компрометация учётных данных, lateral movement, захват хоста в домене.",
             "Сетевой периметр и админ-контур"),
            (("vmware", "hyper-v", "docker", "kubernetes"),
             "Виртуализация/оркестрация",
             "Управление виртуальными машинами и контейнерной инфраструктурой.",
             "Компрометация гипервизора или оркестратора, масштабное влияние на несколько сервисов.",
             "Инфраструктурное ядро"),
            (("windows", "kernel", "lsa", "credential", "system component", "component"),
             "Системный компонент ОС",
             "Ключевые функции операционной системы и безопасности.",
             "Повышение привилегий, обход защитных механизмов, полный контроль над узлом.",
             "Хостовый уровень"),
        ]

        for keywords, cat, purp, imp, scp in rules:
            if any(k in sw_l for k in keywords):
                category, purpose, impact, scope = cat, purp, imp, scp
                break

        if port_l and port_l not in ("Локальный вектор (без порта)", "Локальный", "None", ""):
            scope = f"{scope}; сетевой доступ через порт {port_l}"

        # Дополнительный акцент по характеру уязвимости
        if any(k in desc_l for k in ("remote code execution", "rce")) or "capec-242" in capec_l:
            impact = "Высокий риск удалённого выполнения кода и последующего захвата узла/сервиса."
        elif any(k in desc_l for k in ("sql", "injection")) or "cwe-89" in cwe_l:
            impact = "Риск прямого доступа к данным и обхода прикладной логики через инъекцию."
        elif "cwe-79" in cwe_l or "xss" in desc_l:
            impact = "Риск компрометации пользовательских сессий и внедрения клиентского вредоносного кода."

        return {
            "category": category,
            "purpose": purpose,
            "impact": impact,
            "scope": scope,
        }

    def _build_summary_data(self, js_data, raw_js_data):
        """Строит данные для перечней CVE, CWE, CAPEC, ПО."""
        all_cves = set()
        all_cwes = set()
        all_capecs = set()
        all_software = {}  # name -> version

        # Из агрегированных данных
        for item in js_data:
            # CVEs
            for cve in item.get('cve', '').split(', '):
                cve = cve.strip()
                if cve and cve != 'Нет CVE' and cve != 'N/A':
                    all_cves.add(cve)
            # CWE
            cwe = item.get('cwe', '')
            if cwe and cwe != 'CWE-Неизвестно' and cwe != 'Нет CWE':
                for c in cwe.split(', '):
                    c = c.strip()
                    if c: all_cwes.add(c)
            # CAPEC
            capec = item.get('capec', '')
            if capec and capec != 'CAPEC-Неизвестно' and capec != 'Нет CAPEC':
                for c in capec.split(', '):
                    c = c.strip()
                    if c: all_capecs.add(c)
            # ПО
            sw = item.get('sw', '')
            if sw and 'Неидентифицированн' not in sw:
                all_software[sw] = {
                    "port": item.get('port', ''),
                    "category": item.get('sw_category', ''),
                    "purpose": item.get('sw_purpose', ''),
                    "impact": item.get('sw_impact', ''),
                }

        # Из сырых данных
        for item in raw_js_data:
            cve = item.get('cve', '')
            if cve and cve != 'N/A':
                all_cves.add(cve)
            sw = item.get('sw', '')
            if sw and 'Неидентифицированн' not in sw:
                if sw not in all_software:
                    all_software[sw] = {
                        "port": item.get('port', ''),
                        "category": "",
                        "purpose": "",
                        "impact": "",
                    }

        # Из данных Trivy (если есть)
        if self.trivy_result:
            vulns = []
            if isinstance(self.trivy_result, dict):
                vulns = self.trivy_result.get('vulnerabilities', [])
            elif hasattr(self.trivy_result, 'vulnerabilities'):
                vulns = self.trivy_result.vulnerabilities

            for v in vulns:
                if isinstance(v, dict):
                    vid = v.get('vuln_id', '')
                    pkg = v.get('pkg_name', '')
                    ver = v.get('installed_version', '')
                    cwes = v.get('cwe_ids', [])
                    capecs = v.get('capec_ids', [])
                else:
                    vid = getattr(v, 'vuln_id', '')
                    pkg = getattr(v, 'pkg_name', '')
                    ver = getattr(v, 'installed_version', '')
                    cwes = getattr(v, 'cwe_ids', [])
                    capecs = getattr(v, 'capec_ids', [])

                if vid: all_cves.add(vid)
                if pkg: all_software[f"{pkg} {ver}".strip()] = ''
                for c in (cwes or []): all_cwes.add(c)
                for c in (capecs or []): all_capecs.add(c)

        # Форматируем для JS
        cve_list = sorted(list(all_cves))
        cwe_list = []
        for c in sorted(list(all_cwes)):
            desc = self._get_cwe_description(c)
            cwe_list.append({"id": c, "desc": desc[:80] + "..." if len(desc) > 80 else desc})

        capec_list = []
        capac_db = self.capec_db
        for c in sorted(list(all_capecs)):
            desc = ""
            if isinstance(capac_db, dict) and c in capac_db:
                desc = capac_db[c].get('description', '')[:80]
            elif isinstance(capac_db, list):
                for item in capac_db:
                    if item.get('id') == c or item.get('capec_id') == c:
                        desc = item.get('description', '')[:80]
                        break
            capec_list.append({"id": c, "desc": desc})

        sw_list = []
        for name, meta in sorted(all_software.items()):
            port = meta.get("port", "")
            cat = meta.get("category", "")
            purp = meta.get("purpose", "")
            parts = []
            if cat:
                parts.append(cat)
            if port:
                parts.append(f"Порт: {port}")
            if purp:
                parts.append(purp)
            sw_list.append({"id": name, "desc": " | ".join(parts)})

        return {
            "cves": cve_list,
            "cwes": cwe_list,
            "capecs": capec_list,
            "software": sw_list,
        }

    def _build_atk_def_data(self, js_data):
        """Строит данные для раздела атак и защиты."""
        atk_def_list = []

        for item in js_data:
            cves_str = item.get('cve', '')
            cve_list = [c.strip() for c in cves_str.split(',') if c.strip() and c.strip() != 'Нет CVE']

            attack_tools = []
            defense_tools = []

            if self.toolkit:
                # Ищем инструменты атаки по CVE
                for cve_id in cve_list[:5]:  # Ограничиваем для производительности
                    tools = self.toolkit.get_attack_commands(cve_id)
                    for tool in tools:
                        attack_tools.append({
                            "name": tool.get('tool_name', ''),
                            "desc": tool.get('description', ''),
                            "skill": tool.get('skill_level', ''),
                            "commands": tool.get('commands', []),
                        })

                    defenses = self.toolkit.get_defense_tools(cve_id)
                    for d in defenses:
                        defense_tools.append({
                            "name": d.get('tool_name', ''),
                            "desc": d.get('defense_description', d.get('tool_description', '')),
                            "priority": d.get('priority', ''),
                            "commands": d.get('commands', []),
                        })

            # Если нет инструментов из toolkit, ищем в локальных БД
            if not attack_tools and isinstance(self.tools_db, list):
                for cve_id in cve_list[:5]:
                    for tool in self.tools_db:
                        if cve_id in tool.get('applicable_cve', []):
                            cmds = tool.get('commands', {}).get(cve_id, [])
                            if not cmds:
                                cmds = tool.get('commands', {}).get('default', [])
                            attack_tools.append({
                                "name": tool.get('name', ''),
                                "desc": tool.get('description', ''),
                                "skill": tool.get('skill_level', ''),
                                "commands": cmds,
                            })

            if not defense_tools and isinstance(self.defense_db, list):
                for cve_id in cve_list[:5]:
                    for defense in self.defense_db:
                        if cve_id in defense.get('cve_ids', []):
                            for dt in defense.get('tools', []):
                                defense_tools.append({
                                    "name": dt.get('name', ''),
                                    "desc": dt.get('description', ''),
                                    "priority": defense.get('priority', ''),
                                    "commands": dt.get('commands', []),
                                })

            cve_short = cve_list[0] if cve_list else 'N/A'
            if len(cve_list) > 1:
                cve_short += f" +{len(cve_list)-1}"

            atk_def_list.append({
                "sw": item.get('sw', ''),
                "capec": item.get('capec', ''),
                "cwe": item.get('cwe', ''),
                "cve_short": cve_short,
                "sev": item.get('sev', 'INFO'),
                "feas": item.get('feas', 'UNKNOWN'),
                "recommendation": item.get('rec', ''),
                "attack_tools": attack_tools,
                "defense_tools": defense_tools,
            })

        return atk_def_list

    def generate_json(self, filepath):
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
        except Exception:
            pass

        out = {
            "system_summary": self.system_summary,
            "summary": self.summary,
            "aggregated_groups": [],
        }

        for key, g in self.aggregated_groups.items():
            base_r = g["base_record"]
            port_raw = getattr(base_r, "target_port", None)
            if port_raw in (None, "None", "null", "", 0, "0"):
                port = "Локальный вектор (без порта)"
            else:
                port = str(port_raw)

            out["aggregated_groups"].append(
                {
                    "software": g.get("mapped_sw", ""),
                    "software_key": key,
                    "port": port,
                    "capec": getattr(base_r, "capec_id", "") or "Нет CAPEC",
                    "cwe": getattr(base_r, "cwe_id", "") or "Нет CWE",
                    "cves": sorted(list(g.get("cves", set()))),
                    "attack_names": sorted(list(g.get("names", set()))),
                    "severity": self._get_max_sev(g.get("sevs", [])),
                    "feasibility": self._get_worst_feas(g.get("feas", [])),
                    "count": int(g.get("count", 1)),
                }
            )

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)

        return filepath

    def generate_html(self, filepath):
        js_data = []
        
        # 1. Готовим данные агрегированных групп для карт
        for i, (key, g) in enumerate(self.aggregated_groups.items()):
            base_r = g['base_record']
            representative_r = self._select_group_representative(g.get('records', [])) or base_r
            
            cves_joined = ", ".join(sorted(list(g['cves'])))
            names_joined = " / ".join(sorted(list(g['names'])))
            found_by_joined = " & ".join(sorted(list(g['found_by'])))
            
            max_sev = self._get_max_sev(g['sevs'])
            worst_feas = self._get_worst_feas(g['feas'])
            
            port_raw = getattr(base_r, 'target_port', None)
            if port_raw in (None, "None", "null", "", 0, "0"):
                port = "Локальный вектор (без порта)"
            else:
                port = str(port_raw)

            cwe_raw = getattr(representative_r, 'cwe_id', '') or getattr(base_r, 'cwe_id', '')
            cwe_tokens = self._canonical_cwe_list(cwe_raw)
            cwe_id = ", ".join(cwe_tokens) if cwe_tokens else (str(cwe_raw).strip() or "")
            if not cwe_id or cwe_id.upper() == "N/A":
                cwe_id = "CWE-Неизвестно"
            cwe_desc = self._get_cwe_description(cwe_raw)

            tools = getattr(representative_r, 'attack_software', None) or getattr(base_r, 'attack_software', None)
            steps = getattr(representative_r, 'attack_steps', None) or getattr(base_r, 'attack_steps', None)
            mitre_raw = getattr(representative_r, "mitre_technique", None) or getattr(base_r, "mitre_technique", None) or ""

            if not tools and self.tools_db and cwe_tokens:
                db_info = None
                for tok in cwe_tokens:
                    if tok in self.tools_db:
                        db_info = self.tools_db[tok]
                        break
            else:
                db_info = None
            if not tools and db_info:
                tools_list = db_info.get('tools', [])
                tools = ", ".join(tools_list) if tools_list else "Nmap, Metasploit"
                steps = db_info.get('exploitation_steps', "1. Сканирование сети.\\n2. Выбор эксплоита.\\n3. Запуск.")
            
            if not tools: tools = "Burp Suite, SQLMap, Nmap"
            if not steps: steps = "1. Анализ порта.\\n2. Идентификация службы.\\n3. Подбор эксплоита."

            feasibility_explanation = getattr(representative_r, 'reason', None) or "Подробные пояснения недоступны."
            representative_trace = getattr(representative_r, "feasibility_trace", None) or {}
            if not isinstance(representative_trace, dict):
                representative_trace = {}
            sw_ctx = self._build_software_context(
                g['mapped_sw'],
                port,
                getattr(representative_r, 'capec_id', None) or getattr(base_r, 'capec_id', None) or '',
                cwe_id or '',
                getattr(representative_r, 'description', None) or getattr(base_r, 'description', None) or ''
            )
            
            js_data.append({
                "id": i,
                "cve": cves_joined,  
                "cwe": cwe_id or 'CWE-Неизвестно',
                "cwe_desc": cwe_desc, # Передаем описание CWE в JavaScript
                "capec": getattr(representative_r, 'capec_id', None) or getattr(base_r, 'capec_id', None) or 'CAPEC-Неизвестно',
                "mitre": mitre_raw,
                "name": names_joined,
                "sw": g['mapped_sw'], 
                "port": port,
                "feas": worst_feas,
                "sev": max_sev,
                "desc": getattr(representative_r, 'description', None) or 'Описание отсутствует.',
                "rec": getattr(representative_r, 'recommendation', None) or 'Специфичных рекомендаций нет.',
                "reason": feasibility_explanation,  # Подробные пояснения реализуемости
                "feasibility_trace": representative_trace,
                "count": g['count'], 
                "found_by": found_by_joined,
                "tools": tools,
                "steps": steps,
                "sw_category": sw_ctx["category"],
                "sw_purpose": sw_ctx["purpose"],
                "sw_impact": sw_ctx["impact"],
                "sw_scope": sw_ctx["scope"],
            })

        # 2. Готовим сырые данные для динамической агрегации и расширенного меню
        raw_findings_data = []
        raw_js_data = []
        for idx, r in enumerate(self.raw_results):
            cve_str = getattr(r, 'cve_id', 'N/A')
            cve_list = [c.strip() for c in cve_str.split(',')] if cve_str else ["N/A"]

            port_raw = getattr(r, 'target_port', None)
            if port_raw in (None, "None", "null", "", 0, "0"):
                port = "Локальный"
            else:
                port = str(port_raw)

            # ИСПОЛЬЗУЕМ НОВЫЙ АЛГОРИТМ ДЛЯ СЫРЫХ ДАННЫХ
            real_sw = self.sw_enricher.identify_real_software(r, port)
            cwe_raw_row = getattr(r, "cwe_id", "") or ""
            cwe_tokens_row = self._canonical_cwe_list(cwe_raw_row)
            cwe_display_row = ", ".join(cwe_tokens_row) if cwe_tokens_row else (str(cwe_raw_row).strip() or "CWE-Неизвестно")
            if not cwe_tokens_row and cwe_display_row.upper() == "N/A":
                cwe_display_row = "CWE-Неизвестно"
            sw_ctx_raw = self._build_software_context(
                real_sw,
                port,
                getattr(r, 'capec_id', ''),
                cwe_display_row,
                getattr(r, 'description', '')
            )
            cwe_desc_raw = self._get_cwe_description(cwe_raw_row)
            found_by_raw = getattr(r, 'found_by', 'Сервер') if hasattr(r, 'found_by') else 'Сервер'
            _trace = getattr(r, "feasibility_trace", None) or {}
            if not isinstance(_trace, dict):
                _trace = {}
            raw_findings_data.append({
                "raw_id": idx,
                "cve": cve_str if cve_str else "N/A",
                "cwe": cwe_display_row,
                "cwe_desc": cwe_desc_raw,
                "capec": getattr(r, 'capec_id', None) or 'CAPEC-Неизвестно',
                "mitre": getattr(r, "mitre_technique", None) or "",
                "name": getattr(r, 'attack_name', None) or 'Атака',
                "sw": real_sw,
                "port": port,
                "feas": normalize_feasibility(self._get_worst_feas([getattr(r, 'feasibility', 'UNKNOWN')])),
                "sev": normalize_severity(getattr(r, 'severity', 'INFO')),
                "desc": getattr(r, 'description', None) or 'Описание отсутствует.',
                "rec": getattr(r, 'recommendation', None) or 'Специфичных рекомендаций нет.',
                "reason": getattr(r, 'reason', None) or 'Подробные пояснения недоступны.',
                "count": 1,
                "found_by": found_by_raw,
                "tools": getattr(r, 'attack_software', None) or "Burp Suite, SQLMap, Nmap",
                "steps": getattr(r, 'attack_steps', None) or "1. Анализ порта.\\n2. Идентификация службы.\\n3. Подбор эксплоита.",
                "sw_category": sw_ctx_raw["category"],
                "sw_purpose": sw_ctx_raw["purpose"],
                "sw_impact": sw_ctx_raw["impact"],
                "sw_scope": sw_ctx_raw["scope"],
                "feasibility_trace": _trace,
            })

            for single_cve in cve_list:
                if single_cve == "N/A" and len(cve_list) > 1:
                    continue

                raw_js_data.append({
                    "cve": single_cve,
                    "sev": getattr(r, 'severity', 'INFO'),
                    "sw": real_sw,
                    "port": port,
                    "capec": getattr(r, 'capec_id', 'N/A'),
                    "sw_category": sw_ctx_raw["category"],
                    "sw_purpose": sw_ctx_raw["purpose"],
                    "sw_impact": sw_ctx_raw["impact"],
                    "sw_scope": sw_ctx_raw["scope"],
                })

        # 3. Готовим данные для перечней CVE/CWE/CAPEC/ПО
        summary_data = self._build_summary_data(js_data, raw_js_data)

        # 4. Готовим данные для раздела атак и защиты
        atk_def_data = self._build_atk_def_data(js_data)
            
        sys_data = {
            "hostname": self.system_summary.get('hostname', 'Целевой Сервер'),
            "os": self.system_summary.get('os', 'Неизвестная ОС'),
            "ips": ", ".join(self.system_summary.get('ip_addresses', [])),
            "ports_count": self.system_summary.get('open_ports_count', 0)
        }

        capec_ids = set()
        cve_ids = set()
        mitre_ids = set()

        def _collect_ids(value, prefix, out_set: set):
            if value is None:
                return
            for part in str(value).split(","):
                tok = part.strip()
                if not tok:
                    continue
                up = tok.upper()
                if prefix == "CAPEC" and up.startswith("CAPEC-"):
                    out_set.add(up)
                elif prefix == "CVE" and up.startswith("CVE-"):
                    out_set.add(up)
                elif prefix == "MITRE":
                    if up.startswith("T") and up[1:].isdigit():
                        out_set.add(up)

        for it in (raw_findings_data or []):
            _collect_ids(it.get("capec"), "CAPEC", capec_ids)
            _collect_ids(it.get("cve"), "CVE", cve_ids)
            _collect_ids(it.get("mitre"), "MITRE", mitre_ids)

        for it in (js_data or []):
            _collect_ids(it.get("capec"), "CAPEC", capec_ids)
            _collect_ids(it.get("cve"), "CVE", cve_ids)
            _collect_ids(it.get("mitre"), "MITRE", mitre_ids)

        capec_index = {}
        if isinstance(self.capec_db, dict):
            for k, v in self.capec_db.items():
                capec_index[str(k).upper()] = v
        elif isinstance(self.capec_db, list):
            for v in self.capec_db:
                cid = (v or {}).get("id") or (v or {}).get("capec_id")
                if cid:
                    capec_index[str(cid).upper()] = v

        cve_index = {}
        if isinstance(self.cve_db, dict):
            for k, v in self.cve_db.items():
                cve_index[str(k).upper()] = v
        elif isinstance(self.cve_db, list):
            for v in self.cve_db:
                cid = (v or {}).get("id") or (v or {}).get("cve_id")
                if cid:
                    cve_index[str(cid).upper()] = v

        mitre_index = {}
        if isinstance(self.mitre_db, dict):
            for k, v in self.mitre_db.items():
                mitre_index[str(k).upper()] = v
        elif isinstance(self.mitre_db, list):
            for v in self.mitre_db:
                mid = (v or {}).get("id") or (v or {}).get("technique_id")
                if mid:
                    mitre_index[str(mid).upper()] = v

        capec_meta = {}
        for cid in sorted(capec_ids):
            entry = capec_index.get(cid, {}) or {}
            mitigations = entry.get("mitigations", []) or []
            prerequisites = entry.get("prerequisites", []) or []
            capec_meta[cid] = {
                "id": cid,
                "name": entry.get("name", "") or "",
                "description": entry.get("description", "") or "",
                "prerequisites": prerequisites[:50] if isinstance(prerequisites, list) else [],
                "mitigations": mitigations[:50] if isinstance(mitigations, list) else [],
            }

        cve_meta = {}
        for cid in sorted(cve_ids):
            entry = cve_index.get(cid, {}) or {}
            cve_meta[cid] = {
                "id": cid,
                "description": entry.get("description", "") or "",
                "severity": entry.get("severity", "") or "",
                "cvss_score": entry.get("cvss_score", None),
                "attack_type": entry.get("attack_type", "") or "",
                "affected_software": (entry.get("affected_software", []) or [])[:80] if isinstance(entry.get("affected_software", []), list) else [],
                "related_cwe": (entry.get("related_cwe", []) or [])[:80] if isinstance(entry.get("related_cwe", []), list) else [],
                "related_capec": (entry.get("related_capec", []) or [])[:80] if isinstance(entry.get("related_capec", []), list) else [],
                "related_mitre": (entry.get("related_mitre", []) or [])[:80] if isinstance(entry.get("related_mitre", []), list) else [],
                "requires_service": (entry.get("requires_service", []) or [])[:80] if isinstance(entry.get("requires_service", []), list) else [],
                "requires_port": (entry.get("requires_port", []) or [])[:80] if isinstance(entry.get("requires_port", []), list) else [],
                "prerequisites": (entry.get("prerequisites", []) or [])[:80] if isinstance(entry.get("prerequisites", []), list) else [],
                "mitigations": (entry.get("mitigations", []) or [])[:80] if isinstance(entry.get("mitigations", []), list) else [],
            }

        mitre_meta = {}
        for mid in sorted(mitre_ids):
            entry = mitre_index.get(mid, {}) or {}
            platforms = entry.get("platforms", []) or []
            mitigations = entry.get("mitigations", []) or []
            related_cwe = entry.get("related_cwe", []) or []
            related_capec = entry.get("related_capec", []) or []
            requires_service = entry.get("requires_service", []) or []
            mitre_meta[mid] = {
                "id": mid,
                "name": entry.get("name", "") or "",
                "tactic": entry.get("tactic", "") or "",
                "description": entry.get("description", "") or "",
                "platforms": platforms[:50] if isinstance(platforms, list) else [],
                "detection": entry.get("detection", "") or "",
                "mitigations": mitigations[:80] if isinstance(mitigations, list) else [],
                "related_cwe": related_cwe[:80] if isinstance(related_cwe, list) else [],
                "related_capec": related_capec[:80] if isinstance(related_capec, list) else [],
                "requires_service": requires_service[:80] if isinstance(requires_service, list) else [],
            }
        
        with open(filepath, "w", encoding="utf-8") as f:
            html = HTML_TEMPLATE.replace('__REPORT_DATA__', json.dumps(js_data, ensure_ascii=False))
            html = html.replace('__RAW_FINDINGS_DATA__', json.dumps(raw_findings_data, ensure_ascii=False))
            html = html.replace('__RAW_CVE_DATA__', json.dumps(raw_js_data, ensure_ascii=False))
            html = html.replace('__SYS_DATA__', json.dumps(sys_data, ensure_ascii=False))
            html = html.replace('__SUMMARY_DATA__', json.dumps(summary_data, ensure_ascii=False))
            html = html.replace('__ATK_DEF_DATA__', json.dumps(atk_def_data, ensure_ascii=False))
            html = html.replace('__CAPEC_META__', json.dumps(capec_meta, ensure_ascii=False))
            html = html.replace('__CVE_META__', json.dumps(cve_meta, ensure_ascii=False))
            html = html.replace('__MITRE_META__', json.dumps(mitre_meta, ensure_ascii=False))
            html = html.replace('__STATUS_META__', json.dumps(report_status_meta(), ensure_ascii=False))
            f.write(html)

        return filepath
