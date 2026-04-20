"""
Расширенный резолвер CVE с интеграцией внешних источников.
Улучшенная система определения и классификации уязвимостей.

Функциональность:
- Интеграция с NVD API для получения актуальных CVE
- Поддержка CIRCL CVE API
- Расширенный анализ баннеров с поддержкой дополнительных форматов
- Классификация уязвимостей по CWE
- Кэширование результатов для повышения производительности
"""

import json
import re
import time
import urllib.request
import urllib.error
import ssl
import os
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import hashlib

# Отключаем проверку SSL сертификатов для совместимости
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

class CVECache:
    """Система кэширования CVE данных для уменьшения сетевых запросов."""

    def __init__(self, cache_dir: str = "cve_cache", cache_ttl: int = 86400):
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl  # Время жизни кэша в секундах (24 часа)
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_path(self, key: str) -> str:
        """Генерирует путь к кэш-файлу на основе хеша ключа."""
        key_hash = hashlib.md5(key.encode('utf-8')).hexdigest()
        return os.path.join(self.cache_dir, f"{key_hash}.json")

    def get(self, key: str) -> Optional[Dict]:
        """Получает данные из кэша, если они актуальны."""
        cache_path = self._get_cache_path(key)
        if not os.path.exists(cache_path):
            return None

        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cached_data = json.load(f)

            # Проверяем срок годности кэша
            cache_time = cached_data.get('timestamp', 0)
            if time.time() - cache_time > self.cache_ttl:
                return None

            return cached_data.get('data')
        except (json.JSONDecodeError, IOError):
            return None

    def set(self, key: str, data: Dict) -> None:
        """Сохраняет данные в кэш."""
        cache_path = self._get_cache_path(key)
        cache_data = {
            'timestamp': time.time(),
            'data': data
        }

        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
        except IOError:
            pass

class NVDAPIClient:
    """Клиент для работы с NVD API (National Vulnerability Database)."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, cache: Optional[CVECache] = None):
        self.cache = cache or CVECache()
        self.api_key = None  # Можно добавить поддержку API ключа

    def get_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """Получает информацию о конкретном CVE по идентификатору."""
        if not cve_id or not cve_id.startswith('CVE-'):
            return None

        cache_key = f"nvd_cve_{cve_id}"
        cached_data = self.cache.get(cache_key)
        if cached_data:
            return cached_data

        url = f"{self.BASE_URL}?cveId={cve_id}"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ssl_context, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

            if data.get('totalResults', 0) > 0:
                cve_data = data['vulnerabilities'][0]['cve']
                result = self._parse_nvd_cve(cve_data)
                self.cache.set(cache_key, result)
                return result

        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            print(f"Ошибка при получении CVE {cve_id} из NVD: {e}")
            return None

        return None

    def search_cves_by_keyword(self, keyword: str, limit: int = 20) -> List[Dict]:
        """Поиск CVE по ключевому слову."""
        if not keyword:
            return []

        cache_key = f"nvd_search_{keyword}_{limit}"
        cached_data = self.cache.get(cache_key)
        if cached_data:
            return cached_data

        url = f"{self.BASE_URL}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage={limit}"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ssl_context, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

            results = []
            for vuln in data.get('vulnerabilities', []):
                cve_data = vuln['cve']
                parsed = self._parse_nvd_cve(cve_data)
                if parsed:
                    results.append(parsed)

            self.cache.set(cache_key, results)
            return results

        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            print(f"Ошибка при поиске CVE по ключевому слову '{keyword}': {e}")
            return []

        return []

    def _parse_nvd_cve(self, cve_data: Dict) -> Dict:
        """Парсинг данных CVE из NVD в унифицированный формат."""
        try:
            cve_id = cve_data['id']
            descriptions = cve_data['descriptions']
            metrics = cve_data.get('metrics', {})

            # Получаем описание
            description = ""
            for desc in descriptions:
                if desc['lang'] == 'en':
                    description = desc['value']
                    break

            # Получаем оценку CVSS
            cvss_score = 0.0
            cvss_vector = ""
            severity = "INFO"

            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', "")
                severity = self._cvss_score_to_severity(cvss_score)
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', "")
                severity = self._cvss_score_to_severity(cvss_score)

            # Получаем CWE
            weaknesses = []
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc['lang'] == 'en':
                        weaknesses.append({
                            'cwe_id': weakness.get('cweId', ''),
                            'description': desc['value']
                        })
                        break

            return {
                'id': cve_id,
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'weaknesses': weaknesses,
                'published_date': cve_data.get('published', ''),
                'last_modified': cve_data.get('lastModified', ''),
                'source': 'NVD'
            }

        except (KeyError, IndexError) as e:
            print(f"Ошибка парсинга CVE данных: {e}")
            return {}

    def _cvss_score_to_severity(self, score: float) -> str:
        """Конвертация CVSS оценки в уровень серьезности."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "INFO"

class CIRCLAPIClient:
    """Клиент для работы с CIRCL CVE API."""

    BASE_URL = "https://cve.circl.lu/api"

    def __init__(self, cache: Optional[CVECache] = None):
        self.cache = cache or CVECache()

    def get_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """Получает информацию о CVE из CIRCL API."""
        if not cve_id or not cve_id.startswith('CVE-'):
            return None

        cache_key = f"circl_cve_{cve_id}"
        cached_data = self.cache.get(cache_key)
        if cached_data:
            return cached_data

        url = f"{self.BASE_URL}/cve/{cve_id}"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ssl_context, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

            result = self._parse_circl_cve(data)
            self.cache.set(cache_key, result)
            return result

        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            print(f"Ошибка при получении CVE {cve_id} из CIRCL: {e}")
            return None

        return None

    def search_cves_by_product(self, product: str, limit: int = 20) -> List[Dict]:
        """Поиск CVE по продукту/вендору."""
        if not product:
            return []

        cache_key = f"circl_product_{product}_{limit}"
        cached_data = self.cache.get(cache_key)
        if cached_data:
            return cached_data

        url = f"{self.BASE_URL}/search/{urllib.parse.quote(product)}?limit={limit}"

        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ssl_context, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

            results = []
            for cve_id in data:
                cve_data = self.get_cve_by_id(cve_id)
                if cve_data:
                    results.append(cve_data)

            self.cache.set(cache_key, results)
            return results

        except (urllib.error.URLError, json.JSONDecodeError) as e:
            print(f"Ошибка при поиске CVE по продукту '{product}': {e}")
            return []

        return []

    def _parse_circl_cve(self, cve_data: Dict) -> Dict:
        """Парсинг данных CVE из CIRCL в унифицированный формат."""
        try:
            cve_id = cve_data.get('id', '')
            summary = cve_data.get('summary', '')
            cvss = cve_data.get('cvss', 0.0)
            severity = self._cvss_score_to_severity(cvss)

            # Извлекаем CWE
            weaknesses = []
            if 'weakness' in cve_data:
                weakness = cve_data['weakness']
                if isinstance(weakness, dict):
                    weaknesses.append({
                        'cwe_id': weakness.get('id', ''),
                        'description': weakness.get('description', '')
                    })
                elif isinstance(weakness, list):
                    for w in weakness:
                        weaknesses.append({
                            'cwe_id': w.get('id', ''),
                            'description': w.get('description', '')
                        })

            return {
                'id': cve_id,
                'description': summary,
                'severity': severity,
                'cvss_score': cvss,
                'cvss_vector': cve_data.get('cvss-vector', ''),
                'weaknesses': weaknesses,
                'published_date': cve_data.get('Published', ''),
                'last_modified': cve_data.get('Last Modified', ''),
                'source': 'CIRCL'
            }

        except Exception as e:
            print(f"Ошибка парсинга CIRCL CVE данных: {e}")
            return {}

    def _cvss_score_to_severity(self, score: float) -> str:
        """Конвертация CVSS оценки в уровень серьезности."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "INFO"

class EnhancedBannerAnalyzer:
    """Улучшенный анализатор баннеров с поддержкой дополнительных форматов."""

    # Расширенные паттерны для анализа баннеров
    EXTENDED_BANNER_PATTERNS = {
        # Веб-серверы
        r"Server:\s*(.+?)\r?\n": "web_server",
        r"X-Powered-By:\s*(.+?)\r?\n": "web_framework",
        r"Apache[/ ](\d+\.\d+\.\d+)": "apache_version",
        r"nginx[/ ](\d+\.\d+\.\d+)": "nginx_version",
        r"Microsoft-IIS[/ ](\d+\.\d+)": "iis_version",

        # Базы данных
        r"MySQL\s+(\d+\.\d+\.\d+)": "mysql_version",
        r"PostgreSQL\s+(\d+\.\d+)": "postgresql_version",
        r"MongoDB\s+(\d+\.\d+\.\d+)": "mongodb_version",

        # SSH
        r"SSH-.*OpenSSH[_ ](\d+\.\d+)": "openssh_version",

        # FTP
        r"ProFTPD\s+(\d+\.\d+\.\d+)": "proftpd_version",
        r"vsftpd\s+(\d+\.\d+\.\d+)": "vsftpd_version",

        # Redis
        r"redis_version:(\d+\.\d+\.\d+)": "redis_version",

        # SSL/TLS
        r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)": "openssl_version",

        # Облачные сервисы
        r"VMware.*(\d+\.\d+\.\d+)": "vmware_version",
        r"AWS.*(\d+\.\d+\.\d+)": "aws_version",
    }

    def __init__(self, nvd_client: Optional[NVDAPIClient] = None, circl_client: Optional[CIRCLAPIClient] = None):
        self.nvd_client = nvd_client or NVDAPIClient()
        self.circl_client = circl_client or CIRCLAPIClient()

    def analyze_banner(self, banner: str, service: str = "", port: int = 0) -> Dict:
        """
        Расширенный анализ баннера с извлечением версий и определением CVE.

        Args:
            banner: Текст баннера
            service: Название сервиса
            port: Номер порта

        Returns:
            Словарь с информацией о баннере и найденных уязвимостях
        """
        if not banner:
            return {'banner': '', 'versions': {}, 'cves': [], 'service': service, 'port': port}

        result = {
            'banner': banner[:500],  # Ограничиваем длину
            'versions': {},
            'cves': [],
            'service': service,
            'port': port
        }

        # Извлекаем версии из баннера
        versions = self._extract_versions(banner)
        result['versions'] = versions

        # Определяем CVE на основе извлеченных версий
        cves = self._find_cves_for_versions(versions, service)
        result['cves'] = cves

        return result

    def _extract_versions(self, banner: str) -> Dict[str, str]:
        """Извлекает версии из баннера с использованием расширенных паттернов."""
        versions = {}

        # Пробуем стандартные паттерны
        for pattern, version_type in self.EXTENDED_BANNER_PATTERNS.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                versions[version_type] = match.group(1)

        # Дополнительные эвристики
        if not versions:
            # Попытка извлечь версию в формате X.Y.Z
            version_match = re.search(r'(\d+\.\d+\.\d+)', banner)
            if version_match:
                versions['generic_version'] = version_match.group(1)

        return versions

    def _find_cves_for_versions(self, versions: Dict[str, str], service: str) -> List[Dict]:
        """Поиск CVE для извлеченных версий."""
        cves = []

        # Поиск по конкретным сервисам
        if 'apache_version' in versions:
            cves.extend(self._search_apache_cves(versions['apache_version']))
        elif 'nginx_version' in versions:
            cves.extend(self._search_nginx_cves(versions['nginx_version']))
        elif 'openssh_version' in versions:
            cves.extend(self._search_openssh_cves(versions['openssh_version']))
        elif 'mysql_version' in versions:
            cves.extend(self._search_mysql_cves(versions['mysql_version']))

        # Общий поиск по сервису
        if service:
            cves.extend(self._search_service_cves(service))

        # Поиск по ключевым словам из баннера
        keywords = self._extract_keywords_from_banner(versions)
        for keyword in keywords:
            cves.extend(self.nvd_client.search_cves_by_keyword(keyword, limit=5))

        # Удаляем дубликаты
        unique_cves = []
        seen_ids = set()
        for cve in cves:
            if cve.get('id') and cve['id'] not in seen_ids:
                seen_ids.add(cve['id'])
                unique_cves.append(cve)

        return unique_cves

    def _search_apache_cves(self, version: str) -> List[Dict]:
        """Поиск CVE для Apache."""
        return self.nvd_client.search_cves_by_keyword(f"Apache {version}", limit=10)

    def _search_nginx_cves(self, version: str) -> List[Dict]:
        """Поиск CVE для Nginx."""
        return self.nvd_client.search_cves_by_keyword(f"Nginx {version}", limit=10)

    def _search_openssh_cves(self, version: str) -> List[Dict]:
        """Поиск CVE для OpenSSH."""
        return self.nvd_client.search_cves_by_keyword(f"OpenSSH {version}", limit=10)

    def _search_mysql_cves(self, version: str) -> List[Dict]:
        """Поиск CVE для MySQL."""
        return self.nvd_client.search_cves_by_keyword(f"MySQL {version}", limit=10)

    def _search_service_cves(self, service: str) -> List[Dict]:
        """Поиск CVE для сервиса."""
        return self.nvd_client.search_cves_by_keyword(service, limit=10)

    def _extract_keywords_from_banner(self, versions: Dict[str, str]) -> List[str]:
        """Извлекает ключевые слова из баннера для поиска CVE."""
        keywords = []

        # Добавляем найденные версии
        for version_type, version in versions.items():
            if version_type != 'generic_version':
                keywords.append(f"{version_type.replace('_', ' ')} {version}")

        return keywords

class AdvancedCVEResolver:
    """Основной класс для расширенного разрешения CVE."""

    def __init__(self):
        self.cache = CVECache()
        self.nvd_client = NVDAPIClient(self.cache)
        self.circl_client = CIRCLAPIClient(self.cache)
        self.banner_analyzer = EnhancedBannerAnalyzer(self.nvd_client, self.circl_client)

    def resolve_cve(self, cve_id: str) -> Optional[Dict]:
        """Получает информацию о CVE из нескольких источников."""
        # Пробуем NVD
        cve_data = self.nvd_client.get_cve_by_id(cve_id)
        if cve_data:
            return cve_data

        # Пробуем CIRCL
        cve_data = self.circl_client.get_cve_by_id(cve_id)
        if cve_data:
            return cve_data

        return None

    def analyze_banner(self, banner: str, service: str = "", port: int = 0) -> Dict:
        """Анализирует баннер и возвращает информацию об уязвимостях."""
        return self.banner_analyzer.analyze_banner(banner, service, port)

    def search_related_cves(self, service: str, version: str = "", limit: int = 10) -> List[Dict]:
        """Поиск связанных CVE для сервиса и версии."""
        cves = []

        # Поиск по сервису
        if service:
            cves.extend(self.nvd_client.search_cves_by_keyword(service, limit=limit//2))

        # Поиск по версии
        if version:
            cves.extend(self.nvd_client.search_cves_by_keyword(f"{service} {version}", limit=limit//2))

        # Удаляем дубликаты
        unique_cves = []
        seen_ids = set()
        for cve in cves:
            if cve.get('id') and cve['id'] not in seen_ids:
                seen_ids.add(cve['id'])
                unique_cves.append(cve)

        return unique_cves

# Тестирование модуля
if __name__ == "__main__":
    print("Тестирование расширенного резолвера CVE...")

    resolver = AdvancedCVEResolver()

    # Тест 1: Получение информации о CVE
    print("\n1. Получение информации о CVE-2021-41773:")
    cve_info = resolver.resolve_cve("CVE-2021-41773")
    if cve_info:
        print(f"   ID: {cve_info['id']}")
        print(f"   Severity: {cve_info['severity']}")
        print(f"   Description: {cve_info['description'][:100]}...")
    else:
        print("   CVE не найден")

    # Тест 2: Анализ баннера
    print("\n2. Анализ баннера Apache:")
    banner = "Server: Apache/2.4.49 (Ubuntu) OpenSSL/1.1.1f"
    analysis = resolver.analyze_banner(banner, "HTTP", 80)
    print(f"   Баннер: {analysis['banner']}")
    print(f"   Версии: {analysis['versions']}")
    print(f"   Найдено CVE: {len(analysis['cves'])}")

    # Тест 3: Поиск связанных CVE
    print("\n3. Поиск CVE для Apache 2.4.49:")
    related_cves = resolver.search_related_cves("Apache", "2.4.49", limit=5)
    print(f"   Найдено связанных CVE: {len(related_cves)}")
    for cve in related_cves[:3]:
        print(f"   - {cve['id']} ({cve['severity']}): {cve['description'][:80]}...")