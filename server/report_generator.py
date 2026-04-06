"""
Генератор отчётов по результатам анализа безопасности.
Создаёт HTML-отчёт с разделением на реализуемые и нереализуемые атаки.
"""

import os
import json
from datetime import datetime
from dataclasses import asdict

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.models import VulnerabilityMatch, AttackFeasibility
from common.config import REPORTS_DIR


class ReportGenerator:
    """Генерация отчётов по анализу безопасности."""

    def __init__(self, system_summary: dict, correlation_results: list,
                 correlation_summary: dict, scan_summary: dict = None):
        self.system_summary = system_summary
        self.results = correlation_results
        self.summary = correlation_summary
        self.scan_summary = scan_summary or {}
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_html(self, output_path: str = None) -> str:
        """Генерация полного HTML-отчёта."""
        if not output_path:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            output_path = os.path.join(REPORTS_DIR, filename)

        feasible = [r for r in self.results if r.feasibility == AttackFeasibility.FEASIBLE.value]
        partial = [r for r in self.results if r.feasibility == AttackFeasibility.PARTIALLY_FEASIBLE.value]
        not_feasible = [r for r in self.results if r.feasibility == AttackFeasibility.NOT_FEASIBLE.value]
        unknown = [r for r in self.results if r.feasibility == AttackFeasibility.REQUIRES_ANALYSIS.value]

        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчёт по безопасности — {self.timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #f0f2f5; color: #1a1a2e; padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            text-align: center; padding: 30px; background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: #fff; border-radius: 12px; margin-bottom: 20px;
        }}
        h1 small {{ display: block; font-size: 14px; opacity: 0.7; margin-top: 8px; }}
        h2 {{
            padding: 15px 20px; border-radius: 8px 8px 0 0;
            color: #fff; margin-top: 30px;
        }}
        .section {{ background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 20px; overflow: hidden; }}
        .section-body {{ padding: 20px; }}

        /* Сводка */
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{
            background: #f8f9fa; border-radius: 10px; padding: 20px; text-align: center;
            border-left: 4px solid #ccc;
        }}
        .stat-card .number {{ font-size: 36px; font-weight: bold; }}
        .stat-card .label {{ font-size: 13px; color: #666; margin-top: 5px; }}
        .stat-card.critical {{ border-color: #e63946; }}
        .stat-card.critical .number {{ color: #e63946; }}
        .stat-card.warning {{ border-color: #f4a261; }}
        .stat-card.warning .number {{ color: #f4a261; }}
        .stat-card.safe {{ border-color: #2a9d8f; }}
        .stat-card.safe .number {{ color: #2a9d8f; }}
        .stat-card.info {{ border-color: #457b9d; }}
        .stat-card.info .number {{ color: #457b9d; }}

        /* Таблицы */
        table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
        th {{ background: #f1f3f5; padding: 12px; text-align: left; font-weight: 600; }}
        td {{ padding: 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}

        /* Цвета секций */
        .h-danger {{ background: #e63946; }}
        .h-warning {{ background: #f4a261; }}
        .h-safe {{ background: #2a9d8f; }}
        .h-info {{ background: #457b9d; }}
        .h-system {{ background: #6c757d; }}

        /* Severity badges */
        .badge {{
            display: inline-block; padding: 3px 10px; border-radius: 12px;
            font-size: 11px; font-weight: 600; color: #fff;
        }}
        .badge-critical {{ background: #e63946; }}
        .badge-high {{ background: #f4a261; color: #1a1a2e; }}
        .badge-medium {{ background: #e9c46a; color: #1a1a2e; }}
        .badge-low {{ background: #2a9d8f; }}
        .badge-info {{ background: #457b9d; }}

        .recommendation {{
            background: #f1f8ff; border-left: 3px solid #457b9d;
            padding: 10px 15px; margin-top: 8px; font-size: 13px;
            white-space: pre-line; border-radius: 0 6px 6px 0;
        }}
        .reason {{
            color: #495057; font-style: italic; font-size: 13px; margin-top: 4px;
        }}

        /* Системная информация */
        .sys-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
        .sys-item {{ background: #f8f9fa; padding: 12px; border-radius: 8px; }}
        .sys-item strong {{ color: #1a1a2e; }}
        .sys-item .val {{ color: #495057; }}
        .status-active {{ color: #2a9d8f; font-weight: 600; }}
        .status-inactive {{ color: #e63946; font-weight: 600; }}

        @media print {{
            body {{ background: #fff; }}
            .section {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
<div class="container">

<h1>
    Отчёт по анализу безопасности сервера
    <small>{self.system_summary.get('hostname', 'N/A')} — {self.timestamp}</small>
</h1>

<!-- СВОДКА -->
<div class="stats">
    <div class="stat-card critical">
        <div class="number">{self.summary.get('feasible_attacks', 0)}</div>
        <div class="label">Реализуемые атаки</div>
    </div>
    <div class="stat-card warning">
        <div class="number">{self.summary.get('partially_feasible', 0)}</div>
        <div class="label">Частично реализуемые</div>
    </div>
    <div class="stat-card safe">
        <div class="number">{self.summary.get('not_feasible_attacks', 0)}</div>
        <div class="label">Нереализуемые</div>
    </div>
    <div class="stat-card info">
        <div class="number">{self.summary.get('total_vulnerabilities_analyzed', 0)}</div>
        <div class="label">Всего проанализировано</div>
    </div>
</div>

<!-- ИНФОРМАЦИЯ О СИСТЕМЕ -->
<div class="section">
    <h2 class="h-system">Информация о сервере</h2>
    <div class="section-body">
        <div class="sys-grid">
            <div class="sys-item"><strong>ОС:</strong> <span class="val">{self.system_summary.get('os', 'N/A')}</span></div>
            <div class="sys-item"><strong>Имя хоста:</strong> <span class="val">{self.system_summary.get('hostname', 'N/A')}</span></div>
            <div class="sys-item"><strong>IP-адреса:</strong> <span class="val">{', '.join(self.system_summary.get('ip_addresses', []))}</span></div>
            <div class="sys-item"><strong>Установленное ПО:</strong> <span class="val">{self.system_summary.get('installed_software_count', 0)} программ</span></div>
            <div class="sys-item"><strong>Работающих сервисов:</strong> <span class="val">{self.system_summary.get('running_services_count', 0)}</span></div>
            <div class="sys-item"><strong>Открытых портов:</strong> <span class="val">{self.system_summary.get('open_ports_count', 0)}</span></div>
            <div class="sys-item"><strong>Базы данных:</strong> <span class="val">{'Да (' + ', '.join(self.system_summary.get('database_types', [])) + ')' if self.system_summary.get('has_database') else 'Не обнаружены'}</span></div>
            <div class="sys-item"><strong>Веб-серверы:</strong> <span class="val">{'Да (' + ', '.join(self.system_summary.get('web_server_types', [])) + ')' if self.system_summary.get('has_web_server') else 'Не обнаружены'}</span></div>
            <div class="sys-item"><strong>RDP:</strong> <span class="{'status-active' if self.system_summary.get('has_rdp') else 'status-inactive'}"">{'Включён' if self.system_summary.get('has_rdp') else 'Выключен'}</span></div>
            <div class="sys-item"><strong>SMB:</strong> <span class="{'status-active' if self.system_summary.get('has_smb') else 'status-inactive'}"">{'Активен' if self.system_summary.get('has_smb') else 'Не обнаружен'}</span></div>
            <div class="sys-item"><strong>Брандмауэр:</strong> <span class="{'status-active' if self.system_summary.get('firewall') else 'status-inactive'}"">{'Активен' if self.system_summary.get('firewall') else 'Не активен'}</span></div>
            <div class="sys-item"><strong>Антивирус:</strong> <span class="{'status-active' if self.system_summary.get('antivirus') else 'status-inactive'}"">{'Активен' if self.system_summary.get('antivirus') else 'Не активен'}</span></div>
        </div>
    </div>
</div>
"""
        # РЕАЛИЗУЕМЫЕ АТАКИ
        if feasible:
            html += self._render_section(
                "РЕАЛИЗУЕМЫЕ АТАКИ — ТРЕБУЕТСЯ ДЕЙСТВИЕ", "h-danger", feasible
            )

        # ЧАСТИЧНО РЕАЛИЗУЕМЫЕ
        if partial:
            html += self._render_section(
                "ЧАСТИЧНО РЕАЛИЗУЕМЫЕ АТАКИ", "h-warning", partial
            )

        # ТРЕБУЮТ АНАЛИЗА
        if unknown:
            html += self._render_section(
                "ТРЕБУЮТ ДОПОЛНИТЕЛЬНОГО АНАЛИЗА", "h-info", unknown
            )

        # НЕРЕАЛИЗУЕМЫЕ
        if not_feasible:
            html += self._render_section(
                "НЕРЕАЛИЗУЕМЫЕ АТАКИ (защита обеспечена)", "h-safe", not_feasible
            )

        # РЕКОМЕНДАЦИИ ПО ЗАЩИТЕ
        html += self._render_recommendations_section(feasible + partial)

        html += """
</div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[+] HTML-отчёт сохранён: {output_path}")
        return output_path

    def _render_section(self, title: str, css_class: str, items: list) -> str:
        html = f"""
<div class="section">
    <h2 class="{css_class}">{title} ({len(items)})</h2>
    <div class="section-body">
    <table>
        <tr>
            <th style="width:130px">CVE</th>
            <th style="width:90px">Серьёзность</th>
            <th>Описание</th>
            <th style="width:130px">CWE</th>
            <th style="width:130px">MITRE</th>
        </tr>
"""
        for item in items:
            sev = item.severity if isinstance(item.severity, str) else item.severity
            badge_class = f"badge-{sev.lower()}" if sev else "badge-info"
            html += f"""
        <tr>
            <td><strong>{item.cve_id}</strong></td>
            <td><span class="badge {badge_class}">{sev}</span></td>
            <td>
                {item.description}
                <div class="reason">Оценка: {item.feasibility}. {item.reason}</div>
                <div class="recommendation">{item.recommendation}</div>
            </td>
            <td>{item.cwe_id}</td>
            <td>{item.mitre_technique}</td>
        </tr>
"""
        html += """
    </table>
    </div>
</div>"""
        return html

    def _render_recommendations_section(self, actionable: list) -> str:
        """Секция сводных рекомендаций."""
        if not actionable:
            return """
<div class="section">
    <h2 class="h-safe">Сводные рекомендации по защите</h2>
    <div class="section-body">
        <p>Все проанализированные атаки признаны нереализуемыми в текущей конфигурации.
        Рекомендуется поддерживать текущий уровень безопасности и регулярно обновлять ПО.</p>
    </div>
</div>"""

        # Собираем уникальные рекомендации
        all_recs = set()
        for item in actionable:
            for line in item.recommendation.split("\n"):
                line = line.strip()
                if line and not line.startswith("ВНИМАНИЕ") and not line.startswith("ПРИОРИТЕТ") and not line.startswith("Рекомендуемые"):
                    # Убираем нумерацию
                    clean = line.lstrip("0123456789. ")
                    if clean:
                        all_recs.add(clean)

        html = """
<div class="section">
    <h2 class="h-danger">Сводные рекомендации по защите сервера</h2>
    <div class="section-body">
    <table>
        <tr><th style="width:40px">№</th><th>Рекомендация</th></tr>
"""
        for i, rec in enumerate(sorted(all_recs), 1):
            html += f"        <tr><td>{i}</td><td>{rec}</td></tr>\n"

        html += """
    </table>
    </div>
</div>"""
        return html

    def generate_json(self, output_path: str = None) -> str:
        """Генерация JSON-отчёта."""
        if not output_path:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            output_path = os.path.join(REPORTS_DIR, filename)

        report = {
            "timestamp": self.timestamp,
            "system_info": self.system_summary,
            "summary": self.summary,
            "results": [asdict(r) for r in self.results],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"[+] JSON-отчёт сохранён: {output_path}")
        return output_path
