"""
Генератор отчётов безопасности.
Создаёт HTML и JSON отчёты с 5 схемами:
  1. Реализуемые атаки (исходная)
  2. Нереализуемые атаки (исходная)
  3. Сравнение уязвимостей (сервер vs атакующий) — НОВАЯ
  4. Уязвимости и как их устранить — НОВАЯ
  5. Уязвимости и как их использовать (ПО + команды) — НОВАЯ
ИСПРАВЛЕНИЯ:
  - Полная дедупликация по (cve_id, attack_name)
  - История отчётов записывается автоматически
  - Обогащение инструментами атаки/защиты
  - ИСПРАВЛЕН AttributeError: 'VulnerabilityMatch' object has no attribute 'get'
"""
import json
import os
import sys
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.logger import get_server_logger
logger = get_server_logger()


def _esc(s: str) -> str:
    """HTML escape."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _sev_color(sev: str) -> str:
    return {
        "CRITICAL": "#e74c3c",
        "HIGH": "#e67e22",
        "MEDIUM": "#f39c12",
        "LOW": "#27ae60",
        "INFO": "#3498db",
    }.get(str(sev).upper(), "#888")


def _feas_color(feas: str) -> str:
    if "НЕ РЕАЛИЗУЕМА" in str(feas):
        return "#27ae60"
    if "РЕАЛИЗУЕМА" in str(feas):
        return "#e74c3c"
    return "#f39c12"


def _get_feasibility(r) -> str:
    """
    Безопасное получение поля feasibility из объекта или словаря.
    Исправляет AttributeError: 'VulnerabilityMatch' object has no attribute 'get'
    """
    if hasattr(r, "feasibility"):
        return str(getattr(r, "feasibility", "") or "")
    elif isinstance(r, dict):
        return str(r.get("feasibility", "") or "")
    return ""


def _deduplicate(results: list) -> list:
    """
    Дедупликация результатов по ключу (cve_id, attack_name).
    Оставляем первое вхождение (наиболее актуальное).
    """
    seen = set()
    unique = []
    for r in results:
        if hasattr(r, "cve_id"):
            cve = str(r.cve_id or "")
            name = str(r.attack_name or "")
        elif isinstance(r, dict):
            cve = str(r.get("cve_id") or "")
            name = str(r.get("attack_name") or "")
        else:
            unique.append(r)
            continue
        key = f"{cve}||{name}"
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


class ReportGenerator:
    """Генератор HTML и JSON отчётов."""

    def __init__(
        self,
        system_summary: dict,
        results: list,
        summary: dict,
        toolkit=None,
        local_scan_report=None,
        attacker_scan_data: dict = None,
    ):
        self.system_summary = system_summary or {}
        # Дедупликация на входе
        self.results = _deduplicate(results or [])
        self.summary = summary or {}
        self.toolkit = toolkit          # AttackToolkit — для схем 3,4,5
        self.local_scan = local_scan_report  # ScanReport — для схемы 3
        self.attacker_data = attacker_scan_data or {}  # данные атакующего
        logger.info(
            f"[REPORT] Результатов после дедупликации: {len(self.results)} "
            f"(из {len(results or [])} входных)"
        )

    # ──────────────────────────────────────────────
    #  JSON
    # ──────────────────────────────────────────────
    def generate_json(self, output_path: str) -> str:
        """Генерация JSON-отчёта."""
        def to_dict(r):
            if hasattr(r, "__dataclass_fields__"):
                from dataclasses import asdict
                return asdict(r)
            return dict(r)

        data = {
            "generated_at": datetime.now().isoformat(),
            "server_info": self.system_summary,
            "summary": self.summary,
            "results": [to_dict(r) for r in self.results],
            # ИСПРАВЛЕНО: используем _get_feasibility() вместо некорректного
            # getattr(r, "feasibility", r.get("feasibility", "")) который вызывал
            # AttributeError т.к. r.get() вычислялся как аргумент getattr до проверки
            "feasible": [
                to_dict(r) for r in self.results
                if "НЕ" not in _get_feasibility(r)
                and "РЕАЛИЗУЕМА" in _get_feasibility(r)
            ],
            "not_feasible": [
                to_dict(r) for r in self.results
                if "НЕ РЕАЛИЗУЕМА" in _get_feasibility(r)
            ],
        }
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"[REPORT] JSON сохранён: {output_path}")
        return output_path

    # ──────────────────────────────────────────────
    #  HTML
    # ──────────────────────────────────────────────
    def generate_html(self, output_path: str) -> str:
        """Генерация полного HTML-отчёта."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        feasible = [r for r in self.results if self._is_feasible(r)]
        not_feasible = [r for r in self.results if self._is_not_feasible(r)]
        other = [r for r in self.results if r not in feasible and r not in not_feasible]
        ts = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        hostname = self.system_summary.get("hostname", "Неизвестно")
        os_name = self.system_summary.get("os", "Неизвестно")
        ip_list = ", ".join(self.system_summary.get("ip_addresses", []))
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Отчёт безопасности — {_esc(hostname)} — {ts}</title>
{self._css()}
</head>
<body>
<div class="container">
  {self._header(ts, hostname, os_name, ip_list, feasible, not_feasible)}
  {self._nav_tabs()}
  <!-- ─── Схема 1: Реализуемые атаки ─── -->
  <div class="tab-content active" id="tab-feasible">
    {self._section_feasible(feasible)}
  </div>
  <!-- ─── Схема 2: Нереализуемые атаки ─── -->
  <div class="tab-content" id="tab-not-feasible">
    {self._section_not_feasible(not_feasible)}
  </div>
  <!-- ─── Схема 3: Сравнение уязвимостей ─── -->
  <div class="tab-content" id="tab-compare">
    {self._section_comparison()}
  </div>
  <!-- ─── Схема 4: Уязвимости и как их устранить ─── -->
  <div class="tab-content" id="tab-defense">
    {self._section_defense(feasible + other)}
  </div>
  <!-- ─── Схема 5: Уязвимости и как их использовать ─── -->
  <div class="tab-content" id="tab-attack">
    {self._section_attack(feasible)}
  </div>
  {self._footer(ts)}
</div>
{self._js()}
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"[REPORT] HTML сохранён: {output_path}")
        return output_path

    # ──────────────────────────────────────────────
    #  Вспомогательные методы
    # ──────────────────────────────────────────────
    def _is_feasible(self, r) -> bool:
        feas = self._get(r, "feasibility")
        return "РЕАЛИЗУЕМА" in str(feas) and "НЕ" not in str(feas)

    def _is_not_feasible(self, r) -> bool:
        feas = self._get(r, "feasibility")
        return "НЕ РЕАЛИЗУЕМА" in str(feas)

    def _get(self, r, field: str, default="") -> str:
        if hasattr(r, field):
            return getattr(r, field, default) or default
        elif isinstance(r, dict):
            return r.get(field, default) or default
        return default

    # ──────────────────────────────────────────────
    #  CSS
    # ──────────────────────────────────────────────
    def _css(self) -> str:
        return """<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface2: #21262d;
  --border: #30363d;
  --text: #c9d1d9;
  --text-dim: #8b949e;
  --accent: #58a6ff;
  --red: #f85149;
  --green: #3fb950;
  --yellow: #d29922;
  --orange: #db6d28;
  --purple: #bc8cff;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }
.container { max-width: 1400px; margin: 0 auto; padding: 24px 16px; }
/* Header */
.report-header { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 28px 32px; margin-bottom: 24px; }
.report-header h1 { font-size: 26px; font-weight: 700; color: var(--accent); margin-bottom: 16px; }
.header-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 20px; }
.header-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; }
.header-card .label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }
.header-card .value { font-size: 15px; font-weight: 600; margin-top: 4px; }
.stat-chips { display: flex; gap: 10px; flex-wrap: wrap; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 20px; font-size: 13px; font-weight: 600; border: 1px solid; }
.chip-red { color: var(--red); border-color: var(--red); background: rgba(248,81,73,0.1); }
.chip-green { color: var(--green); border-color: var(--green); background: rgba(63,185,80,0.1); }
.chip-blue { color: var(--accent); border-color: var(--accent); background: rgba(88,166,255,0.1); }
/* Tabs */
.tabs-nav { display: flex; gap: 4px; margin-bottom: 16px; flex-wrap: wrap; }
.tab-btn { padding: 10px 20px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text-dim); cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s; }
.tab-btn:hover { color: var(--text); border-color: var(--accent); }
.tab-btn.active { background: var(--accent); color: #000; border-color: var(--accent); font-weight: 700; }
.tab-content { display: none; }
.tab-content.active { display: block; }
/* Cards */
.section-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }
.vuln-grid { display: grid; gap: 12px; }
.vuln-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; border-left: 4px solid; transition: border-color 0.2s; }
.vuln-card:hover { border-color: var(--accent) !important; }
.vuln-card-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
.vuln-title { font-size: 15px; font-weight: 700; }
.badges { display: flex; gap: 6px; flex-wrap: wrap; }
.badge { padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; letter-spacing: 0.3px; }
.badge-cve { background: rgba(88,166,255,0.15); color: var(--accent); border: 1px solid rgba(88,166,255,0.3); }
.badge-sev { color: #fff; }
.badge-feas { color: #fff; font-size: 10px; }
.vuln-desc { color: var(--text-dim); margin-bottom: 10px; font-size: 13px; }
.meta-row { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px; color: var(--text-dim); margin-bottom: 8px; }
.meta-item { display: flex; align-items: center; gap: 4px; }
.expand-btn { background: none; border: 1px solid var(--border); border-radius: 6px; color: var(--text-dim); cursor: pointer; padding: 4px 10px; font-size: 11px; margin-top: 6px; }
.expand-btn:hover { color: var(--text); border-color: var(--accent); }
.detail-block { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); display: none; }
.detail-block.open { display: block; }
.detail-label { font-size: 11px; text-transform: uppercase; color: var(--text-dim); letter-spacing: 0.5px; margin-bottom: 4px; margin-top: 10px; }
.detail-value { font-size: 13px; color: var(--text); }
.recommendation-box { background: rgba(63,185,80,0.08); border: 1px solid rgba(63,185,80,0.25); border-radius: 8px; padding: 10px 14px; margin-top: 8px; font-size: 13px; color: var(--green); }
.reason-box { background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.2); border-radius: 8px; padding: 10px 14px; margin-top: 8px; font-size: 13px; color: #e06c75; }
/* Empty state */
.empty-state { text-align: center; padding: 60px 20px; color: var(--text-dim); }
.empty-state .icon { font-size: 48px; margin-bottom: 16px; }
/* Table */
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.data-table th { background: var(--surface2); color: var(--text-dim); padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
.data-table td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
.data-table tr:last-child td { border-bottom: none; }
.data-table tr:hover td { background: var(--surface2); }
/* Compare section */
.compare-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 768px) { .compare-grid { grid-template-columns: 1fr; } }
.compare-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.compare-card h3 { font-size: 14px; font-weight: 700; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
/* Footer */
.report-footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); text-align: center; color: var(--text-dim); font-size: 12px; }
/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }
</style>"""

    # ──────────────────────────────────────────────
    #  Header
    # ──────────────────────────────────────────────
    def _header(self, ts, hostname, os_name, ip_list, feasible, not_feasible) -> str:
        total = len(self.results)
        f_cnt = len(feasible)
        nf_cnt = len(not_feasible)
        return f"""
<div class="report-header">
  <h1>🔒 Отчёт оценки безопасности</h1>
  <div class="header-grid">
    <div class="header-card">
      <div class="label">Хост</div>
      <div class="value">{_esc(hostname)}</div>
    </div>
    <div class="header-card">
      <div class="label">Операционная система</div>
      <div class="value">{_esc(os_name)}</div>
    </div>
    <div class="header-card">
      <div class="label">IP-адреса</div>
      <div class="value">{_esc(ip_list) or "—"}</div>
    </div>
    <div class="header-card">
      <div class="label">Дата анализа</div>
      <div class="value">{_esc(ts)}</div>
    </div>
  </div>
  <div class="stat-chips">
    <div class="chip chip-blue">📊 Всего результатов: {total}</div>
    <div class="chip chip-red">🔴 Реализуемых атак: {f_cnt}</div>
    <div class="chip chip-green">🟢 Нереализуемых: {nf_cnt}</div>
  </div>
</div>"""

    # ──────────────────────────────────────────────
    #  Nav tabs
    # ──────────────────────────────────────────────
    def _nav_tabs(self) -> str:
        return """
<div class="tabs-nav">
  <button class="tab-btn active" onclick="switchTab('tab-feasible', this)">🔴 Реализуемые атаки</button>
  <button class="tab-btn" onclick="switchTab('tab-not-feasible', this)">🟢 Нереализуемые атаки</button>
  <button class="tab-btn" onclick="switchTab('tab-compare', this)">📊 Сравнение уязвимостей</button>
  <button class="tab-btn" onclick="switchTab('tab-defense', this)">🛡️ Меры защиты</button>
  <button class="tab-btn" onclick="switchTab('tab-attack', this)">⚔️ Инструменты атаки</button>
</div>"""

    # ──────────────────────────────────────────────
    #  Секция 1: Реализуемые атаки
    # ──────────────────────────────────────────────
    def _section_feasible(self, feasible: list) -> str:
        if not feasible:
            return """
<div class="empty-state">
  <div class="icon">✅</div>
  <h3>Реализуемых атак не обнаружено</h3>
  <p>Все проверенные векторы атак не реализуемы в текущей конфигурации.</p>
</div>"""
        cards = ""
        for r in feasible:
            cards += self._vuln_card(r, border_color="#e74c3c")
        return f"""
<div class="section-title">🔴 Реализуемые атаки ({len(feasible)})</div>
<div class="vuln-grid">{cards}</div>"""

    # ──────────────────────────────────────────────
    #  Секция 2: Нереализуемые атаки
    # ──────────────────────────────────────────────
    def _section_not_feasible(self, not_feasible: list) -> str:
        if not not_feasible:
            return """
<div class="empty-state">
  <div class="icon">⚠️</div>
  <h3>Нереализуемых атак не найдено</h3>
  <p>Все обнаруженные векторы требуют дополнительного анализа.</p>
</div>"""
        cards = ""
        for r in not_feasible:
            cards += self._vuln_card(r, border_color="#27ae60")
        return f"""
<div class="section-title">🟢 Нереализуемые атаки ({len(not_feasible)})</div>
<div class="vuln-grid">{cards}</div>"""

    # ──────────────────────────────────────────────
    #  Карточка уязвимости
    # ──────────────────────────────────────────────
    def _vuln_card(self, r, border_color="#888") -> str:
        cve_id = _esc(self._get(r, "cve_id", "—"))
        cwe_id = _esc(self._get(r, "cwe_id", "—"))
        capec = _esc(self._get(r, "capec_id", "—"))
        mitre = _esc(self._get(r, "mitre_technique", "—"))
        name = _esc(self._get(r, "attack_name", "Неизвестная атака"))
        desc = _esc(self._get(r, "description", ""))
        sev = self._get(r, "severity", "INFO")
        feas = self._get(r, "feasibility", "")
        reason = _esc(self._get(r, "reason", ""))
        rec = _esc(self._get(r, "recommendation", ""))
        sev_col = _sev_color(sev)
        feas_col = _feas_color(feas)
        uid = abs(hash(f"{cve_id}{name}"))
        reason_html = f'<div class="reason-box">⚠️ {reason}</div>' if reason else ""
        rec_html = f'<div class="recommendation-box">✅ {rec}</div>' if rec else ""
        return f"""
<div class="vuln-card" style="border-left-color:{border_color}">
  <div class="vuln-card-header">
    <div class="vuln-title">{name}</div>
    <div class="badges">
      <span class="badge badge-cve">{cve_id}</span>
      <span class="badge badge-sev" style="background:{sev_col}">{_esc(sev)}</span>
      <span class="badge badge-feas" style="background:{feas_col}">{_esc(feas)}</span>
    </div>
  </div>
  <div class="vuln-desc">{desc}</div>
  <div class="meta-row">
    <span class="meta-item">🔷 CWE: {cwe_id}</span>
    <span class="meta-item">🎯 CAPEC: {capec}</span>
    <span class="meta-item">🗂 MITRE: {mitre}</span>
  </div>
  <button class="expand-btn" onclick="toggleDetail('detail-{uid}', this)">▼ Подробнее</button>
  <div class="detail-block" id="detail-{uid}">
    {reason_html}
    {rec_html}
    <div class="detail-label">CVE ID</div>
    <div class="detail-value">{cve_id}</div>
    <div class="detail-label">CWE</div>
    <div class="detail-value">{cwe_id}</div>
    <div class="detail-label">CAPEC</div>
    <div class="detail-value">{capec}</div>
    <div class="detail-label">MITRE ATT&CK</div>
    <div class="detail-value">{mitre}</div>
  </div>
</div>"""

    # ──────────────────────────────────────────────
    #  Секция 3: Сравнение уязвимостей
    # ──────────────────────────────────────────────
    def _section_comparison(self) -> str:
        sys_info = self.system_summary
        attacker = self.attacker_data

        # Порты сервера
        srv_ports = sys_info.get("open_ports", [])
        # Порты атакующего
        atk_ports = attacker.get("open_ports", [])

        def fmt_ports(ports):
            if not ports:
                return "<em style='color:var(--text-dim)'>нет данных</em>"
            rows = ""
            for p in ports[:30]:
                if isinstance(p, dict):
                    port = p.get("port", "?")
                    svc = p.get("service", "")
                    banner = p.get("banner", "")
                    rows += f"<tr><td>{port}</td><td>{_esc(svc)}</td><td>{_esc(banner[:60])}</td></tr>"
                else:
                    rows += f"<tr><td colspan='3'>{_esc(str(p))}</td></tr>"
            return f"""<table class="data-table">
              <thead><tr><th>Порт</th><th>Сервис</th><th>Баннер</th></tr></thead>
              <tbody>{rows}</tbody></table>"""

        # Векторы атак
        atk_vectors = attacker.get("attack_vectors", [])
        vec_rows = ""
        for v in atk_vectors[:20]:
            if isinstance(v, dict):
                vec_rows += f"""<tr>
                  <td>{_esc(str(v.get('id', '')))}</td>
                  <td>{_esc(str(v.get('name', '')))}</td>
                  <td>{_esc(str(v.get('severity', '')))}</td>
                  <td>{_esc(str(v.get('target_service', '')))}</td>
                </tr>"""
        vectors_table = f"""<table class="data-table">
          <thead><tr><th>ID</th><th>Название</th><th>Серьёзность</th><th>Сервис</th></tr></thead>
          <tbody>{vec_rows if vec_rows else '<tr><td colspan=4><em>нет данных</em></td></tr>'}</tbody>
        </table>""" if vec_rows else "<em style='color:var(--text-dim)'>нет данных</em>"

        # Локальный скан
        local_html = ""
        if self.local_scan:
            findings = getattr(self.local_scan, "findings", [])
            vuln_count = sum(1 for f in findings if getattr(f, "status", "") == "VULNERABLE")
            secure_count = sum(1 for f in findings if getattr(f, "status", "") == "SECURE")
            risk = getattr(self.local_scan, "risk_score", 0)
            local_html = f"""
<div class="compare-card" style="margin-top:16px;grid-column:1/-1">
  <h3>🔍 Локальный скан уязвимостей</h3>
  <div class="stat-chips" style="margin-bottom:12px">
    <div class="chip chip-red">Уязвимо: {vuln_count}</div>
    <div class="chip chip-green">Защищено: {secure_count}</div>
    <div class="chip chip-blue">Риск-оценка: {risk:.1f}/100</div>
  </div>
</div>"""

        return f"""
<div class="section-title">📊 Сравнение уязвимостей (сервер vs атакующий)</div>
<div class="compare-grid">
  <div class="compare-card">
    <h3>🖥️ Открытые порты сервера</h3>
    {fmt_ports(srv_ports)}
  </div>
  <div class="compare-card">
    <h3>🎯 Открытые порты (обнаружены атакующим)</h3>
    {fmt_ports(atk_ports)}
  </div>
  <div class="compare-card" style="grid-column:1/-1">
    <h3>⚔️ Векторы атак от атакующего агента</h3>
    {vectors_table}
  </div>
  {local_html}
</div>"""

    # ──────────────────────────────────────────────
    #  Секция 4: Меры защиты
    # ──────────────────────────────────────────────
    def _section_defense(self, items: list) -> str:
        if not items:
            return """
<div class="empty-state">
  <div class="icon">🛡️</div>
  <h3>Нет данных для рекомендаций</h3>
</div>"""
        rows = ""
        seen_recs = set()
        for r in items:
            rec = self._get(r, "recommendation", "")
            if not rec or rec in seen_recs:
                continue
            seen_recs.add(rec)
            cve = self._get(r, "cve_id", "—")
            name = self._get(r, "attack_name", "—")
            sev = self._get(r, "severity", "INFO")
            sev_col = _sev_color(sev)
            rows += f"""<tr>
              <td><span class="badge badge-cve">{_esc(cve)}</span></td>
              <td>{_esc(name)}</td>
              <td><span class="badge badge-sev" style="background:{sev_col}">{_esc(sev)}</span></td>
              <td style="color:var(--green)">{_esc(rec)}</td>
            </tr>"""

        # Меры из toolkit
        toolkit_html = ""
        if self.toolkit:
            defenses = getattr(self.toolkit, "defense_measures", [])
            if defenses:
                def_rows = ""
                for d in defenses:
                    if isinstance(d, dict):
                        def_rows += f"""<tr>
                          <td>{_esc(str(d.get('name', '')))}</td>
                          <td>{_esc(str(d.get('category', '')))}</td>
                          <td>{_esc(str(d.get('description', '')))}</td>
                          <td style="color:var(--green)">{_esc(str(d.get('command', '')))}</td>
                        </tr>"""
                toolkit_html = f"""
<div class="section-title" style="margin-top:24px">🛠️ Инструменты защиты (из базы)</div>
<table class="data-table">
  <thead><tr><th>Инструмент</th><th>Категория</th><th>Описание</th><th>Команда</th></tr></thead>
  <tbody>{def_rows}</tbody>
</table>"""

        return f"""
<div class="section-title">🛡️ Рекомендации по защите</div>
<table class="data-table">
  <thead><tr><th>CVE</th><th>Атака</th><th>Серьёзность</th><th>Рекомендация</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan=4><em style="color:var(--text-dim)">Нет рекомендаций</em></td></tr>'}</tbody>
</table>
{toolkit_html}"""

    # ──────────────────────────────────────────────
    #  Секция 5: Инструменты атаки
    # ──────────────────────────────────────────────
    def _section_attack(self, feasible: list) -> str:
        toolkit_html = ""
        if self.toolkit:
            tools = getattr(self.toolkit, "attack_tools", [])
            if tools:
                tool_rows = ""
                for t in tools:
                    if isinstance(t, dict):
                        tool_rows += f"""<tr>
                          <td>{_esc(str(t.get('name', '')))}</td>
                          <td>{_esc(str(t.get('category', '')))}</td>
                          <td>{_esc(str(t.get('description', '')))}</td>
                          <td><code style="color:var(--orange);font-size:11px">{_esc(str(t.get('command', '')))}</code></td>
                          <td>{_esc(str(t.get('target_cve', '')))}</td>
                        </tr>"""
                toolkit_html = f"""
<div class="section-title" style="margin-top:24px">🛠️ База инструментов атаки</div>
<table class="data-table">
  <thead><tr><th>Инструмент</th><th>Категория</th><th>Описание</th><th>Команда</th><th>CVE</th></tr></thead>
  <tbody>{tool_rows}</tbody>
</table>"""

        if not feasible and not toolkit_html:
            return """
<div class="empty-state">
  <div class="icon">⚔️</div>
  <h3>Нет реализуемых атак для отображения</h3>
</div>"""

        rows = ""
        for r in feasible:
            cve = self._get(r, "cve_id", "—")
            name = self._get(r, "attack_name", "—")
            sev = self._get(r, "severity", "INFO")
            sev_col = _sev_color(sev)
            reason = self._get(r, "reason", "")
            rows += f"""<tr>
              <td><span class="badge badge-cve">{_esc(cve)}</span></td>
              <td>{_esc(name)}</td>
              <td><span class="badge badge-sev" style="background:{sev_col}">{_esc(sev)}</span></td>
              <td style="color:var(--red);font-size:12px">{_esc(reason)}</td>
            </tr>"""

        return f"""
<div class="section-title">⚔️ Реализуемые векторы атак</div>
<table class="data-table">
  <thead><tr><th>CVE</th><th>Атака</th><th>Серьёзность</th><th>Причина реализуемости</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan=4><em style="color:var(--text-dim)">Нет данных</em></td></tr>'}</tbody>
</table>
{toolkit_html}"""

    # ──────────────────────────────────────────────
    #  Footer
    # ──────────────────────────────────────────────
    def _footer(self, ts: str) -> str:
        return f"""
<div class="report-footer">
  <p>Сгенерировано: {_esc(ts)} · Система оценки безопасности · Только для авторизованных учений</p>
</div>"""

    # ──────────────────────────────────────────────
    #  JavaScript
    # ──────────────────────────────────────────────
    def _js(self) -> str:
        return """<script>
function switchTab(id, btn) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}
function toggleDetail(id, btn) {
  const el = document.getElementById(id);
  el.classList.toggle('open');
  btn.textContent = el.classList.contains('open') ? '▲ Скрыть' : '▼ Подробнее';
}
</script>"""
