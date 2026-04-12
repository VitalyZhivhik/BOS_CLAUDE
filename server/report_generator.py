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
            "feasible": [to_dict(r) for r in self.results
                         if "НЕ" not in str(getattr(r, "feasibility", r.get("feasibility", "")) if hasattr(r, "feasibility") else r.get("feasibility", ""))
                         and "РЕАЛИЗУЕМА" in str(getattr(r, "feasibility", r.get("feasibility", "")) if hasattr(r, "feasibility") else r.get("feasibility", ""))],
            "not_feasible": [to_dict(r) for r in self.results
                             if "НЕ РЕАЛИЗУЕМА" in str(getattr(r, "feasibility", r.get("feasibility", "")) if hasattr(r, "feasibility") else r.get("feasibility", ""))],
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
.report-header h1 { font-size: 26px; font-weight: 700; color: var(--accent); margin-bottom: 6px; }
.report-header .subtitle { color: var(--text-dim); font-size: 13px; margin-bottom: 20px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-top: 20px; }
.stat-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; text-align: center; }
.stat-card .val { font-size: 28px; font-weight: 700; }
.stat-card .lbl { color: var(--text-dim); font-size: 11px; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-red .val { color: var(--red); }
.stat-green .val { color: var(--green); }
.stat-yellow .val { color: var(--yellow); }
.stat-blue .val { color: var(--accent); }
.stat-purple .val { color: var(--purple); }
/* Info grid */
.info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; margin-top: 16px; }
.info-item { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; }
.info-item .key { color: var(--text-dim); font-size: 11px; text-transform: uppercase; }
.info-item .val { font-size: 13px; font-weight: 600; color: var(--text); margin-top: 2px; word-break: break-all; }
/* Tabs */
.tab-nav { display: flex; gap: 4px; border-bottom: 2px solid var(--border); margin-bottom: 24px; overflow-x: auto; padding-bottom: 0; flex-wrap: nowrap; }
.tab-btn { background: none; border: none; color: var(--text-dim); padding: 10px 18px; cursor: pointer; font-size: 13px; font-weight: 600; border-bottom: 2px solid transparent; margin-bottom: -2px; white-space: nowrap; transition: all 0.2s; border-radius: 6px 6px 0 0; }
.tab-btn:hover { color: var(--text); background: var(--surface2); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); background: var(--surface); }
.tab-content { display: none; }
.tab-content.active { display: block; }
/* Section title */
.section-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
.section-desc { color: var(--text-dim); font-size: 13px; margin-bottom: 20px; background: var(--surface2); border-left: 3px solid var(--accent); padding: 10px 14px; border-radius: 0 6px 6px 0; }
/* Cards */
.vuln-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 16px; overflow: hidden; transition: border-color 0.2s; }
.vuln-card:hover { border-color: var(--accent); }
.vuln-card.feasible { border-left: 4px solid var(--red); }
.vuln-card.not-feasible { border-left: 4px solid var(--green); }
.vuln-card.defense-card { border-left: 4px solid var(--accent); }
.vuln-card.attack-card { border-left: 4px solid var(--orange); }
.card-header { display: flex; align-items: center; gap: 12px; padding: 14px 18px; cursor: pointer; }
.card-header:hover { background: var(--surface2); }
.badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; color: #fff; }
.card-title { font-weight: 600; font-size: 14px; flex: 1; }
.card-cve { font-family: monospace; font-size: 12px; color: var(--text-dim); }
.expand-icon { color: var(--text-dim); font-size: 18px; transition: transform 0.2s; user-select: none; }
.expanded .expand-icon { transform: rotate(180deg); }
.card-body { display: none; padding: 0 18px 18px; border-top: 1px solid var(--border); }
.card-body.open { display: block; }
/* Card body content */
.meta-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 14px 0; }
.meta-item { background: var(--surface2); border-radius: 6px; padding: 8px 12px; }
.meta-item .mk { color: var(--text-dim); font-size: 11px; text-transform: uppercase; }
.meta-item .mv { font-size: 12px; font-weight: 600; margin-top: 2px; font-family: monospace; }
.desc-block { margin-top: 12px; }
.desc-block h4 { color: var(--accent); font-size: 12px; text-transform: uppercase; margin-bottom: 6px; }
.desc-block p { color: var(--text-dim); font-size: 13px; line-height: 1.6; }
.reason-block { background: var(--surface2); border-radius: 6px; padding: 10px 14px; margin-top: 10px; font-size: 13px; color: var(--text-dim); }
.reason-block strong { color: var(--text); }
/* Code blocks */
.code-block { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 14px; margin-top: 10px; overflow-x: auto; }
.code-block pre { font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; color: #c9d1d9; white-space: pre-wrap; word-break: break-word; line-height: 1.7; }
.code-block pre .comment { color: #8b949e; }
.code-block pre .cmd { color: #79c0ff; }
.code-line { display: block; }
.code-line.comment-line { color: #8b949e; }
.code-line.cmd-line { color: #79c0ff; }
/* Tool card */
.tool-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-top: 10px; }
.tool-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.tool-name { font-weight: 700; font-size: 14px; }
.tool-type-badge { font-size: 10px; padding: 2px 6px; border-radius: 3px; background: var(--surface); border: 1px solid var(--border); color: var(--text-dim); }
.tool-desc { color: var(--text-dim); font-size: 12px; margin-bottom: 10px; }
.tool-meta { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
.tool-meta span { font-size: 11px; background: var(--surface); border-radius: 3px; padding: 2px 6px; color: var(--text-dim); }
.tool-link { color: var(--accent); font-size: 11px; text-decoration: none; }
.tool-link:hover { text-decoration: underline; }
/* Comparison schema */
.compare-grid { display: grid; grid-template-columns: 1fr 60px 1fr; gap: 0; margin: 20px 0; align-items: start; }
.compare-col { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.compare-col-header { padding: 14px 16px; font-weight: 700; font-size: 14px; text-align: center; }
.compare-col-header.server-header { background: rgba(88,166,255,0.1); color: var(--accent); }
.compare-col-header.attacker-header { background: rgba(248,81,73,0.1); color: var(--red); }
.compare-col-body { padding: 8px; }
.compare-item { padding: 8px 10px; border-radius: 6px; margin-bottom: 4px; font-size: 12px; background: var(--surface2); border: 1px solid var(--border); }
.compare-item .ci-id { font-family: monospace; font-weight: 700; color: var(--text); }
.compare-item .ci-desc { color: var(--text-dim); font-size: 11px; margin-top: 2px; }
.compare-center { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px 4px; gap: 8px; }
.overlap-badge { background: rgba(63,185,80,0.2); border: 1px solid var(--green); color: var(--green); border-radius: 50%; width: 50px; height: 50px; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; text-align: center; line-height: 1.2; }
.compare-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin-top: 16px; }
.compare-stat { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px; text-align: center; }
.compare-stat .cs-val { font-size: 22px; font-weight: 700; }
.compare-stat .cs-lbl { color: var(--text-dim); font-size: 11px; }
.both-section { background: var(--surface); border: 1px solid var(--green); border-radius: 10px; padding: 16px; margin-top: 16px; }
.both-section h3 { color: var(--green); margin-bottom: 12px; font-size: 14px; }
.both-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; background: var(--surface2); border-radius: 6px; margin-bottom: 6px; }
.both-check { color: var(--green); font-size: 16px; }
/* Empty state */
.empty-state { text-align: center; padding: 48px 24px; color: var(--text-dim); }
.empty-state .icon { font-size: 48px; margin-bottom: 12px; }
.empty-state p { font-size: 14px; }
/* Priority badges */
.priority-critical { background: var(--red); }
.priority-high { background: var(--orange); }
.priority-medium { background: var(--yellow); }
.priority-low { background: var(--green); }
.priority-info { background: var(--accent); }
/* Defense tool */
.defense-tool { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-top: 8px; }
.defense-tool h5 { color: var(--accent); font-size: 12px; margin-bottom: 6px; }
.defense-tool p { color: var(--text-dim); font-size: 12px; margin-bottom: 8px; }
.effort-bar { display: flex; gap: 6px; align-items: center; font-size: 11px; color: var(--text-dim); margin-bottom: 8px; }
.effort-dot { width: 8px; height: 8px; border-radius: 50%; }
/* Step list */
.step-list { counter-reset: steps; }
.step-item { counter-increment: steps; display: flex; gap: 12px; margin-bottom: 12px; }
.step-num { background: var(--accent); color: #000; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 11px; flex-shrink: 0; margin-top: 2px; }
.step-body { flex: 1; }
.step-title { font-weight: 600; font-size: 13px; margin-bottom: 4px; }
.step-desc { color: var(--text-dim); font-size: 12px; }
/* Warning banner */
.warning-banner { background: rgba(248,81,73,0.1); border: 1px solid var(--red); border-radius: 8px; padding: 12px 16px; margin-bottom: 20px; display: flex; align-items: flex-start; gap: 10px; }
.warning-banner .wi { font-size: 20px; flex-shrink: 0; }
.warning-banner .wt { font-size: 13px; color: var(--text-dim); }
.warning-banner strong { color: var(--red); }
/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }
/* Responsive */
@media (max-width: 768px) {
  .compare-grid { grid-template-columns: 1fr; }
  .compare-center { flex-direction: row; padding: 10px; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>"""
    # ──────────────────────────────────────────────
    #  Header
    # ──────────────────────────────────────────────
    def _header(self, ts, hostname, os_name, ip_list, feasible, not_feasible) -> str:
        total = len(self.results)
        crit = sum(1 for r in self.results if str(self._get(r, "severity")).upper() == "CRITICAL")
        high = sum(1 for r in self.results if str(self._get(r, "severity")).upper() == "HIGH")
        medium = sum(1 for r in self.results if str(self._get(r, "severity")).upper() == "MEDIUM")
        return f"""
<div class="report-header">
  <h1>🔒 Отчёт анализа безопасности</h1>
  <p class="subtitle">Создан: {ts} | Хост: {_esc(hostname)} | ОС: {_esc(os_name)}</p>
  <div class="info-grid">
    <div class="info-item"><div class="key">Хост</div><div class="val">{_esc(hostname)}</div></div>
    <div class="info-item"><div class="key">ОС</div><div class="val">{_esc(os_name)}</div></div>
    <div class="info-item"><div class="key">IP-адреса</div><div class="val">{_esc(ip_list or "—")}</div></div>
    <div class="info-item"><div class="key">Дата анализа</div><div class="val">{ts}</div></div>
  </div>
  <div class="stats-grid" style="margin-top:20px">
    <div class="stat-card stat-blue"><div class="val">{total}</div><div class="lbl">Всего записей</div></div>
    <div class="stat-card stat-red"><div class="val">{len(feasible)}</div><div class="lbl">Реализуемых атак</div></div>
    <div class="stat-card stat-green"><div class="val">{len(not_feasible)}</div><div class="lbl">Нереализуемых</div></div>
    <div class="stat-card stat-red"><div class="val">{crit}</div><div class="lbl">CRITICAL</div></div>
    <div class="stat-card stat-yellow"><div class="val">{high}</div><div class="lbl">HIGH</div></div>
    <div class="stat-card stat-purple"><div class="val">{medium}</div><div class="lbl">MEDIUM</div></div>
  </div>
</div>"""
    # ──────────────────────────────────────────────
    #  Navigation Tabs
    # ──────────────────────────────────────────────
    def _nav_tabs(self) -> str:
        tabs = [
            ("tab-feasible", "🔴 Реализуемые атаки", True),
            ("tab-not-feasible", "🟢 Нереализуемые атаки", False),
            ("tab-compare", "⚖️ Сравнение уязвимостей", False),
            ("tab-defense", "🛡️ Как устранить", False),
            ("tab-attack", "⚔️ Как атаковать (учебные цели)", False),
        ]
        btns = ""
        for tid, label, active in tabs:
            cls = "tab-btn active" if active else "tab-btn"
            btns += f'<button class="{cls}" data-tab="{tid}">{label}</button>\n'
        return f'<nav class="tab-nav">{btns}</nav>'
    # ──────────────────────────────────────────────
    #  Схема 1: Реализуемые атаки
    # ──────────────────────────────────────────────
    def _section_feasible(self, feasible: list) -> str:
        html = f"""
<h2 class="section-title">🔴 Схема 1: Реализуемые атаки</h2>
<div class="section-desc">
Атаки, которые <strong>могут б��ть проведены</strong> в текущей конфигурации сервера.
Каждая запись содержит идентификаторы CVE/CWE/CAPEC/MITRE ATT&CK, уровень серьёзности и рекомендации.
</div>
"""
        if not feasible:
            return html + '<div class="empty-state"><div class="icon">✅</div><p>Реализуемых атак не обнаружено. Конфигурация сервера защищена!</p></div>'
        for r in feasible:
            html += self._vuln_card(r, "feasible")
        return html
    # ──────────────────────────────────────────────
    #  Схема 2: Нереализуемые атаки
    # ──────────────────────────────────────────────
    def _section_not_feasible(self, not_feasible: list) -> str:
        html = f"""
<h2 class="section-title">🟢 Схема 2: Нереализуемые атаки</h2>
<div class="section-desc">
Атаки, которые <strong>не могут быть проведены</strong> в текущей конфигурации —
отсутствует необходимый сервис, порт закрыт или защита активна.
</div>
"""
        if not not_feasible:
            return html + '<div class="empty-state"><div class="icon">ℹ️</div><p>Все обнаруженные уязвимости являются реализуемыми.</p></div>'
        for r in not_feasible:
            html += self._vuln_card(r, "not-feasible")
        return html
    # ──────────────────────────────────────────────
    #  Схема 3: Сравнение уязвимостей
    # ──────────────────────────────────────────────
    def _section_comparison(self) -> str:
        html = """
<h2 class="section-title">⚖️ Схема 3: Сравнение уязвимостей</h2>
<div class="section-desc">
  Сравнение уязвимостей, <strong>найденных на сервере</strong> (локальное сканирование) и
  <strong>найденных атакующим</strong> (внешнее сканирование).
  Пересечение показывает наиболее критичные уязвимости — они видны с обеих сторон.
</div>
"""
        # Уязвимости со стороны сервера (из результатов корреляции)
        server_vulns = []
        for r in self.results:
            cve = self._get(r, "cve_id")
            desc = self._get(r, "description")
            sev = self._get(r, "severity")
            if cve:
                server_vulns.append({"cve_id": cve, "description": desc, "severity": sev})
        # Уязвимости со стороны атакующего
        attacker_vulns = []
        for av in self.attacker_data.get("attack_vectors", []):
            if isinstance(av, dict):
                cve = av.get("cve_id", "")
                if not cve:
                    # Используем ID вектора атаки как условный идентификатор
                    cve = av.get("id", "")
                if cve:
                    attacker_vulns.append({
                        "cve_id": cve,
                        "description": av.get("name", av.get("description", "")),
                        "severity": av.get("severity", "MEDIUM"),
                    })
        # Если нет данных атакующего — показываем все результаты как реализуемые
        if not attacker_vulns:
            attacker_vulns = [{"cve_id": self._get(r, "cve_id"),
                                "description": self._get(r, "attack_name"),
                                "severity": self._get(r, "severity")}
                               for r in self.results if self._is_feasible(r)]
        server_ids = {v["cve_id"] for v in server_vulns if v["cve_id"]}
        attacker_ids = {v["cve_id"] for v in attacker_vulns if v["cve_id"]}
        both_ids = server_ids & attacker_ids
        only_server = [v for v in server_vulns if v["cve_id"] in (server_ids - attacker_ids)]
        only_attacker = [v for v in attacker_vulns if v["cve_id"] in (attacker_ids - server_ids)]
        both_vulns = [v for v in server_vulns if v["cve_id"] in both_ids]
        overlap_pct = round(len(both_ids) / max(len(server_ids | attacker_ids), 1) * 100, 1)
        # Статистика
        html += f"""
<div class="compare-stats">
  <div class="compare-stat"><div class="cs-val" style="color:var(--accent)">{len(server_ids)}</div><div class="cs-lbl">Уязвимостей на сервере</div></div>
  <div class="compare-stat"><div class="cs-val" style="color:var(--red)">{len(attacker_ids)}</div><div class="cs-lbl">Найдено атакующим</div></div>
  <div class="compare-stat"><div class="cs-val" style="color:var(--green)">{len(both_ids)}</div><div class="cs-lbl">Подтверждено обеими сторонами</div></div>
  <div class="compare-stat"><div class="cs-val" style="color:var(--yellow)">{overlap_pct}%</div><div class="cs-lbl">Процент совпадения</div></div>
</div>
"""
        # Визуальная схема сравнения
        server_col = self._compare_items(only_server, "Только сервер видит")
        attacker_col = self._compare_items(only_attacker, "Только атакующий нашёл")
        html += f"""
<div class="compare-grid" style="margin-top:20px">
  <div class="compare-col">
    <div class="compare-col-header server-header">🖥️ Сервер (локальный скан)</div>
    <div class="compare-col-body">{server_col}</div>
  </div>
  <div class="compare-center">
    <div class="overlap-badge">{len(both_ids)}<br>общих</div>
    <div style="width:2px;flex:1;background:var(--border);min-height:40px"></div>
    <div style="font-size:10px;color:var(--text-dim);text-align:center;writing-mode:vertical-rl;transform:rotate(180deg)">{overlap_pct}%</div>
  </div>
  <div class="compare-col">
    <div class="compare-col-header attacker-header">🎯 Атакующий (внешний скан)</div>
    <div class="compare-col-body">{attacker_col}</div>
  </div>
</div>
"""
        # Совпадающие уязвимости — самые опасные
        if both_vulns:
            items = ""
            for v in both_vulns:
                sev_color = _sev_color(v.get("severity", "MEDIUM"))
                items += f"""
<div class="both-item">
  <span class="both-check">✅</span>
  <span class="badge" style="background:{sev_color}">{_esc(v.get('severity','?'))}</span>
  <span style="font-family:monospace;font-weight:700">{_esc(v.get('cve_id',''))}</span>
  <span style="color:var(--text-dim);font-size:12px">{_esc(v.get('description','')[:80])}</span>
</div>"""
            html += f"""
<div class="both-section">
  <h3>⚠️ Уязвимости, подтверждённые обеими сторонами ({len(both_vulns)}) — наивысший приоритет устранения!</h3>
  {items}
</div>"""
        else:
            html += '<div class="empty-state" style="margin-top:20px"><div class="icon">🔍</div><p>Совпадений между сканированиями не обнаружено.</p></div>'
        return html
    def _compare_items(self, vulns: list, label: str) -> str:
        if not vulns:
            return f'<div style="color:var(--text-dim);font-size:12px;padding:10px;text-align:center">Нет уникальных уязвимостей</div>'
        out = ""
        for v in vulns[:20]:  # Ограничиваем для читаемости
            sev_color = _sev_color(v.get("severity", "MEDIUM"))
            out += f"""
<div class="compare-item">
  <div style="display:flex;gap:6px;align-items:center">
    <span class="badge" style="background:{sev_color};font-size:9px">{_esc(v.get('severity','?'))}</span>
    <span class="ci-id">{_esc(v.get('cve_id',''))}</span>
  </div>
  <div class="ci-desc">{_esc(v.get('description','')[:70])}</div>
</div>"""
        if len(vulns) > 20:
            out += f'<div style="color:var(--text-dim);font-size:11px;padding:6px;text-align:center">... и ещё {len(vulns)-20}</div>'
        return out
    # ──────────────────────────────────────────────
    #  Схема 4: Уязвимости и как их устранить
    # ──────────────────────────────────────────────
    def _section_defense(self, results: list) -> str:
        html = """
<h2 class="section-title">🛡️ Схема 4: Уязвимости и меры защиты</h2>
<div class="section-desc">
  Для каждой обнаруженной уязвимости показаны конкретные инструменты и команды для её <strong>устранения</strong>.
  Приоритеты расставлены по уровню серьёзности.
</div>
"""
        if not results:
            return html + '<div class="empty-state"><div class="icon">✅</div><p>Уязвимостей для отображения нет.</p></div>'
        # Группируем по серьёзности
        by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for r in results:
            sev = str(self._get(r, "severity")).upper()
            by_sev.get(sev, by_sev["INFO"]).append(r)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = by_sev[sev]
            if not items:
                continue
            sev_color = _sev_color(sev)
            html += f'<h3 style="color:{sev_color};margin:20px 0 12px;font-size:15px">{"⚫" if sev=="CRITICAL" else "🔴" if sev=="HIGH" else "🟡" if sev=="MEDIUM" else "🟢"} {sev} ({len(items)} уязвимостей)</h3>'
            for r in items:
                html += self._defense_card(r)
        return html
    def _defense_card(self, r) -> str:
        cve = self._get(r, "cve_id")
        name = self._get(r, "attack_name")
        sev = self._get(r, "severity")
        rec = self._get(r, "recommendation")
        desc = self._get(r, "description")
        cwe = self._get(r, "cwe_id")
        capec = self._get(r, "capec_id")
        sev_color = _sev_color(sev)
        card_id = f"def-{id(r)}"
        # Данные защиты из toolkit
        defense_tools_html = ""
        if self.toolkit:
            defense_tools = self.toolkit.get_defense_tools(cve)
            if not defense_tools:
                # Fallback по типу атаки
                attack_type = self._get(r, "attack_type", "")
                for def_item in self.toolkit.get_defense_for_attack_type(attack_type):
                    for tool in def_item.get("tools", []):
                        defense_tools.append({
                            "defense_name": def_item["name"],
                            "priority": def_item.get("priority", "MEDIUM"),
                            "tool_name": tool.get("name", ""),
                            "tool_description": tool.get("description", ""),
                            "commands": tool.get("commands", []),
                        })
            for dt in defense_tools[:3]:
                cmds = dt.get("commands", [])
                cmds_html = self._render_commands(cmds)
                priority = dt.get("priority", "MEDIUM")
                pcolor = _sev_color(priority)
                defense_tools_html += f"""
<div class="defense-tool">
  <h5>🔧 {_esc(dt.get('tool_name',''))} — {_esc(dt.get('defense_name',''))}</h5>
  <p>{_esc(dt.get('tool_description', dt.get('description', '')))}</p>
  <div class="effort-bar">
    <span class="effort-dot" style="background:{pcolor}"></span>
    Приоритет: <strong style="color:{pcolor}">{_esc(priority)}</strong>
  </div>
  {cmds_html}
</div>"""
        if not defense_tools_html and rec:
            defense_tools_html = f'<div class="reason-block"><strong>Рекомендация:</strong> {_esc(rec)}</div>'
        return f"""
<div class="vuln-card defense-card">
  <div class="card-header" onclick="toggleCard('{card_id}')">
    <span class="badge" style="background:{sev_color}">{_esc(sev)}</span>
    <span class="card-title">{_esc(name or cve)}</span>
    <span class="card-cve">{_esc(cve)}</span>
    <span class="expand-icon">▼</span>
  </div>
  <div class="card-body" id="{card_id}">
    <div class="meta-row">
      <div class="meta-item"><div class="mk">CVE</div><div class="mv">{_esc(cve)}</div></div>
      <div class="meta-item"><div class="mk">CWE</div><div class="mv">{_esc(cwe or '—')}</div></div>
      <div class="meta-item"><div class="mk">CAPEC</div><div class="mv">{_esc(capec or '—')}</div></div>
      <div class="meta-item"><div class="mk">Серьёзность</div><div class="mv" style="color:{sev_color}">{_esc(sev)}</div></div>
    </div>
    <div class="desc-block"><h4>📝 Описание</h4><p>{_esc(desc)}</p></div>
    <div class="desc-block" style="margin-top:14px">
      <h4>🛡️ Меры защиты и устранения</h4>
      {defense_tools_html if defense_tools_html else f'<p style="color:var(--text-dim)">{_esc(rec or "Применить обновления безопасности")}</p>'}
    </div>
  </div>
</div>"""
    # ──────────────────────────────────────────────
    #  Схема 5: Уязвимости и как атаковать
    # ──────────────────────────────────────────────
    def _section_attack(self, feasible: list) -> str:
        html = """
<div class="warning-banner">
  <span class="wi">⚠️</span>
  <div class="wt">
    <strong>УЧЕБНЫЕ ЦЕЛИ ТОЛЬКО!</strong> Данная информация предназначена исключительно для
    обучения специалистов по безопасности в рамках авторизованных Red Team / Blue Team учений.
    Использование против систем без явного разрешения является нарушением закона.
  </div>
</div>
<h2 class="section-title">⚔️ Схема 5: Инструменты и методы атак</h2>
<div class="section-desc">
  Для каждой <strong>реализуемой</strong> уязвимости показаны инструменты атаки, пошаговые команды
  и последовательность действий. Используйте только в учебных и авторизованных целях.
</div>
"""
        if not feasible:
            return html + '<div class="empty-state"><div class="icon">✅</div><p>Нет реализуемых атак для отображения инструментов.</p></div>'
        target_ip = self.attacker_data.get("target_ip", "<TARGET_IP>")
        for r in feasible:
            html += self._attack_card(r, target_ip)
        return html
    def _attack_card(self, r, target_ip: str) -> str:
        cve = self._get(r, "cve_id")
        name = self._get(r, "attack_name")
        sev = self._get(r, "severity")
        desc = self._get(r, "description")
        cwe = self._get(r, "cwe_id")
        capec = self._get(r, "capec_id")
        mitre = self._get(r, "mitre_technique")
        sev_color = _sev_color(sev)
        card_id = f"atk-{id(r)}"
        # Инструменты атаки из toolkit
        attack_tools_html = ""
        if self.toolkit:
            tools = self.toolkit.get_attack_commands(cve, target_ip)
            if not tools:
                attack_type = self._get(r, "attack_type", "")
                for tool in self.toolkit.get_tools_for_attack_type(attack_type):
                    cmds = tool.get("commands", {}).get("default", [])
                    if cmds:
                        tools.append({
                            "tool_name": tool["name"],
                            "tool_type": tool["type"],
                            "description": tool["description"],
                            "skill_level": tool.get("skill_level", "Unknown"),
                            "phases": tool.get("phases", []),
                            "commands": [c.replace("<TARGET_IP>", target_ip) if not c.startswith("#") else c for c in cmds],
                            "url": tool.get("url", ""),
                        })
            for tool in tools:
                phases_html = " ".join(
                    f'<span style="background:rgba(88,166,255,0.1);border:1px solid var(--accent);color:var(--accent);border-radius:3px;padding:1px 6px;font-size:10px">{p}</span>'
                    for p in tool.get("phases", [])
                )
                skill = tool.get("skill_level", "")
                skill_color = {"Beginner": "#3fb950", "Intermediate": "#d29922", "Advanced": "#e67e22", "Expert": "#e74c3c"}.get(skill, "#888")
                cmds_html = self._render_commands(tool.get("commands", []))
                url = tool.get("url", "")
                url_html = f'<a href="{_esc(url)}" target="_blank" class="tool-link">🔗 Официальный сайт / репозиторий</a>' if url else ""
                attack_tools_html += f"""
<div class="tool-card">
  <div class="tool-header">
    <span class="tool-name">{_esc(tool.get('tool_name',''))}</span>
    <span class="tool-type-badge">{_esc(tool.get('tool_type',''))}</span>
    <span style="color:{skill_color};font-size:11px;font-weight:700">{_esc(skill)}</span>
  </div>
  <div class="tool-desc">{_esc(tool.get('description',''))}</div>
  <div class="tool-meta">{phases_html}</div>
  {url_html}
  {cmds_html}
</div>"""
        if not attack_tools_html:
            attack_tools_html = '<div class="reason-block">Для этой уязвимости инструменты атаки отсутствуют в базе. Обратитесь к документации CVE.</div>'
        return f"""
<div class="vuln-card attack-card">
  <div class="card-header" onclick="toggleCard('{card_id}')">
    <span class="badge" style="background:{sev_color}">{_esc(sev)}</span>
    <span class="card-title">{_esc(name or cve)}</span>
    <span class="card-cve">{_esc(cve)}</span>
    <span class="expand-icon">▼</span>
  </div>
  <div class="card-body" id="{card_id}">
    <div class="meta-row">
      <div class="meta-item"><div class="mk">CVE</div><div class="mv">{_esc(cve)}</div></div>
      <div class="meta-item"><div class="mk">CWE</div><div class="mv">{_esc(cwe or '—')}</div></div>
      <div class="meta-item"><div class="mk">CAPEC</div><div class="mv">{_esc(capec or '—')}</div></div>
      <div class="meta-item"><div class="mk">MITRE ATT&CK</div><div class="mv">{_esc(mitre or '—')}</div></div>
    </div>
    <div class="desc-block"><h4>📝 Описание уязвимости</h4><p>{_esc(desc)}</p></div>
    <div class="desc-block" style="margin-top:14px">
      <h4>⚔️ Инструменты и команды атаки</h4>
      {attack_tools_html}
    </div>
  </div>
</div>"""
    # ──────────────────────────────────────────────
    #  Общая карточка уязвимости (схемы 1 и 2)
    # ──────────────────────────────────────────────
    def _vuln_card(self, r, card_class: str) -> str:
        cve = self._get(r, "cve_id") or "Нет CVE"
        name = self._get(r, "attack_name") or "Неизвестная атака"
        sev = self._get(r, "severity") or "INFO"
        feas = self._get(r, "feasibility") or "UNKNOWN"
        desc = self._get(r, "description")
        rec = self._get(r, "recommendation")
        reason = self._get(r, "reason")
        cwe = self._get(r, "cwe_id")
        capec = self._get(r, "capec_id")
        mitre = self._get(r, "mitre_technique")
        sev_color = _sev_color(sev)
        feas_color = _feas_color(feas)
        card_id = f"card-{id(r)}"
        return f"""
<div class="vuln-card {card_class}">
  <div class="card-header" onclick="toggleCard('{card_id}')">
    <span class="badge" style="background:{sev_color}">{_esc(sev)}</span>
    <span class="badge" style="background:{feas_color};margin-left:4px">{_esc(feas)}</span>
    <span class="card-title">{_esc(name)}</span>
    <span class="card-cve">{_esc(cve)}</span>
    <span class="expand-icon">▼</span>
  </div>
  <div class="card-body" id="{card_id}">
    <div class="meta-row">
      <div class="meta-item"><div class="mk">CVE</div><div class="mv">{_esc(cve)}</div></div>
      <div class="meta-item"><div class="mk">CWE</div><div class="mv">{_esc(cwe or '—')}</div></div>
      <div class="meta-item"><div class="mk">CAPEC</div><div class="mv">{_esc(capec or '—')}</div></div>
      <div class="meta-item"><div class="mk">MITRE ATT&CK</div><div class="mv">{_esc(mitre or '—')}</div></div>
      <div class="meta-item"><div class="mk">Серьёзность</div><div class="mv" style="color:{sev_color}">{_esc(sev)}</div></div>
      <div class="meta-item"><div class="mk">Статус</div><div class="mv" style="color:{feas_color}">{_esc(feas)}</div></div>
    </div>
    <div class="desc-block"><h4>📝 Описание</h4><p>{_esc(desc)}</p></div>
    {f'<div class="reason-block"><strong>Причина:</strong> {_esc(reason)}</div>' if reason else ''}
    {f'<div class="desc-block" style="margin-top:10px"><h4>🛠️ Рекомендации</h4><p>{_esc(rec)}</p></div>' if rec else ''}
  </div>
</div>"""
    # ──────────────────────────────────────────────
    #  Render commands
    # ──────────────────────────────────────────────
    def _render_commands(self, commands: list) -> str:
        if not commands:
            return ""
        lines = ""
        for cmd in commands:
            if str(cmd).startswith("#"):
                lines += f'<span class="code-line comment-line">{_esc(cmd)}</span>'
            elif str(cmd).strip() == "":
                lines += '<span class="code-line">&nbsp;</span>'
            else:
                lines += f'<span class="code-line cmd-line">{_esc(cmd)}</span>'
        return f'<div class="code-block"><pre>{lines}</pre></div>'
    # ──────────────────────────────────────────────
    #  Footer
    # ──────────────────────────────────────────────
    def _footer(self, ts: str) -> str:
        return f"""
<div style="text-align:center;color:var(--text-dim);font-size:11px;padding:32px 0 16px;border-top:1px solid var(--border);margin-top:32px">
  Security Assessment Report &bull; Создан: {ts} &bull;
  Используется исключительно в учебных целях для авторизованного тестирования безопасности
</div>"""
    # ──────────────────────────────────────────────
    #  JavaScript
    # ──────────────────────────────────────────────
    def _js(self) -> str:
        return """<script>
function toggleCard(id) {
  const body = document.getElementById(id);
  const header = body.previousElementSibling;
  const icon = header.querySelector('.expand-icon');
  if (!body) return;
  const isOpen = body.classList.contains('open');
  body.classList.toggle('open', !isOpen);
  if (icon) icon.style.transform = isOpen ? '' : 'rotate(180deg)';
}
// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    const tab = document.getElementById(btn.dataset.tab);
    if (tab) tab.classList.add('active');
  });
});
// Auto-open first card in each section
document.querySelectorAll('.tab-content.active .vuln-card').forEach((card, i) => {
  if (i === 0) {
    const header = card.querySelector('.card-header');
    if (header) header.click();
  }
});
</script>"""
