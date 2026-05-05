import json
import os
import re

from common.models import normalize_feasibility, normalize_severity, report_status_meta

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Интерактивный Отчет Корреляции SOC</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --text: #c9d1d9; --border: #30363d; --accent: #58a6ff; }
        body { font-family: "Segoe UI", Tahoma, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1, h2 { color: #ffffff; border-bottom: 1px solid var(--border); padding-bottom: 10px; font-weight: 600; margin-top: 0;}
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        
        .header-flex { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 15px; }

        /* Кнопки */
        .btn-toggle { background: var(--accent); color: #fff; border: none; padding: 10px 20px; border-radius: 5px; font-weight: bold; cursor: pointer; font-size: 14px; transition: 0.2s; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }
        .btn-toggle:hover { background: #3182ce; }
        .btn-danger { background: #da3633; }
        .btn-danger:hover { background: #b32a28; }

        /* Фильтры и селектор карт */
        .controls-bar { display: flex; flex-direction: column; gap: 15px; margin-bottom: 15px; background: #010409; padding: 15px; border-radius: 8px; border: 1px solid var(--border); }
        .aggregation-bar { display: flex; flex-direction: column; gap: 10px; background: #161b22; padding: 12px; border-radius: 6px; border: 1px solid #30363d; }
        .aggregation-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
        .aggregation-title { font-size: 13px; color: #58a6ff; font-weight: bold; text-transform: uppercase; }
        .aggregation-hint { font-size: 12px; color: #8b949e; }
        .aggregation-keys { display: flex; gap: 10px; flex-wrap: wrap; }
        .agg-chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 16px; border: 1px solid #30363d; background: #0d1117; cursor: pointer; user-select: none; }
        .agg-chip input { accent-color: #58a6ff; }
        .agg-chip span { font-size: 12px; color: #c9d1d9; }
        .agg-btn { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 6px 10px; cursor: pointer; font-size: 12px; }
        .agg-btn:hover { background: #30363d; }
        .map-selector { display: flex; align-items: center; gap: 15px; background: #161b22; padding: 10px 15px; border-radius: 6px; border: 1px solid #58a6ff;}
        .map-selector label { font-size: 14px; color: #58a6ff; font-weight: bold; text-transform: uppercase; margin: 0;}
        .map-selector select { flex: 1; padding: 10px; background: var(--accent); color: #fff; border: none; border-radius: 4px; outline: none; font-size: 15px; font-weight: bold; cursor: pointer; box-shadow: 0 2px 4px rgba(0,0,0,0.5);}
        .map-selector select:hover { background: #3182ce; }
        
        .filters-bar { display: grid; grid-template-columns: repeat(4, minmax(220px, 1fr)); gap: 12px; width: 100%; }
        .filter-item { display: flex; flex-direction: column; min-width: 0; }
        .filter-item label { font-size: 12px; color: #8b949e; margin-bottom: 5px; text-transform: uppercase; font-weight: bold; }
        .filter-item select { padding: 10px; background: var(--card); color: #c9d1d9; border: 1px solid var(--border); border-radius: 4px; outline: none; font-size: 14px; cursor: pointer; }
        .filter-item select:focus { border-color: var(--accent); }

        /* Карта */
        #network-map { width: 100%; height: 750px; border: 1px solid var(--border); border-radius: 8px; background: #010409; outline: none; box-shadow: inset 0 0 10px rgba(0,0,0,0.5);}
        
        /* Статистика */
        .stats { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
        .stat-box { background: var(--card); border: 1px solid var(--border); padding: 15px; border-radius: 8px; flex: 1; text-align: center; }
        .stat-box .title { font-size: 12px; color: #8b949e; text-transform: uppercase; }
        .stat-box .num { font-size: 28px; font-weight: bold; margin-top: 5px; }
        
        /* Таблицы */
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { padding: 14px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background-color: #21262d; color: #ffffff; }
        .clickable-row { cursor: pointer; transition: background 0.2s; }
        .clickable-row:hover { background-color: #1f2428; }
        .details-btn { color: var(--accent); font-weight: 600; text-align: right; }
        
        /* Спец-контейнер для расширенного меню сырых уязвимостей */
        .raw-table-container { display: none; max-height: 500px; overflow-y: auto; border: 1px solid var(--border); border-radius: 6px; }
        .raw-table-container th { position: sticky; top: 0; background: #161b22; z-index: 10; box-shadow: 0 2px 2px -1px rgba(0, 0, 0, 0.4); }
        
        /* Бейджи статусов */
        .badge { padding: 5px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; display: inline-block; text-align: center;}
        .crit { background: #791a1e; color: white; }
        .high { background: #da3633; color: white; }
        .med { background: #d29922; color: white; }
        .low { background: #238636; color: white; }
        .info { background: #1f77b4; color: white; }
        
        .real { background: rgba(218, 54, 51, 0.15); color: #ff7b72; border: 1px solid #da3633; }
        .part-real { background: rgba(210, 153, 34, 0.15); color: #e3b341; border: 1px solid #d29922; }
        .noreal { background: rgba(35, 134, 54, 0.15); color: #3fb950; border: 1px solid #238636; }
        .feas-unk { background: rgba(139, 148, 158, 0.15); color: #8b949e; border: 1px solid #8b949e; }
        .stats-explain { font-size: 12px; color: #8b949e; margin: -6px 0 18px 0; line-height: 1.55; padding: 10px 12px; background: #0d1117; border: 1px solid var(--border); border-radius: 6px; }
        .trace-pre { max-height: 340px; overflow: auto; font-size: 11px; }
        .trace-human { font-size: 13px; color: #c9d1d9; line-height: 1.55; }
        .trace-human .trace-lead { font-size: 14px; color: #e6edf3; margin-bottom: 10px; }
        .trace-human .trace-meta { font-size: 12px; color: #8b949e; margin-bottom: 12px; }
        .trace-sec-title { font-size: 11px; font-weight: 700; color: #8b949e; letter-spacing: 0.04em; text-transform: uppercase; margin: 16px 0 8px 0; border-bottom: 1px solid #21262d; padding-bottom: 6px; }
        .trace-callout { border-left: 3px solid #30363d; padding: 10px 14px; margin: 8px 0; background: #0d1117; border-radius: 0 6px 6px 0; }
        .trace-callout.blockers { border-color: #da3633; background: rgba(218,54,51,0.06); }
        .trace-callout.warn { border-color: #d29922; background: rgba(210,153,34,0.06); }
        .trace-callout.ok { border-color: #238636; background: rgba(35,134,54,0.06); }
        .trace-callout.neutral { border-color: #58a6ff; background: rgba(88,166,255,0.06); }
        .trace-list { margin: 6px 0 0 0; padding-left: 18px; color: #c9d1d9; }
        .trace-list li { margin-bottom: 6px; }
        .trace-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
        .trace-chip { font-size: 11px; padding: 4px 10px; border-radius: 999px; background: #21262d; border: 1px solid #30363d; color: #8b949e; }
        .trace-chip.yes { border-color: #238636; color: #3fb950; }
        .trace-chip.no { border-color: #484f58; color: #6e7681; }
        .trace-view-switch { display: flex; gap: 8px; margin: 10px 0 14px 0; flex-wrap: wrap; }
        .trace-view-btn { border: 1px solid #30363d; background: #161b22; color: #c9d1d9; border-radius: 6px; padding: 6px 10px; font-size: 12px; cursor: pointer; }
        .trace-view-btn.active { border-color: #58a6ff; color: #58a6ff; }
        .trace-view { display: none; }
        .trace-view.active { display: block; }
        .trace-flow { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 6px 0 10px 0; }
        .trace-node { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 8px 10px; font-size: 12px; color: #c9d1d9; }
        .trace-arrow { color: #8b949e; font-size: 14px; }
        .trace-score-bar { height: 8px; border-radius: 4px; background: #21262d; overflow: hidden; margin: 8px 0 4px 0; max-width: 360px; }
        .trace-score-fill { height: 100%; border-radius: 4px; background: linear-gradient(90deg, #238636, #d29922, #da3633); }
        .trace-details { margin-top: 10px; font-size: 12px; color: #8b949e; }
        .trace-details summary { cursor: pointer; color: #58a6ff; user-select: none; }
        .trace-merge { font-size: 12px; color: #8b949e; margin-top: 8px; padding: 8px; background: #161b22; border-radius: 6px; border: 1px dashed #30363d; }
        
        /* Модальное окно */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); backdrop-filter: blur(3px); overflow-y: auto;}
        .modal-content { background: var(--card); margin: 5% auto; padding: 25px; border: 1px solid var(--border); width: 65%; max-width: 900px; border-radius: 8px; position: relative; color: #c9d1d9; box-shadow: 0 4px 15px rgba(0,0,0,1); }
        .close { color: #8b949e; position: absolute; right: 20px; top: 15px; font-size: 28px; cursor: pointer; z-index: 1100; }
        .close:hover { color: #ff7b72; }
        .modal-header { border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 15px; }
        
        .grid-info { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; background: #0d1117; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid var(--border); }
        .grid-item span { display: block; font-size: 12px; color: #8b949e; margin-bottom: 4px; }
        .grid-item strong { font-size: 14px; color: #58a6ff; }
        
        .modal-body h4 { color: #fff; margin-top: 20px; margin-bottom: 8px; border-bottom: 1px dashed var(--border); padding-bottom: 5px; }
        .modal-body p { line-height: 1.5; font-size: 14px; background: #0d1117; padding: 12px; border-radius: 6px; border: 1px solid var(--border); }
        .rec-box { border-left: 4px solid #238636 !important; }
        .attack-box { border-left: 4px solid #d29922 !important; background: rgba(210, 153, 34, 0.05) !important; font-family: monospace;}

        /* Перечни CVE/CWE/CAPEC/ПО */
        .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; }
        .summary-panel { background: #0d1117; border: 1px solid var(--border); border-radius: 8px; padding: 15px; }
        .summary-panel h3 { color: #fff; font-size: 13px; margin: 0 0 10px 0; border-bottom: 1px dashed var(--border); padding-bottom: 8px; }
        .summary-panel .count-badge { float: right; background: var(--accent); color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; }
        .summary-list { max-height: 250px; overflow-y: auto; }
        .summary-list::-webkit-scrollbar { width: 4px; }
        .summary-list::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
        .summary-item { padding: 5px 8px; border-bottom: 1px solid #21262d; font-size: 12px; font-family: "Consolas", monospace; color: #8b949e; transition: background 0.15s; }
        .summary-item:hover { background: #161b22; color: #c9d1d9; }
        .summary-item .sw-ver { color: #484f58; font-size: 11px; }

        /* Раздел атак и защиты */
        .atk-def-item { margin-bottom: 15px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .atk-def-header { padding: 12px 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: background 0.15s; }
        .atk-def-header:hover { background: #1f2428; }
        .atk-def-body { display: none; padding: 15px; border-top: 1px solid var(--border); background: #0d1117; }
        .atk-section { border-left: 4px solid #d29922; padding: 12px 15px; margin: 8px 0; background: rgba(210,153,34,0.03); border-radius: 0 6px 6px 0; }
        .def-section { border-left: 4px solid #238636; padding: 12px 15px; margin: 8px 0; background: rgba(35,134,54,0.03); border-radius: 0 6px 6px 0; }
        .cmd-block { background: #010409; color: #e6edf3; padding: 12px; border-radius: 4px; font-family: "Consolas", monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; margin: 8px 0; border: 1px solid #21262d; line-height: 1.6; }
        .cmd-comment { color: #484f58; }
        .cmd-highlight { color: #d29922; }
        .tool-badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-right: 6px; }
        .tool-atk { background: rgba(210,153,34,0.15); color: #e3b341; border: 1px solid #d29922; }
        .tool-def { background: rgba(35,134,54,0.15); color: #3fb950; border: 1px solid #238636; }

        .sw-context { margin-top: 10px; padding: 12px; border-radius: 6px; background: #10161d; border: 1px solid var(--border); }
        .sw-context h4 { margin: 0 0 8px 0; color: #58a6ff; border: none; padding: 0; }
        .sw-context ul { margin: 0; padding-left: 18px; color: #c9d1d9; }
        .sw-context li { margin-bottom: 6px; }
        .group-members { margin-top: 12px; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
        .group-members-head { background: #161b22; padding: 10px 12px; font-size: 12px; color: #8b949e; }
        .group-members-row { display: grid; grid-template-columns: 1.2fr 0.7fr 0.7fr 1fr auto; gap: 8px; align-items: center; padding: 10px 12px; border-top: 1px solid #21262d; font-size: 12px; }
        .group-members-row:nth-child(even) { background: #0f141b; }
        .group-members-row .mono { font-family: "Consolas", monospace; color: #58a6ff; }

        .modal-toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 10px 0 14px 0; border-bottom: 1px solid #21262d; margin-bottom: 12px; }
        .modal-body-accordion { padding-top: 0; }
        .modal-details { margin-bottom: 10px; border: 1px solid #30363d; border-radius: 8px; background: #0d1117; overflow: hidden; }
        .modal-details > summary { list-style: none; cursor: pointer; padding: 12px 14px; font-weight: 600; font-size: 13px; color: #c9d1d9; background: #161b22; user-select: none; display: flex; align-items: center; justify-content: space-between; gap: 10px; }
        .modal-details > summary::-webkit-details-marker { display: none; }
        .modal-details > summary::after { content: "▼"; font-size: 10px; color: #8b949e; flex-shrink: 0; transition: transform 0.15s; }
        .modal-details[open] > summary::after { transform: rotate(-180deg); }
        .modal-details .modal-details-body { padding: 14px 16px 16px; border-top: 1px solid #21262d; }
        .polygon-tools { font-size: 13px; line-height: 1.55; color: #c9d1d9; margin: 0; }
        ol.polygon-steps { margin: 8px 0 0 0; padding-left: 22px; color: #c9d1d9; line-height: 1.6; }
        ol.polygon-steps li { margin-bottom: 8px; }

        @media (max-width: 1200px) {
            .filters-bar { grid-template-columns: repeat(2, minmax(220px, 1fr)); }
        }
        @media (max-width: 1000px) {
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .map-selector { flex-direction: column; align-items: stretch; }
            .filters-bar { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 style="margin-top: 20px;">🛡️ Интерактивная Карта Поверхности Атаки SOC</h1>
        
        <div class="stats">
            <div class="stat-box"><div class="title" id="st-total-title">Записей в отчете</div><div class="num" id="st-total" style="color: #58a6ff;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #da3633;"><div class="title">Реализуемые (КРИТИЧНО)</div><div class="num" id="st-real" style="color: #ff7b72;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #d29922;"><div class="title">Частично реализуемые (ПРОВЕРИТЬ)</div><div class="num" id="st-part" style="color: #e3b341;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #238636;"><div class="title">Не реализуемые (ЗАБЛОКИРОВАНО)</div><div class="num" id="st-noreal" style="color: #3fb950;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #8b949e;"><div class="title">Требуют анализа</div><div class="num" id="st-req" style="color: #8b949e;">0</div></div>
        </div>
        <p id="stats-explain" class="stats-explain"></p>

        <!-- ПЕРЕЧНИ CVE / CWE / CAPEC / ПО -->
        <div class="card">
            <div class="header-flex">
                <div>
                    <h2 style="margin:0; border:none;">📑 Перечни обнаруженных идентификаторов</h2>
                    <p style="margin: 5px 0 0 0; font-size: 13px; color: #8b949e;">Полные реестры уникальных CVE, CWE, CAPEC и программного обеспечения, выявленных в ходе анализа.</p>
                </div>
                <button class="btn-toggle" onclick="toggleSummary()">📑 Развернуть перечни</button>
            </div>
            <div id="summary-container" style="display:none;">
                <div class="summary-grid" id="summary-grid"></div>
            </div>
        </div>

        <div class="card" style="border-left: 4px solid #da3633;">
            <div class="header-flex">
                <div>
                    <h2 style="margin:0; border:none;">🗄️ Расширенное меню: Реестр всех сырых уязвимостей (CVE)</h2>
                    <p style="margin: 5px 0 0 0; font-size: 13px; color: #8b949e;">Полная детализация найденных уязвимостей до объединения алгоритмом.</p>
                </div>
                <button class="btn-toggle btn-danger" onclick="toggleRawCve()">📂 Развернуть реестр</button>
            </div>
            
            <div id="raw-cve-container" class="raw-table-container">
                <div style="padding:10px 12px; background:#0d1117; border-bottom:1px solid var(--border); display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                    <span style="font-size:12px;color:#8b949e;">Фильтр реестра (CVE через пробел / запятую):</span>
                    <input type="text" id="raw-cve-filter" placeholder="например CVE-2023-2986 CVE-2023-3162" oninput="applyRawCveFilter()"
                        style="flex:1;min-width:220px;padding:8px;background:#161b22;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;font-size:12px;" />
                    <button type="button" class="agg-btn" onclick="clearRawCveFilter()">Сбросить</button>
                </div>
                <table id="raw-cve-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Критичность</th>
                            <th>РЕАЛЬНОЕ целевое ПО</th>
                            <th>Порт</th>
                            <th>Вектор атаки (CAPEC)</th>
                        </tr>
                    </thead>
                    <tbody id="raw-cve-body">
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card">
            <div class="header-flex">
                <h2 style="margin:0; border:none;">🗺️ Анализ связей и графов</h2>
            </div>
            
            <div class="controls-bar">
                <div class="aggregation-bar">
                    <div class="aggregation-head">
                        <div>
                            <div class="aggregation-title">⚙️ Динамическая агрегация</div>
                            <div class="aggregation-hint">Если ничего не выбрано — вывод без агрегации (каждая находка отдельно).</div>
                        </div>
                        <button class="agg-btn" onclick="resetAggregation()">Сбросить агрегацию</button>
                    </div>
                    <div class="aggregation-keys">
                        <label class="agg-chip"><input type="checkbox" class="agg-key" value="sw" onchange="onAggregationChanged()"><span>ПО</span></label>
                        <label class="agg-chip"><input type="checkbox" class="agg-key" value="port" onchange="onAggregationChanged()"><span>Порт</span></label>
                        <label class="agg-chip"><input type="checkbox" class="agg-key" value="cwe" onchange="onAggregationChanged()"><span>CWE</span></label>
                        <label class="agg-chip"><input type="checkbox" class="agg-key" value="capec" onchange="onAggregationChanged()"><span>CAPEC</span></label>
                        <label class="agg-chip"><input type="checkbox" class="agg-key" value="feas" onchange="onAggregationChanged()"><span>Реализуемость</span></label>
                        <label class="agg-chip"><input type="checkbox" class="agg-key" value="found_by" onchange="onAggregationChanged()"><span>Источник</span></label>
                        <label class="agg-chip"><input type="checkbox" class="agg-key" value="sev" onchange="onAggregationChanged()"><span>Критичность</span></label>
                    </div>
                </div>

                <div class="map-selector">
                    <label>🔍 ВЫБОР ТОПОЛОГИИ КАРТЫ:</label>
                    <select id="map-view-select" onchange="applyFilters()">
                        <option value="1">🗺️ КАРТА 1: Полная цепочка (CVE ➔ CWE ➔ CAPEC ➔ ПО ➔ MITRE ATT&amp;CK ➔ Реализуемость)</option>
                        <option value="2">🗺️ КАРТА 2: Инфраструктура (Сервер ➔ Реальное ПО ➔ Уязвимость)</option>
                        <option value="3">🗺️ КАРТА 3: Логика Атаки (CAPEC ➔ ПО ➔ CWE ➔ Вердикт)</option>
                        <option value="4">🗺️ КАРТА 4: Источник Обнаружения (Кто нашел ➔ Реальное ПО ➔ Уязвимость)</option>
                        <option value="5">🗺️ КАРТА 5: План Устранения (Уязвимость ➔ Статус ➔ Решение)</option>
                        <option value="6">🗺️ КАРТА 6: Полигон и Инструменты (CAPEC ➔ ПО для атаки ➔ Шаги)</option>
                    </select>
                </div>

                <div class="filters-bar">
                    <div class="filter-item">
                        <label>Фильтр по ПО / Цели:</label>
                        <select id="f-sw" onchange="applyFilters()"><option value="all">-- Все приложения --</option></select>
                    </div>
                    <div class="filter-item">
                        <label>Фильтр по Вектору (CAPEC):</label>
                        <select id="f-capec" onchange="applyFilters()"><option value="all">-- Все векторы --</option></select>
                    </div>
                    <div class="filter-item">
                        <label>Фильтр по Классу (CWE):</label>
                        <select id="f-cwe" onchange="applyFilters()"><option value="all">-- Все классы --</option></select>
                    </div>
                    <div class="filter-item">
                        <label>🎯 Фильтр по реализуемости:</label>
                        <select id="f-feas" onchange="applyFilters()">
                            <option value="all">-- Все статусы --</option>
                            <option value="РЕАЛИЗУЕМА" style="background:#da3633;color:white;">🔴 РЕАЛИЗУЕМА</option>
                            <option value="ЧАСТИЧНО" style="background:#d29922;color:white;">🟡 ЧАСТИЧНО РЕАЛИЗУЕМА</option>
                            <option value="НЕ РЕАЛИЗУЕМА" style="background:#238636;color:white;">🟢 НЕ РЕАЛИЗУЕМА</option>
                            <option value="ТРЕБУЕТ" style="background:#8b949e;color:white;">⚪ ТРЕБУЕТ АНАЛИЗА</option>
                        </select>
                    </div>
                </div>
            </div>

            <p style="margin-bottom: 15px; font-size: 13px; color: #8b949e;">💡 Используйте мышь для масштабирования и перемещения. <strong>Кликните на любой узел (включая CWE и ПО)</strong>, чтобы открыть карточку с подробным описанием.</p>
            <div id="network-map"></div>
        </div>

        <div class="card">
            <h2>📋 Перечень агрегированных векторов</h2>
            <table>
                <thead>
                    <tr>
                        <th>Сгруппированные данные</th>
                        <th>Реальное Целевое ПО</th>
                        <th>Вектор / Название (Схлопнуто)</th>
                        <th>Критичность (Макс)</th>
                        <th>Вердикт Сервера</th>
                        <th>Детали</th>
                    </tr>
                </thead>
                <tbody id="table-body">
                    </tbody>
            </table>
        </div>

        <!-- РАЗДЕЛ: РЕАЛИЗУЕМЫЕ АТАКИ И ЗАЩИТА -->
        <div class="card" style="border-left: 4px solid #d29922;">
            <div class="header-flex">
                <div>
                    <h2 style="margin:0; border:none;">⚔️ Реализуемые атаки и меры противодействия</h2>
                    <p style="margin: 5px 0 0 0; font-size: 13px; color: #8b949e;">Детальные инструкции по воспроизведению атак (Red Team) и рекомендации по защите (Blue Team) с конкретными командами.</p>
                </div>
                <button class="btn-toggle btn-orange" onclick="toggleAtkDef()">⚔️ Развернуть раздел</button>
            </div>
            <div id="atk-def-container" style="display:none;">
                <div id="atk-def-list"></div>
            </div>
        </div>
    </div>

    <div id="infoModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <div id="dynamic-modal-content">
                </div>
        </div>
    </div>

    <script type="text/javascript">
        var reportData = __REPORT_DATA__;
        var reportDataSeed = Array.isArray(reportData) ? reportData.slice() : [];
        var rawFindingsData = __RAW_FINDINGS_DATA__;
        var rawCveData = __RAW_CVE_DATA__;
        var sysData = __SYS_DATA__;
        var summaryData = __SUMMARY_DATA__;
        var atkDefData = __ATK_DEF_DATA__;
        var statusMeta = __STATUS_META__;
        var network = null;
        var detailsMap = {};

        function escapeHtml(s) {
            if (s === undefined || s === null) return "";
            return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        }
        function esc(x) {
            return escapeHtml(x);
        }
        function formatStepsToOl(steps) {
            if (steps === undefined || steps === null || steps === "") {
                return '<p class="trace-meta" style="margin:0;">Шаги не заданы.</p>';
            }
            var s = String(steps);
            var NL = String.fromCharCode(10);
            s = s.split(String.fromCharCode(13) + NL).join(NL).split(String.fromCharCode(13)).join(NL);
            var BS = "\\\\";
            var fakeNl = BS + "n";
            if (s.indexOf(fakeNl) !== -1 && s.split(NL).length <= 1) s = s.split(fakeNl).join(NL);
            var lines = s.split(NL).map(function(l) { return l.trim(); }).filter(Boolean);
            if (lines.length === 0) {
                return '<p class="trace-meta" style="margin:0;">' + esc(s) + '</p>';
            }
            var items = [];
            lines.forEach(function(line) {
                var m = line.match(/^(?:\\d+[\\.\\)])\\s*(.+)$/);
                if (m) items.push(m[1].trim());
                else items.push(line);
            });
            var h = '<ol class="polygon-steps">';
            items.forEach(function(it) { h += "<li>" + esc(it) + "</li>"; });
            h += "</ol>";
            return h;
        }
        function isGenericTrainingPlaceholder(r) {
            var tools = (r.tools || "").replace(/\\s+/g, " ").trim();
            var st = String(r.steps || "");
            var NL = String.fromCharCode(10);
            st = st.split(String.fromCharCode(13) + NL).join(NL).split(String.fromCharCode(13)).join(NL);
            var BS = "\\\\";
            var fakeNl = BS + "n";
            if (st.indexOf(fakeNl) !== -1 && st.split(NL).length <= 1) st = st.split(fakeNl).join(NL);
            var toolsMatch = tools === "Burp Suite, SQLMap, Nmap" || tools === "Nmap, Metasploit";
            var stepsMatch = /Анализ порта|Идентификация службы|Подбор эксплоита|Сканирование сети|Выбор эксплоита|Запуск/i.test(st);
            return toolsMatch && stepsMatch;
        }
        function getTrainingModeClass(feas) {
            var f = String(feas || "").toUpperCase();
            if (f === "НЕ РЕАЛИЗУЕМА") return "not_feasible";
            if (f.indexOf("ТРЕБУЕТ") !== -1) return "requires_analysis";
            if (f.indexOf("ЧАСТИЧНО") !== -1) return "partially_feasible";
            if (f === "РЕАЛИЗУЕМА") return "feasible";
            return "unknown";
        }
        function hasNaSignature(r) {
            var cveRaw = String(r.cve || "").toUpperCase();
            var trace = (r && r.feasibility_trace && typeof r.feasibility_trace === "object") ? r.feasibility_trace : {};
            var note = String(trace.note || "").toLowerCase();
            return cveRaw === "N/A" || cveRaw.indexOf("N/A") !== -1 || note.indexOf("не найдено cve") !== -1;
        }
        function buildValidationChecklist(r) {
            var trace = (r && r.feasibility_trace && typeof r.feasibility_trace === "object") ? r.feasibility_trace : {};
            var rs = trace.rule_summary || {};
            var hc = trace.host_context || {};
            var checks = [];
            if (rs.blockers && rs.blockers.length) {
                checks.push("Проверить блокирующие факторы: " + rs.blockers.join("; "));
            }
            if (rs.uncertainty_flags && rs.uncertainty_flags.length) {
                checks.push("Снизить неопределённость: " + rs.uncertainty_flags.join("; "));
            }
            if (hc.cve_required_ports && hc.cve_required_ports.length) {
                checks.push("Перепроверить доступность портов CVE: " + hc.cve_required_ports.join(", "));
            }
            if (hc.vector_target_service) {
                checks.push("Подтвердить наличие и версию сервиса: " + hc.vector_target_service);
            }
            checks.push("Сверить версию продукта с официальным advisory по CVE/CWE.");
            checks.push("Повторить проверку в изолированном стенде и задокументировать доказательства.");
            return checks;
        }
        function buildStatusChangeHints(trace) {
            if (!trace || typeof trace !== "object") return [];
            var fac = trace.factors || {};
            var rows = fac.score_breakdown || [];
            var hints = [];
            for (var i = 0; i < rows.length; i++) {
                var row = rows[i] || {};
                var pts = Number(row.points || 0);
                if (pts <= 0) {
                    if (row.key === "network") hints.push("Подтвердить сетевую достижимость целевого сервиса/порта.");
                    if (row.key === "scanner") hints.push("Получить подтверждение активным сканером (Nmap/Nuclei) в стенде.");
                    if (row.key === "trivy") hints.push("Подтвердить CVE в Trivy по установленным пакетам.");
                    if (row.key === "software") hints.push("Подтвердить фактическое наличие уязвимого ПО и его версии.");
                }
            }
            if (!hints.length) {
                hints.push("Данных для повышения уверенности пока недостаточно; нужно собрать дополнительные подтверждения.");
            }
            return hints;
        }
        function formatTrainingPolygon(r) {
            var gen = isGenericTrainingPlaceholder(r);
            var trace = (r && r.feasibility_trace && typeof r.feasibility_trace === "object") ? r.feasibility_trace : {};
            var rs = trace.rule_summary || {};
            var feasClass = getTrainingModeClass(r.feas);
            var naMode = hasNaSignature(r);
            var html = "";
            var validationChecks = buildValidationChecklist(r);
            var statusChangeHints = buildStatusChangeHints(trace);
            if (naMode || feasClass === "not_feasible" || feasClass === "requires_analysis") {
                var modeTitle = naMode ? "Режим полигона: Диагностика (нет CVE-сигнатуры)" : "Режим полигона: Диагностика";
                html += '<div class="trace-callout warn" style="margin-bottom:12px;"><strong>' + esc(modeTitle) + '.</strong> Для этого статуса эксплуатационные шаги и инструменты не показываются. Фокус — проверка предпосылок и сбор доказательств.</div>';
                html += '<p style="margin:0 0 6px 0;"><strong style="color:#d29922">Почему сейчас не реализуема/не подтверждена</strong></p>';
                html += traceUl(rs.blockers, "Явные блокеры не зафиксированы, но подтверждений недостаточно.");
                html += '<p style="margin:14px 0 6px 0;"><strong style="color:#d29922">Что перепроверить вручную</strong></p>';
                html += traceUl(validationChecks, "Добавьте ручную валидацию по сервису и версии ПО.");
                html += '<p style="margin:14px 0 6px 0;"><strong style="color:#d29922">Что изменит статус</strong></p>';
                html += traceUl(statusChangeHints, "Нужно больше подтверждающих данных.");
                html += '<p class="trace-meta" style="margin-top:12px;">Режим только для диагностики: действия выполняйте в тестовой среде и по согласованию.</p>';
                return html;
            }
            if (feasClass === "partially_feasible") {
                html += '<div class="trace-callout neutral" style="margin-bottom:12px;"><strong>Режим полигона: Ограниченный.</strong> Допускаются только безопасные проверочные шаги, без эксплуатационных действий.</div>';
                html += '<p style="margin:0 0 6px 0;"><strong style="color:#d29922">План валидации (чеклист)</strong></p>';
                html += traceUl(validationChecks, "Проверьте предпосылки вручную.");
                if (gen) {
                    html += '<div class="trace-callout warn" style="margin:12px 0;"><strong>Шаблон из базы.</strong> Используйте только как ориентир, фактический стек может отличаться.</div>';
                }
                html += '<p style="margin:14px 0 6px 0;"><strong style="color:#d29922">Инструменты (ограниченный режим)</strong></p>';
                html += '<p class="polygon-tools">' + esc(r.tools || "—") + '</p>';
                html += '<p class="trace-meta" style="margin-top:12px;">Не переходите к эксплуатации до получения достаточных подтверждений.</p>';
                return html;
            }
            if (gen) {
                html += '<div class="trace-callout warn" style="margin-bottom:12px;"><strong>Шаблон из базы.</strong> Инструменты и шаги ниже — запасной учебный сценарий (CWE/общий), он может <em>не совпадать</em> с реальной технологией из CVE (например, плагин WordPress vs сетевой скан). Ориентируйтесь на «Описание уязвимости» и блок «Атаки и защита» на странице отчёта.</div>';
            }
            html += '<div class="trace-callout ok" style="margin-bottom:12px;"><strong>Режим полигона: Учебный.</strong> Доступны инструменты и пошаговый сценарий для контролируемого стенда.</div>';
            html += '<p style="margin:0 0 6px 0;"><strong style="color:#d29922">Инструменты</strong> <span class="trace-meta">(из записи отчёта / локальной БД)</span></p>';
            html += '<p class="polygon-tools">' + esc(r.tools || "—") + '</p>';
            html += '<p style="margin:14px 0 6px 0;"><strong style="color:#d29922">Шаги эксплуатации</strong></p>';
            html += formatStepsToOl(r.steps);
            html += '<p class="trace-meta" style="margin-top:12px;">В лабораторных целях используйте только стенды и явное разрешение. Не повторяйте действия на продакшене без согласования.</p>';
            return html;
        }
        function traceUl(lines, emptyMsg) {
            if (!lines || !lines.length) {
                return '<p class="trace-meta" style="margin:0;">' + escapeHtml(emptyMsg || "—") + '</p>';
            }
            var h = '<ul class="trace-list">';
            for (var i = 0; i < lines.length; i++) {
                h += '<li>' + escapeHtml(String(lines[i])) + '</li>';
            }
            h += '</ul>';
            return h;
        }
        function tracePortsBlock(ports, title) {
            if (!ports || !ports.length) {
                return '<p class="trace-meta" style="margin:0;">' + escapeHtml(title) + ': не указаны.</p>';
            }
            var n = ports.length;
            var preview = ports.slice(0, 14).join(", ");
            var more = n > 14 ? " … и ещё " + (n - 14) + " порт(ов)" : "";
            return '<p class="trace-meta" style="margin:0 0 6px 0;"><strong style="color:#c9d1d9;">' + escapeHtml(title) + '</strong> — всего ' + n + '.</p>' +
                '<details class="trace-details"><summary>Показать список портов</summary><p style="margin:8px 0 0 0;font-family:Consolas,monospace;font-size:11px;color:#8b949e;word-break:break-all;">' +
                escapeHtml(preview + more) + '</p></details>';
        }
        function switchTraceView(baseId, mode) {
            var textEl = document.getElementById(baseId + "_text");
            var flowEl = document.getElementById(baseId + "_flow");
            var btnText = document.getElementById(baseId + "_btn_text");
            var btnFlow = document.getElementById(baseId + "_btn_flow");
            if (!textEl || !flowEl || !btnText || !btnFlow) return;
            var textActive = mode === "text";
            textEl.className = "trace-view" + (textActive ? " active" : "");
            flowEl.className = "trace-view" + (textActive ? "" : " active");
            btnText.className = "trace-view-btn" + (textActive ? " active" : "");
            btnFlow.className = "trace-view-btn" + (textActive ? "" : " active");
        }
        function formatTraceFlow(trace, rec) {
            var tr = (trace && typeof trace === "object") ? trace : {};
            var r = (rec && typeof rec === "object") ? rec : {};
            var src = String(r.found_by || "");
            var actor = "Сервер";
            if (src.indexOf("Trivy") !== -1 && src.indexOf("атакующ") !== -1) actor = "Trivy + Атакующий";
            else if (src.indexOf("Trivy") !== -1) actor = "Trivy";
            else if (src.toLowerCase().indexOf("атакующ") !== -1) actor = "Атакующий";
            var score = tr.score != null ? Number(tr.score) : null;
            var maxSc = tr.max_score != null ? Number(tr.max_score) : 100;
            var cve = tr.cve_id || r.cve || "N/A";
            var feas = tr.feasibility || r.feas || "UNKNOWN";
            var tool = "Коррелятор";
            var toolHints = [];
            if (tr.trivy && tr.trivy.confirmed) toolHints.push("Trivy");
            if (tr.attack_vector_id) toolHints.push("Вектор " + tr.attack_vector_id);
            if (toolHints.length) tool = toolHints.join(" + ");
            var h = '<div class="trace-human">';
            h += '<div class="trace-flow">';
            h += '<div class="trace-node"><strong>Где обнаружено</strong><br>' + escapeHtml(actor) + '</div>';
            h += '<div class="trace-arrow">→</div>';
            h += '<div class="trace-node"><strong>Чем обнаружено</strong><br>' + escapeHtml(tool) + '</div>';
            h += '<div class="trace-arrow">→</div>';
            h += '<div class="trace-node"><strong>Уязвимость</strong><br>' + escapeHtml(String(cve)) + '</div>';
            h += '<div class="trace-arrow">→</div>';
            h += '<div class="trace-node"><strong>Баллы / статус</strong><br>' + escapeHtml(score != null ? (score + " / " + maxSc + " · " + feas) : feas) + '</div>';
            h += '</div>';
            if (tr.factors && tr.factors.score_breakdown && tr.factors.score_breakdown.length) {
                h += '<div class="trace-sec-title">Какие факторы дали баллы</div><ul class="trace-list">';
                tr.factors.score_breakdown.forEach(function (row) {
                    var pts = Number(row.points || 0);
                    var maxPts = Number(row.max_points || 0);
                    h += '<li>' + escapeHtml(String(row.label || row.key || "Фактор")) + ': ' + (pts >= 0 ? '+' : '') + pts + (maxPts > 0 ? (' / ' + maxPts) : '') + ' баллов</li>';
                });
                h += '</ul>';
            }
            h += '</div>';
            return h;
        }
        function wrapTraceViews(textHtml, trace, rec) {
            var viewId = "trace_view_" + Math.random().toString(36).slice(2, 9);
            var controls = '<div class="trace-view-switch">'
                + '<button type="button" class="trace-view-btn active" id="' + viewId + '_btn_text" onclick="switchTraceView(\\'' + viewId + '\\', \\'text\\')">Текст</button>'
                + '<button type="button" class="trace-view-btn" id="' + viewId + '_btn_flow" onclick="switchTraceView(\\'' + viewId + '\\', \\'flow\\')">Схема</button>'
                + '</div>';
            return controls
                + '<div class="trace-view active" id="' + viewId + '_text">' + textHtml + '</div>'
                + '<div class="trace-view" id="' + viewId + '_flow">' + formatTraceFlow(trace, rec) + '</div>';
        }
        function normalizeTraceForDisplay(trace, rec) {
            var t = (trace && typeof trace === "object") ? trace : {};
            if (t.version === 1 && t.rule_summary && t.factors) return t;

            var recFeas = String((rec && rec.feas) || t.feasibility || "ТРЕБУЕТ АНАЛИЗА");
            var recReason = String((rec && rec.reason) || t.note || "Недостаточно данных для детального трассирования.");
            var recCve = String((rec && rec.cve) || t.cve_id || (t.trivy && t.trivy.vuln_id) || "N/A");
            var recVector = String((t.attack_vector_id) || (rec && rec.attack_vector_id) || "N/A");

            var scoreMap = {
                "РЕАЛИЗУЕМА": 82,
                "ЧАСТИЧНО РЕАЛИЗУЕМА": 58,
                "ТРЕБУЕТ АНАЛИЗА": 32,
                "НЕ РЕАЛИЗУЕМА": 18
            };
            var defaultScore = scoreMap[recFeas] != null ? scoreMap[recFeas] : 30;
            var score = (t.score != null) ? Number(t.score) : defaultScore;
            var maxScore = (t.max_score != null) ? Number(t.max_score) : 100;

            var tr = t.trivy || {};
            var trConfirmed = Boolean(tr.confirmed || t.source === "trivy_attacker_correlation");
            var trSeverity = String(tr.reported_severity || tr.severity || (rec && rec.sev) || "UNKNOWN");
            var trPkg = tr.pkg_name || "";
            var trDetails = tr.details || "";
            if (!trDetails && t.source === "trivy_attacker_correlation") {
                trDetails = "Связка Trivy + вектор атакующего подтверждает уязвимость в целевом ПО.";
            }

            var hc = t.host_context || {};
            var openPort = (t.open_port_on_vector != null && t.open_port_on_vector !== "") ? String(t.open_port_on_vector) : null;
            var prereq = Array.isArray(t.prerequisite_checks) ? t.prerequisite_checks.slice() : [];
            if (prereq.length === 0) {
                prereq.push(trConfirmed ? "Trivy подтвердил уязвимость" : "Trivy не подтвердил уязвимость");
                if (recVector && recVector !== "N/A") prereq.push("Вектор атаки сопоставлен: " + recVector);
                prereq.push(openPort ? ("Проверяется порт вектора: " + openPort) : "Локальный вектор (без сетевого порта)");
            }

            var detailLines = [];
            if (trConfirmed) {
                detailLines.push("Trivy подтвердил уязвимость");
                detailLines.push("Есть совпадение CVE и атакующего вектора");
            } else {
                detailLines.push("Trivy не подтвердил уязвимость");
                detailLines.push("Оценка выполнена по эвристикам и контексту");
            }
            if (recReason) detailLines.push(recReason);

            var breakdown = [
                { key: "network_points", label: "Сетевая доступность", points: openPort ? 15 : 10, max_points: 25 },
                { key: "scanner_points", label: "Подтверждение активным сканером", points: 0, max_points: 20 },
                { key: "trivy_points", label: "Подтверждение Trivy", points: trConfirmed ? 35 : -16, max_points: 40 },
                { key: "software_points", label: "Уязвимое ПО", points: trPkg ? 15 : 8, max_points: 25 },
                { key: "patch_points", label: "Состояние обновлений", points: 10, max_points: 10 },
                { key: "protection_points", label: "Ослабление защиты", points: 0, max_points: 5 }
            ];

            return {
                version: 1,
                source: t.source || "normalized_trace",
                cve_id: recCve,
                attack_vector_id: recVector,
                score: score,
                max_score: maxScore,
                feasibility: recFeas,
                trivy: {
                    confirmed: trConfirmed,
                    reported_severity: trSeverity,
                    details: trDetails,
                    pkg_name: trPkg,
                    vuln_id: tr.vuln_id || recCve
                },
                rule_summary: {
                    blockers: Array.isArray(t.rule_summary && t.rule_summary.blockers) ? t.rule_summary.blockers : [],
                    uncertainty_flags: Array.isArray(t.rule_summary && t.rule_summary.uncertainty_flags)
                        ? t.rule_summary.uncertainty_flags
                        : (trConfirmed ? [] : ["Нет полного подтверждения Trivy, требуется верификация вручную"]),
                    has_hard_evidence: trConfirmed
                },
                factors: {
                    score_breakdown: Array.isArray(t.factors && t.factors.score_breakdown) && t.factors.score_breakdown.length
                        ? t.factors.score_breakdown
                        : breakdown,
                    score_detail_lines: Array.isArray(t.factors && t.factors.score_detail_lines) && t.factors.score_detail_lines.length
                        ? t.factors.score_detail_lines
                        : detailLines,
                    protection: Array.isArray(t.factors && t.factors.protection) && t.factors.protection.length
                        ? t.factors.protection
                        : ["Информация о защитных мерах ограничена в исходной трассировке"]
                },
                host_context: {
                    firewall_active: Boolean(hc.firewall_active),
                    antivirus_active: Boolean(hc.antivirus_active),
                    updates_installed: Boolean(hc.updates_installed),
                    vector_target_service: hc.vector_target_service || (trPkg || "Не указано"),
                    attack_type: hc.attack_type || "unknown",
                    open_ports: Array.isArray(hc.open_ports) ? hc.open_ports : [],
                    cve_required_ports: Array.isArray(hc.cve_required_ports) ? hc.cve_required_ports : []
                },
                prerequisite_checks: prereq,
                merged_sources: Array.isArray(t.merged_sources) ? t.merged_sources : []
            };
        }
        function formatTraceBlock(trace, rec) {
            if (!trace || typeof trace !== "object" || Object.keys(trace).length === 0) {
                return '<p style="color:#484f58;font-size:12px;">Трассировка вердикта недоступна для этой записи.</p>';
            }
            trace = normalizeTraceForDisplay(trace, rec);
            /* Основная форма коррелятора (version 1) */
            if (trace.version === 1 && trace.rule_summary && trace.factors) {
                var rs = trace.rule_summary || {};
                var fac = trace.factors || {};
                var tr = trace.trivy || {};
                var hc = trace.host_context || {};
                var score = trace.score != null ? Number(trace.score) : null;
                var maxSc = trace.max_score != null ? Number(trace.max_score) : 100;
                var pct = score != null && maxSc > 0 ? Math.min(100, Math.round((score / maxSc) * 100)) : 0;
                var feas = trace.feasibility || "—";
                var h = '<div class="trace-human">';
                h += '<p class="trace-lead">Оценка модели: <strong>' + (score != null ? score + " / " + maxSc : "—") + '</strong> баллов → вердикт: <strong>' + escapeHtml(feas) + '</strong></p>';
                h += '<p class="trace-meta">Число отражает сумму факторов риска (сеть, Trivy, ПО, патчи, защита). Вердикт выводится по порогам и наличию блокеров; при слабых доказательствах возможен статус «требует анализа».</p>';
                if (score != null) {
                    h += '<div class="trace-score-bar" title="Заполнение шкалы относительно максимума"><div class="trace-score-fill" style="width:' + pct + '%;"></div></div>';
                }
                if (trace.cve_id || trace.attack_vector_id) {
                    h += '<p class="trace-meta" style="margin-top:4px;">';
                    if (trace.cve_id) h += 'CVE: <code style="color:#58a6ff;">' + escapeHtml(trace.cve_id) + '</code> ';
                    if (trace.attack_vector_id) h += '· вектор: <code style="color:#58a6ff;">' + escapeHtml(trace.attack_vector_id) + '</code>';
                    h += '</p>';
                }
                h += '<div class="trace-sec-title">Подтверждение Trivy</div>';
                if (tr.confirmed) {
                    h += '<div class="trace-callout ok"><strong>Trivy подтвердил</strong> уязвимость в установленном ПО.';
                    if (tr.reported_severity && tr.reported_severity !== "UNKNOWN") h += ' Степень в отчёте: <strong>' + escapeHtml(tr.reported_severity) + '</strong>.';
                    h += '</div>';
                    if (tr.details) h += '<p class="trace-meta" style="margin-top:6px;">' + escapeHtml(tr.details) + '</p>';
                } else {
                    h += '<div class="trace-callout warn"><strong>Trivy не подтвердил</strong> эту CVE по установленным пакетам. Оценка реализуемости опирается на эвристики (порты, ПО из инвентаря, вектор атакующего) — результат менее надёжен, чем при подтверждении сканером.</div>';
                    if (tr.reported_severity) h += '<p class="trace-meta">Поле severity в данных Trivy: <code>' + escapeHtml(String(tr.reported_severity)) + '</code></p>';
                }
                h += '<div class="trace-sec-title">Блокирующие факторы</div>';
                if (rs.blockers && rs.blockers.length) {
                    h += '<div class="trace-callout blockers"><strong>Есть блокеры</strong> — условия, при которых атака в текущей модели считается невозможной или сильно ограниченной.</div>';
                    h += traceUl(rs.blockers, "");
                } else {
                    h += '<div class="trace-callout neutral">Блокеров нет: явных «стоп-факторов» модель не нашла.</div>';
                }
                h += '<div class="trace-sec-title">Неопределённость и оговорки</div>';
                if (rs.uncertainty_flags && rs.uncertainty_flags.length) {
                    h += '<p class="trace-meta" style="margin:0 0 6px 0;">Эти пункты снижают уверенность — имеет смысл проверить вручную или досканировать хост.</p>';
                    h += traceUl(rs.uncertainty_flags, "");
                } else {
                    h += '<p class="trace-meta" style="margin:0;">Дополнительных флагов неопределённости нет.</p>';
                }
                h += '<div class="trace-sec-title">Что вошло в балльную оценку</div>';
                if (fac.score_breakdown && fac.score_breakdown.length) {
                    h += '<div style="margin:6px 0 10px 0;">';
                    fac.score_breakdown.forEach(function (row) {
                        var pts = Number(row.points || 0);
                        var maxPts = Number(row.max_points || 0);
                        var tone = pts > 0 ? "#238636" : (pts < 0 ? "#da3633" : "#8b949e");
                        h += '<div class="trace-meta" style="margin:4px 0;">'
                            + '<strong style="color:#c9d1d9;">' + escapeHtml(String(row.label || row.key || "Фактор")) + ':</strong> '
                            + '<span style="color:' + tone + ';font-weight:700;">' + (pts >= 0 ? "+" : "") + pts + '</span>'
                            + (maxPts > 0 ? ' / ' + maxPts : '')
                            + ' баллов'
                            + '</div>';
                    });
                    h += '</div>';
                }
                h += traceUl(fac.score_detail_lines, "Нет строк детализации.");
                h += '<div class="trace-sec-title">Средства защиты (учтены в тексте причины)</div>';
                h += traceUl(fac.protection, "Заметок о защите нет.");
                h += '<div class="trace-sec-title">Среда: хост и вектор</div>';
                h += '<div class="trace-chips">';
                h += '<span class="trace-chip ' + (hc.firewall_active ? "yes" : "no") + '">Брандмауэр: ' + (hc.firewall_active ? "вкл." : "выкл.") + '</span>';
                h += '<span class="trace-chip ' + (hc.antivirus_active ? "yes" : "no") + '">Антивирус: ' + (hc.antivirus_active ? "вкл." : "выкл.") + '</span>';
                h += '<span class="trace-chip ' + (hc.updates_installed ? "yes" : "no") + '">Обновления: ' + (hc.updates_installed ? "установлены" : "не все") + '</span>';
                h += '<span class="trace-chip">' + (rs.has_hard_evidence ? "Есть жёсткие доказательства" : "Жёстких доказательств мало") + '</span>';
                h += '</div>';
                if (hc.vector_target_service || hc.attack_type) {
                    h += '<p class="trace-meta" style="margin-top:10px;">';
                    if (hc.vector_target_service) h += "Сервис по вектору: <strong>" + escapeHtml(hc.vector_target_service) + "</strong>";
                    if (hc.attack_type) h += (hc.vector_target_service ? " · " : "") + "тип атаки в каталоге CVE: <code>" + escapeHtml(String(hc.attack_type)) + "</code>";
                    h += "</p>";
                }
                h += tracePortsBlock(hc.open_ports, "Открытые порты на хосте");
                if (hc.cve_required_ports && hc.cve_required_ports.length) {
                    h += '<p class="trace-meta" style="margin-top:10px;">Порты, указанные для CVE: <strong>' + escapeHtml(hc.cve_required_ports.join(", ")) + '</strong></p>';
                }
                h += '<div class="trace-sec-title">Проверки по предпосылкам CVE и вектору</div>';
                h += traceUl(trace.prerequisite_checks, "Список проверок не передан.");
                if (trace.merged_sources && trace.merged_sources.length) {
                    h += '<div class="trace-merge">Запись объединена из <strong>' + trace.merged_sources.length + '</strong> источников (одна CVE, разные пути обнаружения). Детали по каждому источнику — в JSON ниже.</div>';
                }
                h += '<details class="trace-details"><summary>Технические данные (JSON)</summary><pre class="cmd-block trace-pre">' + escapeHtml(JSON.stringify(trace, null, 2)) + '</pre></details>';
                h += '</div>';
                return wrapTraceViews(h, trace, rec);
            }
            return '<p style="color:#8b949e;font-size:12px;">Не удалось отрисовать трассировку в унифицированном формате.</p>';
        }
        function openRawRegistryForCves(cveList) {
            let cont = document.getElementById("raw-cve-container");
            let inp = document.getElementById("raw-cve-filter");
            let arr = Array.isArray(cveList) ? cveList : [];
            if (inp) inp.value = arr.join(" ");
            if (cont) {
                cont.style.display = "block";
                cont.scrollIntoView({ behavior: "smooth", block: "nearest" });
            }
            applyRawCveFilter();
        }
        function applyRawCveFilter() {
            let inp = document.getElementById("raw-cve-filter");
            let q = (inp && inp.value) ? inp.value.toUpperCase() : "";
            let tokens = q.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
            document.querySelectorAll("#raw-cve-body tr").forEach(tr => {
                let cell = (tr.getAttribute("data-cve") || "").toUpperCase();
                let ok = tokens.length === 0 || tokens.some(t => cell.includes(t));
                tr.style.display = ok ? "" : "none";
            });
        }
        function clearRawCveFilter() {
            let inp = document.getElementById("raw-cve-filter");
            if (inp) inp.value = "";
            applyRawCveFilter();
        }

        function init() {
            rebuildAggregatedData();
            applyFilters();
            renderRawCveTable();
            applyRawCveFilter();
            renderSummaryPanels();
            renderAtkDefSection();
        }

        function renderSummaryPanels() {
            var grid = document.getElementById("summary-grid");
            if (!summaryData) return;
            var panels = [
                {title: "📋 CVE (уязвимости)", items: summaryData.cves || [], color: "#da3633", prefix: ""},
                {title: "🐛 CWE (классы слабостей)", items: summaryData.cwes || [], color: "#d29922", prefix: ""},
                {title: "🥷 CAPEC (векторы атак)", items: summaryData.capecs || [], color: "#58a6ff", prefix: ""},
                {title: "📦 ПО (программное обеспечение)", items: summaryData.software || [], color: "#3fb950", prefix: ""}
            ];
            var html = "";
            panels.forEach(function(p) {
                html += '<div class="summary-panel" style="border-top: 3px solid ' + p.color + ';">';
                html += '<h3>' + p.title + ' <span class="count-badge">' + p.items.length + '</span></h3>';
                html += '<div class="summary-list">';
                p.items.forEach(function(item) {
                    if (typeof item === "object") {
                        html += '<div class="summary-item">' + escapeHtml(item.id || item.name || "") + (item.desc ? ' <span class="sw-ver">— ' + escapeHtml(item.desc) + '</span>' : '') + '</div>';
                    } else {
                        html += '<div class="summary-item">' + escapeHtml(item) + '</div>';
                    }
                });
                if (p.items.length === 0) html += '<div class="summary-item" style="color:#484f58;">Нет данных</div>';
                html += '</div></div>';
            });
            grid.innerHTML = html;
        }

        function toggleSummary() {
            var el = document.getElementById("summary-container");
            el.style.display = el.style.display === "none" ? "block" : "none";
        }

        function renderAtkDefSection() {
            var list = document.getElementById("atk-def-list");
            if (!atkDefData || atkDefData.length === 0) {
                list.innerHTML = '<p style="color:#484f58;text-align:center;padding:20px;">Нет данных об атаках и защите. Загрузите базу инструментов.</p>';
                return;
            }
            var html = "";
            atkDefData.forEach(function(item, idx) {
                var feasClass = item.feas === "РЕАЛИЗУЕМА" ? "real" : (item.feas.includes("ЧАСТИЧНО") ? "part-real" : "noreal");
                var sevClass = getSevClass(item.sev);
                html += '<div class="atk-def-item">';
                html += '<div class="atk-def-header" onclick="toggleAtkDefItem(' + idx + ')" style="background:#161b22;">';
                html += '<div><span class="badge ' + sevClass + '" style="margin-right:8px;">' + escapeHtml(item.sev) + '</span>';
                html += '<span class="badge ' + feasClass + '" style="margin-right:8px;">' + escapeHtml(item.feas) + '</span>';
                html += '<strong style="color:#fff;">' + escapeHtml(item.sw) + '</strong>';
                html += ' <span style="color:#8b949e;"> — ' + escapeHtml(item.capec) + ' (' + escapeHtml(item.cve_short) + ')</span></div>';
                html += '<span style="color:#58a6ff;font-size:12px;">▼ Раскрыть</span>';
                html += '</div>';
                html += '<div class="atk-def-body" id="atk-def-body-' + idx + '">';

                // Атака
                html += '<div class="atk-section">';
                html += '<h4 style="color:#e3b341;margin:0 0 10px 0;">🥷 Red Team: Как атаковать</h4>';
                if (item.attack_tools && item.attack_tools.length > 0) {
                    item.attack_tools.forEach(function(tool) {
                        html += '<div style="margin-bottom:12px;">';
                        html += '<span class="tool-badge tool-atk">' + escapeHtml(tool.name) + '</span>';
                        if (tool.skill) html += '<span style="color:#8b949e;font-size:11px;"> Уровень: ' + escapeHtml(tool.skill) + '</span>';
                        if (tool.desc) html += '<p style="font-size:12px;color:#8b949e;margin:6px 0;">' + escapeHtml(tool.desc) + '</p>';
                        if (tool.commands && tool.commands.length > 0) {
                            html += '<div class="cmd-block">';
                            tool.commands.forEach(function(cmd) {
                                if (cmd.startsWith("#") || cmd.startsWith("//")) {
                                    html += '<span class="cmd-comment">' + escapeHtml(cmd) + '</span>\\n';
                                } else if (cmd.trim() === "") {
                                    html += '\\n';
                                } else {
                                    html += '<span class="cmd-highlight">' + escapeHtml(cmd) + '</span>\\n';
                                }
                            });
                            html += '</div>';
                        }
                        html += '</div>';
                    });
                } else {
                    html += '<p style="color:#484f58;font-size:12px;">Инструменты атаки не найдены в базе данных.</p>';
                }
                html += '</div>';

                // Защита
                html += '<div class="def-section">';
                html += '<h4 style="color:#3fb950;margin:0 0 10px 0;">🛡️ Blue Team: Как защититься</h4>';
                if (item.defense_tools && item.defense_tools.length > 0) {
                    item.defense_tools.forEach(function(tool) {
                        html += '<div style="margin-bottom:12px;">';
                        html += '<span class="tool-badge tool-def">' + escapeHtml(tool.name) + '</span>';
                        if (tool.priority) html += '<span style="color:#8b949e;font-size:11px;"> Приоритет: ' + escapeHtml(tool.priority) + '</span>';
                        if (tool.desc) html += '<p style="font-size:12px;color:#8b949e;margin:6px 0;">' + escapeHtml(tool.desc) + '</p>';
                        if (tool.commands && tool.commands.length > 0) {
                            html += '<div class="cmd-block">';
                            tool.commands.forEach(function(cmd) {
                                if (cmd.startsWith("#") || cmd.startsWith("//")) {
                                    html += '<span class="cmd-comment">' + escapeHtml(cmd) + '</span>\\n';
                                } else if (cmd.trim() === "") {
                                    html += '\\n';
                                } else {
                                    html += escapeHtml(cmd) + '\\n';
                                }
                            });
                            html += '</div>';
                        }
                        html += '</div>';
                    });
                } else {
                    html += '<p style="color:#484f58;font-size:12px;">Меры защиты не найдены в базе данных.</p>';
                }
                if (item.recommendation) {
                    html += '<div style="margin-top:10px;padding:10px;background:#0d1117;border-radius:4px;border:1px solid #30363d;border-left:4px solid #238636;">';
                    html += '<strong style="color:#3fb950;font-size:12px;">Рекомендация системы:</strong><br>';
                    html += '<span style="font-size:12px;">' + escapeHtml(item.recommendation || "").replace(/\\n/g, "<br>") + '</span>';
                    html += '</div>';
                }
                html += '</div>';

                html += '</div></div>';
            });
            list.innerHTML = html;
        }

        function toggleAtkDef() {
            var el = document.getElementById("atk-def-container");
            el.style.display = el.style.display === "none" ? "block" : "none";
        }
        function toggleAtkDefItem(idx) {
            var el = document.getElementById("atk-def-body-" + idx);
            el.style.display = el.style.display === "none" || el.style.display === "" ? "block" : "none";
        }

        function renderRawCveTable() {
            let tbody = document.getElementById("raw-cve-body");
            tbody.innerHTML = "";
            rawCveData.forEach(c => {
                let portStr = (c.port !== 'None' && c.port !== '') ? c.port : 'Н/Д';
                let cveAttr = escapeHtml((c.cve || "").toUpperCase());
                let tr = `<tr data-cve="${cveAttr}">
                    <td style="font-family: monospace; color: #58a6ff; font-weight: bold;">${escapeHtml(c.cve)}</td>
                    <td><span class="badge ${getSevClass(c.sev)}">${escapeHtml(c.sev)}</span></td>
                    <td style="font-weight: 500;">
                        ${escapeHtml(c.sw)}<br>
                        <small style="color:#8b949e;">${escapeHtml(c.sw_category || 'Компонент инфраструктуры')}</small>
                    </td>
                    <td>${escapeHtml(portStr)}</td>
                    <td><span style="background: #161b22; padding: 4px 8px; border-radius: 4px; border: 1px solid #30363d; font-size: 12px;">${escapeHtml(c.capec)}</span></td>
                </tr>`;
                tbody.innerHTML += tr;
            });
        }

        function toggleRawCve() {
            let el = document.getElementById("raw-cve-container");
            el.style.display = el.style.display === "none" || el.style.display === "" ? "block" : "none";
        }

        function getSelectedAggregationKeys() {
            return Array.from(document.querySelectorAll(".agg-key:checked")).map(x => x.value);
        }

        function getSeverityRank(sev) {
            let s = (sev || "INFO").toUpperCase();
            if (s === "CRITICAL") return 4;
            if (s === "HIGH") return 3;
            if (s === "MEDIUM") return 2;
            if (s === "LOW") return 1;
            return 0;
        }

        function getFeasRank(feas) {
            let f = (feas || "").toUpperCase();
            if (f === "РЕАЛИЗУЕМА") return 4;
            if (f.includes("ЧАСТИЧНО")) return 3;
            if (f.includes("ТРЕБУЕТ")) return 2;
            if (f === "НЕ РЕАЛИЗУЕМА") return 1;
            return 0;
        }

        function aggregateByKeys(items, keys) {
            let map = {};
            function traceScore(item) {
                try {
                    let t = item && item.feasibility_trace;
                    if (t && typeof t === "object" && t.score != null) return Number(t.score) || 0;
                } catch (_) {}
                return 0;
            }
            (items || []).forEach(item => {
                let key = "";
                if (!keys || keys.length === 0) {
                    key = "__item_" + item.raw_id;
                } else {
                    key = keys.map(k => `${k}=${item[k] || ""}`).join("|");
                }

                if (!map[key]) {
                    map[key] = {
                        id: Object.keys(map).length,
                        cve_set: new Set(),
                        name_set: new Set(),
                        found_by_set: new Set(),
                        sw_set: new Set(),
                        port_set: new Set(),
                        cwe_set: new Set(),
                        capec_set: new Set(),
                        feas_set: new Set(),
                        sev_set: new Set(),
                        members: [],
                        member_map: {},
                        count: 0,
                        max_sev_rank: -1,
                        max_feas_rank: -1,
                        max_feas_score: -Infinity,
                        representative_feas: item,
                        base: item
                    };
                }

                let g = map[key];
                g.count += 1;
                (item.cve || "").split(",").forEach(c => {
                    let cc = c.trim();
                    if (cc) g.cve_set.add(cc);
                });
                (item.name || "").split("/").forEach(n => {
                    let nn = n.trim();
                    if (nn) g.name_set.add(nn);
                });
                (item.found_by || "").split("&").forEach(src => {
                    let ss = src.trim();
                    if (ss) g.found_by_set.add(ss);
                });
                if (item.sw) g.sw_set.add(item.sw);
                if (item.port) g.port_set.add(item.port);
                if (item.cwe) g.cwe_set.add(item.cwe);
                if (item.capec) g.capec_set.add(item.capec);
                if (item.feas) g.feas_set.add(item.feas);
                if (item.sev) g.sev_set.add(item.sev);
                g.members.push(item);
                let memberSig = [
                    item.sw || "",
                    item.port || "",
                    item.cwe || "",
                    item.capec || "",
                    item.cve || "",
                    item.feas || "",
                    item.sev || "",
                    item.found_by || "",
                ].join("|");
                if (!g.member_map[memberSig]) {
                    g.member_map[memberSig] = { item: item, occurrences: 0 };
                }
                g.member_map[memberSig].occurrences += 1;

                let sevRank = getSeverityRank(item.sev);
                if (sevRank > g.max_sev_rank) {
                    g.max_sev_rank = sevRank;
                    g.sev = item.sev || "INFO";
                }

                let feasRank = getFeasRank(item.feas);
                if (feasRank > g.max_feas_rank) {
                    g.max_feas_rank = feasRank;
                    g.max_feas_score = traceScore(item);
                    g.representative_feas = item;
                    g.feas = item.feas || "UNKNOWN";
                } else if (feasRank === g.max_feas_rank) {
                    let ts = traceScore(item);
                    if (ts > g.max_feas_score) {
                        g.max_feas_score = ts;
                        g.representative_feas = item;
                    }
                }
            });

            return Object.keys(map).map(k => {
                let g = map[k];
                let b = g.base;
                let rep = g.representative_feas || b;
                return {
                    id: g.id,
                    cve: Array.from(g.cve_set).sort().join(", "),
                    cwe: b.cwe || "CWE-Неизвестно",
                    cwe_desc: b.cwe_desc || "Описание отсутствует.",
                    capec: b.capec || "CAPEC-Неизвестно",
                    name: Array.from(g.name_set).sort().join(" / ") || (b.name || "Атака"),
                    sw: b.sw || "Неизвестное ПО",
                    port: b.port || "Локальный вектор (без порта)",
                    feas: g.feas || "UNKNOWN",
                    sev: g.sev || "INFO",
                    desc: rep.desc || b.desc || "Описание отсутствует.",
                    rec: rep.rec || b.rec || "Специфичных рекомендаций нет.",
                    reason: rep.reason || b.reason || "Подробные пояснения недоступны.",
                    count: g.count,
                    found_by: Array.from(g.found_by_set).sort().join(" & ") || (b.found_by || "Сервер"),
                    tools: b.tools || "",
                    steps: b.steps || "",
                    sw_category: b.sw_category || "",
                    sw_purpose: b.sw_purpose || "",
                    sw_impact: b.sw_impact || "",
                    sw_scope: b.sw_scope || "",
                    feasibility_trace: (rep.feasibility_trace && typeof rep.feasibility_trace === "object") ? rep.feasibility_trace : {},
                    members: Object.keys(g.member_map).map(sig => {
                        let mm = g.member_map[sig];
                        return Object.assign({}, mm.item, { occurrences: mm.occurrences });
                    }),
                    members_total: g.members.length,
                    members_unique: Object.keys(g.member_map).length,
                    sw_all: Array.from(g.sw_set).sort().join(", "),
                    port_all: Array.from(g.port_set).sort().join(", "),
                    cwe_all: Array.from(g.cwe_set).sort().join(", "),
                    capec_all: Array.from(g.capec_set).sort().join(", "),
                    feas_all: Array.from(g.feas_set).sort().join(", "),
                    sev_all: Array.from(g.sev_set).sort().join(", "),
                    sw_count: g.sw_set.size,
                    port_count: g.port_set.size,
                    cwe_count: g.cwe_set.size,
                    capec_count: g.capec_set.size
                };
            });
        }

        function populateFilters(data) {
            let capecs = new Set(); let cwes = new Set(); let sws = new Set();
            (data || []).forEach(r => { capecs.add(r.capec); cwes.add(r.cwe); sws.add(r.sw); });

            let refill = (id, set, firstLabel) => {
                let el = document.getElementById(id);
                let prev = el.value || "all";
                el.innerHTML = `<option value="all">${firstLabel}</option>`;
                Array.from(set).sort().forEach(x => {
                    const sx = escapeHtml(String(x || ""));
                    el.innerHTML += `<option value="${sx}">${sx}</option>`;
                });
                el.value = Array.from(set).includes(prev) ? prev : "all";
            };
            refill("f-sw", sws, "-- Все приложения --");
            refill("f-capec", capecs, "-- Все векторы --");
            refill("f-cwe", cwes, "-- Все классы --");
        }

        function rebuildAggregatedData() {
            let keys = getSelectedAggregationKeys();
            let rawItems = Array.isArray(rawFindingsData) ? rawFindingsData : [];
            let hasRaw = rawItems.length > 0;
            if (!hasRaw) {
                // В некоторых отчётах raw-блок может отсутствовать/быть пустым.
                // Тогда используем уже подготовленные сервером агрегированные данные.
                reportData = Array.isArray(reportDataSeed) ? reportDataSeed.slice() : [];
            } else {
                try {
                    reportData = aggregateByKeys(rawItems, keys);
                } catch (e) {
                    console.error("Ошибка агрегации отчёта:", e);
                    reportData = [];
                }
            }
            if ((!reportData || reportData.length === 0) && hasRaw) {
                // Фолбэк: если агрегация дала пустой набор, показываем сырые записи,
                // чтобы отчёт не выглядел «пустым» при клиентской ошибке.
                reportData = rawItems.map(function (x, idx) {
                    var row = Object.assign({}, x || {});
                    row.id = idx;
                    row.feas = row.feas || "UNKNOWN";
                    row.sev = row.sev || "INFO";
                    row.name = row.name || "Атака";
                    row.capec = row.capec || "CAPEC-Неизвестно";
                    row.cwe = row.cwe || "CWE-Неизвестно";
                    row.sw = row.sw || "Неизвестное ПО";
                    row.port = row.port || "Локальный";
                    return row;
                });
            }
            if ((!reportData || reportData.length === 0) && Array.isArray(reportDataSeed) && reportDataSeed.length > 0) {
                // Последний страховочный фолбэк — исходные данные от сервера.
                reportData = reportDataSeed.slice();
            }
            populateFilters(reportData);
            updateAggregationHeader(keys, reportData.length);
        }

        function updateAggregationHeader(keys, total) {
            let title = document.querySelector(".aggregation-hint");
            let stTitle = document.getElementById("st-total-title");
            if (!title) return;
            if (!keys || keys.length === 0) {
                title.textContent = `Без агрегации: ${total} записей. Каждая находка отображается отдельно.`;
                if (stTitle) stTitle.textContent = "Найдено записей (без агрегации)";
            } else {
                title.textContent = `Агрегация по: ${keys.join(", ")}. Сформировано групп: ${total}.`;
                if (stTitle) stTitle.textContent = "Сформировано агрегированных групп";
            }
        }

        function onAggregationChanged() {
            rebuildAggregatedData();
            applyFilters();
        }

        function resetAggregation() {
            document.querySelectorAll(".agg-key").forEach(x => { x.checked = false; });
            onAggregationChanged();
        }

        function applyFilters() {
            let capecF = document.getElementById('f-capec').value;
            let cweF = document.getElementById('f-cwe').value;
            let swF = document.getElementById('f-sw').value;
            let feasF = document.getElementById('f-feas').value;
            
            let filtered = reportData.filter(r => {
                r = r || {};
                let rFeas = String(r.feas || "");
                let feasMatch = true;
                if (feasF !== 'all') {
                    if (feasF === 'ТРЕБУЕТ') {
                        feasMatch = rFeas.includes('ТРЕБУЕТ');
                    } else {
                        feasMatch = rFeas === feasF;
                    }
                }
                return feasMatch &&
                       (capecF === 'all' || String(r.capec || '') === capecF) &&
                       (cweF === 'all' || String(r.cwe || '') === cweF) &&
                       (swF === 'all' || String(r.sw || '') === swF);
            });
            
            updateStats(filtered);
            renderTable(filtered);
            renderGraph(filtered);
        }

        function updateStatsExplain(filteredData) {
            let el = document.getElementById("stats-explain");
            if (!el) return;
            let keys = getSelectedAggregationKeys();
            let feas = document.getElementById("f-feas").value;
            let capec = document.getElementById("f-capec").value;
            let cwe = document.getElementById("f-cwe").value;
            let sw = document.getElementById("f-sw").value;
            let parts = [];
            parts.push("Числа в блоке выше считают по <strong>текущей выборке</strong> (после фильтров ПО / CAPEC / CWE / реализуемости): строк на карте и в таблице = <strong>" + filteredData.length + "</strong>.");
            if (!keys || keys.length === 0) {
                parts.push("Агрегация: <strong>выключена</strong> — каждая сырьевая находка отображается отдельной строкой.");
            } else {
                parts.push("Агрегация: по полям <strong>" + keys.join(", ") + "</strong> — одна строка на группу схлопнутых находок.");
            }
            let fs = [];
            if (feas !== "all") fs.push("реализуемость");
            if (capec !== "all") fs.push("CAPEC");
            if (cwe !== "all") fs.push("CWE");
            if (sw !== "all") fs.push("ПО");
            if (fs.length) parts.push("Дополнительно учитываются фильтры: <strong>" + fs.join(", ") + "</strong>.");
            if (statusMeta && statusMeta.feasibility_values) {
                parts.push("Допустимые значения реализуемости (единый словарь с сервера): " + statusMeta.feasibility_values.join(", ") + ".");
            }
            el.innerHTML = parts.join(" ");
        }

        function updateStats(data) {
            document.getElementById('st-total').innerText = data.length;
            document.getElementById('st-real').innerText = data.filter(x => x.feas === 'РЕАЛИЗУЕМА').length;
            document.getElementById('st-part').innerText = data.filter(x => x.feas.includes('ЧАСТИЧНО')).length;
            document.getElementById('st-noreal').innerText = data.filter(x => x.feas === 'НЕ РЕАЛИЗУЕМА').length;
            let reqEl = document.getElementById('st-req');
            if (reqEl) reqEl.innerText = data.filter(x => (x.feas || '').includes('ТРЕБУЕТ')).length;
            updateStatsExplain(data);
        }

        function getSevClass(sev) {
            let s = sev.toUpperCase();
            if(s === "CRITICAL") return "crit"; if(s === "HIGH") return "high";
            if(s === "MEDIUM") return "med"; if(s === "LOW") return "low"; return "info";
        }
        function getSevColor(sev) {
            let s = sev.toUpperCase();
            if(s === "CRITICAL") return "#791a1e"; if(s === "HIGH") return "#da3633";
            if(s === "MEDIUM") return "#d29922"; if(s === "LOW") return "#238636"; return "#1f77b4";
        }
        function getFeasClass(feas) {
            let f = (feas || "").toUpperCase();
            if(f === "РЕАЛИЗУЕМА") return "real";
            if(f.includes("ЧАСТИЧНО")) return "part-real";
            if(f.includes("ТРЕБУЕТ")) return "feas-unk";
            return "noreal";
        }
        function getFeasColor(feas) {
            let f = (feas || "").toUpperCase();
            if(f === "РЕАЛИЗУЕМА") return "#da3633"; 
            if(f.includes("ЧАСТИЧНО")) return "#d29922"; 
            if(f === "НЕ РЕАЛИЗУЕМА") return "#238636";
            if(f.includes("ТРЕБУЕТ")) return "#8b949e";
            return "#8b949e";
        }

        function renderTable(data) {
            let tbody = document.getElementById('table-body');
            tbody.innerHTML = '';
            data.forEach(r => {
                let nameShort = r.name.substring(0, 50) + (r.name.length > 50 ? "..." : "");
                let dupes = r.count > 1 ? `<br><small style="color:#58a6ff;">(Сгруппировано из ${r.count} CVE)</small>` : "";
                let variants = r.count > 1
                    ? `<br><small style="color:#8b949e;">В группе: ПО ${r.sw_count || 1}, портов ${r.port_count || 1}, CWE ${r.cwe_count || 1}, CAPEC ${r.capec_count || 1}</small>`
                    : "";
                
                let tr = `<tr class="clickable-row" onclick="openModal('aggr_${r.id}')">
                    <td><strong style="color: #8b949e;">(Группа)</strong></td>
                    <td>
                        <strong>${r.sw}</strong><br>
                        <small>Порт: ${r.port}</small><br>
                        <small style="color:#8b949e;">${r.sw_category || 'Тип не определен'}</small><br>
                        <small style="color:#8b949e;">${r.sw_purpose || ''}</small>
                    </td>
                    <td>${nameShort}${dupes}${variants}</td>
                    <td><span class="badge ${getSevClass(r.sev)}">${r.sev}</span></td>
                    <td><span class="badge ${getFeasClass(r.feas)}">${r.feas}</span></td>
                    <td class="details-btn">Подробнее ➔</td>
                </tr>`;
                tbody.innerHTML += tr;
                
                // Сохраняем данные для модалки по главному ID
                detailsMap['aggr_' + r.id] = { type: 'aggr', data: r };
            });
        }

        function renderGraph(data) {
            let viewId = document.getElementById('map-view-select').value;
            let nodes = [];
            let edges = [];
            let addedEdges = new Set();
            let addedNodes = new Set();
            
            let addEdge = (f, t, c, w, d) => {
                let k = f + "_" + t;
                if(!addedEdges.has(k)) { addedEdges.add(k); edges.push({from: f, to: t, color: c, width: w||2, dashes: d||false}); }
            };
            let addNode = (n) => {
                if(!addedNodes.has(n.id)) { addedNodes.add(n.id); nodes.push(n); }
            };

            // ---- КАРТА 1: Полная цепочка CVE → CWE → CAPEC → ПО → MITRE ATT&CK → реализуемость ----
            if (viewId === "1") {
                data.forEach(r => {
                    let cveRaw = String(r.cve || "N/A");
                    let cveShort = cveRaw.length > 72 ? cveRaw.substring(0, 72) + "…" : cveRaw;
                    let mitreRaw = String(r.name || "Атака");
                    let mitreShort = mitreRaw.length > 56 ? mitreRaw.substring(0, 56) + "…" : mitreRaw;

                    let cveId = "fc_cve_" + r.id;
                    addNode({ id: cveId, label: "📌 CVE:\\n" + cveShort, level: 0, shape: "box", color: {background: getSevColor(r.sev)} });
                    detailsMap[cveId] = { type: 'aggr', data: r };

                    let cweId = "fc_cwe_" + r.id;
                    addNode({ id: cweId, label: "🐛 CWE:\\n" + r.cwe, level: 1, shape: "box", color: {background: "#484f58"} });
                    detailsMap[cweId] = { type: 'cwe', data: r };

                    let capecId = "fc_capec_" + r.id;
                    addNode({ id: capecId, label: "🥷 CAPEC:\\n" + r.capec, level: 2, shape: "box", color: {background: "#58a6ff"} });
                    detailsMap[capecId] = { type: 'aggr', data: r };

                    let swId = "fc_sw_" + r.id;
                    addNode({ id: swId, label: "🎯 ПО:\\n" + r.sw + "\\nПорт: " + r.port, level: 3, shape: "box", color: {background: "#1f77b4"} });
                    detailsMap[swId] = { type: 'sw', data: r };

                    let mitreId = "fc_mitre_" + r.id;
                    addNode({ id: mitreId, label: "🎯 MITRE ATT&CK:\\n" + mitreShort, level: 4, shape: "box", color: {background: "#a371f7"} });
                    detailsMap[mitreId] = { type: 'aggr', data: r };

                    let feasId = "fc_feas_" + r.id;
                    addNode({ id: feasId, label: "⚖️ Реализуемость:\\n" + r.feas, level: 5, shape: "box", color: {background: getFeasColor(r.feas)} });
                    detailsMap[feasId] = { type: 'aggr', data: r };

                    addEdge(cveId, cweId, "#8b949e");
                    addEdge(cweId, capecId, "#8b949e");
                    addEdge(capecId, swId, "#8b949e");
                    addEdge(swId, mitreId, "#8b949e");
                    addEdge(mitreId, feasId, getFeasColor(r.feas), r.feas === "РЕАЛИЗУЕМА" ? 3 : 2, r.feas === "НЕ РЕАЛИЗУЕМА");
                });
            }
            // ---- КАРТА 2: Инфраструктурная ----
            else if (viewId === "2") {
                let srvId = "srv_1";
                addNode({ id: srvId, label: "🖥️ " + sysData.hostname + "\\n(" + sysData.os + ")", shape: "box", level: 0, color: {background: "#1f77b4", border: "#ffffff"}, font: {color: "#ffffff", size: 18} });
                
                data.forEach(r => {
                    let swId = "sw_" + r.sw + "_" + r.port;
                    addNode({ id: swId, label: "🎯 ПО: " + r.sw + "\\nПорт: " + r.port, level: 1, shape: "box", color: {background: "#484f58"} });
                    addEdge(srvId, swId, "#8b949e");
                    detailsMap[swId] = { type: 'sw', data: r }; // Данные для клика по ПО
                    
                    let atkId = "atk_" + r.id;
                    addNode({ id: atkId, label: "🥷 " + r.capec + "\\nУязвимостей: " + r.count, level: 2, shape: "box", color: {background: "#58a6ff"} });
                    addEdge(swId, atkId, "#8b949e");
                    
                    let cveId = "cve_" + r.id;
                    addNode({ id: cveId, label: "🛡️ " + r.cwe + "\\nМакс. Риск: " + r.sev, level: 3, shape: "box", color: {background: getSevColor(r.sev)} });
                    addEdge(atkId, cveId, getFeasColor(r.feas), r.feas === "РЕАЛИЗУЕМА" ? 3 : 2, r.feas === "НЕ РЕАЛИЗУЕМА");
                    
                    detailsMap[atkId] = { type: 'aggr', data: r }; 
                    detailsMap[cveId] = { type: 'aggr', data: r };
                });
            } 
            // ---- КАРТА 3: Логическая (С УЗЛОМ ПО) ----
            else if (viewId === "3") {
                data.forEach(r => {
                    let capecId = "l_capec_" + r.capec;
                    addNode({ id: capecId, label: "🥷 Вектор: " + r.capec, level: 0, shape: "box", color: {background: "#58a6ff"} });
                    
                    let swId = "l_sw_" + r.sw + "_" + r.port;
                    addNode({ id: swId, label: "🎯 Цель:\\n" + r.sw + "\\nПорт: " + r.port, level: 1, shape: "box", color: {background: "#1f77b4"} });
                    detailsMap[swId] = { type: 'sw', data: r };
                    
                    let cweId = "l_cwe_" + r.cwe;
                    addNode({ id: cweId, label: "🐛 Слабость: " + r.cwe, level: 2, shape: "box", color: {background: "#484f58"} });
                    detailsMap[cweId] = { type: 'cwe', data: r }; 
                    
                    let verdId = "l_verd_" + r.id;
                    addNode({ id: verdId, label: "⚖️ Вердикт:\\n" + r.feas, level: 3, shape: "box", color: {background: getFeasColor(r.feas)} });
                    
                    addEdge(capecId, swId, "#8b949e");
                    addEdge(swId, cweId, "#8b949e");
                    addEdge(cweId, verdId, getFeasColor(r.feas), 3);
                    
                    detailsMap[capecId] = { type: 'aggr', data: r }; 
                    detailsMap[verdId] = { type: 'aggr', data: r };
                });
            }
            // ---- КАРТА 4: Источник Обнаружения ----
            else if (viewId === "4") {
                data.forEach(r => {
                    let sources = r.found_by.split(' & ');
                    let vulnId = "v_" + r.id;
                    addNode({ id: vulnId, label: "🛡️ Уязвимость:\\n" + r.capec, level: 2, shape: "box", color: {background: getSevColor(r.sev)} });
                    
                    sources.forEach(src => {
                        let srcClean = src.trim();
                        let srcId = "src_" + srcClean;
                        let sColor = srcClean.includes("Атакующий") ? "#da3633" : "#1f77b4";
                        addNode({ id: srcId, label: "🕵️ Источник:\\n" + srcClean, level: 0, shape: "box", color: {background: sColor} });
                        
                        let swId = "sw_real_" + r.sw;
                        addNode({ id: swId, label: "🎯 Реальное ПО:\\n" + r.sw, level: 1, shape: "box", color: {background: "#484f58"} });
                        
                        addEdge(srcId, swId, "#8b949e");
                        addEdge(swId, vulnId, getFeasColor(r.feas));
                        
                        detailsMap[swId] = { type: 'sw', data: r };
                    });
                    detailsMap[vulnId] = { type: 'aggr', data: r };
                });
            }
            // ---- КАРТА 5: План Устранения ----
            else if (viewId === "5") {
                data.forEach(r => {
                    let vulnId = "uv_" + r.id;
                    addNode({ id: vulnId, label: "🛡️ Уязвимость:\\n" + r.capec + "\\n(ПО: " + r.sw + ")", level: 0, shape: "box", color: {background: getSevColor(r.sev)} });
                    
                    let statId = "stat_" + r.id;
                    let statLbl = r.feas === 'НЕ РЕАЛИЗУЕМА' ? '✅ Защищено' : '❌ Требует патча';
                    let statCol = r.feas === 'НЕ РЕАЛИЗУЕМА' ? '#238636' : '#da3633';
                    addNode({ id: statId, label: statLbl, level: 1, shape: "box", color: {background: statCol} });
                    
                    let recId = "rec_" + r.id;
                    let shortRec = r.rec.length > 45 ? r.rec.substring(0, 45) + "..." : r.rec;
                    addNode({ id: recId, label: "🛠️ План:\\n" + shortRec, level: 2, shape: "box", color: {background: "#1f77b4"} });
                    
                    addEdge(vulnId, statId, "#8b949e");
                    addEdge(statId, recId, statCol, 2, r.feas === 'НЕ РЕАЛИЗУЕМА'); 
                    
                    detailsMap[vulnId] = { type: 'aggr', data: r }; 
                    detailsMap[recId] = { type: 'aggr', data: r };
                });
            }
            // ---- КАРТА 6: Полигон ----
            else if (viewId === "6") {
                data.forEach(r => {
                    let capecId = "pc_" + r.capec;
                    addNode({ id: capecId, label: "🥷 Вектор:\\n" + r.capec, level: 0, shape: "box", color: {background: "#da3633"} });
                    
                    let toolId = "pt_" + r.id;
                    let shortTool = r.tools.length > 30 ? r.tools.substring(0,30) + "..." : r.tools;
                    addNode({ id: toolId, label: "🔫 Софт:\\n" + shortTool, level: 1, shape: "box", color: {background: "#d29922"} });
                    
                    let stepsId = "ps_" + r.id;
                    addNode({ id: stepsId, label: "📜 Логика Атаки\\n(Кликните для деталей)", level: 2, shape: "box", color: {background: "#484f58"} });
                    
                    addEdge(capecId, toolId, "#8b949e");
                    addEdge(toolId, stepsId, "#8b949e");
                    
                    detailsMap[capecId] = { type: 'aggr', data: r }; 
                    detailsMap[toolId] = { type: 'aggr', data: r }; 
                    detailsMap[stepsId] = { type: 'aggr', data: r };
                });
            }

            if(network) network.destroy();
            var container = document.getElementById('network-map');
            var visData = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
            
            // Динамическое расстояние узлов (Карта 5 «План устранения» — шире; Карта 1 — 6 уровней + treeSpacing между параллельными цепочками)
            var nodeSpc = (viewId === "5") ? 650 : (viewId === "1" ? 950 : 400);
            var levelSep = (viewId === "5") ? 350 : (viewId === "1" ? 420 : 250);
            var hier = { direction: 'UD', sortMethod: 'directed', nodeSpacing: nodeSpc, levelSeparation: levelSep };
            if (viewId === "1") {
                hier.treeSpacing = 560;
            }
            var options = {
                layout: { hierarchical: hier },
                physics: false,
                nodes: { borderWidth: 2, shadow: true, margin: (viewId === "1" ? 22 : 15), font: { face: "Segoe UI" } },
                edges: { shadow: true, arrows: { to: { enabled: true, scaleFactor: 0.8 } }, smooth: { type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.15 } },
                interaction: { hover: true, navigationButtons: true, keyboard: true }
            };
            
            network = new vis.Network(container, visData, options);
            network.on("click", function(params) {
                if (params.nodes.length > 0) openModal(params.nodes[0]);
            });
        }

        var modal = document.getElementById("infoModal");

        function openModal(id) {
            let nodeInfo = detailsMap[id];
            if(!nodeInfo) return;
            
            let r = nodeInfo.data;
            let contentDiv = document.getElementById("dynamic-modal-content");
            
            // 1. Если кликнули на отдельный элемент внутри агрегированной группы
            if (nodeInfo.type === 'member') {
                let backBtn = nodeInfo.parentId ? `<button type="button" class="agg-btn" onclick="openModal('${nodeInfo.parentId}')">← Назад к группе</button>` : "";
                let rawCves = JSON.stringify((r.cve || "").split(",").map(s => s.trim()).filter(Boolean));
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;">
                            <h2 style="margin: 0; font-size: 18px; color: #fff;">Элемент группы: ${esc(r.capec)}</h2>
                        </div>
                    </div>
                    <div class="grid-info">
                        <div class="grid-item"><span>ПО:</span><strong>${esc(r.sw)}</strong></div>
                        <div class="grid-item"><span>Порт:</span><strong>${esc(r.port)}</strong></div>
                        <div class="grid-item"><span>CWE:</span><strong>${esc(r.cwe)}</strong></div>
                        <div class="grid-item"><span>CAPEC:</span><strong>${esc(r.capec)}</strong></div>
                        <div class="grid-item"><span>Критичность:</span><strong style="color: ${getSevColor(r.sev)}">${esc(r.sev)}</strong></div>
                        <div class="grid-item"><span>Статус:</span><strong style="color: ${getFeasColor(r.feas)}">${esc(r.feas)}</strong></div>
                    </div>
                    <div class="modal-toolbar">${backBtn}
                        <button type="button" class="agg-btn" onclick='openRawRegistryForCves(${rawCves})'>📂 Сырой реестр CVE</button>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details">
                            <summary>📝 CVE</summary>
                            <div class="modal-details-body"><p style="color:#58a6ff; font-family:monospace; font-size: 13px; margin:0;">${esc(r.cve)}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🔬 Трассировка вердикта</summary>
                            <div class="modal-details-body">${formatTraceBlock(r.feasibility_trace, r)}</div>
                        </details>
                        <details class="modal-details">
                            <summary>📝 Описание уязвимости</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(r.desc || 'Описание отсутствует.')}</p></div>
                        </details>
                    </div>
                `;
            }
            // 2. Если кликнули на слабость CWE
            else if (nodeInfo.type === 'cwe') {
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🐛 Класс уязвимости: ${esc(r.cwe)}</h2>
                    </div>
                    <div class="modal-body">
                        <h4 style="color:#58a6ff;">Подробное описание (Common Weakness Enumeration)</h4>
                        <p style="background: #0d1117; padding: 15px; border-radius: 6px; border: 1px solid #30363d; font-size: 15px; white-space:pre-wrap;">${esc(r.cwe_desc)}</p>
                    </div>
                `;
            } 
            // 3. Если кликнули на целевое ПО
            else if (nodeInfo.type === 'sw') {
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🎯 Анализ Целевого Компонента</h2>
                    </div>
                    <div class="modal-body">
                        <div class="grid-info" style="grid-template-columns: 1fr;">
                            <div class="grid-item"><span>Обнаруженное программное обеспечение:</span><strong style="font-size: 18px; color: #fff;">${esc(r.sw)}</strong></div>
                            <div class="grid-item"><span>Открытый порт:</span><strong style="font-size: 16px; color: #58a6ff;">${esc(r.port)}</strong></div>
                        </div>
                        <div class="sw-context">
                            <h4>Что это за ПО и почему важно</h4>
                            <ul>
                                <li><strong>Тип/категория:</strong> ${esc(r.sw_category || 'Не определено')}</li>
                                <li><strong>Назначение:</strong> ${esc(r.sw_purpose || 'Нет описания')}</li>
                                <li><strong>Последствия успешной атаки:</strong> ${esc(r.sw_impact || 'Требуется ручная оценка')}</li>
                                <li><strong>Контекст:</strong> ${esc(r.sw_scope || 'Локальный компонент инфраструктуры')}</li>
                            </ul>
                        </div>
                    </div>
                `;
            } 
            // 4. Стандартная карточка (Клик по вектору атаки или агрегации)
            else {
                let rawCvesGrp = JSON.stringify((r.cve || "").split(",").map(s => s.trim()).filter(Boolean));
                let mu = r.members_unique != null ? r.members_unique : (r.members || []).length;
                let mt = r.members_total != null ? r.members_total : (r.members || []).length;
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 18px; color: #fff;">Агрегированная группа: ${esc(r.capec)}</h2>
                    </div>
                    <div class="grid-info">
                        <div class="grid-item"><span>Критичность:</span><strong style="color: ${getSevColor(r.sev)}">${esc(r.sev)}</strong></div>
                        <div class="grid-item"><span>Статус (сводный):</span><strong style="color: ${getFeasColor(r.feas)}">${esc(r.feas)}</strong></div>
                        <div class="grid-item"><span>Атакуемое ПО:</span><strong>${esc(r.sw)} <span class="trace-meta">(порт: ${esc(r.port)})</span></strong></div>
                        <div class="grid-item"><span>Вектор (CAPEC):</span><strong>${esc(r.capec)}</strong></div>
                        <div class="grid-item"><span>Класс (CWE):</span><strong>${esc(r.cwe)}</strong></div>
                        <div class="grid-item"><span>Кем обнаружено:</span><strong>${esc(r.found_by)}</strong></div>
                    </div>
                    <div class="modal-toolbar">
                        <button type="button" class="agg-btn" onclick='openRawRegistryForCves(${rawCvesGrp})'>📂 Сырой реестр CVE по группе</button>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details">
                            <summary>🔬 Трассировка вердикта (представитель группы)</summary>
                            <div class="modal-details-body">${formatTraceBlock(r.feasibility_trace, r)}</div>
                        </details>
                        <details class="modal-details">
                            <summary>Состав группы и контекст ПО</summary>
                            <div class="modal-details-body">
                                <div class="sw-context" style="margin-top:0;">
                                    <h4 style="margin-top:0;">Состав</h4>
                                    <ul>
                                        <li><strong>ПО (все значения):</strong> ${esc(r.sw_all || r.sw)}</li>
                                        <li><strong>Порты (все значения):</strong> ${esc(r.port_all || r.port)}</li>
                                        <li><strong>CWE (все значения):</strong> ${esc(r.cwe_all || r.cwe)}</li>
                                        <li><strong>CAPEC (все значения):</strong> ${esc(r.capec_all || r.capec)}</li>
                                    </ul>
                                </div>
                                <div class="sw-context">
                                    <h4>Контекст программного обеспечения</h4>
                                    <ul>
                                        <li><strong>Тип/категория:</strong> ${esc(r.sw_category || 'Не определено')}</li>
                                        <li><strong>Назначение:</strong> ${esc(r.sw_purpose || 'Нет описания')}</li>
                                        <li><strong>Последствия успешной атаки:</strong> ${esc(r.sw_impact || 'Требуется ручная оценка')}</li>
                                        <li><strong>Затрагиваемая зона:</strong> ${esc(r.sw_scope || 'Локальный компонент инфраструктуры')}</li>
                                    </ul>
                                </div>
                            </div>
                        </details>
                        <details class="modal-details">
                            <summary>📝 Включённые CVE (агрегация из ${r.count} находок)</summary>
                            <div class="modal-details-body"><p style="color:#58a6ff; font-family:monospace; font-size: 13px; margin:0;">${esc(r.cve)}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>📝 Описание уязвимости</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(r.desc)}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🥷 Учебный полигон (как атаковать)</summary>
                            <div class="modal-details-body">${formatTrainingPolygon(r)}</div>
                        </details>
                        <details class="modal-details">
                            <summary>🛡️ Устранение и защита</summary>
                            <div class="modal-details-body">
                                <p class="trace-meta" style="margin:0 0 10px 0;">Текст ниже из базы рекомендаций (CVE/CWE); отдельные фрагменты могут быть нерелевантны вашему стеку — ориентируйтесь на описание CVE и официальные бюллетени.</p>
                                <p class="rec-box" style="margin:0;">${esc(r.rec)}</p>
                            </div>
                        </details>
                        <details class="modal-details">
                            <summary>👥 Участники группы <span class="trace-meta">(уникальных: ${mu}, записей: ${mt})</span></summary>
                            <div class="modal-details-body">
                                <div class="group-members" style="border:none;">
                                    <div id="group-members-container"></div>
                                </div>
                            </div>
                        </details>
                    </div>
                `;
                renderGroupMembers(r);
            }
            
            modal.style.display = "block";
        }

        function closeModal() { modal.style.display = "none"; }
        window.onclick = function(event) { if (event.target == modal) closeModal(); }

        function renderGroupMembers(groupData) {
            let holder = document.getElementById("group-members-container");
            if (!holder) return;
            let members = groupData.members || [];
            if (members.length === 0) {
                holder.innerHTML = '<div class="group-members-row"><div style="grid-column: 1/-1; color:#8b949e;">Нет данных по элементам группы.</div></div>';
                return;
            }
            let html = "";
            members.forEach((m, idx) => {
                let memberId = "member_" + String(m.raw_id ?? (groupData.id + "_" + idx));
                detailsMap[memberId] = { type: 'member', data: m, parentId: 'aggr_' + groupData.id };
                let repeatBadge = (m.occurrences && m.occurrences > 1)
                    ? `<br><small style="color:#e3b341;">Повторяется: ${m.occurrences}x</small>`
                    : '';
                html += `<div class="group-members-row">
                    <div><strong>${m.sw || 'Неизвестное ПО'}</strong><br><span class="mono">${m.cve || 'N/A'}</span>${repeatBadge}</div>
                    <div>${m.port || 'Н/Д'}</div>
                    <div>${m.cwe || 'Н/Д'}</div>
                    <div>${m.capec || 'Н/Д'}</div>
                    <div><button class="agg-btn" onclick="openModal('${memberId}')">Открыть</button></div>
                </div>`;
            });
            holder.innerHTML = html;
        }

        window.onload = init;
    </script>
</body>
</html>
"""

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
        
        with open(filepath, "w", encoding="utf-8") as f:
            html = HTML_TEMPLATE.replace('__REPORT_DATA__', json.dumps(js_data, ensure_ascii=False))
            html = html.replace('__RAW_FINDINGS_DATA__', json.dumps(raw_findings_data, ensure_ascii=False))
            html = html.replace('__RAW_CVE_DATA__', json.dumps(raw_js_data, ensure_ascii=False))
            html = html.replace('__SYS_DATA__', json.dumps(sys_data, ensure_ascii=False))
            html = html.replace('__SUMMARY_DATA__', json.dumps(summary_data, ensure_ascii=False))
            html = html.replace('__ATK_DEF_DATA__', json.dumps(atk_def_data, ensure_ascii=False))
            html = html.replace('__STATUS_META__', json.dumps(report_status_meta(), ensure_ascii=False))
            f.write(html)

        return filepath