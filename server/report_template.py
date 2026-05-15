# server/report_template.py

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
        .mini-btn { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; padding: 6px 10px; border-radius: 6px; cursor: pointer; font-size: 12px; transition: 0.15s; }
        .mini-btn:hover { background: #30363d; }
        .mini-btn.primary { border-color: #58a6ff; color: #58a6ff; }
        .mini-btn.success { border-color: #238636; color: #3fb950; }

        /* Улучшенные рекомендации и карточки защиты */
        .rec-structured { background: #0d1117; border-radius: 6px; padding: 15px; margin-top: 15px; border: 1px solid #30363d; border-left: 4px solid #238636; }
        .rec-alert { background: rgba(218,54,51,0.1); border-left: 4px solid #da3633; padding: 12px; border-radius: 4px; margin-bottom: 15px; }
        .rec-monitor { background: rgba(88,166,255,0.1); border-left: 4px solid #58a6ff; padding: 12px; border-radius: 4px; margin-bottom: 15px; }
        .rec-list { display: flex; flex-direction: column; gap: 8px; margin-top: 10px; }
        .rec-item { background: #161b22; padding: 10px 15px; border-radius: 6px; border: 1px solid #21262d; font-size: 13px; color: #c9d1d9; line-height: 1.5; cursor: pointer; transition: 0.2s;}
        .rec-item:hover { background: #1f2428; border-color: #3fb950; }
        .rec-item-num { font-weight: bold; color: #3fb950; margin-right: 8px; }
        
        .tool-link { color: #58a6ff; text-decoration: none; font-size: 12px; display: inline-block; margin-left: 10px; }
        .tool-link:hover { text-decoration: underline; }
        .cmd-explain { background: #010409; border-left: 3px solid #d29922; padding: 8px 12px; margin-top: -10px; margin-bottom: 10px; font-size: 12px; color: #8b949e; border-radius: 0 0 6px 6px; font-family: monospace;}

        /* Раздел атак и защиты */
        .atk-def-item { margin-bottom: 15px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .atk-def-header { padding: 12px 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: background 0.15s; }
        .atk-def-header:hover { background: #1f2428; }
        .atk-def-body { display: none; padding: 15px; border-top: 1px solid var(--border); background: #0d1117; }
        .atk-section { border-left: 4px solid #da3633; padding: 15px; margin: 8px 0; background: rgba(218,54,51,0.03); border-radius: 0 6px 6px 0; }
        .def-section { border-left: 4px solid #238636; padding: 15px; margin: 8px 0; background: rgba(35,134,54,0.03); border-radius: 0 6px 6px 0; }
        
        /* Пошаговые карточки атаки */
        .step-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
        .step-header { font-size: 15px; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }
        .step-num { background: #da3633; color: #fff; padding: 2px 8px; border-radius: 12px; font-weight: bold; font-size: 12px; }
        .step-title { color: #58a6ff; font-weight: 600; }
        
        .cmd-block { background: #010409; color: #00dd00; padding: 12px; border-radius: 6px; font-family: "Consolas", monospace; font-size: 13px; overflow-x: auto; white-space: pre-wrap; margin: 10px 0; border: 1px solid #21262d; line-height: 1.6; }
        .cmd-comment { color: #8b949e; }
        .cmd-highlight { color: #00dd00; }
        
        /* Обратная связь (комментарии) */
        .step-feedback { margin-top: 12px; display: flex; gap: 10px; align-items: center; background: #0d1117; padding: 10px; border-radius: 6px; border: 1px dashed #30363d; }
        .step-feedback input { flex: 1; background: #161b22; border: 1px solid #484f58; color: #c9d1d9; padding: 8px 12px; border-radius: 4px; font-size: 13px; outline: none; transition: 0.2s; }
        .step-feedback input:focus { border-color: #da3633; box-shadow: 0 0 5px rgba(218,54,51,0.3); }
        .step-feedback label { font-size: 12px; color: #8b949e; font-weight: bold; cursor: help; }
        
        /* Кнопка генерации отчета */
        .btn-report-bugs { background: #5a2a2a; color: #fff; border: 1px solid #791a1e; padding: 12px 20px; border-radius: 6px; font-weight: bold; font-size: 14px; cursor: pointer; transition: 0.2s; display: block; margin: 0 0 20px 0; width: 100%; text-align: center; }
        .btn-report-bugs:hover { background: #791a1e; box-shadow: 0 2px 8px rgba(218,54,51,0.4); }

        .tool-badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-right: 6px; }
        .tool-def { background: rgba(35,134,54,0.15); color: #3fb950; border: 1px solid #238636; }

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
        .verified { background: rgba(35, 134, 54, 0.15); color: #3fb950; border: 1px solid #238636; }
        .not-verified { background: rgba(139, 148, 158, 0.15); color: #8b949e; border: 1px solid #8b949e; }
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
                        <option value="1_1">🗺️ КАРТА 1.1: Asset-Centric (ПО ➔ CVE ➔ CWE ➔ CAPEC ➔ MITRE ➔ Реализуемость)</option>
                        <option value="1_2">🗺️ КАРТА 1.2: Attacker-Centric (MITRE ➔ CAPEC ➔ CWE ➔ CVE ➔ ПО ➔ Реализуемость)</option>
                        <option value="1_3">🗺️ КАРТА 1.3: Causal Chain (CWE ➔ CVE ➔ ПО ➔ CAPEC ➔ MITRE ➔ Реализуемость)</option>
                        <option value="2">🗺️ КАРТА 2: Логика Атаки (CAPEC ➔ ПО ➔ CWE ➔ Вердикт)</option>
                        <option value="3">🗺️ КАРТА 3: Источник Обнаружения (Кто нашел ➔ Реальное ПО ➔ Уязвимость)</option>
                        <option value="4">🗺️ КАРТА 4: План Устранения (Уязвимость ➔ Статус ➔ Решение)</option>
                        <option value="5">🗺️ КАРТА 5: Полигон и Инструменты (CAPEC ➔ ПО для атаки ➔ Шаги)</option>
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

        <div class="card" style="border-left: 4px solid #d29922;">
            <div class="header-flex">
                <div>
                    <h2 style="margin:0; border:none;">⚔️ Реализуемые атаки и меры противодействия</h2>
                    <p style="margin: 5px 0 0 0; font-size: 13px; color: #8b949e;">Детальные инструкции по воспроизведению атак (Red Team) и рекомендации по защите (Blue Team) с конкретными командами.</p>
                </div>
                <button class="btn-toggle btn-orange" onclick="toggleAtkDef()">⚔️ Развернуть раздел</button>
            </div>
            <div id="atk-def-container" style="display:none;">
                <button class="btn-report-bugs" onclick="generateBugReport()">🐞 Сгенерировать отчёт об ошибках в сценариях (Markdown)</button>
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
    <div id="editModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeEditModal()">&times;</span>
            <div class="modal-header">
                <h3 style="margin:0; color:#fff;">Редактор шага (Киберполигон)</h3>
            </div>
            <div class="modal-body" id="edit-modal-body"></div>
            <div class="modal-toolbar" style="justify-content:flex-end;">
                <button type="button" class="mini-btn" onclick="closeEditModal()">Отмена</button>
                <button type="button" class="mini-btn primary" onclick="saveEditModal()">Сохранить в БД</button>
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
        var capecMeta = __CAPEC_META__;
        var cveMeta = __CVE_META__;
        var mitreMeta = __MITRE_META__;
        var API_BASE = "http://127.0.0.1:__SERVER_PORT__";
        var network = null;
        var detailsMapRows = {};
        var detailsMapNodes = {};
        function lookupDetails(id) {
            return detailsMapNodes[id] || detailsMapRows[id];
        }

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
                var redVerClass = item.attack_verified ? "verified" : "not-verified";
                var blueVerClass = item.defense_verified ? "verified" : "not-verified";
                html += '<div class="atk-def-item">';
                html += '<div class="atk-def-header" onclick="toggleAtkDefItem(' + idx + ')" style="background:#161b22;">';
                html += '<div><span class="badge ' + sevClass + '" style="margin-right:8px;">' + escapeHtml(item.sev) + '</span>';
                html += '<span class="badge ' + feasClass + '" style="margin-right:8px;">' + escapeHtml(item.feas) + '</span>';
                html += '<span class="badge ' + redVerClass + '" onclick="if(window.event) window.event.stopPropagation(); toggleVerifiedAll(' + idx + ', \\'red\\')" style="margin-right:8px; cursor:pointer;" title="Нажмите, чтобы отметить Red Team сценарий как проверенный">🥷 ' + (item.attack_verified ? "Проверено" : "Не проверено") + '</span>';
                html += '<span class="badge ' + blueVerClass + '" onclick="if(window.event) window.event.stopPropagation(); toggleVerifiedAll(' + idx + ', \\'blue\\')" style="margin-right:8px; cursor:pointer;" title="Нажмите, чтобы отметить Blue Team меры как проверенные">🛡️ ' + (item.defense_verified ? "Проверено" : "Не проверено") + '</span>';
                html += '<strong style="color:#fff;">' + escapeHtml(item.sw) + '</strong>';
                html += ' <span style="color:#8b949e;"> — ' + escapeHtml(item.capec) + ' (' + escapeHtml(item.cve_short) + ')</span></div>';
                html += '<span style="color:#58a6ff;font-size:12px;">▼ Раскрыть сценарий</span>';
                html += '</div>';
                html += '<div class="atk-def-body" id="atk-def-body-' + idx + '">';

                // --- RED TEAM (Атака) ---
                html += '<div class="atk-section">';
                html += '<div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:12px;">';
                html += '<h4 style="color:#da3633;margin:0;font-size:16px;">🥷 Пошаговый сценарий эксплуатации (Red Team)</h4>';
                html += '<button type="button" class="mini-btn" onclick="addNewStep(' + idx + ', \\'red\\')">➕ Добавить шаг</button>';
                html += '</div>';
                
                if (item.attack_tools && item.attack_tools.length > 0) {
                    let stepNum = 1;
                    item.attack_tools.forEach(function(tool, toolIdx) {
                        let feedbackId = `fb_red_${idx}_${stepNum}`;
                        html += '<div class="step-card">';
                        
                        html += '<div class="step-header">';
                        html += '<span class="step-num">Шаг ' + stepNum + '</span>';
                        html += '<span class="step-title">' + escapeHtml(tool.name) + '</span>';
                        html += '<span style="margin-left:auto; display:flex; gap:8px; align-items:center;">';
                        html += '<button type="button" class="mini-btn" onclick="if(window.event) window.event.stopPropagation(); openEditModal(\\'red\\',' + idx + ',' + toolIdx + ');">✏️</button>';
                        html += '<button type="button" class="mini-btn success" onclick="if(window.event) window.event.stopPropagation(); toggleStepVerified(\\'red\\',' + idx + ',' + toolIdx + ');" title="Отметить шаг как проверенный">✅</button>';
                        html += '</span>';
                        if (tool.url) html += `<a href="${tool.url}" target="_blank" class="tool-link">🔗 Официальный сайт/Документация</a>`;
                        if (tool.skill) html += '<span style="color:#8b949e;font-size:11px;margin-left:auto;">Уровень: ' + escapeHtml(tool.skill) + '</span>';
                        html += '</div>';
                        
                        if (tool.desc) html += '<p style="font-size:13px;color:#c9d1d9;margin:8px 0;line-height:1.5;">' + escapeHtml(tool.desc) + '</p>';
                        
                        if (tool.commands && tool.commands.length > 0) {
                            html += '<div class="cmd-block" id="cmd_' + feedbackId + '">';
                            tool.commands.forEach(function(cmd) {
                                if (cmd.startsWith("#") || cmd.startsWith("//")) {
                                    html += '<span class="cmd-comment">' + escapeHtml(cmd) + '</span>\\n';
                                } else if (cmd.trim() !== "") {
                                    html += '<span class="cmd-highlight">' + escapeHtml(cmd) + '</span>\\n';
                                    // Если есть пояснение к команде (имитация из БД)
                                    if (tool.cmd_explanations && tool.cmd_explanations[cmd]) {
                                        html += `</div><div class="cmd-explain">ℹ️ <b>Пояснение:</b> ${escapeHtml(tool.cmd_explanations[cmd])}</div><div class="cmd-block">`;
                                    }
                                }
                            });
                            html += '</div>';
                        }
                        
                        // Обратная связь Red Team
                        html += '<div class="step-feedback">';
                        html += '<label>📝 Ошибка в шаге атаки?</label>';
                        html += `<input type="text" id="${feedbackId}" class="bug-feedback-input" data-team="Red" data-cve="${escapeHtml(item.cve_short)}" data-sw="${escapeHtml(item.sw)}" data-step="${stepNum}" data-tool="${escapeHtml(tool.name)}" placeholder="Напишите, что не так (неверный флаг, нет доступа)...">`;
                        html += '</div>';
                        html += '</div>';
                        stepNum++;
                    });
                } else {
                    html += '<p style="color:#484f58;font-size:13px;">Инструменты атаки не найдены в базе данных.</p>';
                }
                html += '</div>';

                // --- BLUE TEAM (Защита) ---
                html += '<div class="def-section">';
                html += '<div style="display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:12px;">';
                html += '<h4 style="color:#3fb950;margin:0;font-size:16px;">🛡️ Меры противодействия (Blue Team)</h4>';
                html += '<button type="button" class="mini-btn" onclick="addNewStep(' + idx + ', \\'blue\\')">➕ Добавить шаг</button>';
                html += '</div>';
                
                if (item.defense_tools && item.defense_tools.length > 0) {
                    let defStepNum = 1;
                    item.defense_tools.forEach(function(tool, toolIdx) {
                        let feedbackId = `fb_blue_${idx}_${defStepNum}`;
                        html += '<div class="step-card" style="border-left: 3px solid #238636;">';
                        
                        html += '<div class="step-header">';
                        html += '<span class="step-title" style="color:#3fb950;">' + escapeHtml(tool.name) + '</span>';
                        html += '<span style="margin-left:auto; display:flex; gap:8px; align-items:center;">';
                        html += '<button type="button" class="mini-btn" onclick="if(window.event) window.event.stopPropagation(); openEditModal(\\'blue\\',' + idx + ',' + toolIdx + ');">✏️</button>';
                        html += '<button type="button" class="mini-btn success" onclick="if(window.event) window.event.stopPropagation(); toggleStepVerified(\\'blue\\',' + idx + ',' + toolIdx + ');" title="Отметить шаг как проверенный">✅</button>';
                        html += '</span>';
                        if (tool.priority) html += '<span style="color:#8b949e;font-size:11px;margin-left:auto;"> Приоритет: ' + escapeHtml(tool.priority) + '</span>';
                        html += '</div>';
                        
                        if (tool.desc) html += '<p style="font-size:13px;color:#c9d1d9;margin:8px 0;">' + escapeHtml(tool.desc) + '</p>';
                        
                        if (tool.commands && tool.commands.length > 0) {
                            html += '<div class="cmd-block" id="cmd_' + feedbackId + '" style="color:#e6edf3; border-color:#238636;">';
                            tool.commands.forEach(function(cmd) {
                                html += escapeHtml(cmd) + '\\n';
                            });
                            html += '</div>';
                        }
                        
                        // Обратная связь Blue Team
                        html += '<div class="step-feedback" style="border-color:#238636;">';
                        html += '<label>📝 Ошибка в конфигурации/команде защиты?</label>';
                        html += `<input type="text" id="${feedbackId}" class="bug-feedback-input" data-team="Blue" data-cve="${escapeHtml(item.cve_short)}" data-sw="${escapeHtml(item.sw)}" data-step="${defStepNum}" data-tool="${escapeHtml(tool.name)}" placeholder="Например: эта команда ломает прод, нужен другой синтаксис...">`;
                        html += '</div>';
                        html += '</div>';
                        defStepNum++;
                    });
                }
                
                // Умный парсер стены текста рекомендаций
                if (item.recommendation) {
                    html += parseAndFormatRecommendations(item.recommendation);
                }
                
                html += '</div>'; // Конец def-section
                html += '</div></div>';
            });
            list.innerHTML = html;
        }

        async function postJson(url, data) {
            const res = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data || {})
            });
            const text = await res.text();
            let parsed = {};
            try { parsed = JSON.parse(text); } catch (e) { parsed = { raw: text }; }
            if (!res.ok) {
                const msg = parsed && parsed.error ? parsed.error : ("HTTP " + res.status);
                throw new Error(msg);
            }
            return parsed;
        }

        var editState = null;
        function openEditModal(team, idx, toolIdx) {
            editState = { team: team, idx: idx, toolIdx: toolIdx };
            var item = atkDefData[idx] || {};
            var tool = (team === "red" ? (item.attack_tools || [])[toolIdx] : (item.defense_tools || [])[toolIdx]) || {};
            var cmds = Array.isArray(tool.commands) ? tool.commands.join("\\n") : String(tool.commands || "");
            var name = String(tool.name || "");
            var desc = String(tool.desc || "");
            var verified = Boolean(tool.verified);
            var h = '';
            h += '<div class="grid-info" style="grid-template-columns: 1fr 1fr; margin-bottom: 14px;">';
            h += '<div class="grid-item"><span>Команда</span><strong>' + (team === "red" ? "Red Team" : "Blue Team") + '</strong></div>';
            h += '<div class="grid-item"><span>CVE</span><strong>' + escapeHtml(item.cve_primary || "N/A") + '</strong></div>';
            h += '</div>';
            h += '<div style="display:flex; flex-direction:column; gap:10px;">';
            h += '<div><label style="font-size:12px;color:#8b949e;font-weight:bold;text-transform:uppercase;">Название шага</label>';
            h += '<input id="edit_name" style="width:100%; margin-top:6px; background:#161b22; border:1px solid #30363d; color:#c9d1d9; padding:10px; border-radius:6px;" value="' + escapeHtml(name) + '"></div>';
            h += '<div><label style="font-size:12px;color:#8b949e;font-weight:bold;text-transform:uppercase;">Описание</label>';
            h += '<textarea id="edit_desc" style="width:100%; margin-top:6px; background:#161b22; border:1px solid #30363d; color:#c9d1d9; padding:10px; border-radius:6px; min-height:80px;">' + escapeHtml(desc) + '</textarea></div>';
            h += '<div><label style="font-size:12px;color:#8b949e;font-weight:bold;text-transform:uppercase;">Команды (по строкам)</label>';
            h += '<textarea id="edit_cmds" style="width:100%; margin-top:6px; background:#010409; border:1px solid #30363d; color:#c9d1d9; padding:10px; border-radius:6px; min-height:200px; font-family:Consolas,monospace; font-size:12px;">' + escapeHtml(cmds) + '</textarea></div>';
            h += '<div style="display:flex; align-items:center; gap:10px;">';
            h += '<input id="edit_verified" type="checkbox" ' + (verified ? "checked" : "") + ' style="transform:scale(1.15); accent-color:#3fb950;">';
            h += '<label for="edit_verified" style="font-size:13px;color:#c9d1d9;cursor:pointer;">Отметить как проверено</label>';
            h += '</div>';
            h += '</div>';
            document.getElementById("edit-modal-body").innerHTML = h;
            document.getElementById("editModal").style.display = "block";
        }

        function closeEditModal() {
            document.getElementById("editModal").style.display = "none";
            editState = null;
        }

        async function saveEditModal() {
            if (!editState) return;
            var team = editState.team;
            var idx = editState.idx;
            var toolIdx = editState.toolIdx;
            var item = atkDefData[idx] || {};
            var tool = (team === "red" ? (item.attack_tools || [])[toolIdx] : (item.defense_tools || [])[toolIdx]) || {};
            var cveId = String(item.cve_primary || "").trim();
            var name = document.getElementById("edit_name").value || "";
            var desc = document.getElementById("edit_desc").value || "";
            var cmds = document.getElementById("edit_cmds").value || "";
            var verified = Boolean(document.getElementById("edit_verified").checked);
            var commands = cmds.split("\\n").map(function (l) { return l.replace(/\\r/g, ""); });

            if (team === "red") {
                var toolId = tool.tool_id || "";
                if (toolId) {
                    await postJson(API_BASE + "/polygon/update_attack_tool", {
                        tool_id: toolId,
                        cve_id: cveId,
                        name: name,
                        description: desc,
                        commands: commands,
                        verified: verified
                    });
                    tool.name = name;
                    tool.desc = desc;
                    tool.commands = commands;
                    tool.verified = verified;
                } else {
                    var res = await postJson(API_BASE + "/polygon/add_attack_tool", {
                        cve_id: cveId,
                        name: name,
                        description: desc,
                        commands: commands,
                        verified: verified
                    });
                    tool.tool_id = res.tool_id;
                    tool.cve_id = cveId;
                    tool.name = name;
                    tool.desc = desc;
                    tool.commands = commands;
                    tool.verified = verified;
                }
            } else {
                await postJson(API_BASE + "/polygon/update_defense_tool", {
                    defense_id: tool.defense_id,
                    tool_index: tool.tool_index,
                    cve_id: cveId,
                    tool_name: name,
                    tool_description: desc,
                    commands: commands,
                    verified: verified
                });
                tool.name = name;
                tool.desc = desc;
                tool.commands = commands;
                tool.verified = verified;
            }

            item.attack_verified = (item.attack_tools || []).length > 0 && (item.attack_tools || []).every(function (t) { return Boolean(t.verified); });
            item.defense_verified = (item.defense_tools || []).length > 0 && (item.defense_tools || []).every(function (t) { return Boolean(t.verified); });
            renderAtkDefSection();
            closeEditModal();
        }

        async function toggleStepVerified(team, idx, toolIdx) {
            var item = atkDefData[idx] || {};
            var cveId = String(item.cve_primary || "").trim();
            if (!cveId) return;
            if (team === "red") {
                var tool = (item.attack_tools || [])[toolIdx];
                if (!tool) return;
                var next = !Boolean(tool.verified);
                await postJson(API_BASE + "/polygon/update_attack_tool", {
                    tool_id: tool.tool_id,
                    cve_id: cveId,
                    verified: next
                });
                tool.verified = next;
            } else {
                var dt = (item.defense_tools || [])[toolIdx];
                if (!dt) return;
                var nextB = !Boolean(dt.verified);
                await postJson(API_BASE + "/polygon/update_defense_tool", {
                    defense_id: dt.defense_id,
                    tool_index: dt.tool_index,
                    cve_id: cveId,
                    verified: nextB
                });
                dt.verified = nextB;
            }
            item.attack_verified = (item.attack_tools || []).length > 0 && (item.attack_tools || []).every(function (t) { return Boolean(t.verified); });
            item.defense_verified = (item.defense_tools || []).length > 0 && (item.defense_tools || []).every(function (t) { return Boolean(t.verified); });
            renderAtkDefSection();
        }

        async function toggleVerifiedAll(idx, team) {
            var item = atkDefData[idx] || {};
            var cveId = String(item.cve_primary || "").trim();
            if (!cveId) return;
            if (team === "red") {
                var tools = item.attack_tools || [];
                var next = !(tools.length > 0 && tools.every(function (t) { return Boolean(t.verified); }));
                for (var i = 0; i < tools.length; i++) {
                    var t = tools[i];
                    if (!t || !t.tool_id) continue;
                    await postJson(API_BASE + "/polygon/update_attack_tool", { tool_id: t.tool_id, cve_id: cveId, verified: next });
                    t.verified = next;
                }
            } else {
                var dtools = item.defense_tools || [];
                var nextB = !(dtools.length > 0 && dtools.every(function (t) { return Boolean(t.verified); }));
                for (var j = 0; j < dtools.length; j++) {
                    var dt = dtools[j];
                    if (!dt || !dt.defense_id) continue;
                    await postJson(API_BASE + "/polygon/update_defense_tool", { defense_id: dt.defense_id, tool_index: dt.tool_index, cve_id: cveId, verified: nextB });
                    dt.verified = nextB;
                }
            }
            item.attack_verified = (item.attack_tools || []).length > 0 && (item.attack_tools || []).every(function (t) { return Boolean(t.verified); });
            item.defense_verified = (item.defense_tools || []).length > 0 && (item.defense_tools || []).every(function (t) { return Boolean(t.verified); });
            renderAtkDefSection();
        }

        async function addNewStep(idx, team) {
            var item = atkDefData[idx] || {};
            var cveId = String(item.cve_primary || "").trim();
            if (!cveId) return;
            if (team === "red") {
                var name = prompt("Название шага атаки (инструмент/действие):", "Новый шаг");
                if (!name) return;
                var desc = prompt("Короткое описание шага:", "");
                var cmds = prompt("Команды (можно много строк, разделяйте через \\n):", "");
                var res = await postJson(API_BASE + "/polygon/add_attack_tool", {
                    cve_id: cveId,
                    name: name,
                    description: desc || "",
                    commands: cmds || ""
                });
                (item.attack_tools || (item.attack_tools = [])).push({
                    tool_id: res.tool_id,
                    cve_id: cveId,
                    name: name,
                    desc: desc || "",
                    commands: (cmds || "").split("\\n").map(function (l) { return l.replace(/\\r/g, ""); }),
                    verified: false,
                    order: 0
                });
            } else {
                var defName = prompt("Название метода защиты:", "Новый метод защиты");
                if (!defName) return;
                var defDesc = prompt("Описание метода защиты:", "");
                var toolName = prompt("Название шага/инструмента защиты:", "Шаг 1");
                if (!toolName) return;
                var cmdsB = prompt("Команды/конфигурация (можно много строк, разделяйте через \\n):", "");
                var resB = await postJson(API_BASE + "/polygon/add_defense_entry", {
                    cve_id: cveId,
                    name: defName,
                    description: defDesc || "",
                    tool_name: toolName,
                    tool_description: "",
                    commands: cmdsB || ""
                });
                (item.defense_tools || (item.defense_tools = [])).push({
                    defense_id: resB.defense_id,
                    tool_index: 0,
                    cve_id: cveId,
                    name: toolName,
                    desc: "",
                    priority: "",
                    commands: (cmdsB || "").split("\\n").map(function (l) { return l.replace(/\\r/g, ""); }),
                    verified: false,
                    order: 0,
                    tool_order: 0
                });
            }
            item.attack_verified = (item.attack_tools || []).length > 0 && (item.attack_tools || []).every(function (t) { return Boolean(t.verified); });
            item.defense_verified = (item.defense_tools || []).length > 0 && (item.defense_tools || []).every(function (t) { return Boolean(t.verified); });
            renderAtkDefSection();
        }

        function parseAndFormatRecommendations(text) {
            let html = '<div class="rec-structured">';
            html += '<strong style="color:#3fb950;font-size:14px;display:block;margin-bottom:10px;">🧠 Аналитика системы (Распознанные паттерны защиты):</strong>';
            
            // Выцепляем приоритет (🚨)
            let alertMatch = text.match(/🚨 ПРИОРИТЕТ:(.*?)(?=🔍|\\d+\\.|$)/s);
            if (alertMatch) {
                let alertLines = alertMatch[1].trim().split('\\n');
                html += '<div class="rec-alert"><strong>🚨 ПРИОРИТЕТ:</strong><br><ul style="margin:5px 0 0 15px; font-size:13px; color:#c9d1d9;">';
                alertLines.forEach(l => { if (l.trim()) html += `<li>${escapeHtml(l.replace(/^- /, '').trim())}</li>`; });
                html += '</ul></div>';
            }

            // Выцепляем мониторинг (🔍)
            let monMatch = text.match(/🔍 Рекомендации по мониторингу:(.*?)(?=🚨|\\d+\\.|$)/s);
            if (monMatch) {
                let monLines = monMatch[1].trim().split('\\n');
                html += '<div class="rec-monitor"><strong>🔍 Мониторинг:</strong><br><ul style="margin:5px 0 0 15px; font-size:13px; color:#c9d1d9;">';
                monLines.forEach(l => { if (l.trim()) html += `<li>${escapeHtml(l.replace(/^- /, '').trim())}</li>`; });
                html += '</ul></div>';
            }

            // Выцепляем нумерованные списки (меры защиты)
            let listRegex = /(\\d+)\\.\\s(.*?)(?=(?:\\n\\d+\\.\\s)|🚨|🔍|$)/gs;
            let match;
            let stepsFound = false;
            html += '<div class="rec-list">';
            while ((match = listRegex.exec(text)) !== null) {
                stepsFound = true;
                let num = match[1];
                let content = match[2].trim().replace(/\\n/g, ' ');
                // Сокращаем длинный текст, прячем под спойлер
                html += `<details class="rec-item">
                            <summary><span class="rec-item-num">${num}.</span> ${escapeHtml(content.substring(0, 80))}...</summary>
                            <div style="margin-top:10px; padding-top:10px; border-top:1px solid #30363d;">${escapeHtml(content)}</div>
                         </details>`;
            }
            html += '</div>';

            // Если парсер ничего не нашел, выводим как есть, но красиво
            if (!alertMatch && !monMatch && !stepsFound) {
                html += `<div style="font-size:13px; color:#c9d1d9; line-height:1.6;">${escapeHtml(text).replace(/\\n/g, '<br>')}</div>`;
            }
            
            html += '</div>';
            return html;
        }

        function generateBugReport() {
            let inputs = document.querySelectorAll('.bug-feedback-input');
            let reportLines = [];
            let hasErrors = false;
            
            reportLines.push("# 🐞 Отчёт об ошибках в сценариях (Киберполигон)");
            reportLines.push(`**Дата генерации:** ${new Date().toLocaleString('ru-RU')}\\n---\\n`);
            
            inputs.forEach(inp => {
                let comment = inp.value.trim();
                if (comment) { 
                    hasErrors = true;
                    let team = inp.getAttribute('data-team');
                    let cve = inp.getAttribute('data-cve');
                    let sw = inp.getAttribute('data-sw');
                    let step = inp.getAttribute('data-step');
                    let tool = inp.getAttribute('data-tool');
                    
                    let cmdBlock = document.getElementById('cmd_' + inp.id);
                    let cmds = cmdBlock ? cmdBlock.innerText.trim() : "Команды отсутствуют";
                    
                    let emoji = team === "Red" ? "🥷" : "🛡️";
                    reportLines.push(`## ${emoji} Команда: ${team} Team | Цель: ${sw} (${cve})`);
                    reportLines.push(`### Шаг ${step}: Инструмент - ${tool}`);
                    reportLines.push(`**Код из базы:**`);
                    reportLines.push(`\`\`\`bash\\n${cmds}\\n\`\`\``);
                    reportLines.push(`**Комментарий/Правка пользователя:**`);
                    reportLines.push(`> ⚠️ ${comment}\\n---\\n`);
                }
            });
            
            if (!hasErrors) {
                alert("Нет заполненных полей с комментариями.");
                return;
            }
            
            let blob = new Blob([reportLines.join("\\n")], { type: 'text/markdown;charset=utf-8;' });
            let link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = `playbook_bugs_${new Date().getTime()}.md`;
            link.click();
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

        function expandSeedToRawItems(seed) {
            let out = [];
            let s = Array.isArray(seed) ? seed : [];
            for (let i = 0; i < s.length; i++) {
                let g = s[i] || {};
                let ms = Array.isArray(g.members) ? g.members : [];
                if (ms.length) {
                    for (let j = 0; j < ms.length; j++) {
                        let m = Object.assign({}, ms[j] || {});
                        if (m.raw_id === undefined || m.raw_id === null || m.raw_id === "") {
                            m.raw_id = "seed_" + String(g.id ?? i) + "_" + String(j);
                        } else {
                            m.raw_id = "m_" + String(m.raw_id);
                        }
                        if (!m.feas) m.feas = g.feas || "UNKNOWN";
                        if (!m.sev) m.sev = g.sev || "INFO";
                        if (!m.desc) m.desc = g.desc || "";
                        if (!m.rec) m.rec = g.rec || "";
                        if (!m.reason) m.reason = g.reason || "";
                        if (!m.tools) m.tools = g.tools || "";
                        if (!m.steps) m.steps = g.steps || "";
                        if (!m.sw_category) m.sw_category = g.sw_category || "";
                        if (!m.sw_purpose) m.sw_purpose = g.sw_purpose || "";
                        if (!m.sw_impact) m.sw_impact = g.sw_impact || "";
                        if (!m.sw_scope) m.sw_scope = g.sw_scope || "";
                        if (!m.feasibility_trace) m.feasibility_trace = g.feasibility_trace || {};
                        out.push(m);
                    }
                } else {
                    let x = Object.assign({}, g);
                    x.raw_id = "seed_" + String(g.id ?? i);
                    out.push(x);
                }
            }
            return out;
        }

        function rebuildAggregatedData() {
            let keys = getSelectedAggregationKeys();
            let rawItems = Array.isArray(rawFindingsData) ? rawFindingsData : [];
            if (!rawItems.length) rawItems = expandSeedToRawItems(reportDataSeed);
            let hasRaw = rawItems.length > 0;
            try {
                reportData = hasRaw ? aggregateByKeys(rawItems, keys) : [];
            } catch (e) {
                console.error("Ошибка агрегации отчёта:", e);
                reportData = [];
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
            detailsMapRows = {};
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
                detailsMapRows['aggr_' + r.id] = { type: 'aggr', data: r };
            });
        }

        function renderGraph(data) {
            detailsMapNodes = {};
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
            let addDetail = (id, type, payload, item) => {
                if (!detailsMapNodes[id]) {
                    detailsMapNodes[id] = Object.assign({ type: type, items: [] }, payload || {});
                }
                if (item) detailsMapNodes[id].items.push(item);
            };
            let safeIdPart = (s) => {
                return String(s ?? "").replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, 140) || "_";
            };
            let splitCsv = (s) => {
                let raw = String(s ?? "");
                if (!raw) return [];
                return raw.split(",").map(x => x.trim()).filter(Boolean);
            };
            let splitSources = (s) => {
                let raw = String(s ?? "");
                if (!raw) return [];
                return raw.split("&").map(x => x.trim()).filter(Boolean);
            };
            let uniq = (arr) => Array.from(new Set((arr || []).filter(Boolean)));
            let keys = getSelectedAggregationKeys();
            let noAgg = !keys || keys.length === 0;

            // ---- КАРТА 1.1: Asset-Centric (От Актива к Атаке — Blue Team) ----
            if (viewId === "1_1") {
                data.forEach((r, idx) => {
                    r = r || {};
                    let rk = String(r.raw_id ?? r.id ?? idx);
                    let swId = "ac_sw_" + (noAgg ? safeIdPart(rk) : (safeIdPart(r.sw) + "_" + safeIdPart(r.port)));
                    addNode({ id: swId, label: "🎯 ПО (Актив):\\n" + (r.sw || "") + "\\nПорт: " + (r.port || ""), level: 0, shape: "box", color: {background: "#1f77b4"} });
                    addDetail(swId, "sw", { data: r, sw: r.sw, port: r.port }, r);

                    let cweTokens = uniq(splitCsv(r.cwe));
                    if (!cweTokens.length) cweTokens = [String(r.cwe || "CWE-Неизвестно")];
                    let capecTokens = uniq(splitCsv(r.capec));
                    if (!capecTokens.length) capecTokens = [String(r.capec || "CAPEC-Неизвестно")];
                    let mitreTokens = uniq(splitCsv(r.mitre));
                    if (!mitreTokens.length) mitreTokens = ["—"];

                    let verdId = "ac_verd_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                    addNode({ id: verdId, label: "⚖️ Вердикт:\\n" + (r.feas || ""), level: 5, shape: "box", color: {background: getFeasColor(r.feas)} });
                    addDetail(verdId, "verdict", { data: r }, r);

                    mitreTokens.forEach(mitreTok => {
                        let mId = "ac_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                        let mt = (mitreMeta && mitreMeta[mitreTok] && mitreMeta[mitreTok].tactic) ? String(mitreMeta[mitreTok].tactic) : "";
                        let lbl = "⚔️ MITRE ATT&CK:\\n" + mitreTok + (mt ? ("\\n" + mt) : "");
                        addNode({ id: mId, label: lbl, level: 4, shape: "box", color: {background: "#d29922"} });
                        addDetail(mId, "mitre", { data: r, mitre: mitreTok }, r);
                        addEdge(mId, verdId, getFeasColor(r.feas), r.feas === "РЕАЛИЗУЕМА" ? 3 : 2, r.feas === "НЕ РЕАЛИЗУЕМА");
                    });

                    if (noAgg) {
                        let cveTokens = uniq(splitCsv(r.cve));
                        if (!cveTokens.length) cveTokens = [String(r.cve || "N/A")];
                        cveTokens.forEach(cveTok => {
                            let cveId = "ac_cve_" + safeIdPart(rk) + "_" + safeIdPart(cveTok);
                            addNode({ id: cveId, label: "🛡️ CVE (Дыра):\\n" + cveTok, level: 1, shape: "box", color: {background: getSevColor(r.sev)} });
                            addDetail(cveId, "cve", { data: r, cve: cveTok }, r);
                            addEdge(swId, cveId, "#8b949e");

                            cweTokens.forEach(cweTok => {
                                let cweId = "ac_cwe_" + safeIdPart(rk) + "_" + safeIdPart(cweTok);
                                addNode({ id: cweId, label: "🐛 CWE (Причина):\\n" + cweTok, level: 2, shape: "box", color: {background: "#484f58"} });
                                addDetail(cweId, "cwe", { data: r, cwe: cweTok }, r);
                                addEdge(cveId, cweId, "#8b949e");

                                capecTokens.forEach(capecTok => {
                                    let capecId = "ac_capec_" + safeIdPart(rk) + "_" + safeIdPart(capecTok);
                                    addNode({ id: capecId, label: "🥷 CAPEC (Метод):\\n" + capecTok, level: 3, shape: "box", color: {background: "#58a6ff"} });
                                    addDetail(capecId, "capec", { data: r, capec: capecTok }, r);
                                    addEdge(cweId, capecId, "#8b949e");
                                    mitreTokens.forEach(mitreTok => {
                                        let mId = "ac_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                                        addEdge(capecId, mId, "#8b949e");
                                    });
                                });
                            });
                        });
                    } else {
                        let cveId = "ac_cve_" + safeIdPart(r.id);
                        let cvesStr = String(r.cve || "");
                        cvesStr = cvesStr.length > 25 ? cvesStr.substring(0, 25) + "..." : cvesStr;
                        addNode({ id: cveId, label: "🛡️ CVE (Дыра):\\n" + cvesStr, level: 1, shape: "box", color: {background: getSevColor(r.sev)} });
                        addDetail(cveId, "finding", { data: r }, r);
                        addEdge(swId, cveId, "#8b949e");

                        cweTokens.forEach(cweTok => {
                            let cweId = "ac_cwe_" + safeIdPart(cweTok);
                            addNode({ id: cweId, label: "🐛 CWE (Причина):\\n" + cweTok, level: 2, shape: "box", color: {background: "#484f58"} });
                            addDetail(cweId, "cwe", { data: r, cwe: cweTok }, r);
                            addEdge(cveId, cweId, "#8b949e");

                            capecTokens.forEach(capecTok => {
                                let capecId = "ac_capec_" + safeIdPart(capecTok);
                                addNode({ id: capecId, label: "🥷 CAPEC (Метод):\\n" + capecTok, level: 3, shape: "box", color: {background: "#58a6ff"} });
                                addDetail(capecId, "capec", { data: r, capec: capecTok }, r);
                                addEdge(cweId, capecId, "#8b949e");
                                mitreTokens.forEach(mitreTok => {
                                    let mId = "ac_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                                    addEdge(capecId, mId, "#8b949e");
                                });
                            });
                        });
                    }
                });
            }
            // ---- КАРТА 1.2: Attacker-Centric (От Цели к Активу — Red Team) ----
            else if (viewId === "1_2") {
                data.forEach((r, idx) => {
                    r = r || {};
                    let rk = String(r.raw_id ?? r.id ?? idx);

                    let mitreTokens = uniq(splitCsv(r.mitre));
                    if (!mitreTokens.length) mitreTokens = ["—"];
                    mitreTokens.forEach(mitreTok => {
                        let mId = "at_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                        let mt = (mitreMeta && mitreMeta[mitreTok] && mitreMeta[mitreTok].tactic) ? String(mitreMeta[mitreTok].tactic) : "";
                        let lbl = "⚔️ MITRE ATT&CK:\\n" + mitreTok + (mt ? ("\\n" + mt) : "");
                        addNode({ id: mId, label: lbl, level: 0, shape: "box", color: {background: "#d29922"} });
                        addDetail(mId, "mitre", { data: r, mitre: mitreTok }, r);
                    });

                    let swId = "at_sw_" + (noAgg ? safeIdPart(rk) : (safeIdPart(r.sw) + "_" + safeIdPart(r.port)));
                    addNode({ id: swId, label: "🎯 Наше ПО (Актив):\\n" + (r.sw || ""), level: 4, shape: "box", color: {background: "#1f77b4"} });
                    addDetail(swId, "sw", { data: r, sw: r.sw, port: r.port }, r);

                    let verdId = "at_verd_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                    addNode({ id: verdId, label: "⚖️ Вердикт:\\n" + (r.feas || ""), level: 5, shape: "box", color: {background: getFeasColor(r.feas)} });
                    addDetail(verdId, "verdict", { data: r }, r);

                    let cweTokens = uniq(splitCsv(r.cwe));
                    if (!cweTokens.length) cweTokens = [String(r.cwe || "CWE-Неизвестно")];
                    let capecTokens = uniq(splitCsv(r.capec));
                    if (!capecTokens.length) capecTokens = [String(r.capec || "CAPEC-Неизвестно")];

                    if (noAgg) {
                        let cveTokens = uniq(splitCsv(r.cve));
                        if (!cveTokens.length) cveTokens = [String(r.cve || "N/A")];
                        capecTokens.forEach(capecTok => {
                            let capecId = "at_capec_" + safeIdPart(rk) + "_" + safeIdPart(capecTok);
                            addNode({ id: capecId, label: "🥷 CAPEC (Метод):\\n" + capecTok, level: 1, shape: "box", color: {background: "#58a6ff"} });
                            addDetail(capecId, "capec", { data: r, capec: capecTok }, r);
                            mitreTokens.forEach(mitreTok => {
                                let mId = "at_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                                addEdge(mId, capecId, "#8b949e");
                            });

                            cweTokens.forEach(cweTok => {
                                let cweId = "at_cwe_" + safeIdPart(rk) + "_" + safeIdPart(cweTok);
                                addNode({ id: cweId, label: "🐛 CWE (Слабость):\\n" + cweTok, level: 2, shape: "box", color: {background: "#484f58"} });
                                addDetail(cweId, "cwe", { data: r, cwe: cweTok }, r);
                                addEdge(capecId, cweId, "#8b949e");

                                cveTokens.forEach(cveTok => {
                                    let cveId = "at_cve_" + safeIdPart(rk) + "_" + safeIdPart(cveTok);
                                    addNode({ id: cveId, label: "🛡️ CVE (Уязвимость):\\n" + cveTok, level: 3, shape: "box", color: {background: getSevColor(r.sev)} });
                                    addDetail(cveId, "cve", { data: r, cve: cveTok }, r);
                                    addEdge(cweId, cveId, "#8b949e");
                                    addEdge(cveId, swId, "#8b949e");
                                });
                            });
                        });
                        addEdge(swId, verdId, getFeasColor(r.feas), r.feas === "РЕАЛИЗУЕМА" ? 3 : 2, r.feas === "НЕ РЕАЛИЗУЕМА");
                    } else {
                        let capecAnchor = capecTokens[0];
                        let capecId = "at_capec_" + safeIdPart(capecAnchor);
                        addNode({ id: capecId, label: "🥷 CAPEC (Метод):\\n" + capecAnchor, level: 1, shape: "box", color: {background: "#58a6ff"} });
                        addDetail(capecId, "capec", { data: r, capec: capecAnchor }, r);
                        mitreTokens.forEach(mitreTok => {
                            let mId = "at_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                            addEdge(mId, capecId, "#8b949e");
                        });

                        cweTokens.forEach(cweTok => {
                            let cweId = "at_cwe_" + safeIdPart(cweTok);
                            addNode({ id: cweId, label: "🐛 CWE (Слабость):\\n" + cweTok, level: 2, shape: "box", color: {background: "#484f58"} });
                            addDetail(cweId, "cwe", { data: r, cwe: cweTok }, r);
                            addEdge(capecId, cweId, "#8b949e");

                            let cveId = "at_cve_" + safeIdPart(r.id);
                            let cvesStr = String(r.cve || "");
                            cvesStr = cvesStr.length > 25 ? cvesStr.substring(0, 25) + "..." : cvesStr;
                            addNode({ id: cveId, label: "🛡️ CVE (Уязвимость):\\n" + cvesStr, level: 3, shape: "box", color: {background: getSevColor(r.sev)} });
                            addDetail(cveId, "finding", { data: r }, r);
                            addEdge(cweId, cveId, "#8b949e");
                            addEdge(cveId, swId, "#8b949e");
                        });
                        addEdge(swId, verdId, getFeasColor(r.feas), r.feas === "РЕАЛИЗУЕМА" ? 3 : 2, r.feas === "НЕ РЕАЛИЗУЕМА");
                    }
                });
            }
            // ---- КАРТА 1.3: Causal Chain (Причинно-следственная связь — RCA) ----
            else if (viewId === "1_3") {
                data.forEach((r, idx) => {
                    r = r || {};
                    let rk = String(r.raw_id ?? r.id ?? idx);
                    let cweTokens = uniq(splitCsv(r.cwe));
                    if (!cweTokens.length) cweTokens = [String(r.cwe || "CWE-Неизвестно")];
                    let capecTokens = uniq(splitCsv(r.capec));
                    if (!capecTokens.length) capecTokens = [String(r.capec || "CAPEC-Неизвестно")];

                    let verdId = "cc_verd_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                    addNode({ id: verdId, label: "⚖️ Вердикт:\\n" + (r.feas || ""), level: 5, shape: "box", color: {background: getFeasColor(r.feas)} });
                    addDetail(verdId, "verdict", { data: r }, r);

                    let mitreTokens = uniq(splitCsv(r.mitre));
                    if (!mitreTokens.length) mitreTokens = ["—"];
                    mitreTokens.forEach(mitreTok => {
                        let mId = "cc_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                        let mt = (mitreMeta && mitreMeta[mitreTok] && mitreMeta[mitreTok].tactic) ? String(mitreMeta[mitreTok].tactic) : "";
                        let lbl = "⚔️ MITRE ATT&CK:\\n" + mitreTok + (mt ? ("\\n" + mt) : "");
                        addNode({ id: mId, label: lbl, level: 4, shape: "box", color: {background: "#d29922"} });
                        addDetail(mId, "mitre", { data: r, mitre: mitreTok }, r);
                        addEdge(mId, verdId, getFeasColor(r.feas), r.feas === "РЕАЛИЗУЕМА" ? 3 : 2, r.feas === "НЕ РЕАЛИЗУЕМА");
                    });
                    let swId = "cc_sw_" + (noAgg ? safeIdPart(rk) : (safeIdPart(r.sw) + "_" + safeIdPart(r.port)));
                    addNode({ id: swId, label: "🎯 ПО (Среда):\\n" + (r.sw || ""), level: 2, shape: "box", color: {background: "#1f77b4"} });
                    addDetail(swId, "sw", { data: r, sw: r.sw, port: r.port }, r);

                    if (noAgg) {
                        let cveTokens = uniq(splitCsv(r.cve));
                        if (!cveTokens.length) cveTokens = [String(r.cve || "N/A")];
                        cweTokens.forEach(cweTok => {
                            let cweId = "cc_cwe_" + safeIdPart(rk) + "_" + safeIdPart(cweTok);
                            addNode({ id: cweId, label: "🐛 CWE (Корень):\\n" + cweTok, level: 0, shape: "box", color: {background: "#484f58"} });
                            addDetail(cweId, "cwe", { data: r, cwe: cweTok }, r);
                            cveTokens.forEach(cveTok => {
                                let cveId = "cc_cve_" + safeIdPart(rk) + "_" + safeIdPart(cveTok);
                                addNode({ id: cveId, label: "🛡️ CVE (Дыра):\\n" + cveTok, level: 1, shape: "box", color: {background: getSevColor(r.sev)} });
                                addDetail(cveId, "cve", { data: r, cve: cveTok }, r);
                                addEdge(cweId, cveId, "#8b949e");
                                addEdge(cveId, swId, "#8b949e");
                                capecTokens.forEach(capecTok => {
                                    let capecId = "cc_capec_" + safeIdPart(rk) + "_" + safeIdPart(capecTok);
                                    addNode({ id: capecId, label: "🥷 CAPEC (Вектор):\\n" + capecTok, level: 3, shape: "box", color: {background: "#58a6ff"} });
                                    addDetail(capecId, "capec", { data: r, capec: capecTok }, r);
                                    addEdge(swId, capecId, "#8b949e");
                                    mitreTokens.forEach(mitreTok => {
                                        let mId = "cc_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                                        addEdge(capecId, mId, "#8b949e");
                                    });
                                });
                            });
                        });
                    } else {
                        let cweAnchor = cweTokens[0];
                        let cweId = "cc_cwe_" + safeIdPart(cweAnchor);
                        addNode({ id: cweId, label: "🐛 CWE (Корень):\\n" + cweAnchor, level: 0, shape: "box", color: {background: "#484f58"} });
                        addDetail(cweId, "cwe", { data: r, cwe: cweAnchor }, r);

                        let cveId = "cc_cve_" + safeIdPart(r.id);
                        let cvesStr = String(r.cve || "");
                        cvesStr = cvesStr.length > 25 ? cvesStr.substring(0, 25) + "..." : cvesStr;
                        addNode({ id: cveId, label: "🛡️ CVE (Дыра):\\n" + cvesStr, level: 1, shape: "box", color: {background: getSevColor(r.sev)} });
                        addDetail(cveId, "finding", { data: r }, r);
                        addEdge(cweId, cveId, "#8b949e");
                        addEdge(cveId, swId, "#8b949e");

                        capecTokens.forEach(capecTok => {
                            let capecId = "cc_capec_" + safeIdPart(capecTok);
                            addNode({ id: capecId, label: "🥷 CAPEC (Вектор):\\n" + capecTok, level: 3, shape: "box", color: {background: "#58a6ff"} });
                            addDetail(capecId, "capec", { data: r, capec: capecTok }, r);
                            addEdge(swId, capecId, "#8b949e");
                            mitreTokens.forEach(mitreTok => {
                                let mId = "cc_mitre_" + (noAgg ? (safeIdPart(rk) + "_" + safeIdPart(mitreTok)) : safeIdPart(mitreTok));
                                addEdge(capecId, mId, "#8b949e");
                            });
                        });
                    }
                });
            }
            // ---- КАРТА 2: Логическая (С УЗЛОМ ПО) ----
            else if (viewId === "2") {
                data.forEach((r, idx) => {
                    r = r || {};
                    let rk = String(r.raw_id ?? r.id ?? idx);
                    let swId = "l_sw_" + (noAgg ? safeIdPart(rk) : (safeIdPart(r.sw) + "_" + safeIdPart(r.port)));
                    addNode({ id: swId, label: "🎯 Цель:\\n" + (r.sw || "") + "\\nПорт: " + (r.port || ""), level: 1, shape: "box", color: {background: "#1f77b4"} });
                    addDetail(swId, "sw", { data: r, sw: r.sw, port: r.port }, r);

                    let verdId = "l_verd_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                    addNode({ id: verdId, label: "⚖️ Вердикт:\\n" + (r.feas || ""), level: 3, shape: "box", color: {background: getFeasColor(r.feas)} });
                    addDetail(verdId, "verdict", { data: r }, r);

                    let cweTokens = uniq(splitCsv(r.cwe));
                    if (!cweTokens.length) cweTokens = [String(r.cwe || "CWE-Неизвестно")];
                    let capecTokens = uniq(splitCsv(r.capec));
                    if (!capecTokens.length) capecTokens = [String(r.capec || "CAPEC-Неизвестно")];

                    capecTokens.forEach(capecTok => {
                        let capecId = "l_capec_" + (noAgg ? safeIdPart(rk) + "_" + safeIdPart(capecTok) : safeIdPart(capecTok));
                        addNode({ id: capecId, label: "🥷 Вектор: " + capecTok, level: 0, shape: "box", color: {background: "#58a6ff"} });
                        addDetail(capecId, "capec", { data: r, capec: capecTok }, r);
                        addEdge(capecId, swId, "#8b949e");
                    });

                    cweTokens.forEach(cweTok => {
                        let cweId = "l_cwe_" + (noAgg ? safeIdPart(rk) + "_" + safeIdPart(cweTok) : safeIdPart(cweTok));
                        addNode({ id: cweId, label: "🐛 Слабость: " + cweTok, level: 2, shape: "box", color: {background: "#484f58"} });
                        addDetail(cweId, "cwe", { data: r, cwe: cweTok }, r);
                        addEdge(swId, cweId, "#8b949e");
                        addEdge(cweId, verdId, getFeasColor(r.feas), 3);
                    });
                });
            }
            // ---- КАРТА 3: Источник Обнаружения ----
            else if (viewId === "3") {
                data.forEach((r, idx) => {
                    r = r || {};
                    let rk = String(r.raw_id ?? r.id ?? idx);
                    let vulnId = "v_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                    let vLabel = String(r.cve || r.capec || "");
                    vLabel = vLabel.length > 30 ? vLabel.substring(0, 30) + "..." : vLabel;
                    addNode({ id: vulnId, label: "🛡️ Уязвимость:\\n" + vLabel, level: 2, shape: "box", color: {background: getSevColor(r.sev)} });
                    addDetail(vulnId, "finding", { data: r }, r);

                    let swId = "sw_real_" + (noAgg ? safeIdPart(rk) : (safeIdPart(r.sw) + "_" + safeIdPart(r.port)));
                    addNode({ id: swId, label: "🎯 Реальное ПО:\\n" + (r.sw || ""), level: 1, shape: "box", color: {background: "#484f58"} });
                    addDetail(swId, "sw", { data: r, sw: r.sw, port: r.port }, r);

                    uniq(splitSources(r.found_by)).forEach(srcClean => {
                        let srcId = "src_" + (noAgg ? safeIdPart(rk) + "_" + safeIdPart(srcClean) : safeIdPart(srcClean));
                        let sColor = String(srcClean).includes("Атакующий") ? "#da3633" : "#1f77b4";
                        addNode({ id: srcId, label: "🕵️ Источник:\\n" + srcClean, level: 0, shape: "box", color: {background: sColor} });
                        addDetail(srcId, "source", { data: r, source: srcClean }, r);
                        addEdge(srcId, swId, "#8b949e");
                    });

                    addEdge(swId, vulnId, getFeasColor(r.feas));
                });
            }
            // ---- КАРТА 4: План Устранения ----
            else if (viewId === "4") {
                data.forEach((r, idx) => {
                    r = r || {};
                    let rk = String(r.raw_id ?? r.id ?? idx);
                    let vulnId = "uv_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                    let vLabel = String(r.cve || r.capec || "");
                    vLabel = vLabel.length > 30 ? vLabel.substring(0, 30) + "..." : vLabel;
                    addNode({ id: vulnId, label: "🛡️ Уязвимость:\\n" + vLabel + "\\n(ПО: " + (r.sw || "") + ")", level: 0, shape: "box", color: {background: getSevColor(r.sev)} });
                    addDetail(vulnId, "finding", { data: r }, r);

                    let statId = "stat_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                    let statLbl = r.feas === 'НЕ РЕАЛИЗУЕМА' ? '✅ Защищено' : '❌ Требует патча';
                    let statCol = r.feas === 'НЕ РЕАЛИЗУЕМА' ? '#238636' : '#da3633';
                    addNode({ id: statId, label: statLbl, level: 1, shape: "box", color: {background: statCol} });

                    let recId = "rec_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                    let shortRec = String(r.rec || "");
                    shortRec = shortRec.length > 45 ? shortRec.substring(0, 45) + "..." : shortRec;
                    addNode({ id: recId, label: "🛠️ План:\\n" + shortRec, level: 2, shape: "box", color: {background: "#1f77b4"} });
                    addDetail(recId, "plan", { data: r }, r);

                    addEdge(vulnId, statId, "#8b949e");
                    addEdge(statId, recId, statCol, 2, r.feas === 'НЕ РЕАЛИЗУЕМА');
                });
            }
            // ---- КАРТА 5: Полигон ----
            else if (viewId === "5") {
                data.forEach((r, idx) => {
                    r = r || {};
                    let rk = String(r.raw_id ?? r.id ?? idx);
                    let capecTokens = uniq(splitCsv(r.capec));
                    if (!capecTokens.length) capecTokens = [String(r.capec || "CAPEC-Неизвестно")];
                    capecTokens.forEach(capecTok => {
                        let capecId = "pc_" + (noAgg ? safeIdPart(rk) + "_" + safeIdPart(capecTok) : safeIdPart(capecTok));
                        addNode({ id: capecId, label: "🥷 Вектор:\\n" + capecTok, level: 0, shape: "box", color: {background: "#da3633"} });
                        addDetail(capecId, "capec", { data: r, capec: capecTok }, r);

                        let toolId = "pt_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                        let shortTool = String(r.tools || "");
                        shortTool = shortTool.length > 30 ? shortTool.substring(0, 30) + "..." : shortTool;
                        addNode({ id: toolId, label: "🔫 Софт:\\n" + shortTool, level: 1, shape: "box", color: {background: "#d29922"} });
                        addDetail(toolId, "tool", { data: r }, r);

                        let stepsId = "ps_" + (noAgg ? safeIdPart(rk) : safeIdPart(r.id));
                        addNode({ id: stepsId, label: "📜 Логика Атаки\\n(Кликните для деталей)", level: 2, shape: "box", color: {background: "#484f58"} });
                        addDetail(stepsId, "steps", { data: r }, r);

                        addEdge(capecId, toolId, "#8b949e");
                        addEdge(toolId, stepsId, "#8b949e");
                    });
                });
            }

            if(network) network.destroy();
            var container = document.getElementById('network-map');
            var visData = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
            
            // Динамическое расстояние узлов
            var nodeSpc = viewId === "4" ? 650 : 400;
            var levelSep = 250;
            if (viewId === "4") {
                levelSep = 350;
            } else if (viewId.startsWith("1_")) {
                levelSep = 180; // Сближаем узлы по вертикали, так как теперь 6 уровней (цепочки)
            }
            
            var options = {
                layout: { hierarchical: { direction: 'UD', sortMethod: 'directed', nodeSpacing: nodeSpc, levelSeparation: levelSep } },
                physics: false,
                nodes: { borderWidth: 2, shadow: true, margin: 15, font: { face: "Segoe UI" } },
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
            let nodeInfo = lookupDetails(id);
            if(!nodeInfo) return;
            
            let contentDiv = document.getElementById("dynamic-modal-content");
            let items = (nodeInfo.items && Array.isArray(nodeInfo.items) && nodeInfo.items.length) ? nodeInfo.items : (nodeInfo.data ? [nodeInfo.data] : []);
            let r = nodeInfo.data || items[0] || {};

            let splitCsv = (s) => {
                let raw = String(s ?? "");
                if (!raw) return [];
                return raw.split(",").map(x => x.trim()).filter(Boolean);
            };
            let uniq = (arr) => Array.from(new Set((arr || []).filter(Boolean)));
            let flatTokens = (field) => {
                let out = [];
                for (let i = 0; i < items.length; i++) {
                    splitCsv(items[i] && items[i][field]).forEach(t => out.push(t));
                }
                return uniq(out);
            };
            let formatEvidenceTable = (rows, limit) => {
                let data = Array.isArray(rows) ? rows : [];
                let lim = Math.max(1, Number(limit || 30));
                let slice = data.slice(0, lim);
                let html = '<div class="group-members" style="border:none;">';
                html += '<div class="group-members-head">Показаны примеры связей (строк): ' + slice.length + (data.length > slice.length ? ' из ' + data.length : '') + '</div>';
                html += '<div class="group-members-row" style="font-weight:700; color:#8b949e; background:#0d1117; border-top:1px solid #21262d;">'
                    + '<div>ПО / CVE</div><div>Порт</div><div>CWE</div><div>CAPEC</div><div>Вердикт</div></div>';
                slice.forEach(function(m) {
                    let feas = String(m.feas || "");
                    html += '<div class="group-members-row">'
                        + '<div><strong>' + esc(m.sw || '—') + '</strong><br><span class="mono">' + esc(m.cve || 'N/A') + '</span></div>'
                        + '<div>' + esc(m.port || 'Н/Д') + '</div>'
                        + '<div>' + esc(m.cwe || 'Н/Д') + '</div>'
                        + '<div>' + esc(m.capec || 'Н/Д') + '</div>'
                        + '<div><span class="badge ' + getFeasClass(feas) + '">' + esc(feas || 'UNKNOWN') + '</span></div>'
                        + '</div>';
                });
                html += '</div>';
                return html;
            };
            
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
            else if (nodeInfo.type === 'capec') {
                let capecId = nodeInfo.capec || (splitCsv(r.capec)[0] || String(r.capec || ""));
                let meta = (capecMeta && capecId && capecMeta[capecId]) ? capecMeta[capecId] : {};
                let name = meta && meta.name ? String(meta.name) : "";
                let desc = meta && meta.description ? String(meta.description) : (meta && meta.desc ? String(meta.desc) : "");
                if (!desc) desc = String(r.name || r.desc || "Описание отсутствует.");
                let cwes = flatTokens("cwe");
                let cves = flatTokens("cve");
                let sws = uniq(items.map(x => String((x && x.sw) || "")).filter(Boolean));
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🥷 CAPEC: ${esc(capecId)}</h2>
                    </div>
                    <div class="grid-info">
                        <div class="grid-item"><span>Название:</span><strong>${esc(name || (r.name || '—'))}</strong></div>
                        <div class="grid-item"><span>Связанных CWE:</span><strong>${cwes.length}</strong></div>
                        <div class="grid-item"><span>Связанных CVE:</span><strong>${cves.length}</strong></div>
                        <div class="grid-item"><span>Целевое ПО (уникальных):</span><strong>${sws.length}</strong></div>
                        <div class="grid-item"><span>Строк-оснований (в отчёте):</span><strong>${items.length}</strong></div>
                        <div class="grid-item"><span>Источник связей:</span><strong>корреляция (поля CVE/CWE/CAPEC)</strong></div>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>📝 Описание CAPEC</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(desc)}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">
                                <p class="trace-meta" style="margin:0 0 10px 0;">Связи построены по строкам отчёта: CAPEC присутствует в поле CAPEC у записей, которые одновременно содержат CWE/CVE/ПО.</p>
                                ${formatEvidenceTable(items, 40)}
                            </div>
                        </details>
                    </div>
                `;
            }
            else if (nodeInfo.type === 'cve') {
                let cveId = nodeInfo.cve || (splitCsv(r.cve)[0] || String(r.cve || ""));
                let meta = (cveMeta && cveId && cveMeta[cveId]) ? cveMeta[cveId] : {};
                let desc = meta && meta.description ? String(meta.description) : String(r.desc || "Описание отсутствует.");
                let cvss = (meta && meta.cvss_score != null) ? String(meta.cvss_score) : "";
                let relCwe = meta && meta.related_cwe ? meta.related_cwe : [];
                let relCapec = meta && meta.related_capec ? meta.related_capec : [];
                let relMitre = meta && meta.related_mitre ? meta.related_mitre : [];
                let sws = uniq(items.map(x => String((x && x.sw) || "")).filter(Boolean));
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🛡️ CVE: ${esc(cveId)}</h2>
                    </div>
                    <div class="grid-info">
                        <div class="grid-item"><span>CVSS:</span><strong>${esc(cvss || '—')}</strong></div>
                        <div class="grid-item"><span>Связанных CWE (из БД):</span><strong>${(relCwe || []).length}</strong></div>
                        <div class="grid-item"><span>Связанных CAPEC (из БД):</span><strong>${(relCapec || []).length}</strong></div>
                        <div class="grid-item"><span>MITRE (из БД):</span><strong>${(relMitre || []).length}</strong></div>
                        <div class="grid-item"><span>ПО в отчёте (уникальных):</span><strong>${sws.length}</strong></div>
                        <div class="grid-item"><span>Строк-оснований (в отчёте):</span><strong>${items.length}</strong></div>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>📝 Описание CVE</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(desc)}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">
                                <p class="trace-meta" style="margin:0 0 10px 0;">Основание: строки отчёта, в которых присутствует этот CVE (поле CVE), а также сопутствующие CWE/CAPEC/ПО.</p>
                                ${formatEvidenceTable(items, 40)}
                            </div>
                        </details>
                    </div>
                `;
            }
            // 2. Если кликнули на слабость CWE
            else if (nodeInfo.type === 'cwe') {
                let cweId = nodeInfo.cwe || (splitCsv(r.cwe)[0] || String(r.cwe || ""));
                let cweDesc = "";
                for (let i = 0; i < items.length; i++) {
                    let d = items[i] && items[i].cwe_desc;
                    if (d) { cweDesc = String(d); break; }
                }
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🐛 Класс уязвимости: ${esc(cweId)}</h2>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>📝 Описание CWE</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(cweDesc || 'Описание отсутствует.')}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">
                                <p class="trace-meta" style="margin:0 0 10px 0;">Основание: строки отчёта, в которых присутствует этот CWE (поле CWE), плюс связанные CVE/CAPEC/ПО.</p>
                                ${formatEvidenceTable(items, 40)}
                            </div>
                        </details>
                    </div>
                `;
            } 
            // 3. Если кликнули на целевое ПО
            else if (nodeInfo.type === 'sw') {
                let swName = nodeInfo.sw || r.sw || "";
                let port = nodeInfo.port || r.port || "";
                let swCategory = r.sw_category || "";
                let swPurpose = r.sw_purpose || "";
                let swImpact = r.sw_impact || "";
                let swScope = r.sw_scope || "";
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🎯 Узел ПО</h2>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <div class="grid-info" style="grid-template-columns: 1fr;">
                            <div class="grid-item"><span>Программное обеспечение:</span><strong style="font-size: 18px; color: #fff;">${esc(swName)}</strong></div>
                            <div class="grid-item"><span>Порт:</span><strong style="font-size: 16px; color: #58a6ff;">${esc(port)}</strong></div>
                        </div>
                        <details class="modal-details" open>
                            <summary>🧾 Характеристики</summary>
                            <div class="modal-details-body">
                                <div class="sw-context" style="margin-top:0;">
                                    <ul>
                                        <li><strong>Тип/категория:</strong> ${esc(swCategory || 'Не определено')}</li>
                                        <li><strong>Назначение:</strong> ${esc(swPurpose || 'Нет описания')}</li>
                                        <li><strong>Последствия успешной атаки:</strong> ${esc(swImpact || 'Требуется ручная оценка')}</li>
                                        <li><strong>Контекст:</strong> ${esc(swScope || 'Локальный компонент инфраструктуры')}</li>
                                    </ul>
                                </div>
                            </div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">
                                <p class="trace-meta" style="margin:0 0 10px 0;">Основание: строки отчёта, в которых фигурирует это ПО/порт, плюс связанные CVE/CWE/CAPEC.</p>
                                ${formatEvidenceTable(items, 40)}
                            </div>
                        </details>
                    </div>
                `;
            } 
            else if (nodeInfo.type === 'source') {
                let src = nodeInfo.source || String(r.found_by || "");
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🕵️ Источник: ${esc(src)}</h2>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">
                                <p class="trace-meta" style="margin:0 0 10px 0;">Основание: строки отчёта, где поле «Кем обнаружено» содержит этот источник.</p>
                                ${formatEvidenceTable(items, 40)}
                            </div>
                        </details>
                    </div>
                `;
            }
            else if (nodeInfo.type === 'tool') {
                let tools = String(r.tools || "");
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🔫 Инструменты</h2>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>🧾 Характеристики</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(tools || '—')}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">${formatEvidenceTable(items, 40)}</div>
                        </details>
                    </div>
                `;
            }
            else if (nodeInfo.type === 'steps') {
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">📜 Логика атаки</h2>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>🧾 Шаги</summary>
                            <div class="modal-details-body">${formatStepsToOl(r.steps)}</div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">${formatEvidenceTable(items, 40)}</div>
                        </details>
                    </div>
                `;
            }
            else if (nodeInfo.type === 'plan') {
                let rec = String(r.rec || "");
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🛠️ План устранения</h2>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>🧾 Рекомендации</summary>
                            <div class="modal-details-body"><p class="rec-box" style="margin:0; white-space:pre-wrap;">${esc(rec || 'Специфичных рекомендаций нет.')}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">${formatEvidenceTable(items, 40)}</div>
                        </details>
                    </div>
                `;
            }
            else if (nodeInfo.type === 'mitre') {
                let mitreId = nodeInfo.mitre || (splitCsv(r.mitre)[0] || "");
                let meta = (mitreMeta && mitreId && mitreMeta[mitreId]) ? mitreMeta[mitreId] : {};
                let name = meta && meta.name ? String(meta.name) : "";
                let tactic = meta && meta.tactic ? String(meta.tactic) : "";
                let desc = meta && meta.description ? String(meta.description) : "";
                let detection = meta && meta.detection ? String(meta.detection) : "";
                let platforms = meta && meta.platforms ? meta.platforms : [];
                let mitigations = meta && meta.mitigations ? meta.mitigations : [];
                let relatedCwe = meta && meta.related_cwe ? meta.related_cwe : [];
                let relatedCapec = meta && meta.related_capec ? meta.related_capec : [];
                let reqServices = meta && meta.requires_service ? meta.requires_service : [];
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">⚔️ MITRE ATT&CK: ${esc(mitreId || '—')}</h2>
                    </div>
                    <div class="grid-info">
                        <div class="grid-item"><span>Техника:</span><strong>${esc(name || '—')}</strong></div>
                        <div class="grid-item"><span>Тактика:</span><strong>${esc(tactic || '—')}</strong></div>
                        <div class="grid-item"><span>Платформы:</span><strong>${esc((platforms || []).join(", ") || '—')}</strong></div>
                        <div class="grid-item"><span>Связанных CWE (из БД):</span><strong>${(relatedCwe || []).length}</strong></div>
                        <div class="grid-item"><span>Связанных CAPEC (из БД):</span><strong>${(relatedCapec || []).length}</strong></div>
                        <div class="grid-item"><span>Строк-оснований (в отчёте):</span><strong>${items.length}</strong></div>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>📝 Описание техники</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(desc || 'Описание отсутствует.')}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🔎 Детектирование</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(detection || 'Не указано.')}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🛡️ Митигирующие меры</summary>
                            <div class="modal-details-body">${traceUl((mitigations || []).map(x => String(x)), "Не указано.")}</div>
                        </details>
                        <details class="modal-details">
                            <summary>🧩 Требуемые сервисы</summary>
                            <div class="modal-details-body">${traceUl((reqServices || []).map(x => String(x)), "Не указано.")}</div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">${formatEvidenceTable(items, 40)}</div>
                        </details>
                    </div>
                `;
            }
            else if (nodeInfo.type === 'finding') {
                let rawCves = JSON.stringify((r.cve || "").split(",").map(s => s.trim()).filter(Boolean));
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 18px; color: #fff;">🧩 Запись корреляции</h2>
                    </div>
                    <div class="grid-info">
                        <div class="grid-item"><span>Критичность:</span><strong style="color: ${getSevColor(r.sev)}">${esc(r.sev)}</strong></div>
                        <div class="grid-item"><span>Статус:</span><strong style="color: ${getFeasColor(r.feas)}">${esc(r.feas)}</strong></div>
                        <div class="grid-item"><span>ПО:</span><strong>${esc(r.sw)} <span class="trace-meta">(порт: ${esc(r.port)})</span></strong></div>
                        <div class="grid-item"><span>CWE:</span><strong>${esc(r.cwe)}</strong></div>
                        <div class="grid-item"><span>CAPEC:</span><strong>${esc(r.capec)}</strong></div>
                        <div class="grid-item"><span>Источник:</span><strong>${esc(r.found_by)}</strong></div>
                    </div>
                    <div class="modal-toolbar">
                        <button type="button" class="agg-btn" onclick='openRawRegistryForCves(${rawCves})'>📂 Сырой реестр CVE</button>
                    </div>
                    <div class="modal-body modal-body-accordion">
                        <details class="modal-details" open>
                            <summary>📝 CVE</summary>
                            <div class="modal-details-body"><p style="color:#58a6ff; font-family:monospace; font-size: 13px; margin:0;">${esc(r.cve || 'N/A')}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>📝 Описание</summary>
                            <div class="modal-details-body"><p style="margin:0; line-height:1.55; white-space:pre-wrap;">${esc(r.desc || 'Описание отсутствует.')}</p></div>
                        </details>
                        <details class="modal-details">
                            <summary>🔬 Трассировка вердикта</summary>
                            <div class="modal-details-body">${formatTraceBlock(r.feasibility_trace, r)}</div>
                        </details>
                        <details class="modal-details">
                            <summary>🔗 Связи и основания</summary>
                            <div class="modal-details-body">${formatEvidenceTable(items, 40)}</div>
                        </details>
                    </div>
                `;
            }
            else if (nodeInfo.type === 'aggr' || nodeInfo.type === 'verdict') {
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
            else {
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 18px; color: #fff;">Детали узла</h2>
                    </div>
                    <div class="modal-body">
                        <p style="margin:0; white-space:pre-wrap;">${esc(JSON.stringify(nodeInfo || {}, null, 2))}</p>
                    </div>
                `;
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
                detailsMapRows[memberId] = { type: 'member', data: m, parentId: 'aggr_' + groupData.id };
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
