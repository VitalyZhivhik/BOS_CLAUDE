import json
import os
import re

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
        .map-selector { display: flex; align-items: center; gap: 15px; background: #161b22; padding: 10px 15px; border-radius: 6px; border: 1px solid #58a6ff;}
        .map-selector label { font-size: 14px; color: #58a6ff; font-weight: bold; text-transform: uppercase; margin: 0;}
        .map-selector select { flex: 1; padding: 10px; background: var(--accent); color: #fff; border: none; border-radius: 4px; outline: none; font-size: 15px; font-weight: bold; cursor: pointer; box-shadow: 0 2px 4px rgba(0,0,0,0.5);}
        .map-selector select:hover { background: #3182ce; }
        
        .filters-bar { display: flex; gap: 15px; }
        .filter-item { display: flex; flex-direction: column; flex: 1; }
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
    </style>
</head>
<body>
    <div class="container">
        <h1 style="margin-top: 20px;">🛡️ Интерактивная Карта Поверхности Атаки SOC</h1>
        
        <div class="stats">
            <div class="stat-box"><div class="title">Агрегированных векторов (Схлопнуто)</div><div class="num" id="st-total" style="color: #58a6ff;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #da3633;"><div class="title">Реализуемые (КРИТИЧНО)</div><div class="num" id="st-real" style="color: #ff7b72;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #d29922;"><div class="title">Частично реализуемые (ПРОВЕРИТЬ)</div><div class="num" id="st-part" style="color: #e3b341;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #238636;"><div class="title">Не реализуемые (ЗАБЛОКИРОВАНО)</div><div class="num" id="st-noreal" style="color: #3fb950;">0</div></div>
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
                <div class="map-selector">
                    <label>🔍 ВЫБОР ТОПОЛОГИИ КАРТЫ:</label>
                    <select id="map-view-select" onchange="applyFilters()">
                        <option value="1">🗺️ КАРТА 1: Инфраструктура (Сервер ➔ Реальное ПО ➔ Уязвимость)</option>
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
        var rawCveData = __RAW_CVE_DATA__;
        var sysData = __SYS_DATA__;
        var network = null;
        var detailsMap = {};

        function init() {
            populateFilters();
            applyFilters();
            renderRawCveTable();
        }

        function renderRawCveTable() {
            let tbody = document.getElementById("raw-cve-body");
            tbody.innerHTML = "";
            rawCveData.forEach(c => {
                let portStr = (c.port !== 'None' && c.port !== '') ? c.port : 'Н/Д';
                let tr = `<tr>
                    <td style="font-family: monospace; color: #58a6ff; font-weight: bold;">${c.cve}</td>
                    <td><span class="badge ${getSevClass(c.sev)}">${c.sev}</span></td>
                    <td style="font-weight: 500;">${c.sw}</td>
                    <td>${portStr}</td>
                    <td><span style="background: #161b22; padding: 4px 8px; border-radius: 4px; border: 1px solid #30363d; font-size: 12px;">${c.capec}</span></td>
                </tr>`;
                tbody.innerHTML += tr;
            });
        }

        function toggleRawCve() {
            let el = document.getElementById("raw-cve-container");
            el.style.display = el.style.display === "none" || el.style.display === "" ? "block" : "none";
        }

        function populateFilters() {
            let capecs = new Set(); let cwes = new Set(); let sws = new Set();
            reportData.forEach(r => { capecs.add(r.capec); cwes.add(r.cwe); sws.add(r.sw); });
            
            let addOpt = (id, set) => {
                let el = document.getElementById(id);
                Array.from(set).sort().forEach(x => { el.innerHTML += `<option value="${x}">${x}</option>`; });
            };
            addOpt('f-sw', sws); addOpt('f-capec', capecs); addOpt('f-cwe', cwes);
        }

        function applyFilters() {
            let capecF = document.getElementById('f-capec').value;
            let cweF = document.getElementById('f-cwe').value;
            let swF = document.getElementById('f-sw').value;
            
            let filtered = reportData.filter(r => {
                return (capecF === 'all' || r.capec === capecF) &&
                       (cweF === 'all' || r.cwe === cweF) &&
                       (swF === 'all' || r.sw === swF);
            });
            
            updateStats(filtered);
            renderTable(filtered);
            renderGraph(filtered);
        }

        function updateStats(data) {
            document.getElementById('st-total').innerText = data.length;
            document.getElementById('st-real').innerText = data.filter(x => x.feas === 'РЕАЛИЗУЕМА').length;
            document.getElementById('st-part').innerText = data.filter(x => x.feas.includes('ЧАСТИЧНО')).length;
            document.getElementById('st-noreal').innerText = data.filter(x => x.feas === 'НЕ РЕАЛИЗУЕМА').length;
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
            let f = feas.toUpperCase();
            if(f === "РЕАЛИЗУЕМА") return "real";
            if(f.includes("ЧАСТИЧНО")) return "part-real";
            return "noreal";
        }
        function getFeasColor(feas) {
            let f = feas.toUpperCase();
            if(f === "РЕАЛИЗУЕМА") return "#da3633"; 
            if(f.includes("ЧАСТИЧНО")) return "#d29922"; 
            if(f === "НЕ РЕАЛИЗУЕМА") return "#238636"; 
            return "#8b949e";
        }

        function renderTable(data) {
            let tbody = document.getElementById('table-body');
            tbody.innerHTML = '';
            data.forEach(r => {
                let nameShort = r.name.substring(0, 50) + (r.name.length > 50 ? "..." : "");
                let dupes = r.count > 1 ? `<br><small style="color:#58a6ff;">(Сгруппировано из ${r.count} CVE)</small>` : "";
                
                let tr = `<tr class="clickable-row" onclick="openModal('aggr_${r.id}')">
                    <td><strong style="color: #8b949e;">(Группа)</strong></td>
                    <td><strong>${r.sw}</strong><br><small>Порт: ${r.port}</small></td>
                    <td>${nameShort}${dupes}</td>
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

            // ---- КАРТА 1: Инфраструктурная ----
            if (viewId === "1") {
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
            // ---- КАРТА 2: Логическая (С УЗЛОМ ПО) ----
            else if (viewId === "2") {
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
            // ---- КАРТА 3: Источник Обнаружения ----
            else if (viewId === "3") {
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
            // ---- КАРТА 4: План Устранения ----
            else if (viewId === "4") {
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
            // ---- КАРТА 5: Полигон ----
            else if (viewId === "5") {
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
            
            // Динамическое расстояние узлов (Для Карты 4 делаем узлы сильно дальше друг от друга)
            var nodeSpc = viewId === "4" ? 650 : 400;
            var levelSep = viewId === "4" ? 350 : 250;
            
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
            let nodeInfo = detailsMap[id];
            if(!nodeInfo) return;
            
            let r = nodeInfo.data;
            let contentDiv = document.getElementById("dynamic-modal-content");
            
            // 1. Если кликнули на слабость CWE
            if (nodeInfo.type === 'cwe') {
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🐛 Класс уязвимости: ${r.cwe}</h2>
                    </div>
                    <div class="modal-body">
                        <h4 style="color:#58a6ff;">Подробное описание (Common Weakness Enumeration)</h4>
                        <p style="background: #0d1117; padding: 15px; border-radius: 6px; border: 1px solid #30363d; font-size: 15px;">${r.cwe_desc}</p>
                    </div>
                `;
            } 
            // 2. Если кликнули на целевое ПО
            else if (nodeInfo.type === 'sw') {
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 20px; color: #fff;">🎯 Анализ Целевого Компонента</h2>
                    </div>
                    <div class="modal-body">
                        <div class="grid-info" style="grid-template-columns: 1fr;">
                            <div class="grid-item"><span>Обнаруженное программное обеспечение:</span><strong style="font-size: 18px; color: #fff;">${r.sw}</strong></div>
                            <div class="grid-item"><span>Открытый порт:</span><strong style="font-size: 16px; color: #58a6ff;">${r.port}</strong></div>
                        </div>
                        <p style="color:#8b949e; font-size:13px; margin-top: 10px;">* Это реальная служба или системный компонент, который был просканирован OVAL-движком на вашем сервере.</p>
                    </div>
                `;
            } 
            // 3. Стандартная карточка (Клик по вектору атаки или агрегации)
            else {
                contentDiv.innerHTML = `
                    <div class="modal-header">
                        <h2 style="margin: 0; font-size: 18px; color: #fff;">Агрегированная группа: ${r.capec}</h2>
                    </div>
                    <div class="grid-info">
                        <div class="grid-item"><span>Критичность:</span><strong style="color: ${getSevColor(r.sev)}">${r.sev}</strong></div>
                        <div class="grid-item"><span>Статус (Сводный):</span><strong style="color: ${getFeasColor(r.feas)}">${r.feas}</strong></div>
                        <div class="grid-item"><span>Атакуемое ПО:</span><strong>${r.sw} (Порт: ${r.port})</strong></div>
                        <div class="grid-item"><span>Вектор (CAPEC):</span><strong>${r.capec}</strong></div>
                        <div class="grid-item"><span>Класс (CWE):</span><strong>${r.cwe}</strong></div>
                        <div class="grid-item"><span>Кем обнаружено:</span><strong>${r.found_by}</strong></div>
                    </div>
                    <div class="modal-body">
                        <h4>📝 Включенные CVE (Агрегация из ${r.count} находок)</h4>
                        <p style="color:#58a6ff; font-family:monospace; font-size: 13px;">${r.cve}</p>

                        <h4>📝 Описание уязвимости</h4>
                        <p>${r.desc}</p>
                        
                        <h4 style="color: #e3b341;">🥷 Учебный полигон (Как атаковать)</h4>
                        <p class="attack-box">
                            <strong style="color:#d29922">Требуемое ПО:</strong> <span>${r.tools}</span><br><br>
                            <strong style="color:#d29922">Шаги эксплуатации:</strong><br>
                            <span>${r.steps.replace(/\\n/g, "<br>")}</span>
                        </p>

                        <h4 style="color: #3fb950;">🛡️ Как защититься (Устранение)</h4>
                        <p class="rec-box">${r.rec}</p>
                    </div>
                `;
            }
            
            modal.style.display = "block";
        }

        function closeModal() { modal.style.display = "none"; }
        window.onclick = function(event) { if (event.target == modal) closeModal(); }

        window.onload = init;
    </script>
</body>
</html>
"""

class SoftwareEnricher:
    """
    Продвинутый алгоритм сопоставления CVE/Вектора с реально установленным ПО на сервере.
    """
    def __init__(self, system_info, cve_db, capec_db):
        self.installed_software = system_info.get('installed_software', [])
        self.open_ports = system_info.get('open_ports', [])
        self.cve_db = cve_db if isinstance(cve_db, dict) else {}
        self.capec_db = capec_db if isinstance(capec_db, dict) else {}

    def identify_real_software(self, record, port_str):
        cve_id = getattr(record, 'cve_id', '')
        capec_id = getattr(record, 'capec_id', '')
        fallback_sw = getattr(record, 'target_software', '').strip()

        # 1. Поиск точного совпадения по тексту CVE
        matched_sw = self._search_in_installed_software(cve_id, capec_id)
        if matched_sw:
            return matched_sw

        # 2. Если сканер OVAL передал явное имя и это не заглушка — верим ему
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
    def __init__(self, system_summary, correlation_results, summary, toolkit=None, **kwargs):
        self.system_summary = system_summary
        self.summary = summary
        self.toolkit = toolkit
        
        self.tools_db = self._load_local_db("databases/tools_database.json")
        self.cwe_db = self._load_local_db("databases/cwe_database.json")
        self.capec_db = self._load_local_db("databases/capec_database.json")
        self.cve_db = self._load_local_db("databases/cve_database.json")
        
        self.raw_results = correlation_results
        
        # Инициализируем обогатитель ПО
        self.sw_enricher = SoftwareEnricher(self.system_summary, self.cve_db, self.capec_db)

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

    def _get_cwe_description(self, cwe_id):
        """Достает подробное описание слабости из БД"""
        if not cwe_id or cwe_id == 'Нет CWE': 
            return "Описание отсутствует."
        db = self.cwe_db
        if isinstance(db, dict):
            if cwe_id in db: return db[cwe_id].get('description', 'Описание не найдено.')
            num = cwe_id.replace("CWE-", "")
            if num in db: return db[num].get('description', 'Описание не найдено.')
        elif isinstance(db, list):
            for item in db:
                if item.get('id') == cwe_id or item.get('cwe_id') == cwe_id:
                    return item.get('description', 'Описание не найдено.')
        return "Детальное описание для данного CWE не найдено в локальной базе."

    def _get_max_sev(self, sevs):
        order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        valid_sevs = [s for s in sevs if s]
        if not valid_sevs: return 'INFO'
        return max(valid_sevs, key=lambda s: order.get(str(s).upper(), 0))

    def _get_worst_feas(self, feas_list):
        valid = [str(f).upper() for f in feas_list if f]
        if any('РЕАЛИЗУЕМА' == f for f in valid): return 'РЕАЛИЗУЕМА'
        if any('ЧАСТИЧНО' in f for f in valid): return 'ЧАСТИЧНО РЕАЛИЗУЕМА'
        if any('НЕ РЕАЛИЗУЕМА' == f for f in valid): return 'НЕ РЕАЛИЗУЕМА'
        return 'UNKNOWN'

    def generate_json(self, filepath):
        pass

    def generate_html(self, filepath):
        js_data = []
        
        # 1. Готовим данные агрегированных групп для карт
        for i, (key, g) in enumerate(self.aggregated_groups.items()):
            base_r = g['base_record']
            
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

            cwe_id = getattr(base_r, 'cwe_id', '')
            cwe_desc = self._get_cwe_description(cwe_id) # Подтягиваем описание CWE
            
            tools = getattr(base_r, 'attack_software', None)
            steps = getattr(base_r, 'attack_steps', None)

            if not tools and self.tools_db and cwe_id in self.tools_db:
                db_info = self.tools_db[cwe_id]
                tools_list = db_info.get('tools', [])
                tools = ", ".join(tools_list) if tools_list else "Nmap, Metasploit"
                steps = db_info.get('exploitation_steps', "1. Сканирование сети.\\n2. Выбор эксплоита.\\n3. Запуск.")
            
            if not tools: tools = "Burp Suite, SQLMap, Nmap"
            if not steps: steps = "1. Анализ порта.\\n2. Идентификация службы.\\n3. Подбор эксплоита."

            js_data.append({
                "id": i,
                "cve": cves_joined,  
                "cwe": cwe_id or 'CWE-Неизвестно',
                "cwe_desc": cwe_desc, # Передаем описание CWE в JavaScript
                "capec": getattr(base_r, 'capec_id', None) or 'CAPEC-Неизвестно',
                "name": names_joined,
                "sw": g['mapped_sw'], 
                "port": port,
                "feas": worst_feas,
                "sev": max_sev,
                "desc": getattr(base_r, 'description', None) or 'Описание отсутствует.',
                "rec": getattr(base_r, 'recommendation', None) or 'Специфичных рекомендаций нет.',
                "count": g['count'], 
                "found_by": found_by_joined,
                "tools": tools,
                "steps": steps
            })

        # 2. Готовим сырые данные для Расширенного Меню
        raw_js_data = []
        for r in self.raw_results:
            cve_str = getattr(r, 'cve_id', 'N/A')
            cve_list = [c.strip() for c in cve_str.split(',')] if cve_str else ["N/A"]
            
            port_raw = getattr(r, 'target_port', None)
            if port_raw in (None, "None", "null", "", 0, "0"):
                port = "Локальный"
            else:
                port = str(port_raw)
                
            # ИСПОЛЬЗУЕМ НОВЫЙ АЛГОРИТМ ДЛЯ СЫРЫХ ДАННЫХ
            real_sw = self.sw_enricher.identify_real_software(r, port)
            
            for single_cve in cve_list:
                if single_cve == "N/A" and len(cve_list) > 1: 
                    continue
                    
                raw_js_data.append({
                    "cve": single_cve,
                    "sev": getattr(r, 'severity', 'INFO'),
                    "sw": real_sw,
                    "port": port,
                    "capec": getattr(r, 'capec_id', 'N/A')
                })
            
        sys_data = {
            "hostname": self.system_summary.get('hostname', 'Целевой Сервер'),
            "os": self.system_summary.get('os', 'Неизвестная ОС'),
            "ips": ", ".join(self.system_summary.get('ip_addresses', [])),
            "ports_count": self.system_summary.get('open_ports_count', 0)
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            html = HTML_TEMPLATE.replace('__REPORT_DATA__', json.dumps(js_data, ensure_ascii=False))
            html = html.replace('__RAW_CVE_DATA__', json.dumps(raw_js_data, ensure_ascii=False))
            html = html.replace('__SYS_DATA__', json.dumps(sys_data, ensure_ascii=False))
            f.write(html)
            
        return filepath