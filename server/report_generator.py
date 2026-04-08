"""
Генератор отчетов об уязвимостях (Дашборд SOC).
ИСПРАВЛЕНИЯ:
  - Агрегация дубликатов (Схлопывание SQLi и других атак по CWE/CAPEC).
  - Панель фильтров (по CWE, CAPEC, ПО).
  - Ортогональные (прямоугольные) стрелки и увеличенное расстояние между узлами.
  - Логическая цепочка (CAPEC -> ПО -> CVE -> CWE -> Вердикт).
  - Корректная обработка портов "None".
"""
import json
import os

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
        
        .btn-toggle { background: var(--accent); color: #fff; border: none; padding: 10px 20px; border-radius: 5px; font-weight: bold; cursor: pointer; font-size: 14px; transition: 0.2s; }
        .btn-toggle:hover { background: #3182ce; }
        .header-flex { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 15px; }

        /* Фильтры */
        .filters-bar { display: flex; gap: 15px; margin-bottom: 15px; background: #0d1117; padding: 15px; border-radius: 8px; border: 1px solid var(--border); }
        .filter-item { display: flex; flex-direction: column; flex: 1; }
        .filter-item label { font-size: 12px; color: #8b949e; margin-bottom: 5px; text-transform: uppercase; font-weight: bold; }
        .filter-item select { padding: 10px; background: var(--card); color: #c9d1d9; border: 1px solid var(--border); border-radius: 4px; outline: none; font-size: 14px; cursor: pointer; }
        .filter-item select:focus { border-color: var(--accent); }

        /* Карта */
        #network-map { width: 100%; height: 750px; border: 1px solid var(--border); border-radius: 8px; background: #010409; outline: none; }
        
        /* Статистика */
        .stats { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
        .stat-box { background: var(--card); border: 1px solid var(--border); padding: 15px; border-radius: 8px; flex: 1; text-align: center; }
        .stat-box .title { font-size: 12px; color: #8b949e; text-transform: uppercase; }
        .stat-box .num { font-size: 28px; font-weight: bold; margin-top: 5px; }
        
        /* Таблица */
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { padding: 14px; text-align: left; border-bottom: 1px solid var(--border); }
        th { background-color: #21262d; color: #ffffff; }
        .clickable-row { cursor: pointer; transition: background 0.2s; }
        .clickable-row:hover { background-color: #1f2428; }
        .details-btn { color: var(--accent); font-weight: 600; text-align: right; }
        
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
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); backdrop-filter: blur(3px); }
        .modal-content { background: var(--card); margin: 5% auto; padding: 25px; border: 1px solid var(--border); width: 65%; max-width: 900px; border-radius: 8px; position: relative; color: #c9d1d9; }
        .close { color: #8b949e; position: absolute; right: 20px; top: 15px; font-size: 28px; cursor: pointer; }
        .close:hover { color: #ff7b72; }
        .modal-header { border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 15px; }
        
        .grid-info { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; background: #0d1117; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid var(--border); }
        .grid-item span { display: block; font-size: 12px; color: #8b949e; margin-bottom: 4px; }
        .grid-item strong { font-size: 14px; color: #58a6ff; }
        
        .modal-body h4 { color: #fff; margin-bottom: 8px; border-bottom: 1px dashed var(--border); padding-bottom: 5px; }
        .modal-body p { line-height: 1.5; font-size: 14px; background: #0d1117; padding: 12px; border-radius: 6px; border: 1px solid var(--border); }
        .rec-box { border-left: 4px solid #238636 !important; }
    </style>
</head>
<body>
    <div class="container">
        <h1 style="margin-top: 20px;">🛡️ Дашборд Безопасности SOC</h1>
        
        <div class="stats">
            <div class="stat-box"><div class="title">Сгруппированных угроз</div><div class="num" id="st-total" style="color: #58a6ff;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #da3633;"><div class="title">Реализуемые (КРИТИЧНО)</div><div class="num" id="st-real" style="color: #ff7b72;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #d29922;"><div class="title">Частично реализуемые (ПРОВЕРИТЬ)</div><div class="num" id="st-part" style="color: #e3b341;">0</div></div>
            <div class="stat-box" style="border-top: 3px solid #238636;"><div class="title">Не реализуемые (ЗАБЛОКИРОВАНО)</div><div class="num" id="st-noreal" style="color: #3fb950;">0</div></div>
        </div>

        <div class="card">
            <div class="header-flex">
                <h2 style="margin:0; border:none;">🗺️ Схема анализа уязвимостей</h2>
                <button id="toggleBtn" class="btn-toggle">🔄 Включить логическую цепочку (CAPEC ➔ ПО ➔ CVE ➔ Вердикт)</button>
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
                    <label>Фильтр по Слабости (CWE):</label>
                    <select id="f-cwe" onchange="applyFilters()"><option value="all">-- Все классы --</option></select>
                </div>
            </div>

            <p style="margin-bottom: 15px; font-size: 13px; color: #8b949e;">💡 Линии строго направлены. Узлы широко расставлены. <strong>Кликните на любой узел</strong> для открытия карточки с подробным описанием.</p>
            <div id="network-map"></div>
        </div>

        <div class="card">
            <h2>📋 Перечень сгруппированных векторов</h2>
            <table>
                <thead>
                    <tr>
                        <th>Идентификатор</th>
                        <th>Целевое ПО</th>
                        <th>Вектор / Название (Дубли)</th>
                        <th>Критичность</th>
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
            <span class="close">&times;</span>
            <div class="modal-header">
                <h2 id="m-title" style="margin: 0; font-size: 18px; color: #fff;">Название</h2>
            </div>
            <div class="grid-info">
                <div class="grid-item"><span>Критичность:</span><strong id="m-sev">INFO</strong></div>
                <div class="grid-item"><span>Статус:</span><strong id="m-feas">UNKNOWN</strong></div>
                <div class="grid-item"><span>Атакуемое ПО / Порт:</span><strong id="m-sw">Н/Д</strong></div>
                <div class="grid-item"><span>Количество дублей (попыток):</span><strong id="m-count">1</strong></div>
                <div class="grid-item"><span>Вектор атаки (CAPEC):</span><strong id="m-capec">Н/Д</strong></div>
                <div class="grid-item"><span>Класс слабости (CWE):</span><strong id="m-cwe">Н/Д</strong></div>
            </div>
            <div class="modal-body">
                <h4>📝 Описание уязвимости</h4>
                <p id="m-desc">Описание...</p>
                <h4>🛠️ Рекомендации по устранению</h4>
                <p id="m-rec" class="rec-box">Рекомендации...</p>
            </div>
        </div>
    </div>

    <script type="text/javascript">
        // Данные инжектируются Python
        var reportData = __REPORT_DATA__;
        var sysData = __SYS_DATA__;

        var currentView = 1;
        var network = null;
        var detailsMap = {};

        function init() {
            populateFilters();
            applyFilters();
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
            if(f === "РЕАЛИЗУЕМА") return "#da3633"; // Красный
            if(f.includes("ЧАСТИЧНО")) return "#d29922"; // Желтый/Оранжевый
            if(f === "НЕ РЕАЛИЗУЕМА") return "#238636"; // Зеленый
            return "#8b949e";
        }

        function renderTable(data) {
            let tbody = document.getElementById('table-body');
            tbody.innerHTML = '';
            data.forEach(r => {
                let nameShort = r.name.substring(0, 50) + (r.name.length > 50 ? "..." : "");
                let dupes = r.count > 1 ? `<br><small style="color:#58a6ff;">(Сгруппировано: ${r.count} попыток)</small>` : "";
                
                let tr = `<tr class="clickable-row" onclick="openModal(${r.id})">
                    <td><strong>${r.cve}</strong></td>
                    <td>${r.sw}<br><small>Порт: ${r.port}</small></td>
                    <td>${nameShort}${dupes}</td>
                    <td><span class="badge ${getSevClass(r.sev)}">${r.sev}</span></td>
                    <td><span class="badge ${getFeasClass(r.feas)}">${r.feas}</span></td>
                    <td class="details-btn">Подробнее ➔</td>
                </tr>`;
                tbody.innerHTML += tr;
                detailsMap[r.id] = r; // Сохраняем для модалки
            });
        }

        function renderGraph(data) {
            let nodes = [];
            let edges = [];
            let addedEdges = new Set();
            
            let addEdge = (f, t, c, w, d) => {
                let k = f + "_" + t;
                if(!addedEdges.has(k)) { addedEdges.add(k); edges.push({from: f, to: t, color: c, width: w||2, dashes: d||false}); }
            };

            if (currentView === 1) {
                // ИНФРАСТРУКТУРНАЯ СХЕМА (Сервер -> ПО -> CAPEC -> CVE)
                let srvId = "srv_1";
                nodes.push({ id: srvId, label: "🖥️ " + sysData.hostname + "\\n(" + sysData.os + ")", shape: "box", level: 0, color: {background: "#1f77b4", border: "#ffffff"}, font: {color: "#ffffff", size: 18} });
                
                let added = new Set();
                data.forEach(r => {
                    let cStr = r.count > 1 ? "\\n(Дублей: " + r.count + ")" : "";
                    
                    let swId = "sw_" + r.sw + "_" + r.port;
                    if(!added.has(swId)) {
                        nodes.push({ id: swId, label: "🎯 ПО: " + r.sw + "\\nПорт: " + r.port, level: 1, shape: "box", color: {background: "#484f58"} });
                        addEdge(srvId, swId, "#8b949e"); added.add(swId);
                    }
                    
                    let atkId = "atk_" + r.id;
                    let nShort = r.name.substring(0, 30) + (r.name.length > 30 ? "..." : "");
                    nodes.push({ id: atkId, label: "🥷 " + r.capec + "\\n" + nShort + cStr, level: 2, shape: "box", color: {background: "#58a6ff"} });
                    addEdge(swId, atkId, "#8b949e");
                    
                    let cveId = "cve_" + r.cve;
                    if(!added.has(cveId)) {
                        nodes.push({ id: cveId, label: "🛡️ " + r.cve + "\\n" + r.sev, level: 3, shape: "box", color: {background: getSevColor(r.sev)} });
                        added.add(cveId);
                    }
                    addEdge(atkId, cveId, getFeasColor(r.feas), r.feas === "РЕАЛИЗУЕМА" ? 3 : 2, r.feas === "НЕ РЕАЛИЗУЕМА");
                    
                    // Хак: привязываем ID из таблицы для открытия модалки по клику на узел графа
                    detailsMap[atkId] = r; detailsMap[cveId] = r;
                });
            } else {
                // ЛОГИЧЕСКАЯ СХЕМА (CAPEC -> ПО -> CVE -> CWE -> Вердикт)
                let added = new Set();
                data.forEach(r => {
                    let cStr = r.count > 1 ? "\\n(Дублей: " + r.count + ")" : "";
                    
                    let capecId = "l_capec_" + r.capec;
                    if(!added.has(capecId)) { nodes.push({ id: capecId, label: "🥷 Вектор: " + r.capec + cStr, level: 0, shape: "box", color: {background: "#58a6ff"} }); added.add(capecId); }
                    
                    let swId = "l_sw_" + r.sw + "_" + r.port;
                    if(!added.has(swId)) { nodes.push({ id: swId, label: "🎯 Цель: " + r.sw + "\\nПорт: " + r.port, level: 1, shape: "box", color: {background: "#1f77b4"} }); added.add(swId); }
                    
                    let cveId = "l_cve_" + r.cve;
                    if(!added.has(cveId)) { nodes.push({ id: cveId, label: "🛡️ " + r.cve + "\\n" + r.sev, level: 2, shape: "box", color: {background: getSevColor(r.sev)} }); added.add(cveId); }
                    
                    let cweId = "l_cwe_" + r.cwe;
                    if(!added.has(cweId)) { nodes.push({ id: cweId, label: "🐛 " + r.cwe, level: 3, shape: "box", color: {background: "#484f58"} }); added.add(cweId); }
                    
                    let verdId = "l_verd_" + r.id;
                    nodes.push({ id: verdId, label: "⚖️ Вердикт:\\n" + r.feas, level: 4, shape: "box", color: {background: getFeasColor(r.feas)} });
                    
                    addEdge(capecId, swId, "#8b949e");
                    addEdge(swId, cveId, "#8b949e");
                    addEdge(cveId, cweId, "#8b949e");
                    addEdge(cweId, verdId, getFeasColor(r.feas), 3);
                    
                    detailsMap[capecId] = r; detailsMap[cveId] = r; detailsMap[verdId] = r;
                });
            }

            if(network) network.destroy();
            
            var container = document.getElementById('network-map');
            var visData = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
            
            // Настройки с жесткими ортогональными(прямоугольными) стрелками и огромным расстоянием
            var options = {
                layout: {
                    hierarchical: {
                        direction: 'UD',
                        sortMethod: 'directed',
                        nodeSpacing: 400,    // ОГРОМНОЕ расстояние по горизонтали
                        levelSeparation: 250 // ОГРОМНОЕ расстояние по вертикали
                    }
                },
                physics: false, // Отключаем прыгание узлов
                nodes: { borderWidth: 2, shadow: true, margin: 15, font: { face: "Segoe UI" } },
                edges: { 
                    shadow: true, 
                    arrows: { to: { enabled: true, scaleFactor: 0.8 } },
                    smooth: { 
                        type: 'cubicBezier', 
                        forceDirection: 'vertical', 
                        roundness: 0.15 // 0.15 делает линии визуально "прямоугольными"
                    } 
                },
                interaction: { hover: true, navigationButtons: true, keyboard: true }
            };
            
            network = new vis.Network(container, visData, options);
            network.on("click", function(params) {
                if (params.nodes.length > 0) openModal(params.nodes[0]);
            });
        }

        document.getElementById('toggleBtn').onclick = function() {
            currentView = currentView === 1 ? 2 : 1;
            this.innerText = currentView === 1 ? "🔄 Включить логическую цепочку (CAPEC ➔ ПО ➔ CVE ➔ Вердикт)" : "🔄 Вернуться к инфраструктурной схеме (Сервер ➔ Атака)";
            applyFilters();
        };

        // Логика Модалки
        var modal = document.getElementById("infoModal");
        var span = document.getElementsByClassName("close")[0];

        function openModal(id) {
            let r = detailsMap[id];
            if(!r) return;
            
            document.getElementById("m-title").innerHTML = "[" + r.cve + "] " + r.name;
            
            document.getElementById("m-sev").innerText = r.sev;
            document.getElementById("m-sev").style.color = getSevColor(r.sev);
            
            document.getElementById("m-feas").innerText = r.feas;
            document.getElementById("m-feas").style.color = getFeasColor(r.feas);
            
            document.getElementById("m-sw").innerText = r.sw + " (Порт: " + r.port + ")";
            document.getElementById("m-count").innerText = r.count + " (дубликаты схлопнуты)";
            document.getElementById("m-capec").innerText = r.capec;
            document.getElementById("m-cwe").innerText = r.cwe;
            
            document.getElementById("m-desc").innerHTML = r.desc;
            document.getElementById("m-rec").innerHTML = r.rec;
            
            modal.style.display = "block";
        }

        span.onclick = function() { modal.style.display = "none"; }
        window.onclick = function(event) { if (event.target == modal) modal.style.display = "none"; }

        // Старт
        window.onload = init;
    </script>
</body>
</html>
"""

class ReportGenerator:
    def __init__(self, system_summary, correlation_results, summary):
        self.system_summary = system_summary
        self.summary = summary
        
        # Агрегация дубликатов (Схлопывание похожих атак)
        self.results = []
        seen = {}
        for r in correlation_results:
            cve = getattr(r, 'cve_id', None) or 'Нет CVE'
            capec = getattr(r, 'capec_id', None) or 'Нет CAPEC'
            cwe = getattr(r, 'cwe_id', None) or 'Нет CWE'
            sw = getattr(r, 'target_software', None) or 'Служба ОС'
            name = getattr(r, 'attack_name', None) or 'Неизвестная атака'
            
            key = f"{cve}_{capec}_{cwe}_{sw}_{name}"
            if key not in seen:
                r._count = 1
                seen[key] = r
                self.results.append(r)
            else:
                seen[key]._count += 1

    def generate_json(self, filepath):
        # Заглушка, если серверу все еще нужен JSON файл отчета
        pass

    def generate_html(self, filepath):
        js_data = []
        for i, r in enumerate(self.results):
            port_raw = getattr(r, 'target_port', None)
            # Надежная проверка на пустой порт
            if port_raw in (None, "None", "null", "", 0):
                port = "Н/Д"
            else:
                port = str(port_raw)
                
            js_data.append({
                "id": i,
                "cve": getattr(r, 'cve_id', None) or 'Нет CVE',
                "cwe": getattr(r, 'cwe_id', None) or 'CWE-Неизвестно',
                "capec": getattr(r, 'capec_id', None) or 'CAPEC-Неизвестно',
                "name": getattr(r, 'attack_name', None) or 'Атака',
                "sw": getattr(r, 'target_software', None) or 'Служба ОС',
                "port": port,
                "feas": getattr(r, 'feasibility', None) or 'UNKNOWN',
                "sev": getattr(r, 'severity', None) or 'INFO',
                "desc": getattr(r, 'description', None) or 'Описание отсутствует.',
                "rec": getattr(r, 'recommendation', None) or 'Специфичных рекомендаций нет.',
                "count": getattr(r, '_count', 1)
            })
            
        sys_data = {
            "hostname": self.system_summary.get('hostname', 'Целевой Сервер'),
            "os": self.system_summary.get('os', 'Неизвестная ОС'),
            "ips": ", ".join(self.system_summary.get('ip_addresses', [])),
            "ports_count": self.system_summary.get('open_ports_count', 0)
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            html = HTML_TEMPLATE.replace('__REPORT_DATA__', json.dumps(js_data, ensure_ascii=False))
            html = html.replace('__SYS_DATA__', json.dumps(sys_data, ensure_ascii=False))
            f.write(html)
            
        return filepath