/**
 * MITRE Parser GUI - Клиентская часть
 */

// Глобальные переменные
let socket;
let currentDb = null;
let currentData = [];
let currentPage = 1;
let recordsPerPage = 25;
let translateCache = {};
let processStates = {
    parsing: 'idle',
    linking: 'idle',
    enriching: 'idle',
    translating: 'idle'
};

// Инициализация при загрузке
$(document).ready(function() {
    initSocket();
    initNavigation();
    initForms();
    loadDashboardData();
});

// ==================== WebSocket ====================

function initSocket() {
    socket = io.connect('http://' + document.domain + ':' + location.port);
    
    socket.on('connect', function() {
        $('#connectionStatus').html('<span class="badge bg-success connected">Подключено</span>');
        addLog('info', 'Подключено к серверу');
    });
    
    socket.on('disconnect', function() {
        $('#connectionStatus').html('<span class="badge bg-danger">Отключено</span>');
        addLog('error', 'Отключено от сервера');
    });
    
    socket.on('connected', function(data) {
        addLog('info', data.message);
    });
    
    socket.on('process_started', function(data) {
        addLog('info', `Процесс "${data.process}" запущen`);
        processStates[data.process] = 'running';
    });
    
    socket.on('process_update', function(data) {
        updateProgress(data.process, data.progress);
        const logType = data.log_type || 'info';
        addProcessLog(data.process, data.log, logType);
    });
    
    socket.on('process_complete', function(data) {
        updateProgress(data.process, 100);
        processStates[data.process] = 'completed';
        addLog('success', `Процесс "${data.process}" завершен`);
        
        // Обновляем статистику
        setTimeout(loadDashboardData, 1000);
    });
    
    socket.on('process_stopped', function(data) {
        processStates[data.process] = 'stopped';
        addLog('warning', `Процесс "${data.process}" остановлен`);
    });
    
    socket.on('log_cleared', function(data) {
        $('#processLogs').html('<div class="log-entry text-muted">Логи очищены</div>');
    });
}

// ==================== Навигация ====================

function initNavigation() {
    // Переключение страниц
    $('a[data-page]').click(function(e) {
        e.preventDefault();
        const page = $(this).data('page');
        showPage(page);
    });
    
    // Выбор базы данных
    $('a[data-db]').click(function(e) {
        e.preventDefault();
        const db = $(this).data('db');
        showDatabase(db);
    });
}

function showPage(pageName) {
    // Скрываем все страницы
    $('.page').removeClass('active');
    
    // Показываем нужную
    $(`#${pageName}Page`).addClass('active');
    
    // Обновляем активный пункт меню
    $('.nav-link').removeClass('active');
    $(`a[data-page="${pageName}"]`).addClass('active');
    
    // Загружаем данные если нужно
    if (pageName === 'translate-cache') {
        loadTranslateCache();
    } else if (pageName === 'settings') {
        loadSettings();
    }
}

// ==================== Панель управления ====================

function loadDashboardData() {
    // Загружаем статистику баз данных
    $.get('/api/databases', function(response) {
        const databases = response.databases || [];
        const totalLinks = response.total_links || 0;
        
        $('#totalDatabases').text(databases.length);
        
        let totalRecords = 0;
        databases.forEach(db => {
            totalRecords += db.records;
        });
        $('#totalRecords').text(totalRecords);
        
        // Обновляем количество связей
        $('#totalLinks').text(totalLinks);
    });
    
    // Загружаем кэш переводов
    $.get('/api/translate-cache', function(cache) {
        // Проверяем, что cache - это объект, а не массив
        if (typeof cache === 'object' && cache !== null) {
            $('#totalTranslations').text(Object.keys(cache).length);
        } else {
            $('#totalTranslations').text(0);
        }
    }).fail(function() {
        // Если кэш не найден или ошибка
        $('#totalTranslations').text(0);
    });
    
    // Загружаем статус процессов
    $.get('/api/status', function(status) {
        Object.keys(status).forEach(process => {
            const state = status[process];
            updateProgress(process, state.progress);
            processStates[process] = state.status;
        });
    });
}

function startProcess(processName) {
    if (processStates[processName] === 'running') {
        showToast('warning', 'Процесс уже запущен');
        return;
    }
    
    // Проверка для AI обогащения (в разработке)
    if (processName === 'enriching') {
        showToast('info', 'AI обогащение находится в разработке. Эта функция скоро будет доступна.');
        addLog('info', '⚠️ AI обогащение находится в разработке');
        return;
    }
    
    socket.emit('start_process', { process: processName });
    showToast('info', `Запуск процесса: ${processName}`);
}

function stopProcess(processName) {
    if (processStates[processName] !== 'running') {
        showToast('warning', 'Процесс не запущен');
        return;
    }
    
    // Отправляем запрос на остановку
    socket.emit('stop_process', { process: processName });
    
    // Также отправляем API запрос для принудительной остановки
    fetch(`/api/process/${processName}/stop`, { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showToast('info', `Процесс ${processName} остановлен`);
            }
        })
        .catch(err => {
            console.error('Error stopping process:', err);
        });
    
    showToast('info', `Отправка команды остановки: ${processName}`);
}

function updateProgress(processName, progress) {
    const progressBar = $(`#${processName}Progress`);
    progressBar.css('width', progress + '%');
    progressBar.text(progress + '%');
    
    // Убираем анимацию если процесс завершен
    if (progress === 100) {
        progressBar.removeClass('progress-bar-animated');
    } else if (progress > 0 && progress < 100) {
        progressBar.addClass('progress-bar-animated');
    }
}

function clearLogs() {
    socket.emit('clear_log', {});
}

function addLog(type, message) {
    const timestamp = new Date().toLocaleTimeString();
    const logHtml = `<div class="log-entry ${type}">[${timestamp}] ${message}</div>`;
    
    const logContainer = $('#processLogs');
    logContainer.append(logHtml);
    
    // Прокручиваем вниз
    logContainer.scrollTop(logContainer[0].scrollHeight);
    
    // Ограничиваем количество записей
    if (logContainer.children().length > 200) {
        logContainer.children().first().remove();
    }
}

function addProcessLog(processName, message, logType = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = `[${processName}]`;
    const logHtml = `<div class="log-entry ${logType}">[${timestamp}] ${prefix} ${message}</div>`;
    
    const logContainer = $('#processLogs');
    logContainer.append(logHtml);
    
    // Прокручиваем вниз
    logContainer.scrollTop(logContainer[0].scrollHeight);
    
    // Ограничиваем количество записей
    if (logContainer.children().length > 200) {
        logContainer.children().first().remove();
    }
}

// ==================== Редактор баз данных ====================

function showDatabase(dbName) {
    currentDb = dbName;
    currentPage = 1;
    
    // Обновляем заголовок
    const dbNames = {
        'capec_database': 'CAPEC',
        'cwe_database': 'CWE',
        'cve_database': 'CVE',
        'mitre_attack': 'MITRE ATT&CK'
    };
    $('#databaseTitle').html(`<i class="bi bi-table"></i> Редактор базы: ${dbNames[dbName]}`);
    
    // Показываем страницу
    showPage('database');
    
    // Загружаем данные
    loadDatabaseData();
}

function loadDatabaseData() {
    if (!currentDb) return;
    
    $.get(`/api/database/${currentDb}`, function(data) {
        currentData = data;
        $('#recordCount').text(`Записей: ${data.length}`);
        renderTable();
    });
}

function renderTable() {
    const tbody = $('#databaseTableBody');
    tbody.empty();
    
    const searchTerm = $('#databaseSearch').val().toLowerCase();
    let filteredData = currentData;
    
    if (searchTerm) {
        filteredData = currentData.filter(record => {
            const id = (record.id || '').toLowerCase();
            const name = (record.name || '').toLowerCase();
            const description = (record.description || '').toLowerCase();
            return id.includes(searchTerm) || name.includes(searchTerm) || description.includes(searchTerm);
        });
    }
    
    // Пагинация
    const startIndex = (currentPage - 1) * recordsPerPage;
    const endIndex = Math.min(startIndex + recordsPerPage, filteredData.length);
    const pageData = filteredData.slice(startIndex, endIndex);
    
    pageData.forEach(record => {
        const row = `
            <tr>
                <td><strong>${record.id || 'N/A'}</strong></td>
                <td>${truncateText(record.name || '', 50)}</td>
                <td>${truncateText(record.description || '', 100)}</td>
                <td>
                    <button class="btn btn-sm btn-primary btn-action" onclick="editRecord('${record.id}')">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-info btn-action" onclick="viewRecord('${record.id}')">
                        <i class="bi bi-eye"></i>
                    </button>
                </td>
            </tr>
        `;
        tbody.append(row);
    });
    
    renderPagination(filteredData.length);
}

function renderPagination(totalRecords) {
    const totalPages = Math.ceil(totalRecords / recordsPerPage);
    const pagination = $('#pagination');
    pagination.empty();
    
    if (totalPages <= 1) return;
    
    // Кнопка "Назад"
    if (currentPage > 1) {
        pagination.append(`
            <li class="page-item">
                <a class="page-link" href="#" onclick="goToPage(${currentPage - 1})">←</a>
            </li>
        `);
    }
    
    // Номера страниц
    for (let i = 1; i <= totalPages; i++) {
        if (i === 1 || i === totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {
            pagination.append(`
                <li class="page-item ${i === currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" onclick="goToPage(${i})">${i}</a>
                </li>
            `);
        } else if (i === currentPage - 3 || i === currentPage + 3) {
            pagination.append('<li class="page-item disabled"><a class="page-link">...</a></li>');
        }
    }
    
    // Кнопка "Вперед"
    if (currentPage < totalPages) {
        pagination.append(`
            <li class="page-item">
                <a class="page-link" href="#" onclick="goToPage(${currentPage + 1})">→</a>
            </li>
        `);
    }
}

function goToPage(page) {
    currentPage = page;
    renderTable();
}

function truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

function editRecord(recordId) {
    const record = currentData.find(r => r.id === recordId);
    if (!record) return;
    
    $('#editRecordId').val(recordId);
    $('#editDbName').val(currentDb);
    
    const fieldsContainer = $('#editRecordFields');
    fieldsContainer.empty();
    
    // Создаем поля для редактирования
    Object.keys(record).forEach(key => {
        const value = record[key];
        const fieldId = `edit_field_${key}`;
        
        if (typeof value === 'string') {
            fieldsContainer.append(`
                <div class="mb-3">
                    <label class="form-label">${key}</label>
                    <textarea class="form-control" id="${fieldId}" rows="3">${value}</textarea>
                </div>
            `);
        } else if (Array.isArray(value)) {
            fieldsContainer.append(`
                <div class="mb-3">
                    <label class="form-label">${key}</label>
                    <textarea class="form-control" id="${fieldId}" rows="3">${value.join('\n')}</textarea>
                </div>
            `);
        } else {
            fieldsContainer.append(`
                <div class="mb-3">
                    <label class="form-label">${key}</label>
                    <input type="text" class="form-control" id="${fieldId}" value="${JSON.stringify(value)}">
                </div>
            `);
        }
    });
    
    const modal = new bootstrap.Modal(document.getElementById('editRecordModal'));
    modal.show();
}

function saveRecord() {
    const recordId = $('#editRecordId').val();
    const dbName = $('#editDbName').val();
    
    const updatedRecord = {};
    
    // Собираем данные из формы
    $('#editRecordFields .mb-3').each(function() {
        const label = $(this).find('label').text();
        const input = $(this).find('textarea, input');
        const value = input.val();
        
        // Определяем тип значения
        try {
            const parsed = JSON.parse(value);
            updatedRecord[label] = parsed;
        } catch {
            updatedRecord[label] = value;
        }
    });
    
    // Отправляем на сервер
    $.ajax({
        url: `/api/database/${dbName}/record/${recordId}`,
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(updatedRecord),
        success: function(response) {
            showToast('success', response.message);
            loadDatabaseData();
            bootstrap.Modal.getInstance(document.getElementById('editRecordModal')).hide();
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении');
        }
    });
}

function viewRecord(recordId) {
    const record = currentData.find(r => r.id === recordId);
    if (!record) return;
    
    // Показываем в модальном окне (можно доработать)
    alert(JSON.stringify(record, null, 2));
}

function refreshDatabase() {
    loadDatabaseData();
    showToast('info', 'Данные обновлены');
}

function saveDatabase() {
    if (!currentDb) return;
    
    $.ajax({
        url: `/api/database/${currentDb}`,
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(currentData),
        success: function(response) {
            showToast('success', response.message);
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении');
        }
    });
}

// Поиск
$('#databaseSearch').on('input', function() {
    currentPage = 1;
    renderTable();
});

// Изменение количества записей на странице
$('#recordsPerPage').change(function() {
    recordsPerPage = parseInt($(this).val());
    currentPage = 1;
    renderTable();
});

// ==================== Кэш переводов ====================

function loadTranslateCache() {
    $.get('/api/translate-cache', function(cache) {
        translateCache = cache;
        renderCacheTable();
    });
}

function renderCacheTable() {
    const tbody = $('#cacheTableBody');
    tbody.empty();
    
    const searchTerm = $('#cacheSearch').val().toLowerCase();
    let count = 0;
    
    Object.entries(translateCache).forEach(([original, translation]) => {
        if (searchTerm && !original.toLowerCase().includes(searchTerm) && !translation.toLowerCase().includes(searchTerm)) {
            return;
        }
        
        count++;
        const row = `
            <tr>
                <td>${truncateText(original, 100)}</td>
                <td>${truncateText(translation, 100)}</td>
                <td>
                    <button class="btn btn-sm btn-primary btn-action" onclick="editTranslation('${escapeForAttr(original)}')">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-danger btn-action" onclick="deleteTranslation('${escapeForAttr(original)}')">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `;
        tbody.append(row);
    });
    
    $('#cacheCount').text(`Записей: ${count}`);
}

function escapeForAttr(text) {
    return text.replace(/'/g, "\\'").replace(/"/g, '\\"');
}

function editTranslation(original) {
    const translation = translateCache[original];
    if (translation === undefined) return;
    
    $('#editTranslationOriginal').val(original);
    $('#editTranslationText').val(translation);
    
    const modal = new bootstrap.Modal(document.getElementById('editTranslationModal'));
    modal.show();
}

function saveTranslation() {
    const original = $('#editTranslationOriginal').val();
    const newTranslation = $('#editTranslationText').val();
    
    translateCache[original] = newTranslation;
    
    $.ajax({
        url: '/api/translate-cache',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(translateCache),
        success: function(response) {
            showToast('success', response.message);
            renderCacheTable();
            bootstrap.Modal.getInstance(document.getElementById('editTranslationModal')).hide();
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении');
        }
    });
}

function deleteTranslation(original) {
    if (!confirm('Удалить эту запись перевода?')) return;
    
    delete translateCache[original];
    
    $.ajax({
        url: '/api/translate-cache',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(translateCache),
        success: function(response) {
            showToast('success', response.message);
            renderCacheTable();
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при удалении');
        }
    });
}

function clearTranslateCache() {
    if (!confirm('Вы уверены, что хотите очистить весь кэш переводов?')) return;
    
    $.ajax({
        url: '/api/translate-cache',
        method: 'DELETE',
        success: function(response) {
            showToast('success', response.message);
            translateCache = {};
            renderCacheTable();
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при очистке');
        }
    });
}

function saveTranslateCache() {
    $.ajax({
        url: '/api/translate-cache',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(translateCache),
        success: function(response) {
            showToast('success', response.message);
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении');
        }
    });
}

// Поиск по кэшу
$('#cacheSearch').on('input', function() {
    renderCacheTable();
});

// ==================== Настройки ====================

function loadSettings() {
    $.get('/api/config', function(config) {
        // Настройки лимитов
        $('input[name="max_capec"]').val(config.limits.max_capec || 330);
        $('input[name="max_cwe"]').val(config.limits.max_cwe || 500);
        $('input[name="max_cve"]').val(config.limits.max_cve || 2000);
        $('input[name="max_attack"]').val(config.limits.max_attack || 300);
        
        // Настройки перевода
        $('select[name="service"]').val(config.translation.service || 'google');
        $('select[name="target_lang"]').val(config.translation.target_lang || 'ru');
        $('input[name="batch_size"]').val(config.translation.batch_size || 25);
        $('input[name="delay"]').val(config.translation.delay || 1.5);
        $('input[name="max_retries"]').val(config.translation.max_retries || 5);
        
        // AI настройки
        $('select[name="provider"]').val(config.ai.provider || 'ollama');
        $('input[name="model"]').val(config.ai.model || 'qwen2.5:3b');
        $('input[name="base_url"]').val(config.ai.base_url || 'http://localhost:11434/v1');
    });
}

function initForms() {
    // Форма лимитов парсинга
    $('#limitsSettings').submit(function(e) {
        e.preventDefault();
        
        const formData = {
            limits: {
                max_capec: parseInt($('input[name="max_capec"]').val()),
                max_cwe: parseInt($('input[name="max_cwe"]').val()),
                max_cve: parseInt($('input[name="max_cve"]').val()),
                max_attack: parseInt($('input[name="max_attack"]').val())
            }
        };
        
        saveLimits(formData);
    });
    
    // Форма настроек перевода
    $('#translationSettings').submit(function(e) {
        e.preventDefault();
        
        const formData = {
            translation: {
                service: $('select[name="service"]').val(),
                target_lang: $('select[name="target_lang"]').val(),
                batch_size: parseInt($('input[name="batch_size"]').val()),
                delay: parseFloat($('input[name="delay"]').val()),
                max_retries: parseInt($('input[name="max_retries"]').val())
            }
        };
        
        saveConfig(formData);
    });
    
    // Форма AI настроек
    $('#aiSettings').submit(function(e) {
        e.preventDefault();
        
        const formData = {
            ai: {
                provider: $('select[name="provider"]').val(),
                model: $('input[name="model"]').val(),
                base_url: $('input[name="base_url"]').val(),
                api_key: $('input[name="api_key"]').val()
            }
        };
        
        saveConfig(formData);
    });
}

function saveLimits(limits) {
    $.ajax({
        url: '/api/config/limits',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(limits),
        success: function(response) {
            showToast('success', response.message);
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении лимитов');
        }
    });
}

function saveConfig(config) {
    $.ajax({
        url: '/api/config',
        method: 'PUT',
        contentType: 'application/json',
        data: JSON.stringify(config),
        success: function(response) {
            showToast('success', response.message);
        },
        error: function(xhr) {
            showToast('error', 'Ошибка при сохранении настроеk');
        }
    });
}

// ==================== Уведомления ====================

function showToast(type, message) {
    const toastContainer = $('#toastContainer');
    if (toastContainer.length === 0) {
        $('body').append('<div id="toastContainer" class="position-fixed top-0 end-0 p-3" style="z-index: 11"></div>');
    }
    
    const bgClass = {
        'success': 'bg-success',
        'error': 'bg-danger',
        'warning': 'bg-warning',
        'info': 'bg-info'
    }[type] || 'bg-primary';
    
    const icon = {
        'success': 'bi-check-circle',
        'error': 'bi-x-circle',
        'warning': 'bi-exclamation-triangle',
        'info': 'bi-info-circle'
    }[type] || 'bi-info-circle';
    
    const toast = `
        <div class="toast show" role="alert">
            <div class="toast-header ${bgClass} text-white">
                <i class="bi ${icon} me-2"></i>
                <strong class="me-auto">MITRE Parser</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    $('#toastContainer').append(toast);
    
    // Автоматическое удаление через 3 секунды
    setTimeout(() => {
        $('#toastContainer .toast').first().remove();
    }, 3000);
}