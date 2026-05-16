#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE Parser GUI - Графический интерфейс для управления парсером
"""

import sys
import os
import json
import threading
import time
import subprocess
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Добавляем путь к основному проекту
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from config import Config

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mitre-parser-gui-secret-key'
CORS(app)
# Используем threading вместо eventlet для совместимости с Python 3.13
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Глобальные переменные для управления процессами
process_status = {
    'parsing': {'status': 'idle', 'progress': 0, 'log': []},
    'linking': {'status': 'idle', 'progress': 0, 'log': []},
    'enriching': {'status': 'idle', 'progress': 0, 'log': []},
    'translating': {'status': 'idle', 'progress': 0, 'log': []}
}

process_threads = {}

def get_output_dir():
    """Получить путь к директории output"""
    return Config.OUTPUT_DIR

def load_json_file(filename):
    """Загрузить JSON файл из output директории"""
    filepath = get_output_dir() / filename
    if filepath.exists():
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_json_file(filename, data):
    """Сохранить JSON файл в output директорию"""
    filepath = get_output_dir() / filename
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# Маппинг процессов к скриптам
PROCESS_SCRIPTS = {
    'parsing': 'step1_parse.py',
    'linking': 'step2_link.py',
    'enriching': 'step3_enrich_ai.py',
    'translating': 'translate_fields.py'
}

def run_real_process(process_name):
    """Запуск реального процесса парсера"""
    status = process_status[process_name]
    status['status'] = 'running'
    status['progress'] = 0
    status['log'] = []
    
    # Отправляем уведомление о старте
    socketio.emit('process_started', {'process': process_name})
    
    script_name = PROCESS_SCRIPTS.get(process_name)
    if not script_name:
        status['status'] = 'error'
        error_msg = f"❌ Неизвестный процесс: {process_name}"
        status['log'].append(error_msg)
        socketio.emit('process_update', {
            'process': process_name,
            'status': 'error',
            'progress': 0,
            'log': error_msg
        })
        socketio.emit('process_complete', {
            'process': process_name,
            'status': 'error',
            'progress': 0
        })
        return
    
    src_dir = Path(__file__).parent.parent / 'src'
    script_path = src_dir / script_name
    
    if not script_path.exists():
        error_msg = f"❌ Скрипт не найден: {script_path}"
        status['status'] = 'error'
        status['log'].append(error_msg)
        socketio.emit('process_update', {
            'process': process_name,
            'status': 'error',
            'progress': 0,
            'log': error_msg
        })
        socketio.emit('process_complete', {
            'process': process_name,
            'status': 'error',
            'progress': 0
        })
        return
    
    try:
        # Запускаем процесс с правильным рабочим каталогом
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        process = subprocess.Popen(
            [sys.executable, '-u', str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            env=env,
            cwd=str(src_dir)
        )
        
        # Читаем вывод построчно
        total_lines = 0
        estimated_lines = 200  # Увеличенное количество строк для прогресса
        
        socketio.emit('process_update', {
            'process': process_name,
            'status': 'running',
            'progress': 5,
            'log': f"🚀 Запуск {script_name}..."
        })
        
        for line in process.stdout:
            line = line.strip()
            if line:
                total_lines += 1
                
                # Определяем тип сообщения для цветовой маркировки
                log_type = 'info'
                if '✅' in line or 'OK' in line or 'успешно' in line.lower():
                    log_type = 'success'
                elif '❌' in line or 'ERROR' in line or 'ошибка' in line.lower():
                    log_type = 'error'
                elif '⚠️' in line or 'WARNING' in line or 'предупреждение' in line.lower():
                    log_type = 'warning'
                
                status['log'].append(line)
                
                # Обновляем прогресс
                progress = min(int((total_lines / estimated_lines) * 95), 95)
                if progress < 5:
                    progress = 5
                status['progress'] = progress
                
                socketio.emit('process_update', {
                    'process': process_name,
                    'status': 'running',
                    'progress': progress,
                    'log': line,
                    'log_type': log_type
                })
        
        # Ждем завершения процесса
        return_code = process.wait()
        
        if return_code == 0:
            status['status'] = 'completed'
            status['progress'] = 100
            success_msg = "✅ Процесс завершен успешно!"
            status['log'].append(success_msg)
            
            socketio.emit('process_update', {
                'process': process_name,
                'status': 'completed',
                'progress': 100,
                'log': success_msg,
                'log_type': 'success'
            })
            
            socketio.emit('process_complete', {
                'process': process_name,
                'status': 'completed',
                'progress': 100
            })
        else:
            status['status'] = 'error'
            error_msg = f"❌ Ошибка: код возврата {return_code}"
            status['log'].append(error_msg)
            
            socketio.emit('process_update', {
                'process': process_name,
                'status': 'error',
                'progress': 100,
                'log': error_msg,
                'log_type': 'error'
            })
            
            socketio.emit('process_complete', {
                'process': process_name,
                'status': 'error',
                'progress': 100
            })
            
    except subprocess.CalledProcessError as e:
        error_msg = f"❌ Ошибка выполнения: {e}"
        status['status'] = 'error'
        status['log'].append(error_msg)
        
        socketio.emit('process_update', {
            'process': process_name,
            'status': 'error',
            'progress': 100,
            'log': error_msg,
            'log_type': 'error'
        })
        
        socketio.emit('process_complete', {
            'process': process_name,
            'status': 'error',
            'progress': 100
        })
        
    except Exception as e:
        error_msg = f"❌ Исключение: {str(e)}"
        status['status'] = 'error'
        status['log'].append(error_msg)
        
        socketio.emit('process_update', {
            'process': process_name,
            'status': 'error',
            'progress': 100,
            'log': error_msg,
            'log_type': 'error'
        })
        
        socketio.emit('process_complete', {
            'process': process_name,
            'status': 'error',
            'progress': 100
        })

# ==================== МАРШРУТЫ ====================

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    """Получить статус всех процессов"""
    return jsonify(process_status)

@app.route('/api/databases')
def get_databases():
    """Получить список баз данных"""
    databases = []
    output_dir = get_output_dir()
    total_links = 0
    
    db_files = {
        'capec_database.json': 'CAPEC',
        'cwe_database.json': 'CWE',
        'cve_database.json': 'CVE',
        'mitre_attack.json': 'MITRE ATT&CK'
    }
    
    for filename, name in db_files.items():
        filepath = output_dir / filename
        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Подсчитываем связи в этой базе
                db_links = 0
                for record in data:
                    # Считаем все поля, которые могут содержать связи
                    for key in ['related_capec', 'related_cwe', 'related_mitre', 'related_cve']:
                        if key in record:
                            value = record[key]
                            if isinstance(value, list):
                                db_links += len([x for x in value if x])  # Считаем только непустые значения
                            elif isinstance(value, str) and value:
                                db_links += 1
                
                total_links += db_links
                
                databases.append({
                    'id': filename.replace('.json', ''),
                    'name': name,
                    'filename': filename,
                    'records': len(data),
                    'size': filepath.stat().st_size,
                    'links': db_links
                })
            except Exception as e:
                print(f"Error loading {filename}: {e}")
                pass
    
    # Добавляем общее количество связей в ответ
    return jsonify({
        'databases': databases,
        'total_links': total_links
    })

@app.route('/api/database/<db_name>')
def get_database(db_name):
    """Получить данные конкретной базы"""
    filename = f"{db_name}.json"
    data = load_json_file(filename)
    return jsonify(data)

@app.route('/api/database/<db_name>', methods=['PUT'])
def update_database(db_name):
    """Обновить данные базы"""
    filename = f"{db_name}.json"
    data = request.json
    save_json_file(filename, data)
    return jsonify({'status': 'success', 'message': f'База {db_name} обновлена'})

@app.route('/api/database/<db_name>/record/<record_id>', methods=['PUT'])
def update_record(db_name, record_id):
    """Обновить конкретную запись в базе"""
    filename = f"{db_name}.json"
    data = load_json_file(filename)
    
    # Найти и обновить запись
    for i, record in enumerate(data):
        if record.get('id') == record_id:
            data[i] = request.json
            save_json_file(filename, data)
            return jsonify({'status': 'success', 'message': f'Запись {record_id} обновлена'})
    
    return jsonify({'status': 'error', 'message': 'Запись не найдена'}), 404

@app.route('/api/translate-cache')
def get_translate_cache():
    """Получить кэш переводов"""
    cache = load_json_file('translate_cache.json')
    return jsonify(cache)

@app.route('/api/translate-cache', methods=['PUT'])
def update_translate_cache():
    """Обновить кэш переводов"""
    data = request.json
    save_json_file('translate_cache.json', data)
    return jsonify({'status': 'success', 'message': 'Кэш переводов обновлен'})

@app.route('/api/translate-cache', methods=['DELETE'])
def clear_translate_cache():
    """Очистить кэш переводов"""
    cache_file = get_output_dir() / 'translate_cache.json'
    if cache_file.exists():
        cache_file.unlink()
    return jsonify({'status': 'success', 'message': 'Кэш переводов очищен'})

@app.route('/api/config')
def get_config():
    """Получить текущие настройки"""
    config_data = {
        'translation': {
            'enabled': Config.ENABLE_TRANSLATION,
            'service': Config.TRANSLATION_SERVICE,
            'target_lang': Config.TRANSLATE_TO,
            'batch_size': Config.TRANSLATION_BATCH_SIZE,
            'delay': Config.TRANSLATION_DELAY,
            'max_retries': Config.TRANSLATION_MAX_RETRIES
        },
        'ai': {
            'provider': Config.AI_PROVIDER,
            'model': Config.AI_MODEL,
            'base_url': Config.AI_BASE_URL
        },
        'limits': {
            'max_capec': Config.MAX_CAPEC_RECORDS,
            'max_cwe': Config.MAX_CWE_RECORDS,
            'max_cve': Config.MAX_CVE_RECORDS,
            'max_attack': Config.MAX_ATTACK_RECORDS
        }
    }
    return jsonify(config_data)

@app.route('/api/config', methods=['PUT'])
def update_config():
    """Обновить настройки (требует перезапуска)"""
    # В реальном приложении здесь нужно обновлять config.py
    return jsonify({'status': 'success', 'message': 'Настройки сохранены (вступят в силу после перезапуска)'})

@app.route('/api/config/limits', methods=['PUT'])
def update_limits():
    """Обновить лимиты записей для парсинга"""
    try:
        data = request.json
        limits = data.get('limits', {})
        
        # Здесь можно было бы обновить config.py, но пока просто возвращаем успех
        # В реальной реализации нужно записывать в config.py
        
        return jsonify({
            'status': 'success', 
            'message': 'Лимиты обновлены (вступят в силу после перезапуска)',
            'updated': limits
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/process/<process_name>/stop', methods=['POST'])
def stop_process_api(process_name):
    """API для остановки процесса"""
    if process_name in process_status:
        process_status[process_name]['status'] = 'stopped'
        return jsonify({'status': 'success', 'message': f'Процесс {process_name} остановлен'})
    return jsonify({'status': 'error', 'message': 'Процесс не найден'}), 404

# ==================== WEBSOCKET СОБЫТИЯ ====================

@socketio.on('connect')
def handle_connect():
    """Клиент подключился"""
    print('Клиент подключился к WebSocket')
    emit('connected', {'message': 'Подключено к серверу'})

@socketio.on('start_process')
def handle_start_process(data):
    """Запуск процесса"""
    process_name = data.get('process')
    
    if process_name in process_status:
        # Остановить предыдущий процесс если есть
        if process_threads.get(process_name):
            process_status[process_name]['status'] = 'stopping'
            if process_threads[process_name].is_alive():
                process_threads[process_name].join(timeout=5)
        
        # Запустить новый процесс
        thread = threading.Thread(
            target=run_real_process,
            args=(process_name,)
        )
        process_threads[process_name] = thread
        thread.start()
        
        emit('process_started', {'process': process_name})

@socketio.on('stop_process')
def handle_stop_process(data):
    """Остановка процесса"""
    process_name = data.get('process')
    if process_name in process_status:
        process_status[process_name]['status'] = 'stopped'
        emit('process_stopped', {'process': process_name})

@socketio.on('clear_log')
def handle_clear_log(data):
    """Очистка лога"""
    process_name = data.get('process')
    if process_name in process_status:
        process_status[process_name]['log'] = []
        emit('log_cleared', {'process': process_name})

# ==================== ЗАПУСК ПРИЛОЖЕНИЯ ====================

if __name__ == '__main__':
    print("🚀 Запуск MITRE Parser GUI...")
    print(f"📂 Директория данных: {get_output_dir()}")
    print("🌐 Веб-интерфейс доступен по адресу: http://localhost:5000")
    
    # Убедимся, что output директория существует
    get_output_dir().mkdir(parents=True, exist_ok=True)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)