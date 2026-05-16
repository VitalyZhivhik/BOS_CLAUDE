#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Запуск графического интерфейса MITRE Parser
"""

import sys
from pathlib import Path

# Добавляем путь к gui
sys.path.insert(0, str(Path(__file__).parent))

from app import socketio, app

if __name__ == '__main__':
    print("=" * 50)
    print("  MITRE Parser GUI - Графический интерфейс")
    print("=" * 50)
    print()
    print("📂 Директория данных: ../output/")
    print()
    print("Для остановки нажмите Ctrl+C")
    print()
    
    # Пробуем запустить на порту 5000, если занят - на 5001
    ports = [5000, 5001]
    for port in ports:
        try:
            print(f"🌐 Откройте браузер и перейдите по адресу:")
            print(f"   http://localhost:{port}")
            print()
            socketio.run(app, host='0.0.0.0', port=port, debug=False)
            break
        except OSError as e:
            if hasattr(e, 'winerror') and e.winerror == 10048:  # Port already in use
                print(f"⚠️  Порт {port} занят. Пробуем порт {ports[ports.index(port)+1] if ports.index(port)+1 < len(ports) else '...'}...")
                if port == ports[-1]:
                    print("\n❌ Не удалось запустить сервер. Проверьте, не заняты ли порты 5000 и 5001.")
                    print("   Закройте другие приложения, использующие эти порты, и попробуйте снова.")
                    sys.exit(1)
            else:
                raise
