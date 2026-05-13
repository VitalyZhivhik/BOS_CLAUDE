# src/menu.py
import subprocess
import sys
from pathlib import Path

def run_script(script_name):
    script_path = Path(__file__).parent / script_name
    subprocess.run([sys.executable, str(script_path)], cwd=str(Path(__file__).parent.parent))

def main():
    while True:
        print("\n" + "="*40)
        print("       MITRE PARSER v3 - МЕНЮ")
        print("="*40)
        print("1. Скачать и распарсить базы (без перевода)")
        print("2. Связать данные (заполнить перекрёстные ссылки)")
        print("3. Перевести выбранные поля (онлайн)")
        print("4. Запустить все этапы последовательно")
        print("0. Выход")
        choice = input("Ваш выбор: ").strip()
        
        if choice == "1":
            run_script("step1_parse.py")
        elif choice == "2":
            run_script("step2_link.py")
        elif choice == "3":
            run_script("translate_fields.py")
        elif choice == "4":
            print("Запуск всех этапов...")
            run_script("step1_parse.py")
            run_script("step2_link.py")
            run_script("translate_fields.py")
        elif choice == "0":
            print("Выход.")
            break
        else:
            print("Неверный ввод, попробуйте снова.")

if __name__ == "__main__":
    main()