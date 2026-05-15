"""
Сборка EXE-файлов с помощью PyInstaller.

Использование:
    python build_exe.py              # Оба агента
    python build_exe.py --server     # Только серверный
    python build_exe.py --attacker   # Только атакующий
    python build_exe.py --onefile    # Один EXE-файл (медленнее запуск)
"""

import subprocess
import sys
import os
import shutil

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
SEP = os.pathsep  # ; на Windows, : на Linux


def _normalize_add_data(spec: str) -> str:
    src, dst = spec.split(SEP, 1)
    if not os.path.isabs(src):
        src = os.path.join(PROJECT_DIR, src)
    return f"{src}{SEP}{dst}"


def check_deps():
    """Проверка зависимостей."""
    ok = True
    try:
        import PyInstaller
        print(f"[+] PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("[!] PyInstaller не установлен — pip install pyinstaller")
        ok = False
    try:
        from PyQt6 import QtCore
        print(f"[+] PyQt6 {QtCore.PYQT_VERSION_STR}")
    except ImportError:
        print("[!] PyQt6 не установлен — pip install PyQt6")
        ok = False
    try:
        import requests
        print(f"[+] requests {requests.__version__}")
    except ImportError:
        print("[!] requests не установлен — pip install requests")
        ok = False
    return ok


def build(name, entry, extra_data=None, onefile=False, dist_dir_name="dist"):
    """Универсальная сборка."""
    print(f"\n{'='*60}")
    print(f"  СБОРКА: {name}")
    print(f"{'='*60}")

    dist_path = os.path.join(PROJECT_DIR, dist_dir_name)
    work_path = os.path.join(PROJECT_DIR, "build", name)
    spec_path = os.path.join(PROJECT_DIR, "build", "specs", name)
    os.makedirs(dist_path, exist_ok=True)
    os.makedirs(work_path, exist_ok=True)
    os.makedirs(spec_path, exist_ok=True)

    tools_src = os.path.join(PROJECT_DIR, "tools")
    data_args = []
    if os.path.isdir(tools_src):
        data_args.append(_normalize_add_data(f"{tools_src}{SEP}tools"))
        print(f"[+] В сборку включена папка tools/ (Trivy, Nuclei, Nmap и др.)")
    else:
        print(f"[!] Папка tools/ не найдена ({tools_src}) — внешние утилиты нужно положить рядом с EXE вручную")

    profiles_src = os.path.join(PROJECT_DIR, "profiles")
    if os.path.isdir(profiles_src):
        data_args.append(_normalize_add_data(f"{profiles_src}{SEP}profiles"))

    cmd = [
        sys.executable, "-m", "PyInstaller",
        f"--name={name}",
        "--onefile" if onefile else "--onedir",
        "--windowed",
        "--noconfirm",
        "--clean",
        f"--distpath={dist_path}",
        f"--workpath={work_path}",
        f"--specpath={spec_path}",
        f"--add-data={_normalize_add_data(f'common{SEP}common')}",
    ]

    for d in data_args:
        cmd.append(f"--add-data={d}")

    if extra_data:
        for d in extra_data:
            cmd.append(f"--add-data={_normalize_add_data(d)}")

    # Скрытые импорты для PyQt6
    for mod in ["common", "common.config", "common.models", "common.logger", "common.bundle_paths"]:
        cmd.append(f"--hidden-import={mod}")

    cmd.append(entry)

    result = subprocess.run(cmd, cwd=PROJECT_DIR)

    if result.returncode == 0:
        if onefile:
            print(f"[+] Собран: {dist_dir_name}/{name}.exe (утилиты из tools/ внутри архива; при запуске — в временной папке)")
        else:
            exe_dir = os.path.join(dist_path, name)
            # Копируем базы данных
            db_src = os.path.join(PROJECT_DIR, "databases")
            db_dst = os.path.join(exe_dir, "databases")
            if os.path.exists(db_src) and not os.path.exists(db_dst):
                shutil.copytree(db_src, db_dst)
                print(f"[+] Базы данных скопированы")
            # Копируем портативные инструменты (nmap и др.)

            tools_src = os.path.join(PROJECT_DIR, "tools")

            tools_dst = os.path.join(exe_dir, "tools")

            if os.path.exists(tools_src) and not os.path.exists(tools_dst):

                shutil.copytree(tools_src, tools_dst)

                print(f"[+] Папка tools/ скопирована ({tools_dst})")

            elif not os.path.exists(tools_src):

                print(f"[!] Папка tools/ не найдена: {tools_src}")

            # Создаём папки
            for d in ["reports", "logs"]:
                os.makedirs(os.path.join(exe_dir, d), exist_ok=True)
            print(f"[+] Собран: {dist_dir_name}/{name}/{name}.exe")
    else:
        print(f"[!] ОШИБКА сборки {name}")

    return result.returncode


def main():
    import argparse
    p = argparse.ArgumentParser(description="Сборка EXE")
    p.add_argument("--server", action="store_true", help="Только серверный агент")
    p.add_argument("--attacker", action="store_true", help="Только атакующий агент")
    p.add_argument("--onefile", action="store_true", help="Один EXE-файл")
    args = p.parse_args()

    print("Security Assessment — Сборка EXE\n")

    if not check_deps():
        print("\nУстановите зависимости: pip install -r requirements.txt")
        sys.exit(1)

    build_all = not args.server and not args.attacker
    errors = 0

    if args.server or build_all:
        errors += build(
            "SecurityServer", "gui_server.py",
            extra_data=[
                f"server{SEP}server",
                f"databases{SEP}databases",
            ],
            onefile=args.onefile,
            dist_dir_name="dist"
        )

    if args.attacker or build_all:
        errors += build(
            "SecurityAttacker", "gui_attacker.py",
            extra_data=[
                f"attacker{SEP}attacker",
                f"databases{SEP}databases",
            ],
            onefile=args.onefile,
            dist_dir_name="dist_attacker"
        )

    print(f"\n{'='*60}")
    if errors == 0:
        if args.attacker and not args.server:
            print(f"  ✔ Сборка завершена! Результат: {os.path.join(PROJECT_DIR, 'dist_attacker')}")
        elif args.server and not args.attacker:
            print(f"  ✔ Сборка завершена! Результат: {os.path.join(PROJECT_DIR, 'dist')}")
        else:
            print(f"  ✔ Сборка завершена! Результат: {os.path.join(PROJECT_DIR, 'dist')} и {os.path.join(PROJECT_DIR, 'dist_attacker')}")
    else:
        print(f"  ✘ Ошибки: {errors}")
    print(f"{'='*60}")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
