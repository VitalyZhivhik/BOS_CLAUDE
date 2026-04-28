"""
Пути для PyInstaller (onefile/onedir) и запуска из исходников.

- bundle_resources_root: где лежат tools/, databases/ из --add-data (часто sys._MEIPASS).
- application_base_dir: папка рядом с .exe для отчётов, data/, logs/ (запись на диск).
"""

from __future__ import annotations

import os
import sys


def _repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def bundle_resources_root() -> str:
    """
    Корень вложенных данных: tools/, databases/ и т.д.

    При --onefile бинарники из tools/ распаковываются в sys._MEIPASS,
    а не рядом с .exe — поэтому сначала проверяем _MEIPASS.
    """
    if not getattr(sys, "frozen", False):
        return _repo_root()

    meipass = getattr(sys, "_MEIPASS", None)
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))

    for base in (meipass, exe_dir):
        if base and os.path.isdir(os.path.join(base, "tools")):
            return base
    return meipass or exe_dir


def application_base_dir() -> str:
    """Каталог для пользовательских файлов: рядом с .exe при frozen, иначе корень репозитория."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return _repo_root()


def tools_dir() -> str:
    return os.path.join(bundle_resources_root(), "tools")
