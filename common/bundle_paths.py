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
    env_keys = (
        "BOS_TOOLS_DIR",
        "BOS_SCANNERS_DIR",
        "TOOLS_DIR",
    )
    for k in env_keys:
        v = str(os.environ.get(k, "") or "").strip()
        if not v:
            continue
        p = os.path.abspath(os.path.expandvars(os.path.expanduser(v)))
        if os.path.isdir(p):
            return p

    base = bundle_resources_root()
    bundled = os.path.join(base, "tools")
    if os.path.isdir(bundled):
        return bundled

    app = application_base_dir()
    near_app = os.path.join(app, "tools")
    if os.path.isdir(near_app):
        return near_app

    return bundled
