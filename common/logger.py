"""
Продвинутая система логирования.
Пишет в файл и предоставляет сигналы для GUI.
"""

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler


# Директория для логов
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def setup_logger(name: str, log_file: str = None, level=logging.DEBUG) -> logging.Logger:
    """
    Создаёт настроенный логгер.

    Args:
        name: Имя логгера ('server' или 'attacker')
        log_file: Имя файла лога (автогенерируется если не указано)
        level: Уровень логирования
    """
    logger = logging.getLogger(name)

    # Если логгер уже настроен — не дублируем обработчики
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # Формат сообщений
    file_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] [%(module)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # Файловый обработчик (ротация: 5 МБ, 3 файла)
    if not log_file:
        log_file = f"{name}_{datetime.now().strftime('%Y%m%d')}.log"
    file_path = os.path.join(LOG_DIR, log_file)

    file_handler = RotatingFileHandler(
        file_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Консольный обработчик
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    logger.info(f"Логгер '{name}' инициализирован. Файл: {file_path}")
    return logger


class GUILogHandler(logging.Handler):
    """
    Обработчик логов для PyQt6 GUI.
    Вызывает callback-функцию для каждого сообщения.
    """

    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] %(message)s",
            datefmt="%H:%M:%S"
        ))

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            self.callback(msg, level)
        except Exception:
            self.handleError(record)


# Предсозданные логгеры
def get_server_logger() -> logging.Logger:
    return setup_logger("server", "server.log")


def get_attacker_logger() -> logging.Logger:
    return setup_logger("attacker", "attacker.log")
