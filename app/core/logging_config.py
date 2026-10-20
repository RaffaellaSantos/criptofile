import json
import logging
import logging.config
import re
from typing import ClassVar

from app.core.config import data_dir

# Controles C0 e DEL, exceto quebra de linha e tabulação (usadas nas mensagens).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _escape_control_chars(text: str) -> str:
    return _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


class ColorFormatter(logging.Formatter):
    """Formatter que adiciona cores aos níveis de log no console."""

    GREY = "\x1b[38;20m"
    GREEN = "\x1b[32;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"

    fmt = "%(levelname)s - %(message)s"

    FORMATS: ClassVar[dict[int, str]] = {
        logging.INFO: f"{GREEN}%(levelname)s{RESET} - %(message)s",
        logging.WARNING: f"{YELLOW}%(levelname)s{RESET} - %(message)s",
        logging.ERROR: f"{RED}%(levelname)s{RESET} - %(message)s",
        logging.CRITICAL: f"{BOLD_RED}%(levelname)s{RESET} - %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        # Mensagens carregam entradas do usuário (usernames tentados, nomes de
        # arquivo): caracteres de controle como ESC são exibidos escapados para
        # não injetarem sequências ANSI no terminal de quem lê os logs.
        safe = logging.makeLogRecord(record.__dict__)
        safe.msg = _escape_control_chars(record.getMessage())
        safe.args = None
        return formatter.format(safe)


class JSONFormatter(logging.Formatter):
    """Formatter que gera logs em formato JSON para o arquivo."""

    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "name": record.name,
            "level": record.levelname,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(log_record, ensure_ascii=False)


def setup_logging():
    """Configura o logging para a aplicação."""
    logging_config = {
        "version": 1,
        # Desativa os logs de bibliotecas de terceiros (opcional)
        "disable_existing_loggers": False,
        "formatters": {
            "json_formatter": {
                "()": JSONFormatter,
            },
            "console": {
                "()": ColorFormatter,
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "console",
                "level": logging.INFO,
            },
            "file": {
                "class": "logging.FileHandler",
                "formatter": "json_formatter",
                "level": logging.DEBUG,
                "filename": str(data_dir() / "app.log"),
                "encoding": "utf8",
            },
        },
        "root": {
            "handlers": ["console", "file"],
            "level": logging.DEBUG,
        },
    }

    logging.config.dictConfig(logging_config)
