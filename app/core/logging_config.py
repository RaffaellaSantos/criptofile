import json
import logging
import logging.config
from typing import ClassVar


class ColorFormatter(logging.Formatter):
    """Formatter que adiciona cores aos níveis de log no console."""
    
    GREY = "\x1b[38;20m"
    GREEN = "\x1b[32;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"
    
    fmt = "%(levelname)s - %(message)s"
    
    FORMATS: ClassVar[dict [int, str]] = {
        logging.INFO:     f"{GREEN}%(levelname)s{RESET} - %(message)s",
        logging.WARNING:  f"{YELLOW}%(levelname)s{RESET} - %(message)s",
        logging.ERROR:    f"{RED}%(levelname)s{RESET} - %(message)s",
        logging.CRITICAL: f"{BOLD_RED}%(levelname)s{RESET} - %(message)s"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

class JSONFormatter(logging.Formatter):
    """Formatter que gera logs em formato JSON para o arquivo."""
    
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "name": record.name,
            "level": record.levelname,
            "message": record.getMessage()
        }
        
        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)
            
        return json.dumps(log_record, ensure_ascii=False)

def setup_logging():
    """Configura o logging para a aplicação."""
    logging_config = {
        'version': 1,
        # Desativa os logs de bibliotecas de terceiros (opcional)
        'disable_existing_loggers': False, 
        'formatters': {
            'json_formatter': {
                '()': JSONFormatter,
            },
            'console': {
                '()': ColorFormatter,
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'console',
                'level': logging.INFO,
            },
            'file': {
                'class': 'logging.FileHandler',
                'formatter': 'json_formatter',
                'level': logging.DEBUG,
                'filename': 'app.log',
                'encoding': 'utf8'
            }
        },
        'root': {
            'handlers': ['console', 'file'],
            'level': logging.DEBUG,
        },
    }
    
    logging.config.dictConfig(logging_config)