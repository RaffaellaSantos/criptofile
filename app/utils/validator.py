import argparse
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def validate_str(value: str = "") -> str:
    """Valida se a string existe."""
    logger.debug(f"Validando string: {value}")
    clean_str = value.strip()

    if not clean_str:
        raise argparse.ArgumentTypeError("[Erro]: Argumento vazio.")

    return clean_str


def validate_path(value: str) -> Path:
    """Valiida se o caminho existe, se é um arquivo"""
    logger.debug(f"Validando caminho do arquivo: {value}")
    path = Path(value)

    if not path.exists():
        raise argparse.ArgumentTypeError(
            f"[Erro]: o arquivo '{path}' não foi encontrado."
        )

    if not path.is_file():
        raise argparse.ArgumentTypeError(
            f"[Erro]: '{path}' é um diretório, esperava-se um arquivo."
        )

    return path


def define_name(path: Path) -> str:
    """Define o nome do arquivo sem extensão."""
    logger.debug(f"Definindo nome do arquivo para: {path.stem}")
    return path.stem


def abs_path(path: Path) -> str:
    """Retorna o caminho absoluto do arquivo."""
    absolute_path = os.path.abspath(path)
    logger.debug(f"Caminho absoluto do arquivo: {absolute_path}")
    return absolute_path
