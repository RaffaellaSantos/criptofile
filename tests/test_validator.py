"""Testes dos validadores de entrada da CLI (tratamento de entrada inválida)."""

import argparse
import os
from pathlib import Path

import pytest

from app.utils.validator import abs_path, define_name, validate_path, validate_str


def test_validate_str_strips_spaces():
    assert validate_str("  alice  ") == "alice"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_validate_str_rejects_empty(value):
    with pytest.raises(argparse.ArgumentTypeError, match="vazio"):
        validate_str(value)


def test_validate_path_accepts_existing_file(tmp_path):
    path = tmp_path / "doc.pdf"
    path.write_bytes(b"conteudo")
    assert validate_path(str(path)) == path


def test_validate_path_rejects_missing_file(tmp_path):
    with pytest.raises(argparse.ArgumentTypeError, match="não foi encontrado"):
        validate_path(str(tmp_path / "inexistente.pdf"))


def test_validate_path_rejects_directory(tmp_path):
    with pytest.raises(argparse.ArgumentTypeError, match="diretório"):
        validate_path(str(tmp_path))


def test_define_name_drops_extension():
    assert define_name(Path("pasta/relatorio.pdf")) == "relatorio"


def test_abs_path_resolves_relative_path():
    result = abs_path(Path("relatorio.pdf"))
    assert os.path.isabs(result)
    assert result == os.path.join(os.getcwd(), "relatorio.pdf")
