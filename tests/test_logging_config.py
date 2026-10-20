"""Testes dos formatadores de log (console colorido e arquivo JSON)."""

import json
import logging

from app.core.logging_config import ColorFormatter, JSONFormatter


def _record(msg: str, *args, level=logging.WARNING, exc_info=None) -> logging.LogRecord:
    return logging.LogRecord("teste", level, __file__, 1, msg, args, exc_info)


def test_color_formatter_includes_level_and_message():
    out = ColorFormatter().format(_record("LOGIN FAIL: usuário '%s'.", "bob"))
    assert "WARNING" in out
    assert "LOGIN FAIL: usuário 'bob'." in out


def test_color_formatter_escapes_terminal_control_sequences():
    """Um username com ESC não injeta sequências ANSI no terminal."""
    forged = "\x1b[2J\x1b[32mSUCCESS\x07"
    out = ColorFormatter().format(_record("LOGIN FAIL: usuário '%s'.", forged))
    message = out.split(" - ", 1)[1]
    assert "\x1b" not in message and "\x07" not in message
    assert "\\x1b[2J" in message


def test_color_formatter_keeps_line_breaks_and_accents():
    out = ColorFormatter().format(_record("Erro no banco.\n  Motivo: conexão recusada"))
    assert "Erro no banco.\n  Motivo: conexão recusada" in out


def test_color_formatter_does_not_mutate_record():
    """O mesmo registro segue intacto para o handler de arquivo (JSON)."""
    record = _record("valor %s", "\x1b")
    ColorFormatter().format(record)
    assert record.getMessage() == "valor \x1b"


def test_json_formatter_produces_valid_json_with_escaped_input():
    out = JSONFormatter().format(
        _record("arquivo '%s'", 'a"b\nc\x1b', level=logging.ERROR)
    )
    data = json.loads(out)
    assert data["level"] == "ERROR"
    assert data["message"] == "arquivo 'a\"b\nc\x1b'"
    assert "\n" not in out  # uma linha por evento: não há como forjar linhas no app.log


def test_json_formatter_includes_exception():
    try:
        raise ValueError("falhou")
    except ValueError:
        import sys

        out = JSONFormatter().format(
            _record("erro", level=logging.ERROR, exc_info=sys.exc_info())
        )
    assert "ValueError: falhou" in json.loads(out)["exc_info"]


def test_log_file_lives_in_data_dir(monkeypatch, tmp_path):
    import logging.handlers

    from app.core import logging_config
    from app.core.config import settings

    monkeypatch.setattr(settings, "CRIPTOFILE_HOME", str(tmp_path))
    root = logging.getLogger()
    previous = root.handlers[:], root.level
    try:
        logging_config.setup_logging()
        files = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
        assert [h.baseFilename for h in files] == [str(tmp_path.resolve() / "app.log")]
    finally:
        for handler in root.handlers:
            if handler not in previous[0]:
                handler.close()
        root.handlers[:] = previous[0]
        root.setLevel(previous[1])
