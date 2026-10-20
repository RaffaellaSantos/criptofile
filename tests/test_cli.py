"""Testes da interface de linha de comando (argparse + handlers).

O banco é um SQLite em memória e as senhas são fornecidas no lugar do
`getpass`, de modo que os comandos rodam de ponta a ponta sem PostgreSQL.
"""

import json
import os

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from rich.console import Console
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from alembic.util import CommandError
from sqlalchemy.exc import OperationalError as SAOperationalError
from sqlalchemy.exc import ProgrammingError

from app import main as main_module
from app.cli import arguments, audit_commands, file_cryptography_commands, iam_commands
from app.core import security
from app.core.config import Settings, settings
from app.core.database import Base, get_engine
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus
from app.model.user_model import Role, User
from app.service import AuditService, IAMService
from app.exceptions.file_cryptography_exceptions import PermissionError as FilePermissionError
from app.service.file_cryptography_service import FileCryptoService

ADMIN_PW = "Admin12345"
BOB_PW = "Bob123456"
TEST_HMAC_KEY = bytes(range(32))
# Implementação real, guardada antes de a fixture substituí-la.
REAL_SERVICE = iam_commands._service


@pytest.fixture
def cli(monkeypatch, tmp_path):
    """Executa a CLI contra um banco em memória; devolve (run, factory, tmp_path).

    `run(*argv, passwords=[...])` responde aos prompts de senha na ordem dada e
    devolve o código de saída (0 quando o comando termina sem `SystemExit`).
    Esgotadas as senhas, o prompt se comporta como um stdin fechado (EOFError).
    """
    monkeypatch.setattr(security, "TIME_COST", 1)
    monkeypatch.setattr(security, "MEMORY_COST", 8)
    monkeypatch.setattr(security, "PARALLELISM", 1)

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    audit = AuditService(factory, hmac_key=TEST_HMAC_KEY, key_file=str(tmp_path / ".audit_key"))

    def service() -> IAMService:
        return IAMService(factory, audit_service=audit)

    for module in (iam_commands, file_cryptography_commands, audit_commands):
        monkeypatch.setattr(module, "_service", service)
    monkeypatch.setattr(file_cryptography_commands, "SessionLocal", factory)
    monkeypatch.setattr(
        FileCryptoService, "_get_user_workspace", lambda self, username: str(tmp_path / username)
    )

    def run(*argv: str, passwords: list[str] = ()) -> int:
        answers = iter(passwords)

        def getpass(prompt=""):
            try:
                return next(answers)
            except StopIteration:
                raise EOFError from None

        monkeypatch.setattr("getpass.getpass", getpass)
        monkeypatch.setattr("sys.argv", ["criptofile", *argv])
        try:
            arguments.run()
        except SystemExit as exit_:
            return exit_.code or 0
        return 0

    yield run, factory, tmp_path
    engine.dispose()


@pytest.fixture
def ready(cli):
    """ADMIN e BOB cadastrados, ambos com chaves geradas."""
    run, factory, tmp_path = cli
    (tmp_path / "admin").mkdir()
    (tmp_path / "bob").mkdir()
    assert run("admin-init", "-u", "admin", passwords=[ADMIN_PW, ADMIN_PW]) == 0
    assert run("user-add", "--as", "admin", "-u", "bob", passwords=[ADMIN_PW, BOB_PW, BOB_PW]) == 0
    assert run("genkeys", "-u", "admin", passwords=[ADMIN_PW]) == 0
    assert run("genkeys", "-u", "bob", passwords=[BOB_PW]) == 0
    return cli


def _source_file(tmp_path, name: str, content: bytes = b"dados secretos") -> str:
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


def _last_event(factory, action: str) -> AuditLog:
    with factory() as db:
        events = db.scalars(select(AuditLog).where(AuditLog.action_type == action)).all()
    assert events, f"nenhum evento {action}"
    return events[-1]


# Ajuda e validação de argumentos (entrada inválida) ----------------------- #
def test_without_arguments_prints_help(cli, capsys):
    run, factory, tmp_path = cli
    assert run() == 0
    assert "criptofile" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv,message",
    [
        (["encrypt", "-p", "inexistente.pdf", "-u", "admin"], "não foi encontrado"),
        (["encrypt", "-u", "admin"], "required"),
        (["login", "-u", "   "], "vazio"),
        (["user-add", "--as", "admin", "-u", "bob", "-r", "ROOT"], "ADMIN ou USER"),
        (["share", "-p", "a.enc", "-u", "admin", "-t", "bob", "--permission", "write"], "invalid choice"),
        (["audit-report", "--as", "admin", "-a", "HACK"], "ação deve ser uma de"),
        (["audit-report", "--as", "admin", "--export", "xml"], "invalid choice"),
        (["comando-inexistente"], "invalid choice"),
    ],
    ids=["arquivo-inexistente", "sem-path", "username-vazio", "papel-invalido",
         "permissao-invalida", "acao-invalida", "formato-invalido", "comando-invalido"],
)
def test_invalid_arguments_exit_with_code_2(cli, capsys, argv, message):
    run, factory, tmp_path = cli
    assert run(*argv) == 2
    assert message in capsys.readouterr().err


def test_encrypt_rejects_directory(cli, capsys):
    run, factory, tmp_path = cli
    assert run("encrypt", "-p", str(tmp_path), "-u", "admin") == 2
    assert "diretório" in capsys.readouterr().err


def test_audit_output_requires_export(ready, capsys):
    run, factory, tmp_path = ready
    assert run("audit-report", "--as", "admin", "-o", str(tmp_path / "r.json")) == 2
    assert "requer --export" in capsys.readouterr().out


# IAM pela CLI (01.2, 02.1, 02.2) ------------------------------------------ #
def test_admin_init_creates_admin(cli, capsys):
    run, factory, tmp_path = cli
    assert run("admin-init", "-u", "admin", passwords=[ADMIN_PW, ADMIN_PW]) == 0
    assert "ADMIN inicial 'admin' criado" in capsys.readouterr().out
    with factory() as db:
        assert db.scalar(select(User)).role == Role.ADMIN.value


def test_admin_init_twice_fails(ready, caplog):
    run, factory, tmp_path = ready
    assert run("admin-init", "-u", "root", passwords=[ADMIN_PW, ADMIN_PW]) == 1
    assert "já foi inicializado" in caplog.text


def test_admin_init_password_mismatch_fails(cli, caplog):
    run, factory, tmp_path = cli
    assert run("admin-init", "-u", "admin", passwords=[ADMIN_PW, "Outra12345"]) == 1
    assert "não coincidem" in caplog.text
    with factory() as db:
        assert db.scalar(select(User)) is None


def test_login_success(ready, capsys):
    run, factory, tmp_path = ready
    assert run("login", "-u", "bob", passwords=[BOB_PW]) == 0
    assert "Autenticado como 'bob' (USER)" in capsys.readouterr().out


@pytest.mark.parametrize("username,password", [("bob", "errada123"), ("ghost", BOB_PW)])
def test_login_failure_exits_with_code_1(ready, caplog, username, password):
    run, factory, tmp_path = ready
    assert run("login", "-u", username, passwords=[password]) == 1
    assert "Usuário ou senha inválidos" in caplog.text


def test_brute_force_locks_account_via_cli(ready, caplog):
    run, factory, tmp_path = ready
    for _ in range(4):
        assert run("login", "-u", "bob", passwords=["errada123"]) == 1
    assert run("login", "-u", "bob", passwords=[BOB_PW]) == 1
    assert "bloqueada" in caplog.text
    assert _last_event(factory, AuditAction.SECURITY_ALERT).username == "bob"


def test_user_cannot_add_users(ready, caplog):
    run, factory, tmp_path = ready
    assert run("user-add", "--as", "bob", "-u", "carol", passwords=[BOB_PW]) == 1
    assert "apenas para usuários ADMIN" in caplog.text
    with factory() as db:
        assert db.scalar(select(User).where(User.username == "carol")) is None


def test_user_cannot_change_roles(ready, caplog):
    run, factory, tmp_path = ready
    assert run("user-role", "--as", "bob", "-u", "bob", "-r", "ADMIN", passwords=[BOB_PW]) == 1
    assert "apenas para usuários ADMIN" in caplog.text
    with factory() as db:
        assert db.scalar(select(User).where(User.username == "bob")).role == Role.USER.value


def test_admin_changes_role_and_lists_users(ready, capsys):
    run, factory, tmp_path = ready
    assert run("user-role", "--as", "admin", "-u", "bob", "-r", "admin", passwords=[ADMIN_PW]) == 0
    assert run("user-list", "--as", "admin", passwords=[ADMIN_PW]) == 0
    out = capsys.readouterr().out
    assert "alterado para ADMIN" in out
    assert "bob" in out


# Arquivos pela CLI (03.1, 03.2, 04.1, 04.2, 04.3) ------------------------- #
def test_encrypt_and_decrypt_roundtrip(ready, capsys):
    run, factory, tmp_path = ready
    src = _source_file(tmp_path, "doc.pdf", b"conteudo original")
    enc_path = str(tmp_path / "admin" / "doc.pdf.enc")

    assert run("encrypt", "-p", src, "-u", "admin", passwords=[ADMIN_PW]) == 0
    assert "Sucesso" in capsys.readouterr().out
    assert os.path.exists(enc_path) and not os.path.exists(src)

    assert run("decrypt", "-p", enc_path, "-u", "admin", passwords=[ADMIN_PW]) == 0
    assert "Desencriptação Concluída" in capsys.readouterr().out
    assert (tmp_path / "admin" / "doc.pdf").read_bytes() == b"conteudo original"


def test_share_verify_update_and_revoke(ready, capsys):
    run, factory, tmp_path = ready
    src = _source_file(tmp_path, "doc.pdf")
    enc_path = str(tmp_path / "admin" / "doc.pdf.enc")
    novo = _source_file(tmp_path, "novo.txt", b"versao do bob")
    assert run("encrypt", "-p", src, "-u", "admin", passwords=[ADMIN_PW]) == 0

    assert run("share", "-p", enc_path, "-u", "admin", "-t", "bob", "--permission", "modify",
               passwords=[ADMIN_PW]) == 0
    assert run("verify", "-p", enc_path, "-u", "bob", passwords=[BOB_PW]) == 0
    assert run("update", "-p", enc_path, "-c", novo, "-u", "bob", passwords=[BOB_PW]) == 0
    assert run("file-list", "-u", "bob", passwords=[BOB_PW]) == 0
    assert run("revoke", "-p", enc_path, "-u", "admin", "-t", "bob", passwords=[ADMIN_PW]) == 0
    assert run("verify", "-p", enc_path, "-u", "bob", passwords=[BOB_PW]) == 1

    out = capsys.readouterr().out
    assert "Acesso concedido" in out
    assert "ÍNTEGRO" in out
    assert "Arquivo modificado" in out
    assert "doc.pdf" in out
    assert "Acesso revogado" in out
    assert "não tem permissão" in out  # verify do bob após o revoke


def test_tampered_file_shows_error_and_records_violation(ready, capsys):
    run, factory, tmp_path = ready
    src = _source_file(tmp_path, "doc.pdf")
    enc_path = tmp_path / "admin" / "doc.pdf.enc"
    assert run("encrypt", "-p", src, "-u", "admin", passwords=[ADMIN_PW]) == 0
    data = enc_path.read_bytes()
    enc_path.write_bytes(data[:-1] + bytes([data[-1] ^ 0xFF]))

    assert run("verify", "-p", str(enc_path), "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert run("decrypt", "-p", str(enc_path), "-u", "admin", passwords=[ADMIN_PW]) == 1

    out = capsys.readouterr().out
    assert "integridade do arquivo foi violada" in out
    assert not (tmp_path / "admin" / "doc.pdf").exists()
    assert _last_event(factory, AuditAction.INTEGRITY_VIOLATION).status == AuditStatus.FAIL


def test_encrypt_of_duplicate_name_is_refused(ready, capsys):
    run, factory, tmp_path = ready
    enc_path = tmp_path / "admin" / "doc.pdf.enc"
    assert run("encrypt", "-p", _source_file(tmp_path, "doc.pdf", b"primeiro"), "-u", "admin",
               passwords=[ADMIN_PW]) == 0
    original_enc = enc_path.read_bytes()
    second = _source_file(tmp_path, "doc.pdf", b"segundo")

    assert run("encrypt", "-p", second, "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "Já existe um arquivo cifrado" in capsys.readouterr().out
    assert enc_path.read_bytes() == original_enc
    assert os.path.exists(second)


def test_decrypt_does_not_overwrite_local_file(ready, capsys):
    run, factory, tmp_path = ready
    enc_path = tmp_path / "admin" / "doc.pdf.enc"
    assert run("encrypt", "-p", _source_file(tmp_path, "doc.pdf"), "-u", "admin",
               passwords=[ADMIN_PW]) == 0
    (tmp_path / "admin" / "doc.pdf").write_bytes(b"versao local")

    assert run("decrypt", "-p", str(enc_path), "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "Já existe um arquivo" in capsys.readouterr().out
    assert (tmp_path / "admin" / "doc.pdf").read_bytes() == b"versao local"
    assert enc_path.exists()


def test_encrypt_for_unknown_target_exits_with_code_1(ready, caplog):
    run, factory, tmp_path = ready
    src = _source_file(tmp_path, "doc.pdf")
    assert run("encrypt", "-p", src, "-u", "admin", "-t", "fantasma", passwords=[ADMIN_PW]) == 1
    assert "não existe" in caplog.text
    assert os.path.exists(src)


@pytest.mark.parametrize("command", ["decrypt", "verify"])
def test_missing_enc_shows_error_without_traceback(ready, capsys, command):
    run, factory, tmp_path = ready
    assert run(command, "-p", str(tmp_path / "nao_existe.enc"), "-u", "admin",
               passwords=[ADMIN_PW]) == 1
    assert "não encontrado" in capsys.readouterr().out


def test_decrypt_without_private_key_shows_error(ready, capsys):
    run, factory, tmp_path = ready
    src = _source_file(tmp_path, "doc.pdf")
    assert run("encrypt", "-p", src, "-u", "admin", "-t", "bob", passwords=[ADMIN_PW]) == 0
    os.remove(tmp_path / "bob" / "private.pem")

    assert run("decrypt", "-p", str(tmp_path / "bob" / "doc.pdf.enc"), "-u", "bob",
               passwords=[BOB_PW]) == 1
    assert "genkeys" in capsys.readouterr().out
    assert (tmp_path / "bob" / "doc.pdf.enc").exists()


def test_unhandled_file_error_exits_with_code_1(ready, caplog, monkeypatch):
    """Rede de segurança do run(): erro de arquivo não tratado vira exit 1, sem traceback."""
    run, factory, tmp_path = ready

    def fail(self, session):
        raise OSError("disco indisponível")

    monkeypatch.setattr(FileCryptoService, "list_files", fail)
    assert run("file-list", "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "disco indisponível" in caplog.text


# Relatório de auditoria pela CLI (05.3) ----------------------------------- #
def test_user_cannot_read_audit_report(ready, caplog):
    run, factory, tmp_path = ready
    assert run("audit-report", "--as", "bob", passwords=[BOB_PW]) == 1
    assert "ADMIN" in caplog.text
    assert _last_event(factory, AuditAction.AUDIT_REPORT).status == AuditStatus.FAIL


def test_admin_exports_filtered_report_to_json(ready):
    run, factory, tmp_path = ready
    report = tmp_path / "relatorio" / "logins.json"
    assert run("audit-report", "--as", "admin", "-a", "login", "--export", "json",
               "-o", str(report), passwords=[ADMIN_PW]) == 0

    events = json.loads(report.read_text(encoding="utf-8"))
    assert events
    assert {e["action_type"] for e in events} == {"LOGIN"}


def test_admin_exports_report_as_cef(ready, capsys):
    run, factory, tmp_path = ready
    assert run("audit-report", "--as", "admin", "-u", "bob", "--export", "cef",
               passwords=[ADMIN_PW]) == 0

    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("CEF:")]
    assert lines
    assert all("suser=bob" in line for line in lines)


def test_json_export_to_stdout_is_valid_json(ready, capsys):
    """Saída crua: linhas longas e colchetes não podem corromper o JSON."""
    run, factory, tmp_path = ready
    src = _source_file(tmp_path, "[confidencial] relatorio com nome bem longo.pdf")
    assert run("encrypt", "-p", src, "-u", "admin", passwords=[ADMIN_PW]) == 0
    capsys.readouterr()

    assert run("audit-report", "--as", "admin", "-a", "FILE_ENCRYPT", "--export", "json",
               passwords=[ADMIN_PW]) == 0

    events = json.loads(capsys.readouterr().out)
    assert events[0]["resource_id"] == src


def test_admin_report_flags_tampered_log(ready, capsys):
    run, factory, tmp_path = ready
    with factory() as db:
        db.scalars(select(AuditLog)).first().status = AuditStatus.FAIL.value
        db.commit()

    assert run("audit-report", "--as", "admin", passwords=[ADMIN_PW]) == 0
    assert "ADULTERADOS" in capsys.readouterr().out


# Comando info ------------------------------------------------------------- #
def test_info_shows_file_details(cli, capsys):
    run, factory, tmp_path = cli
    assert run("info", "-p", _source_file(tmp_path, "relatorio.pdf")) == 0
    out = capsys.readouterr().out
    assert "relatorio" in out
    assert "Caminho absoluto" in out


# Erros de ambiente: saída amigável e código 1, nunca traceback ------------- #
def test_closed_stdin_on_password_prompt_exits_with_code_1(ready, caplog):
    run, factory, tmp_path = ready
    assert run("login", "-u", "admin", passwords=[]) == 1
    assert "terminal interativo" in caplog.text


def test_invalid_audit_key_exits_with_code_1(cli, caplog, monkeypatch):
    run, factory, tmp_path = cli
    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", "zzzz")
    monkeypatch.setattr(iam_commands, "_service", lambda: IAMService(factory))

    assert run("login", "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "AUDIT_HMAC_KEY" in caplog.text


def test_settings_load_without_database_url(monkeypatch):
    """Sem DATABASE_URL no ambiente nem no .env, a importação não quebra: a
    ausência é reportada depois, com mensagem clara (teste seguinte)."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert Settings(_env_file=None).DATABASE_URL is None


def test_missing_database_url_exits_with_code_1(cli, caplog, monkeypatch):
    run, factory, tmp_path = cli
    monkeypatch.setattr(settings, "DATABASE_URL", None)
    monkeypatch.setattr(iam_commands, "_service", REAL_SERVICE)
    get_engine.cache_clear()

    assert run("login", "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "DATABASE_URL não configurada" in caplog.text


@pytest.mark.parametrize(
    "error,message",
    [
        (CommandError("Can't locate revision"), "Falha ao aplicar as migrações"),
        (ProgrammingError("SELECT 1", {}, Exception("relation \"users\" does not exist")),
         "Verifique se as migrações estão atualizadas"),
    ],
    ids=["alembic", "schema-divergente"],
)
def test_database_errors_exit_with_code_1(cli, caplog, monkeypatch, error, message):
    run, factory, tmp_path = cli

    def broken_service():
        raise error

    monkeypatch.setattr(iam_commands, "_service", broken_service)
    assert run("login", "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert message in caplog.text


@pytest.mark.parametrize(
    "error,code",
    [(KeyboardInterrupt(), 130), (ValueError("valor inválido"), 1)],
    ids=["ctrl-c", "value-error"],
)
def test_main_exit_codes(monkeypatch, error, code):
    def interrupted():
        raise error

    monkeypatch.setattr(main_module, "setup_logging", lambda: None)
    monkeypatch.setattr(main_module, "run", interrupted)
    with pytest.raises(SystemExit) as exit_:
        main_module.main()
    assert exit_.value.code == code


# Par de chaves e arquivos de chave pela CLI ------------------------------- #
def test_genkeys_twice_requires_force(ready, capsys):
    run, factory, tmp_path = ready
    assert run("genkeys", "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "--force" in capsys.readouterr().out
    assert run("genkeys", "-u", "admin", "--force", passwords=[ADMIN_PW]) == 0
    assert "Chaves geradas com sucesso" in capsys.readouterr().out


def test_private_key_cannot_be_encrypted_via_cli(ready, capsys):
    run, factory, tmp_path = ready
    priv_path = tmp_path / "admin" / "private.pem"
    assert run("encrypt", "-p", str(priv_path), "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "chave do sistema" in capsys.readouterr().out
    assert priv_path.exists()


# Injeção de marcação do Rich (entrada do usuário exibida no terminal) ----- #
def test_bracketed_file_name_is_shown_literally(ready, capsys):
    run, factory, tmp_path = ready
    src = _source_file(tmp_path, "[final] relatorio.pdf")
    assert run("encrypt", "-p", src, "-u", "admin", passwords=[ADMIN_PW]) == 0
    assert "[final] relatorio.pdf.enc" in capsys.readouterr().out.replace("\n", "")

    assert run("file-list", "-u", "admin", passwords=[ADMIN_PW]) == 0
    assert "[final]" in capsys.readouterr().out


def test_markup_in_username_cannot_crash_user_add(ready, caplog):
    run, factory, tmp_path = ready
    assert run("user-add", "--as", "admin", "-u", "x[/]y",
               passwords=[ADMIN_PW, BOB_PW, BOB_PW]) == 1
    assert "Username deve ter" in caplog.text


def test_markup_in_audit_log_cannot_spoof_report(ready, capsys, monkeypatch):
    """Um username forjado no login não pode quebrar nem falsificar o relatório."""
    run, factory, tmp_path = ready
    # Console largo: a tabela não quebra o username forjado em duas linhas.
    monkeypatch.setattr(audit_commands, "console", Console(width=300))
    for forged in ("[/]", "[green]SUCCESS[/green]"):
        assert run("login", "-u", forged, passwords=["qualquer123"]) == 1

    assert run("audit-report", "--as", "admin", "-a", "LOGIN", passwords=[ADMIN_PW]) == 0
    out = capsys.readouterr().out
    assert "[/]" in out
    assert "[green]SUCCESS[/green]" in out


def test_env_file_is_read_from_project_root():
    """O .env é lido da raiz do projeto, qualquer que seja a pasta atual."""
    from app.core.config import PROJECT_ROOT

    assert Settings.model_config["env_file"] == PROJECT_ROOT / ".env"
    assert (PROJECT_ROOT / "alembic.ini").exists()


# Ramos de erro restantes da CLI ------------------------------------------- #
def test_missing_option_value_is_translated(cli, capsys):
    run, factory, tmp_path = cli
    assert run("encrypt", "-u", "admin", "-p") == 2
    assert "esperava um caminho de arquivo" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv,password",
    [
        (["update", "-p", "{enc}", "-c", "{novo}", "-u", "bob"], BOB_PW),  # READ não modifica
        (["share", "-p", "{enc}", "-u", "admin", "-t", "fantasma"], ADMIN_PW),
        (["revoke", "-p", "{enc}", "-u", "bob", "-t", "admin"], BOB_PW),  # só o dono revoga
    ],
    ids=["update-sem-permissao", "share-alvo-inexistente", "revoke-nao-dono"],
)
def test_file_command_errors_exit_with_code_1(ready, capsys, argv, password):
    run, factory, tmp_path = ready
    enc = str(tmp_path / "admin" / "doc.pdf.enc")
    novo = _source_file(tmp_path, "novo.txt", b"novo")
    assert run("encrypt", "-p", _source_file(tmp_path, "doc.pdf"), "-u", "admin",
               passwords=[ADMIN_PW]) == 0
    assert run("share", "-p", enc, "-u", "admin", "-t", "bob", passwords=[ADMIN_PW]) == 0
    capsys.readouterr()

    args = [a.format(enc=enc, novo=novo) for a in argv]
    assert run(*args, passwords=[password]) == 1
    assert "Erro:" in capsys.readouterr().out


def test_file_list_without_files(ready, capsys):
    run, factory, tmp_path = ready
    assert run("file-list", "-u", "bob", passwords=[BOB_PW]) == 0
    assert "Nenhum arquivo acessível" in capsys.readouterr().out


def test_file_list_error_exits_with_code_1(ready, capsys, monkeypatch):
    run, factory, tmp_path = ready

    def fail(self, session):
        raise FilePermissionError("sem acesso ao banco de arquivos")

    monkeypatch.setattr(FileCryptoService, "list_files", fail)
    assert run("file-list", "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "sem acesso ao banco de arquivos" in capsys.readouterr().out


def test_report_title_shows_user_filter(ready, capsys, monkeypatch):
    run, factory, tmp_path = ready
    monkeypatch.setattr(audit_commands, "console", Console(width=200))
    assert run("audit-report", "--as", "admin", "-u", "bob", passwords=[ADMIN_PW]) == 0
    assert "usuário: bob" in capsys.readouterr().out


def test_export_to_directory_is_refused(ready, capsys):
    run, factory, tmp_path = ready
    assert run("audit-report", "--as", "admin", "--export", "json", "-o", str(tmp_path),
               passwords=[ADMIN_PW]) == 2
    assert "é um diretório" in capsys.readouterr().out


def test_unreachable_database_exits_with_code_1(cli, caplog, monkeypatch):
    run, factory, tmp_path = cli

    def unreachable():
        raise SAOperationalError(
            "connect", {}, Exception('connection to server at "db" failed\nRecusada')
        )

    monkeypatch.setattr(iam_commands, "_service", unreachable)
    assert run("login", "-u", "admin", passwords=[ADMIN_PW]) == 1
    assert "Não foi possível conectar ao banco" in caplog.text
    assert "Recusada" in caplog.text


def test_report_explains_truncated_log(ready, capsys, monkeypatch):
    run, factory, tmp_path = ready
    monkeypatch.setattr(audit_commands, "console", Console(width=200))
    with factory() as db:
        newest = db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc())).first()
        db.delete(newest)
        db.commit()

    assert run("audit-report", "--as", "admin", passwords=[ADMIN_PW]) == 0
    out = capsys.readouterr().out
    assert "eventos mais recentes do log foram REMOVIDOS" in out
    assert "log-trun" not in out
