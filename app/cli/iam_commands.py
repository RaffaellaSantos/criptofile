import argparse
import getpass
import logging
from contextlib import contextmanager

from rich.console import Console
from rich.table import Table

from app.core.session import Session
from app.exceptions.iam_exceptions import IAMError
from app.model.user_model import Role
from app.service import IAMService
from app.utils.validator import validate_str

logger = logging.getLogger(__name__)
console = Console()


def _service() -> IAMService:
    # Importação tardia: o banco só é acessado pelos comandos que precisam dele.
    from app.core.database import SessionLocal, init_db

    init_db()
    return IAMService(SessionLocal)


def _ask_new_password() -> str:
    password = getpass.getpass("Nova senha: ")
    if password != getpass.getpass("Confirme a senha: "):
        raise IAMError("As senhas não coincidem.")
    return password


@contextmanager
def _logged_in(service: IAMService, username: str):
    """Autentica o usuário e garante o encerramento da sessão ao final do comando."""
    session: Session = service.authenticate(username, getpass.getpass(f"Senha de {username}: "))
    try:
        yield session
    finally:
        service.logout(session)


def cmd_admin_init(args: argparse.Namespace) -> None:
    service = _service()
    if service.has_users():
        raise IAMError("O sistema já foi inicializado. Use 'user-add' com um ADMIN.")
    info = service.bootstrap_admin(args.username, _ask_new_password())
    console.print(f"[green]ADMIN inicial '{info.username}' criado com sucesso.[/green]")


def cmd_login(args: argparse.Namespace) -> None:
    service = _service()
    with _logged_in(service, args.username) as session:
        console.print(
            f"[green]Autenticado como '{session.username}' ({session.role.value}).[/green]"
        )


def cmd_user_add(args: argparse.Namespace) -> None:
    service = _service()
    with _logged_in(service, args.as_user) as session:
        # Verifica a permissão antes de pedir a senha do novo usuário.
        service.sessions.require_role(session, Role.ADMIN)
        console.print(f"Cadastrando '{args.username}' ({args.role.value}).")
        info = service.register_user(session, args.username, _ask_new_password(), args.role)
    console.print(f"[green]Usuário '{info.username}' ({info.role.value}) cadastrado.[/green]")


def cmd_user_role(args: argparse.Namespace) -> None:
    service = _service()
    with _logged_in(service, args.as_user) as session:
        info = service.set_role(session, args.username, args.role)
    console.print(f"[green]Papel de '{info.username}' alterado para {info.role.value}.[/green]")


def cmd_user_list(args: argparse.Namespace) -> None:
    service = _service()
    with _logged_in(service, args.as_user) as session:
        users = service.list_users(session)

    table = Table(title="Usuários cadastrados")
    table.add_column("Username")
    table.add_column("Papel")
    table.add_column("Criado em")
    table.add_column("ID", style="dim")
    for u in users:
        table.add_row(u.username, u.role.value, f"{u.created_at:%Y-%m-%d %H:%M}", u.user_id)
    console.print(table)


def _role(value: str) -> Role:
    try:
        return Role(value.upper())
    except ValueError as err:
        raise argparse.ArgumentTypeError("papel deve ser ADMIN ou USER") from err


def register_iam_commands(subparsers) -> None:
    """Registra os subcomandos do módulo IAM no parser principal."""
    p = subparsers.add_parser("admin-init", help="Cria o primeiro usuário ADMIN do sistema.")
    p.add_argument("-u", "--username", type=validate_str, required=True)
    p.set_defaults(func=cmd_admin_init)

    p = subparsers.add_parser("login", help="Valida as credenciais de um usuário.")
    p.add_argument("-u", "--username", type=validate_str, required=True)
    p.set_defaults(func=cmd_login)

    p = subparsers.add_parser("user-add", help="Cadastra um novo usuário (apenas ADMIN).")
    p.add_argument("--as", dest="as_user", type=validate_str, required=True, metavar="ADMIN",
                   help="Username do ADMIN que executa a operação.")
    p.add_argument("-u", "--username", type=validate_str, required=True)
    p.add_argument("-r", "--role", type=_role, default=Role.USER, metavar="{ADMIN,USER}")
    p.set_defaults(func=cmd_user_add)

    p = subparsers.add_parser("user-role", help="Altera o papel de um usuário (apenas ADMIN).")
    p.add_argument("--as", dest="as_user", type=validate_str, required=True, metavar="ADMIN",
                   help="Username do ADMIN que executa a operação.")
    p.add_argument("-u", "--username", type=validate_str, required=True)
    p.add_argument("-r", "--role", type=_role, required=True, metavar="{ADMIN,USER}")
    p.set_defaults(func=cmd_user_role)

    p = subparsers.add_parser("user-list", help="Lista os usuários cadastrados (apenas ADMIN).")
    p.add_argument("--as", dest="as_user", type=validate_str, required=True, metavar="ADMIN",
                   help="Username do ADMIN que executa a operação.")
    p.set_defaults(func=cmd_user_list)
