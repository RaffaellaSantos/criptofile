import argparse
import logging

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich_argparse import RichHelpFormatter

from app.cli.iam_commands import _logged_in, _service
from app.core.database import SessionLocal
from app.exceptions.file_cryptography_exceptions import (
    FileCryptofileError,
)
from app.exceptions.iam_exceptions import IAMError
from app.model.file_model import Permission
from app.service.file_cryptography_service import FileCryptoService
from app.utils.validator import validate_path, validate_str

logger = logging.getLogger(__name__)
console = Console()


def handle_generate_keys(args: argparse.Namespace) -> None:
    """Gera o par de chaves, salva a privada na pasta do usuário e a pública no banco."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions, iam.audit)
    with _logged_in(iam, args.username) as session:
        try:
            priv_path = crypto_service.generate_keys(session, force=args.force)

            success_msg = (
                f"[green]Chaves geradas com sucesso para '{session.username}'![/green]\n\n"
                f"[bold yellow]- {escape(priv_path)}[/bold yellow] (MANTENHA SEGURA)\n"
                f"[bold blue]- Chave pública vinculada ao perfil no banco de dados.[/bold blue]"
            )
            console.print(
                Panel(
                    success_msg,
                    title="[bold green]Geração de Chaves[/bold green]",
                    expand=False,
                )
            )

        except FileCryptofileError as e:
            logger.error(f"Erro inesperado ao gerar chaves: {e}")
            console.print(f"[bold red]Erro inesperado:[/bold red] {escape(str(e))}")
            raise SystemExit(1) from e


def handle_encrypt(args: argparse.Namespace) -> None:
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions, iam.audit)

    with _logged_in(iam, args.username) as session:
        try:
            out_path = crypto_service.encrypt_file(
                session, args.path, args.target, args.output
            )
            console.print(f"[green]Sucesso! Salvo em: {escape(out_path)}[/green]")
        except FileCryptofileError as e:
            console.print(f"[bold red]Erro:[/bold red] {escape(str(e))}")
            raise SystemExit(1) from e


def handle_decrypt(args: argparse.Namespace) -> None:
    """Processa a desencriptação do arquivo via CLI."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions, iam.audit)

    with _logged_in(iam, args.username) as session:
        try:
            out_path = crypto_service.decrypt_file(session, args.path, args.output)

            console.print(
                Panel(
                    f"[green]Arquivo desencriptado com sucesso:[/green]\n[bold]{escape(out_path)}[/bold]",
                    title="[bold green]Desencriptação Concluída[/bold green]",
                    expand=False,
                )
            )
        except FileCryptofileError as e:
            logger.error(f"Erro interno de criptografia: {e}")
            console.print(f"[bold red]Erro de Criptografia:[/bold red] {escape(str(e))}")
            raise SystemExit(1) from e


def handle_verify(args: argparse.Namespace) -> None:
    """Confere a integridade de um arquivo .enc sem descriptografá-lo."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions, iam.audit)

    with _logged_in(iam, args.username) as session:
        try:
            result = crypto_service.verify_file(session, args.path)
        except FileCryptofileError as e:
            logger.error(f"Falha na verificação de integridade: {e}")
            console.print(f"[bold red]Erro:[/bold red] {escape(str(e))}")
            raise SystemExit(1) from e

        success_msg = (
            f"[green]'{escape(result.original_name)}' está ÍNTEGRO:[/green] a tag AES-GCM "
            f"e o hash SHA-256 conferem com o registrado.\n\n"
            f"[bold]SHA-256:[/bold] {result.sha256_hash}\n"
            f"[dim]O arquivo cifrado permanece em {escape(result.encrypted_path)}.[/dim]"
        )
        console.print(
            Panel(
                success_msg,
                title="[bold green]Verificação de Integridade[/bold green]",
                expand=False,
            )
        )


def handle_update(args: argparse.Namespace) -> None:
    """Substitui o conteúdo de um arquivo .enc existente (exige MODIFY)."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions, iam.audit)

    with _logged_in(iam, args.username) as session:
        try:
            out_path = crypto_service.update_file(session, args.path, args.content)
            console.print(
                f"[green]Arquivo modificado:[/green] novo conteúdo gravado em "
                f"[bold]{escape(out_path)}[/bold]."
            )
        except (FileCryptofileError, IAMError) as e:
            console.print(f"[bold red]Erro:[/bold red] {escape(str(e))}")
            raise SystemExit(1) from e


def handle_share(args: argparse.Namespace) -> None:
    """Concede a outro usuário acesso ao arquivo .enc do usuário da sessão."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions, iam.audit)

    with _logged_in(iam, args.username) as session:
        try:
            crypto_service.share_file(
                session, args.path, args.target, Permission(args.permission.upper())
            )
            console.print(
                f"[green]Acesso concedido:[/green] '{args.target}' agora tem permissão "
                f"[bold]{args.permission.upper()}[/bold] sobre '{escape(args.path)}'."
            )
        except (FileCryptofileError, IAMError) as e:
            console.print(f"[bold red]Erro:[/bold red] {escape(str(e))}")
            raise SystemExit(1) from e


def handle_revoke(args: argparse.Namespace) -> None:
    """Revoga o acesso de outro usuário ao arquivo .enc do usuário da sessão."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions, iam.audit)

    with _logged_in(iam, args.username) as session:
        try:
            crypto_service.revoke_share(session, args.path, args.target)
            console.print(
                f"[green]Acesso revogado:[/green] '{args.target}' não tem mais permissão "
                f"sobre '{escape(args.path)}'. A chave do arquivo (DEK) foi trocada."
            )
        except (FileCryptofileError, IAMError) as e:
            console.print(f"[bold red]Erro:[/bold red] {escape(str(e))}")
            raise SystemExit(1) from e


def handle_list(args: argparse.Namespace) -> None:
    """Lista os arquivos acessíveis pelo usuário da sessão (03.2)."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions, iam.audit)

    with _logged_in(iam, args.username) as session:
        try:
            files = crypto_service.list_files(session)
        except FileCryptofileError as e:
            console.print(f"[bold red]Erro:[/bold red] {escape(str(e))}")
            raise SystemExit(1) from e

    if not files:
        console.print(
            f"[yellow]Nenhum arquivo acessível por '{session.username}'.[/yellow] "
            f"Cifre um com [bold]encrypt[/bold] ou receba acesso via [bold]share[/bold]."
        )
        return

    table = Table(title=f"Arquivos acessíveis por '{session.username}'")
    table.add_column("Arquivo")
    table.add_column("Caminho .enc", style="dim", overflow="fold")
    table.add_column("Dono")
    table.add_column("Acesso")
    for file in files:
        owner = (
            f"{file.owner_username} [dim](você)[/dim]"
            if file.is_owner
            else file.owner_username
        )
        table.add_row(
            escape(file.original_name),
            escape(file.encrypted_path),
            owner,
            f"[green]{file.permission}[/green]",
        )
    console.print(table)
    console.print(f"[green]{len(files)} arquivo(s) listado(s).[/green]")


def register_file_crypography_commands(subparsers) -> None:
    parser_keys = subparsers.add_parser(
        "genkeys", help="Gera par de chaves RSA", formatter_class=RichHelpFormatter
    )
    parser_keys.add_argument("-u", "--username", type=validate_str, required=True)
    parser_keys.add_argument(
        "--force",
        action="store_true",
        help="Substitui um par existente (arquivos recebidos via RSA ficam ilegíveis)",
    )
    parser_keys.set_defaults(func=handle_generate_keys)

    parser_enc = subparsers.add_parser(
        "encrypt", help="Encripta um ficheiro", formatter_class=RichHelpFormatter
    )
    parser_enc.add_argument(
        "-p",
        "--path",
        type=validate_path,
        required=True,
        help="Caminho do arquivo a encriptar",
    )
    parser_enc.add_argument("-u", "--username", type=validate_str, required=True)
    parser_enc.add_argument(
        "-t",
        "--target",
        type=validate_str,
        required=False,
        help="Username do usuário que poderá descriptografar",
    )
    parser_enc.add_argument(
        "-o",
        "--output",
        type=str,
        required=False,
        help="Caminho onde será salvo (Padrão: workspace/<user>/)",
    )
    parser_enc.set_defaults(func=handle_encrypt)

    parser_dec = subparsers.add_parser(
        "decrypt", help="Desencripta um arquivo", formatter_class=RichHelpFormatter
    )
    parser_dec.add_argument(
        "-p",
        "--path",
        type=str,
        required=True,
        help="Caminho do arquivo encriptado (.enc)",
    )
    parser_dec.add_argument("-u", "--username", type=validate_str, required=True)
    parser_dec.add_argument(
        "-o",
        "--output",
        type=str,
        required=False,
        help="Caminho onde será salvo (Padrão: workspace/<user>/)",
    )
    parser_dec.set_defaults(func=handle_decrypt)

    parser_share = subparsers.add_parser(
        "share",
        help="Concede a outro usuário acesso a um ficheiro .enc",
        formatter_class=RichHelpFormatter,
    )
    parser_share.add_argument(
        "-p",
        "--path",
        type=str,
        required=True,
        help="Caminho do arquivo encriptado (.enc)",
    )
    parser_share.add_argument("-u", "--username", type=validate_str, required=True)
    parser_share.add_argument(
        "-t",
        "--target",
        type=validate_str,
        required=True,
        help="Username que receberá o acesso",
    )
    parser_share.add_argument(
        "--permission",
        choices=["read", "modify"],
        default="read",
        help="Nível de permissão concedido (padrão: read)",
    )
    parser_share.set_defaults(func=handle_share)

    parser_update = subparsers.add_parser(
        "update",
        help="Substitui o conteúdo de um arquivo .enc existente",
        formatter_class=RichHelpFormatter,
    )
    parser_update.add_argument(
        "-p",
        "--path",
        type=str,
        required=True,
        help="Caminho do arquivo encriptado (.enc)",
    )
    parser_update.add_argument(
        "-c",
        "--content",
        type=validate_path,
        required=True,
        help="Caminho do arquivo com o novo conteúdo",
    )
    parser_update.add_argument("-u", "--username", type=validate_str, required=True)
    parser_update.set_defaults(func=handle_update)

    parser_revoke = subparsers.add_parser(
        "revoke",
        help="Revoga o acesso de um usuário a um ficheiro .enc",
        formatter_class=RichHelpFormatter,
    )
    parser_revoke.add_argument(
        "-p",
        "--path",
        type=str,
        required=True,
        help="Caminho do arquivo encriptado (.enc)",
    )
    parser_revoke.add_argument("-u", "--username", type=validate_str, required=True)
    parser_revoke.add_argument(
        "-t",
        "--target",
        type=validate_str,
        required=True,
        help="Username que perderá o acesso",
    )
    parser_revoke.set_defaults(func=handle_revoke)

    parser_list = subparsers.add_parser(
        "file-list",
        help="Lista os arquivos aos quais o usuário tem acesso",
        formatter_class=RichHelpFormatter,
    )
    parser_list.add_argument("-u", "--username", type=validate_str, required=True)
    parser_list.set_defaults(func=handle_list)

    parser_verify = subparsers.add_parser(
        "verify",
        help="Verifica a integridade de um ficheiro .enc sem alterá-lo",
        formatter_class=RichHelpFormatter,
    )
    parser_verify.add_argument(
        "-p",
        "--path",
        type=str,
        required=True,
        help="Caminho do arquivo encriptado (.enc)",
    )
    parser_verify.add_argument("-u", "--username", type=validate_str, required=True)
    parser_verify.set_defaults(func=handle_verify)
