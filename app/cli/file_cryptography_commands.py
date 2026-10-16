import argparse
import logging
import os

from rich.console import Console
from rich.panel import Panel
from rich_argparse import RichHelpFormatter

from app.cli.iam_commands import _logged_in, _service
from app.core.database import SessionLocal
from app.exceptions.file_cryptography_exceptions import (
    FileCryptofileError,
)
from app.service.file_cryptography_service import FileCryptoService
from app.utils.validator import abs_path, validate_path, validate_str

logger = logging.getLogger(__name__)
console = Console()


def get_user_workspace(username: str) -> str:
    """Cria e retorna o caminho de uma pasta isolada para o usuário."""
    path = abs_path(f"./workspace/{username}")
    os.makedirs(path, exist_ok=True)
    return path


def handle_generate_keys(args: argparse.Namespace) -> None:
    """Gera o par de chaves, salva a privada na pasta do usuário e a pública no banco."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions)
    with _logged_in(iam, args.username) as session:
        try:
            priv_path = crypto_service.generate_keys(session)

            success_msg = (
                f"[green]Chaves geradas com sucesso para '{session.username}'![/green]\n\n"
                f"[bold yellow]- {priv_path}[/bold yellow] (MANTENHA SEGURA)\n"
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
            console.print(f"[bold red]Erro inesperado:[/bold red] {e}")


def handle_encrypt(args: argparse.Namespace) -> None:
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions)

    with _logged_in(iam, args.username) as session:
        try:
            out_path = crypto_service.encrypt_file(
                session, args.path, args.target, args.output
            )
            console.print(f"[green]Sucesso! Salvo em: {out_path}[/green]")
        except FileCryptofileError as e:
            console.print(f"[bold red]Erro:[/bold red] {e}")


def handle_decrypt(args: argparse.Namespace) -> None:
    """Processa a desencriptação do arquivo via CLI."""
    iam = _service()
    crypto_service = FileCryptoService(SessionLocal, iam.sessions)

    with _logged_in(iam, args.username) as session:
        try:
            out_path = crypto_service.decrypt_file(session, args.path, args.output)

            console.print(
                Panel(
                    f"[green]Arquivo desencriptado com sucesso:[/green]\n[bold]{out_path}[/bold]",
                    title="[bold green]Desencriptação Concluída[/bold green]",
                    expand=False,
                )
            )
        except FileCryptofileError as e:
            logger.error(f"Erro interno de criptografia: {e}")
            console.print(f"[bold red]Erro de Criptografia:[/bold red] {e}")


def register_file_crypography_commands(subparsers) -> None:
    parser_keys = subparsers.add_parser(
        "genkeys", help="Gera par de chaves RSA", formatter_class=RichHelpFormatter
    )
    parser_keys.add_argument("-u", "--username", type=validate_str, required=True)
    parser_keys.set_defaults(func=handle_generate_keys)

    parser_enc = subparsers.add_parser(
        "encrypt", help="Encripta um ficheiro", formatter_class=RichHelpFormatter
    )
    parser_enc.add_argument(
        "-p",
        "--path",
        type=validate_path,
        required=True,
        help="Caminho do arquivo (PDF)",
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
