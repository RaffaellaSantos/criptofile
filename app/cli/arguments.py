import argparse
import logging
import sys
import textwrap

from rich.console import Console
from rich.panel import Panel
from rich_argparse import RichHelpFormatter
from sqlalchemy.exc import OperationalError

from app.cli.iam_commands import register_iam_commands
from app.handle.file_cryptography_handle import (
    handle_decrypt,
    handle_encrypt,
    handle_generate_keys,
)
from app.iam import IAMError
from app.utils.validator import abs_path, define_name, validate_path

logger = logging.getLogger(__name__)
console = Console()

class ArgumentParserPT(argparse.ArgumentParser):
    """Classe personalizada para traduzir mensagens de erro para português."""
    def error(self, message):
            if "expected one argument" in message:
                message = message.replace(
                    "expected one argument", 
                    "esperava um caminho de arquivo"
                )
            
            sys.stderr.write(f'ERRO: {message}\n\n')

            self.exit(2)

def print_file_info(args: argparse.Namespace) -> None:
    """Imprime as informações coletadas do arquivo fornecido."""
    path_obj = args.path
    
    info_text = (
    f"[bold cyan]Caminho recebido :[/bold cyan] {path_obj}\n"
    f"[bold cyan]Nome do arquivo  :[/bold cyan] {define_name(path_obj)}\n"
    f"[bold cyan]Caminho absoluto :[/bold cyan] {abs_path(path_obj)}"
    )

    console.print(Panel(info_text, title="[bold green]Informações Iniciais do Arquivo[/bold green]", expand=False))
def build_parser() -> None:
    """Constroi os argumentos a serem passados."""
    parser = ArgumentParserPT(prog="criptofile", description=textwrap.dedent("""
        [bold green]Projeto:[/bold green] CriptoFile CLI\n
        [bold green]Descrição:[/bold green] Ferramenta de linha de comando (CLI), capaz de receber o caminho de um arquivo, criptografar o arquivo, salvar a chave e verificar a integridade do arquivos.\n
        [bold green]Autores:[/bold green] Adriana Raffaella | Davi Aguiar | Guilherme Moraes | Henrique Furtado
    """),
        epilog=textwrap.dedent("""
            Exemplos:
                criptofile -p ./teste.pdf "Exibe as informações (temporário)."
                criptofile admin-init -u admin "Cria o primeiro ADMIN."
                criptofile login -u alice "Valida as credenciais."
                criptofile user-add --as admin -u alice -r USER "Cadastra usuário."
                criptofile user-role --as admin -u alice -r ADMIN "Altera o papel."
                criptofile user-list --as admin "Lista os usuários."
        """), 
    formatter_class=RichHelpFormatter,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponíveis")

    parser_keys = subparsers.add_parser(
        "genkeys", help="Gera par de chaves RSA",
        formatter_class=RichHelpFormatter
    )
    parser_keys.set_defaults(func=handle_generate_keys)

    parser_enc = subparsers.add_parser(
            "encrypt", 
            help="Encripta um ficheiro", 
            formatter_class=RichHelpFormatter
    )
    parser_enc.add_argument(
            '-p', 
            '--path', 
            type=validate_path, 
            required=True, 
            help="Caminho do arquivo (PDF)"
    )
    parser_enc.add_argument(
            '-k', 
            '--key', 
            type=str, 
            required=True, 
            help="Caminho da chave pública (.pem)")
    parser_enc.set_defaults(func=handle_encrypt)

    parser_dec = subparsers.add_parser(
            "decrypt", 
            help="Desencripta um arquivo", 
            formatter_class=RichHelpFormatter
    )
    parser_dec.add_argument(
            '-p', 
            '--path', 
            type=str, 
            required=True, 
            help="Caminho do arquivo encriptado (.enc)"
    )
    parser_dec.add_argument(
            '-k', 
            '--key', 
            type=str, 
            required=True, 
            help="Caminho da chave privada (.pem)"
    )
    parser_dec.set_defaults(func=handle_decrypt)
    
    parser_info = subparsers.add_parser(
        "info",
        help="Exibe as informações iniciais do arquivo",
        formatter_class=RichHelpFormatter
    )
    parser_info.add_argument(
        '-p', 
        '--path', 
        type=validate_path, 
        help="Caminho para o arquivo PDF.", 
        metavar="pdf_path"
    )
    parser_info.set_defaults(func=print_file_info)

    subparsers = parser.add_subparsers(dest="command", metavar="comando")
    register_iam_commands(subparsers)

    return parser

def run() -> None:
    """Declara as funções necessárioas para construir a aplicação."""
    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command is None and args.path is None:
        parser.print_help()
        sys.exit(0)

    if hasattr(args, 'func'):
        try:
            args.func(args)
        except IAMError as err:
            logger.error(err)
            sys.exit(1)
        except OperationalError as err:
            logger.debug("Falha de conexão com o banco.", exc_info=err)
            reason = str(getattr(err, "orig", err)).strip().splitlines()[-1]
            logger.error(
                "Não foi possível conectar ao banco de dados. "
                "Verifique se ele está rodando e se o DATABASE_URL do .env está correto.\n"
                f"  Motivo: {reason}"
            )
            sys.exit(1)
        except ValueError as err:
            logger.error(err)
    else:
        parser.print_help()
