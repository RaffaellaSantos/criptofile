import argparse
import logging
import sys
import textwrap

from alembic.util import CommandError
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich_argparse import RawDescriptionRichHelpFormatter, RichHelpFormatter
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.cli.audit_commands import register_audit_commands
from app.cli.file_cryptography_commands import register_file_crypography_commands
from app.cli.iam_commands import register_iam_commands
from app.exceptions.audit_exceptions import AuditError
from app.exceptions.file_cryptography_exceptions import FileCryptofileError
from app.exceptions.iam_exceptions import IAMError
from app.utils.validator import abs_path, define_name, validate_path

logger = logging.getLogger(__name__)
console = Console()


class ArgumentParserPT(argparse.ArgumentParser):
    """Classe personalizada para traduzir mensagens de erro para português."""

    def error(self, message):
        if "expected one argument" in message:
            message = message.replace(
                "expected one argument", "esperava um caminho de arquivo"
            )

        sys.stderr.write(f"ERRO: {message}\n\n")

        self.exit(2)


def print_file_info(args: argparse.Namespace) -> None:
    """Imprime as informações coletadas do arquivo fornecido."""
    path_obj = args.path

    info_text = (
        f"[bold cyan]Caminho recebido :[/bold cyan] {escape(str(path_obj))}\n"
        f"[bold cyan]Nome do arquivo  :[/bold cyan] {escape(define_name(path_obj))}\n"
        f"[bold cyan]Caminho absoluto :[/bold cyan] {escape(abs_path(path_obj))}"
    )

    console.print(
        Panel(
            info_text,
            title="[bold green]Informações Iniciais do Arquivo[/bold green]",
            expand=False,
        )
    )


def build_parser():
    """Constroi os argumentos a serem passados."""
    parser = ArgumentParserPT(
        prog="criptofile",
        description=textwrap.dedent("""
            [bold green]Projeto:[/bold green] CriptoFile CLI
            [bold green]Descrição:[/bold green] Ferramenta de linha de comando (CLI) capaz de receber um arquivo, criptografar, salvar chaves e verificar integridade.
            [bold green]Autores:[/bold green] Adriana Raffaella | Davi Aguiar | Guilherme Moraes | Henrique Furtado
        """),
        epilog=textwrap.dedent("""
            [bold green]Exemplos de Uso:[/bold green]

            [bold blue]Gestão de Usuários (IAM):[/bold blue]
              criptofile admin-init -u admin                    [dim]# Cria o primeiro ADMIN[/dim]
              criptofile login -u alice                         [dim]# Valida as credenciais[/dim]
              criptofile user-add --as admin -u alice -r USER   [dim]# Cadastra novo usuário[/dim]
              criptofile user-role --as admin -u alice -r ADMIN [dim]# Altera o papel de um usuário[/dim]
              criptofile user-list --as admin                   [dim]# Lista os usuários cadastrados[/dim]
              criptofile audit-report --as admin                [dim]# Relatório de logs (apenas ADMIN)[/dim]

            [bold blue]Criptografia e Arquivos:[/bold blue]
              criptofile genkeys -u alice                       [dim]# Gera o par de chaves RSA na sua pasta[/dim]
              criptofile encrypt -p ./doc.pdf -u alice          [dim]# Encripta um arquivo para você mesmo[/dim]
              criptofile encrypt -p ./doc.pdf -u alice -t bob   [dim]# Encripta para outro usuário ler (bob)[/dim]
              criptofile decrypt -p ./doc.enc -u alice          [dim]# Desencripta um arquivo com a sua chave[/dim]
              criptofile share -p ./doc.enc -u alice -t bob     [dim]# Concede acesso a bob (read ou modify)[/dim]
              criptofile revoke -p ./doc.enc -u alice -t bob    [dim]# Revoga o acesso de bob (só o dono)[/dim]
              criptofile file-list -u alice                     [dim]# Lista arquivos acessíveis por alice[/dim]
              criptofile verify -p ./doc.enc -u alice           [dim]# Confere a integridade sem descriptografar[/dim]
        """),
        formatter_class=RawDescriptionRichHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Comandos disponíveis")

    parser_info = subparsers.add_parser(
        "info",
        help="Exibe as informações iniciais do arquivo",
        formatter_class=RichHelpFormatter,
    )
    parser_info.add_argument(
        "-p",
        "--path",
        type=validate_path,
        required=True,
        help="Caminho para o arquivo.",
        metavar="caminho",
    )
    parser_info.set_defaults(func=print_file_info)

    register_iam_commands(subparsers)
    register_file_crypography_commands(subparsers)
    register_audit_commands(subparsers)

    return parser


def run() -> None:
    """Declara as funções necessárias para construir a aplicação."""
    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Sem subcomando não há args.path: só a ajuda faz sentido.
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if hasattr(args, "func"):
        try:
            args.func(args)
        except IAMError as err:
            logger.error(err)
            sys.exit(1)
        except (FileCryptofileError, OSError) as err:
            # Rede de segurança: falhas de arquivo não tratadas pelo comando
            # encerram com mensagem amigável em vez de traceback.
            logger.error(err)
            sys.exit(1)
        except AuditError as err:
            logger.error(f"Falha na configuração da auditoria: {err}")
            sys.exit(1)
        except EOFError:
            # getpass sem terminal interativo (ex.: `docker compose run` sem -it).
            logger.error(
                "Nenhuma senha informada: o comando precisa de um terminal interativo "
                "(no Docker, use `docker compose run -it`)."
            )
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
        except CommandError as err:
            logger.error(f"Falha ao aplicar as migrações do banco: {err}")
            sys.exit(1)
        except SQLAlchemyError as err:
            logger.debug("Erro de banco de dados.", exc_info=err)
            reason = str(getattr(err, "orig", err)).strip().splitlines()[-1]
            logger.error(
                "Erro no banco de dados. Verifique se as migrações estão atualizadas.\n"
                f"  Motivo: {reason}"
            )
            sys.exit(1)
        except ValueError as err:
            logger.error(err)
            sys.exit(1)
    else:
        parser.print_help()
