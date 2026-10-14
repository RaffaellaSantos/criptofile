import argparse
import logging
import sys
import textwrap

import rich_argparse
from sqlalchemy.exc import OperationalError

from app.cli.iam_commands import register_iam_commands
from app.iam import IAMError
from app.utils.validator import abs_path, define_name, validate_path

logger = logging.getLogger(__name__)

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
    
    print("\n[+] Informações Iniciais do Arquivo [+]")
    print(f"Caminho recebido : {path_obj}")
    print(f"Nome do arquivo  : {define_name(path_obj)}")
    print(f"Caminho absoluto : {abs_path(path_obj)}")
    print("----------------------------------------\n")

def build_parser() -> None:
    """Construi os argumentos a serem passados."""
    parser = ArgumentParserPT(prog="criptofile", description=textwrap.dedent("""
        Projeto: CriptoFile CLI
        Descrição: Ferramenta de linha de comando (CLI), capaz de receber o caminho de um arquivo, criptografar o arquivo, salvar a chave e verificar a integridade do arquivos.
        Autores: Adriana Raffaella | Davi Aguiar | Guilherme Moraes | Henrique Furtado
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
    formatter_class=rich_argparse.RawDescriptionRichHelpFormatter,
    add_help=False
    )

    # Caminho do arquivo
    parser.add_argument(
        '-p', 
        '--path', 
        type=validate_path, 
        help="Caminho para o arquivo PDF.", 
        metavar="pdf_path"
    )

    parser.set_defaults(func=print_file_info)

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