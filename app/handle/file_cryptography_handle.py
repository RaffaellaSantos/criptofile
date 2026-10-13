import argparse
import logging
from rich.console import Console
from rich.panel import Panel
from app.utils.validator import abs_path, define_name
from app.utils.cryptography_utils import generate_priv_pub_key, encrypt, decrypt

logger = logging.getLogger(__name__)
console = Console()


def handle_generate_keys(args: argparse.Namespace) -> None:
    """Gera o par de chaves e guarda-as no diretório atual."""
    priv, pub = generate_priv_pub_key()
    
    with open("private.pem", "wb") as f_priv:
        f_priv.write(priv)
    with open("public.pem", "wb") as f_pub:
        f_pub.write(pub)
        
    success_msg = (
        "[green]Chaves geradas com sucesso![/green]\n\n"
        "[bold yellow]- private.pem[/bold yellow] (MANTENHA SEGURA)\n"
        "[bold blue]- public.pem[/bold blue]  (Para ser guardada na base de dados futuramente)"
    )
    
    console.print(Panel(success_msg, title="[bold green]Geração de Chaves[/bold green]", expand=False))

def handle_encrypt(args: argparse.Namespace) -> None:
    """Processa a encriptação do arquivo via CLI."""
    file_path_str = abs_path(args.path)
    try:
        with open(args.key, "rb") as f_key:
            pub_key = f_key.read()
        out = encrypt(file_path_str, pub_key)
        
        console.print(Panel(f"[green]Arquivo encriptado com sucesso:[/green]\n[bold]{out}[/bold]", title="[bold green]Encriptação Concluída[/bold green]", expand=False))
    except Exception as e:
        logger.error(f"Erro na encriptação: {e}")
        console.print(f"[bold red]Erro na encriptação:[/bold red] {e}")

def handle_decrypt(args: argparse.Namespace) -> None:
    """Processa a desencriptação do arquivo via CLI."""
    file_path_str = args.path if isinstance(args.path, str) else abs_path(args.path)
    try:
        with open(args.key, "rb") as f_key:
            priv_key = f_key.read()
        out = decrypt(file_path_str, priv_key)
        
        console.print(Panel(f"[green]Arquivo desencriptado com sucesso:[/green]\n[bold]{out}[/bold]", title="[bold green]Desencriptação Concluída[/bold green]", expand=False))
    except Exception as e:
        logger.error(f"Erro na desencriptação ou violação de integridade: {e}")
        console.print(f"[bold red]Erro na desencriptação ou integridade comprometida:[/bold red] {e}")
