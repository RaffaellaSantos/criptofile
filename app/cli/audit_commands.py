import argparse
import logging
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from app.cli.iam_commands import _logged_in, _service
from app.model.audit_log_model import AuditAction, AuditLog
from app.service.audit_service import AUDIT_TRUNCATED
from app.utils.validator import validate_str

logger = logging.getLogger(__name__)
console = Console()

DETAILS_MAX = 60


def _action(value: str) -> str:
    try:
        return AuditAction(value.upper()).value
    except ValueError as err:
        options = "|".join(a.value for a in AuditAction)
        raise argparse.ArgumentTypeError(f"ação deve ser uma de: {options}") from err


def cmd_audit_report(args: argparse.Namespace) -> None:
    if args.output and not args.export:
        console.print("[red]Erro:[/red] -o/--output requer --export {json,cef}.")
        raise SystemExit(2)

    service = _service()
    with _logged_in(service, args.as_user) as session:
        # A verificação antecede a exibição: registros adulterados são
        # sinalizados antes que o relatório seja apresentado.
        tampered = service.audit.verify_integrity()
        events = service.audit_report(
            session, username=args.user, action_type=args.action
        )

    if tampered:
        events_hit = [t for t in tampered if t != AUDIT_TRUNCATED]
        lines = []
        if events_hit:
            lines.append(
                f"[bold red]ATENÇÃO:[/bold red] {len(events_hit)} registro(s) do log foram "
                f"ADULTERADOS ou tiveram o evento anterior REMOVIDO.\n"
                f"Eventos comprometidos: {', '.join(t[:8] for t in events_hit)}"
            )
        if AUDIT_TRUNCATED in tampered:
            lines.append(
                "[bold red]ATENÇÃO:[/bold red] os eventos mais recentes do log foram "
                "REMOVIDOS (a ponta registrada da cadeia não existe mais no banco)."
            )
        console.print(
            Panel(
                "\n\n".join(lines),
                title="[bold red]Integridade do Log[/bold red]",
                expand=False,
            )
        )

    if args.export:
        content = _export_content(service, events, args.export)
        _write_export(content, args.output)
        return

    title = "Relatório de Logs de Auditoria"
    if args.user:
        title += f" — usuário: {escape(args.user)}"
    if args.action:
        title += f" — ação: {escape(args.action)}"

    table = Table(title=title)
    table.add_column("Data/Hora (UTC)")
    table.add_column("Usuário")
    table.add_column("Ação")
    table.add_column("Recurso")
    table.add_column("Status")
    table.add_column("Origem")
    table.add_column("Detalhes", style="dim", overflow="fold")
    # Campos do log vêm de entradas do usuário (nomes de arquivo, usernames
    # tentados no login): são escapados para que marcação do Rich embutida
    # neles não falsifique ou oculte linhas do relatório.
    for event in events:
        table.add_row(
            f"{event.timestamp:%Y-%m-%d %H:%M:%S}",
            escape(event.username or "-"),
            escape(event.action_type),
            escape(event.resource_id or "-"),
            _status(event),
            escape(f"{event.ip_address}@{event.hostname}") if event.hostname else "-",
            escape(event.details or "-"),
        )
    console.print(table)
    console.print(f"[green]{len(events)} evento(s) listado(s).[/green]")


def _export_content(service, events, fmt: str) -> str:
    """Serializa os eventos no formato de exportação pedido (JSON ou CEF)."""
    # export_json/export_cef vivem no AuditService (service.audit), não no IAMService.
    if fmt == "json":
        return service.audit.export_json(events)
    return service.audit.export_cef(events)


def _write_export(content: str, output: str | None) -> None:
    if output:
        path = Path(output)
        if path.exists() and path.is_dir():
            console.print(f"[red]Erro:[/red] '{escape(str(path))}' é um diretório.")
            raise SystemExit(2)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        console.print(f"[green]Relatório exportado para '{escape(str(path))}'.[/green]")
    else:
        # Saída crua: o console do Rich quebraria linhas longas e interpretaria
        # trechos entre colchetes como marcação, corrompendo JSON/CEF em pipes.
        print(content)


def _status(event: AuditLog) -> str:
    if event.status == "SUCCESS":
        return "[green]SUCCESS[/green]"
    return "[red]FAIL[/red]"


def register_audit_commands(subparsers) -> None:
    """Registra os subcomandos do relatório de auditoria no parser principal."""
    p = subparsers.add_parser(
        "audit-report",
        help="Exibe o relatório completo de logs do sistema (apenas ADMIN).",
    )
    p.add_argument(
        "--as",
        dest="as_user",
        type=validate_str,
        required=True,
        metavar="ADMIN",
        help="Username do ADMIN que executa a operação.",
    )
    p.add_argument(
        "-u",
        "--user",
        type=validate_str,
        default=None,
        metavar="USER",
        help="Filtrar o relatório por usuário.",
    )
    p.add_argument(
        "-a",
        "--action",
        type=_action,
        default=None,
        metavar="{LOGIN,FILE_ENCRYPT,...}",
        help="Filtrar o relatório por tipo de ação.",
    )
    p.add_argument(
        "--export",
        choices=("json", "cef"),
        default=None,
        metavar="{json,cef}",
        help="Exportar o relatório no formato indicado em vez de exibir a tabela.",
    )
    p.add_argument(
        "-o",
        "--output",
        type=validate_str,
        default=None,
        metavar="FILE",
        help="Gravar a exportação no arquivo indicado (requer --export).",
    )
    p.set_defaults(func=cmd_audit_report)
