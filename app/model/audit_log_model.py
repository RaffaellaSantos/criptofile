import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditAction(StrEnum):
    """Ações auditáveis do sistema (Requisitos 05.1, 05.2)."""

    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    USER_CREATE = "USER_CREATE"
    USER_ROLE_CHANGE = "USER_ROLE_CHANGE"
    # Listagem de usuários (apenas ADMIN); tentativas negadas são auditadas.
    USER_LIST = "USER_LIST"
    KEYS_GENERATE = "KEYS_GENERATE"
    FILE_ENCRYPT = "FILE_ENCRYPT"
    FILE_DECRYPT = "FILE_DECRYPT"
    FILE_SHARE = "FILE_SHARE"
    FILE_REVOKE = "FILE_REVOKE"
    FILE_MODIFY = "FILE_MODIFY"
    # Consulta de metadados/listagem; a verificação de integridade tem ação própria.
    FILE_ACCESS = "FILE_ACCESS"
    FILE_VERIFY = "FILE_VERIFY"
    SECURITY_ALERT = "SECURITY_ALERT"
    INTEGRITY_VIOLATION = "INTEGRITY_VIOLATION"
    AUDIT_REPORT = "AUDIT_REPORT"
    # Conclusão de uma gravação interrompida (queda do processo).
    RECOVERY = "RECOVERY"


class AuditStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAIL = "FAIL"


class AuditLog(Base):
    """Tabela de log de auditoria (seção 2.3 da especificação).

    Cada registro é assinado com HMAC-SHA256 (campo signature_hmac) para
    garantir que logs não possam ser adulterados sem detecção.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint("status IN ('SUCCESS', 'FAIL')", name="ck_audit_log_status"),
        Index("ix_audit_log_timestamp", "timestamp"),
        UniqueConstraint("prev_hmac", name="uq_audit_log_prev_hmac"),
    )

    event_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    # Pode ser nulo: eventos de LOGIN FAIL de usuários inexistentes não têm user_id.
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Username do usuário da ação (ou alvo dela), útil quando o registro não existe mais
    # ou nunca existiu (ex.: tentativa de login com username inexistente).
    username: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Identificador do recurso afetado (ex.: nome de arquivo ou usuário alvo).
    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(7), nullable=False, default=AuditStatus.SUCCESS.value
    )
    # Origem do acesso. Em uma CLI local é sempre localhost, mas o campo segue
    # a especificação para permitir a expansão para acesso remoto.
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Contexto adicional em JSON (ex.: {"reason": "..."}).
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    # HMAC-SHA256 (hex) de todos os campos do registro.
    signature_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    # Encadeamento: assinatura do evento anterior (ou AUDIT_GENESIS no
    # primeiro), coberta pela assinatura deste. Apagar um evento do meio
    # deixa o seguinte apontando para uma assinatura inexistente. UNIQUE
    # impede bifurcar a cadeia em gravações concorrentes. Nulo apenas em
    # registros anteriores ao encadeamento.
    prev_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)

    def __repr__(self) -> str:
        return (
            f"AuditLog(action_type={self.action_type!r}, "
            f"username={self.username!r}, status={self.status!r})"
        )
