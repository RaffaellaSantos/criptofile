import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Permission(StrEnum):
    """Permissões de arquivo (Requisitos 03.2 e 04.2)."""

    READ = "READ"
    MODIFY = "MODIFY"


class WrapAlg(StrEnum):
    """Como a DEK do arquivo foi envolvida (cifrada) para o usuário autorizado."""

    # DEK cifrada com AES-GCM na KEK própria (o dono, durante a sessão).
    KEK = "KEK"
    # DEK cifrada com RSA-OAEP usando a chave pública do usuário alvo.
    RSA = "RSA"


class File(Base):
    """Tabela de metadados de arquivos (seção 2.2 e 3 da especificação).

    Armazena o hash SHA-256 do conteúdo original, calculado antes da cifragem,
    usado para validar a integridade em qualquer operação de leitura (04.3).
    """

    __tablename__ = "files"

    file_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id"), nullable=False
    )
    # Nome de exibição do arquivo original; usado como nome-padrão de saída
    # na descriptografia.
    original_name: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA-256 (hex, 64 caracteres) do arquivo original antes da cifragem.
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Caminho onde o .enc foi gravado (informativo; o file_id embutido no
    # arquivo mantém a referência mesmo que ele seja movido).
    encrypted_path: Mapped[str] = mapped_column(Text, nullable=False)
    # Controle de concorrência otimista: toda alteração (update, share,
    # revoke) incrementa a versão com compare-and-swap; uma operação que leu
    # uma versão desatualizada é recusada em vez de sobrescrever a outra.
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    def __repr__(self) -> str:
        return (
            f"File(file_id={self.file_id!r}, original_name={self.original_name!r}, "
            f"sha256_hash={self.sha256_hash!r})"
        )


class FilePermission(Base):
    """Tabela de permissões e DEKs envolvidas (Envelope Encryption, 03.2/04.2).

    Cada linha concede a um usuário o acesso a um arquivo. A DEK (AES-256)
    única do arquivo é entregue a cada usuário autorizado cifrada com a sua
    chave: a KEK própria da sessão (wrap_alg='KEK') ou a chave pública RSA
    quando o alvo não tem KEK conhecido (wrap_alg='RSA').
    """

    __tablename__ = "file_permissions"
    __table_args__ = (
        CheckConstraint(
            "permission IN ('READ', 'MODIFY')", name="ck_file_permissions_permission"
        ),
        CheckConstraint(
            "wrap_alg IN ('KEK', 'RSA')", name="ck_file_permissions_wrap_alg"
        ),
    )

    file_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("files.file_id"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id"), primary_key=True
    )
    permission: Mapped[str] = mapped_column(
        String(8), nullable=False, default=Permission.MODIFY.value
    )
    # DEK (32 bytes) cifrada conforme wrap_alg.
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_alg: Mapped[str] = mapped_column(
        String(8), nullable=False, default=WrapAlg.KEK.value
    )
    # user_id de quem concedeu o acesso (nulo quando o próprio usuário cifra
    # o arquivo para si).
    granted_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    def __repr__(self) -> str:
        return (
            f"FilePermission(file_id={self.file_id!r}, user_id={self.user_id!r}, "
            f"permission={self.permission!r}, wrap_alg={self.wrap_alg!r})"
        )
