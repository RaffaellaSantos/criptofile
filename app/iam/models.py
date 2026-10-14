import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Role(StrEnum):
    """Papéis do RBAC."""

    ADMIN = "ADMIN"
    USER = "USER"


class User(Base):
    """Tabela de usuários (seção 4.3 da especificação)."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('ADMIN', 'USER')", name="ck_users_role"),
    )

    user_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    # Hash Argon2id (hex) da senha. A senha nunca é armazenada em texto claro.
    password_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Salt aleatório de 16 bytes (hex), único por usuário.
    salt: Mapped[str] = mapped_column(String(32), nullable=False)
    role: Mapped[str] = mapped_column(String(5), nullable=False, default=Role.USER.value)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )

    def __repr__(self) -> str:
        return f"User(username={self.username!r}, role={self.role!r})"
