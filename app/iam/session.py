"""Sessão local mantida apenas em memória (seção 4.2.1).

Após a autenticação é gerado um token temporário aleatório. O registro de
sessões vive somente no processo da CLI e desaparece ao término da execução.
"""

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.iam.exceptions import AuthenticationError, AuthorizationError
from app.iam.models import Role

SESSION_TTL = timedelta(minutes=15)


def _wipe(buffer: bytearray) -> None:
    for i in range(len(buffer)):
        buffer[i] = 0


@dataclass
class Session:
    token: str
    user_id: str
    username: str
    role: Role
    expires_at: datetime
    # Chave mestre do usuário (KEK); nunca persistida nem exibida.
    kek: bytearray = field(repr=False)

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    def is_expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at


class SessionManager:
    """Registro em memória das sessões ativas."""

    def __init__(self, ttl: timedelta = SESSION_TTL):
        self._ttl = ttl
        self._sessions: dict[str, Session] = {}

    def create(self, user_id: str, username: str, role: Role, kek: bytes) -> Session:
        session = Session(
            token=secrets.token_urlsafe(32),
            user_id=user_id,
            username=username,
            role=Role(role),
            expires_at=datetime.now(UTC) + self._ttl,
            kek=bytearray(kek),
        )
        self._sessions[session.token] = session
        return session

    def validate(self, session: Session | None) -> Session:
        """Garante que a sessão foi emitida por este gerenciador e está ativa."""
        if session is None:
            raise AuthenticationError("Sessão inexistente. Faça login.")

        active = self._sessions.get(session.token)
        if active is None or not secrets.compare_digest(active.token, session.token):
            raise AuthenticationError("Sessão inválida. Faça login novamente.")

        if active.is_expired():
            self.revoke(active)
            raise AuthenticationError("Sessão expirada. Faça login novamente.")

        return active

    def require_role(self, session: Session | None, role: Role) -> Session:
        active = self.validate(session)
        if active.role != role:
            raise AuthorizationError(
                f"Operação permitida apenas para usuários {role.value}."
            )
        return active

    def revoke(self, session: Session) -> None:
        """Encerra a sessão e sobrescreve a KEK em memória."""
        removed = self._sessions.pop(session.token, None)
        _wipe(session.kek)
        if removed is not None and removed is not session:
            _wipe(removed.kek)

    def revoke_all(self) -> None:
        for session in list(self._sessions.values()):
            self.revoke(session)
