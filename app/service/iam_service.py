"""Serviço de Autenticação e Gestão de Acessos (Requisitos 01.1, 01.2, 02.1, 02.2)."""

import logging
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.core import security
from app.core.session import Session, SessionManager
from app.exceptions.iam_exceptions import (
    AccountLockedError,
    AuthenticationError,
    AuthorizationError,
    IAMError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from app.model.audit_log_model import AuditAction, AuditLog, AuditStatus
from app.model.user_model import Role, User
from app.service.audit_service import AuditService

logger = logging.getLogger(__name__)

# Salt fixo usado apenas para gastar o mesmo tempo quando o usuário não existe,
# evitando que a resposta revele quais usernames estão cadastrados.
_DUMMY_SALT = bytes(security.SALT_SIZE)
_DUMMY_HASH = bytes(security.HASH_LEN)

# ------------------------------------------------------------------ #
# Detecção de força bruta (regra obrigatória do projeto)
# ------------------------------------------------------------------ #
# Mais de MAX_LOGIN_FAILURES falhas de login dentro de BRUTE_FORCE_WINDOW
# bloqueia a conta temporariamente. O contador vem da própria tabela
# `audit_log` (assinada com HMAC), então o contador persiste entre execuções
# da CLI e não pode ser adulterado pelo atacante.
BRUTE_FORCE_WINDOW = timedelta(seconds=60)
MAX_LOGIN_FAILURES = 3  # bloqueio a partir da 4ª falha na janela


def _utcnow() -> datetime:
    """Agora em UTC como datetime naive (o SQLite devolve timestamps sem fuso)."""
    return datetime.now(UTC).replace(tzinfo=None)


@dataclass(frozen=True)
class UserInfo:
    """Visão pública de um usuário (sem hash nem salt)."""

    user_id: str
    username: str
    role: Role
    created_at: datetime


def _to_info(user: User) -> UserInfo:
    return UserInfo(user.user_id, user.username, Role(user.role), user.created_at)


class IAMService:
    def __init__(
        self,
        session_factory: Callable[[], DBSession],
        session_manager: SessionManager | None = None,
        audit_service: AuditService | None = None,
    ):
        self._db = session_factory
        self.sessions = session_manager or SessionManager()
        self.audit = audit_service or AuditService(session_factory)

    # ------------------------------------------------------------------ #
    # Autenticação (01.2) + força bruta (05.1)
    # ------------------------------------------------------------------ #
    def authenticate(self, username: str, password: str) -> Session:
        """Valida as credenciais e abre uma sessão em memória."""
        username = username.strip()
        with self._db() as db:
            user = db.scalar(select(User).where(User.username == username))
            if user is not None:
                failures = self._consecutive_failures(db, user.username, _utcnow())

        if user is None:
            security.verify_password(password, _DUMMY_SALT, _DUMMY_HASH)
            logger.warning("LOGIN FAIL: usuário '%s' inexistente.", username)
            self.audit.record(
                AuditAction.LOGIN,
                username=username,
                status=AuditStatus.FAIL,
                details={"reason": "usuário inexistente"},
            )
            raise AuthenticationError("Usuário ou senha inválidos.")

        if len(failures) > MAX_LOGIN_FAILURES:
            # O bloqueio termina quando a falha mais antiga do grupo bloqueador
            # (a 4ª mais recente) sai da janela de 60s.
            unlock_in = max(
                1,
                math.ceil(
                    (failures[MAX_LOGIN_FAILURES] + BRUTE_FORCE_WINDOW - _utcnow()).total_seconds()
                ),
            )
            logger.error(
                "LOGIN BLOCKED: '%s' bloqueada por força bruta (%d falhas em %ds).",
                user.username, len(failures), BRUTE_FORCE_WINDOW.total_seconds(),
            )
            raise AccountLockedError(
                "Conta temporariamente bloqueada por excesso de falhas de login. "
                f"Tente novamente em ~{unlock_in}s."
            )

        kek = security.verify_password(
            password, bytes.fromhex(user.salt), bytes.fromhex(user.password_hash)
        )
        if kek is None:
            logger.warning("LOGIN FAIL: senha incorreta para '%s'.", username)
            self.audit.record(
                AuditAction.LOGIN,
                user_id=user.user_id,
                username=user.username,
                status=AuditStatus.FAIL,
                details={"reason": "senha incorreta"},
            )
            self._check_brute_force(user)
            raise AuthenticationError("Usuário ou senha inválidos.")

        logger.info("LOGIN SUCCESS: '%s' (%s).", user.username, user.role)
        self.audit.record(
            AuditAction.LOGIN, user_id=user.user_id, username=user.username
        )
        return self.sessions.create(user.user_id, user.username, Role(user.role), kek)

    def _consecutive_failures(
        self, db: DBSession, username: str, now: datetime
    ) -> list[datetime]:
        """Timestamps (mais recente primeiro) das falhas de login consecutivas
        para o usuário dentro de `BRUTE_FORCE_WINDOW`.

        Um LOGIN SUCCESS dentro da janela zera o contador ("falhas
        consecutivas"), pois é buscado junto e interrompe a contagem.
        """
        events = db.scalars(
            select(AuditLog)
            .where(
                AuditLog.username == username,
                AuditLog.action_type == AuditAction.LOGIN.value,
                AuditLog.status.in_(
                    [AuditStatus.FAIL.value, AuditStatus.SUCCESS.value]
                ),
                AuditLog.timestamp > now - BRUTE_FORCE_WINDOW,
            )
            .order_by(AuditLog.timestamp.desc())
        ).all()
        failures: list[datetime] = []
        for event in events:
            if event.status == AuditStatus.SUCCESS.value:
                break
            failures.append(event.timestamp)
        return failures

    def _check_brute_force(self, user: User) -> None:
        """Após uma falha de login, emite `SECURITY_ALERT` quando o limite é
        ultrapassado (mais de MAX_LOGIN_FAILURES falhas na janela)."""
        with self._db() as db:
            failures = self._consecutive_failures(db, user.username, _utcnow())
        if len(failures) <= MAX_LOGIN_FAILURES:
            return
        logger.error(
            "SECURITY ALERT: força bruta em '%s' (%d falhas em %ds).",
            user.username, len(failures), BRUTE_FORCE_WINDOW.total_seconds(),
        )
        self.audit.record(
            AuditAction.SECURITY_ALERT,
            user_id=user.user_id,
            username=user.username,
            resource_id=user.username,
            status=AuditStatus.FAIL,
            details={
                "reason": "forca_bruta",
                "failures": len(failures),
                "window_seconds": int(BRUTE_FORCE_WINDOW.total_seconds()),
            },
        )

    def logout(self, session: Session) -> None:
        self.sessions.revoke(session)
        logger.info("LOGOUT: '%s'.", session.username)
        self.audit.record(
            AuditAction.LOGOUT, user_id=session.user_id, username=session.username
        )

    # ------------------------------------------------------------------ #
    # Cadastro (01.1 + 02.1)
    # ------------------------------------------------------------------ #
    def has_users(self) -> bool:
        with self._db() as db:
            return bool(db.scalar(select(func.count()).select_from(User)))

    def bootstrap_admin(self, username: str, password: str) -> UserInfo:
        """Cria o primeiro ADMIN. Só é permitido quando não há usuários."""
        if self.has_users():
            raise IAMError(
                "O sistema já possui usuários. Novos cadastros exigem um ADMIN."
            )
        info = self._create_user(username, password, Role.ADMIN)
        logger.info("BOOTSTRAP: ADMIN inicial '%s' criado.", info.username)
        self.audit.record(
            AuditAction.USER_CREATE,
            user_id=info.user_id,
            username=info.username,
            resource_id=info.username,
            details={"role": Role.ADMIN.value, "by": "bootstrap"},
        )
        return info

    def register_user(
        self, session: Session, username: str, password: str, role: Role = Role.USER
    ) -> UserInfo:
        """Cadastra um novo usuário. Apenas ADMIN (Requisito 02.1)."""
        admin = self.sessions.require_role(session, Role.ADMIN)
        info = self._create_user(username, password, Role(role))
        logger.info(
            "USER_CREATE: '%s' (%s) criado por '%s'.",
            info.username, info.role, admin.username,
        )
        self.audit.record(
            AuditAction.USER_CREATE,
            user_id=info.user_id,
            username=info.username,
            resource_id=info.username,
            details={"role": info.role.value, "by": admin.username},
        )
        return info

    def _create_user(self, username: str, password: str, role: Role) -> UserInfo:
        username = security.validate_username(username)
        security.validate_password(password, username)

        salt = security.generate_salt()
        password_hash, _kek = security.derive_credentials(password, salt)

        user = User(
            username=username,
            password_hash=password_hash.hex(),
            salt=salt.hex(),
            role=role.value,
        )
        with self._db() as db:
            if db.scalar(select(User.user_id).where(User.username == username)):
                raise UserAlreadyExistsError(f"O usuário '{username}' já existe.")
            db.add(user)
            try:
                db.commit()
            except IntegrityError as err:
                db.rollback()
                raise UserAlreadyExistsError(f"O usuário '{username}' já existe.") from err
            db.refresh(user)
            return _to_info(user)

    # ------------------------------------------------------------------ #
    # Gestão de acesso (02.2)
    # ------------------------------------------------------------------ #
    def set_role(self, session: Session, username: str, role: Role) -> UserInfo:
        """Altera o papel de um usuário. Apenas ADMIN (Requisito 02.2)."""
        admin = self.sessions.require_role(session, Role.ADMIN)
        role = Role(role)

        with self._db() as db:
            user = db.scalar(select(User).where(User.username == username.strip()))
            if user is None:
                raise UserNotFoundError(f"Usuário '{username}' não encontrado.")

            if user.role == Role.ADMIN and role != Role.ADMIN:
                admins = db.scalar(
                    select(func.count()).select_from(User).where(User.role == Role.ADMIN.value)
                )
                if admins <= 1:
                    raise IAMError("Não é possível rebaixar o último ADMIN do sistema.")

            old_role = user.role
            user.role = role.value
            db.commit()
            db.refresh(user)
            info = _to_info(user)

        logger.info(
            "ROLE_CHANGE: '%s' %s -> %s por '%s'.",
            info.username, old_role, info.role, admin.username,
        )
        self.audit.record(
            AuditAction.USER_ROLE_CHANGE,
            user_id=session.user_id,
            username=admin.username,
            resource_id=info.username,
            details={
                "old_role": old_role,
                "new_role": info.role.value,
            },
        )
        return info

    def list_users(self, session: Session) -> list[UserInfo]:
        """Lista os usuários cadastrados. Apenas ADMIN."""
        self.sessions.require_role(session, Role.ADMIN)
        with self._db() as db:
            users = db.scalars(select(User).order_by(User.created_at)).all()
            return [_to_info(u) for u in users]

    def get_user(self, session: Session, username: str) -> UserInfo:
        """Consulta um usuário pelo username (ex.: destinatário de compartilhamento)."""
        self.sessions.validate(session)
        with self._db() as db:
            user = db.scalar(select(User).where(User.username == username.strip()))
            if user is None:
                raise UserNotFoundError(f"Usuário '{username}' não encontrado.")
            return _to_info(user)

    # ------------------------------------------------------------------ #
    # Relatório de logs (05.3)
    # ------------------------------------------------------------------ #
    def audit_report(
        self,
        session: Session,
        *,
        username: str | None = None,
        action_type: str | None = None,
    ) -> list[AuditLog]:
        """Retorna o relatório de usuários e alterações. Apenas ADMIN (05.3).

        O acesso ao relatório também é auditado: um acesso bem-sucedido grava
        `AUDIT_REPORT (SUCCESS)` e uma tentativa de usuário sem papel ADMIN
        grava `AUDIT_REPORT (FAIL)` com o motivo do bloqueio.
        """
        try:
            active = self.sessions.require_role(session, Role.ADMIN)
        except AuthorizationError:
            logger.warning(
                "AUDIT_REPORT FAIL: '%s' tentou ler o relatório sem permissão.",
                session.username,
            )
            self.audit.record(
                AuditAction.AUDIT_REPORT,
                user_id=session.user_id,
                username=session.username,
                status=AuditStatus.FAIL,
                details={"reason": "acesso negado: papel insuficiente"},
            )
            raise

        events = self.audit.list_events(username=username, action_type=action_type)
        self.audit.record(
            AuditAction.AUDIT_REPORT,
            user_id=active.user_id,
            username=active.username,
            details={
                "events": len(events),
                "filter_user": username,
                "filter_action": action_type,
            },
        )
        return events
