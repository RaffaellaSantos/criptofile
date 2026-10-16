"""Serviço de Autenticação e Gestão de Acessos (Requisitos 01.1, 01.2, 02.1, 02.2)."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.core import security
from app.core.session import Session, SessionManager
from app.exceptions.iam_exceptions import (
    AuthenticationError,
    IAMError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from app.model.user_model import Role, User

logger = logging.getLogger(__name__)

# Salt fixo usado apenas para gastar o mesmo tempo quando o usuário não existe,
# evitando que a resposta revele quais usernames estão cadastrados.
_DUMMY_SALT = bytes(security.SALT_SIZE)
_DUMMY_HASH = bytes(security.HASH_LEN)


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
    ):
        self._db = session_factory
        self.sessions = session_manager or SessionManager()

    # ------------------------------------------------------------------ #
    # Autenticação (01.2)
    # ------------------------------------------------------------------ #
    def authenticate(self, username: str, password: str) -> Session:
        """Valida as credenciais e abre uma sessão em memória."""
        username = username.strip()
        with self._db() as db:
            user = db.scalar(select(User).where(User.username == username))

        if user is None:
            security.verify_password(password, _DUMMY_SALT, _DUMMY_HASH)
            logger.warning("LOGIN FAIL: usuário '%s' inexistente.", username)
            raise AuthenticationError("Usuário ou senha inválidos.")

        kek = security.verify_password(
            password, bytes.fromhex(user.salt), bytes.fromhex(user.password_hash)
        )
        if kek is None:
            logger.warning("LOGIN FAIL: senha incorreta para '%s'.", username)
            raise AuthenticationError("Usuário ou senha inválidos.")

        logger.info("LOGIN SUCCESS: '%s' (%s).", user.username, user.role)
        return self.sessions.create(user.user_id, user.username, Role(user.role), kek)

    def logout(self, session: Session) -> None:
        self.sessions.revoke(session)
        logger.info("LOGOUT: '%s'.", session.username)

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
