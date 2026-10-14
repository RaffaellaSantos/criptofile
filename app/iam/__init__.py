"""Módulo de Autenticação e Gestão de Acessos (IAM)."""

from app.iam.exceptions import (
    AuthenticationError,
    AuthorizationError,
    CredentialValidationError,
    IAMError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from app.iam.models import Role, User
from app.iam.service import IAMService, UserInfo
from app.iam.session import Session, SessionManager

__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "CredentialValidationError",
    "IAMError",
    "IAMService",
    "Role",
    "Session",
    "SessionManager",
    "User",
    "UserAlreadyExistsError",
    "UserInfo",
    "UserNotFoundError",
]
