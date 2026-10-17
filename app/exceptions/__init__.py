"""Módulo de Excessões"""

from app.exceptions.audit_exceptions import AuditError, AuditIntegrityViolationError
from app.exceptions.file_cryptography_exceptions import (
    FileNotFoundError,
    IntegrityError,
    InvalidKeyError,
    PermissionError,
)
from app.exceptions.iam_exceptions import (
    AuthenticationError,
    AuthorizationError,
    CredentialValidationError,
    IAMError,
    UserAlreadyExistsError,
    UserNotFoundError,
)

__all__ = [
    "AuditError",
    "AuditIntegrityViolationError",
    "AuthenticationError",
    "AuthorizationError",
    "CredentialValidationError",
    "FileNotFoundError",
    "IAMError",
    "IntegrityError",
    "InvalidKeyError",
    "PermissionError",
    "UserAlreadyExistsError",
    "UserNotFoundError",
]