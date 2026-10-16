"""Módulo de Excessões"""

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