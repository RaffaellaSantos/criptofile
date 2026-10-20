"""Derivação de credenciais com Argon2id (Requisito 01.1).

Uma única derivação Argon2id gera 64 bytes, divididos em duas partes:
  - os primeiros 32 bytes são o hash de verificação da senha (armazenado);
  - os últimos 32 bytes são a chave mestre do usuário (KEK), que nunca é
    armazenada e só existe em memória durante a sessão. A KEK é usada pelo
    motor criptográfico para cifrar/decifrar as DEKs dos arquivos.
"""

import hmac
import os
import re

from argon2.low_level import Type, hash_secret_raw

from app.exceptions.iam_exceptions import CredentialValidationError

SALT_SIZE = 16
HASH_LEN = 32
KEK_LEN = 32

# Parâmetros recomendados pela RFC 9106 (perfil de baixa memória).
TIME_COST = 3
MEMORY_COST = 64 * 1024  # KiB
PARALLELISM = 4

PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 128
# O username vira nome de diretório (workspace/<username>): começa e termina
# com letra ou número porque o Windows descarta pontos finais ("abc.." viraria
# "abc") e nomes como "..." não são diretórios comuns.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,30}[A-Za-z0-9]$")
# Nomes de dispositivo reservados do Windows não podem ser diretórios.
RESERVED_USERNAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)


def generate_salt() -> bytes:
    """Gera um salt aleatório criptograficamente seguro de 16 bytes."""
    return os.urandom(SALT_SIZE)


def derive_credentials(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Deriva (hash_da_senha, kek) a partir da senha e do salt."""
    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=HASH_LEN + KEK_LEN,
        type=Type.ID,
    )
    return raw[:HASH_LEN], raw[HASH_LEN:]


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bytes | None:
    """Retorna a KEK se a senha for válida, ou None caso contrário.

    A comparação é feita em tempo constante para evitar ataques de temporização.
    """
    password_hash, kek = derive_credentials(password, salt)
    if hmac.compare_digest(password_hash, expected_hash):
        return kek
    return None


def validate_username(username: str) -> str:
    """Valida o formato do username e retorna-o normalizado."""
    username = username.strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise CredentialValidationError(
            "Username deve ter de 3 a 32 caracteres (letras, números, '_', '.' ou '-'), "
            "começando e terminando com letra ou número."
        )
    if username.lower() in RESERVED_USERNAMES:
        raise CredentialValidationError(f"'{username}' é um nome reservado do sistema.")
    return username


def validate_password(password: str, username: str) -> None:
    """Aplica a política mínima de senhas."""
    if not PASSWORD_MIN_LEN <= len(password) <= PASSWORD_MAX_LEN:
        raise CredentialValidationError(
            f"A senha deve ter entre {PASSWORD_MIN_LEN} e {PASSWORD_MAX_LEN} caracteres."
        )
    if password.lower() == username.lower():
        raise CredentialValidationError("A senha não pode ser igual ao username.")
    if not (any(c.isalpha() for c in password) and any(c.isdigit() for c in password)):
        raise CredentialValidationError("A senha deve conter letras e números.")
