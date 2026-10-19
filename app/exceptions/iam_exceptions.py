class IAMError(Exception):
    """Erro base do módulo IAM."""


class AuthenticationError(IAMError):
    """Credenciais inválidas ou sessão inexistente/expirada."""


class AccountLockedError(AuthenticationError):
    """Conta temporariamente bloqueada por excesso de falhas de login (força bruta)."""


class AuthorizationError(IAMError):
    """Usuário autenticado sem permissão para a operação."""


class UserAlreadyExistsError(IAMError):
    """Já existe um usuário com o username informado."""


class UserNotFoundError(IAMError):
    """Usuário não encontrado."""


class CredentialValidationError(IAMError):
    """Username ou senha não atendem à política do sistema."""
