from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Raiz do projeto (onde ficam alembic.ini e pyproject.toml).
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Configurações do Sistema"""

    POSTGRES_USER: str | None = "ps_user"
    POSTGRES_PASSWORD: str | None = "strong!password"
    POSTGRES_DB: str | None = "ps_db"
    POSTGRES_PORT: int | None = 5432
    # Sem padrão obrigatório: a ausência é reportada com mensagem clara por
    # `get_engine()` em vez de quebrar a importação da aplicação.
    DATABASE_URL: str | None = None
    # Chave (hex, 32 bytes) do HMAC que assina o log de auditoria.
    # Se ausente, uma chave é gerada uma única vez e guardada em .audit_key.
    AUDIT_HMAC_KEY: str | None = None
    # Diretório de dados locais (workspace/, .audit_key, app.log). Fixo para
    # que o resultado não dependa da pasta de onde o comando é executado;
    # padrão: a raiz do projeto. No Docker aponta para um volume persistente.
    CRIPTOFILE_HOME: str | None = None
    # .env da raiz do projeto, independentemente da pasta atual.
    model_config = SettingsConfigDict(env_file=PROJECT_ROOT / ".env")


settings = Settings()


def data_dir() -> Path:
    """Diretório de dados locais (ver `CRIPTOFILE_HOME`), criado se preciso."""
    path = Path(settings.CRIPTOFILE_HOME) if settings.CRIPTOFILE_HOME else PROJECT_ROOT
    path.mkdir(parents=True, exist_ok=True)
    return path.resolve()
