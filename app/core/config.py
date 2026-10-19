from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações do Sistema"""

    POSTGRES_USER: str | None= "ps_user"
    POSTGRES_PASSWORD: str | None= "strong!password"
    POSTGRES_DB: str | None= "ps_db"
    POSTGRES_PORT: int | None= 5432
    DATABASE_URL: str | None
    # Chave (hex, 32 bytes) do HMAC que assina o log de auditoria.
    # Se ausente, uma chave é gerada uma única vez e guardada em .audit_key.
    AUDIT_HMAC_KEY: str | None = None
    model_config = SettingsConfigDict(env_file='.env')

settings = Settings()