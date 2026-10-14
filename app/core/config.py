from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configurações do Sistema"""

    POSTGRES_USER: str | None= "ps_user"
    POSTGRES_PASSWORD: str | None= "strong!password"
    POSTGRES_DB: str | None= "ps_db"
    POSTGRES_PORT: int | None= 5432
    DATABASE_URL: str | None
    model_config = SettingsConfigDict(env_file='.env')

settings = Settings()