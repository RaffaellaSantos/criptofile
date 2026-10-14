from functools import cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.core.config import settings

CONNECT_TIMEOUT = 5  # segundos

Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False)


@cache
def get_engine() -> Engine:
    """Cria a conexão com o banco apenas quando ela é necessária."""
    if not settings.DATABASE_URL:
        raise ValueError("DATABASE_URL não configurada. Verifique o arquivo .env.")

    connect_args = {}
    if settings.DATABASE_URL.startswith("postgresql"):
        # O psycopg espera até ~2 min por padrão quando o banco está inacessível.
        connect_args["connect_timeout"] = CONNECT_TIMEOUT

    engine = create_engine(
        settings.DATABASE_URL, pool_pre_ping=True, connect_args=connect_args
    )
    SessionLocal.configure(bind=engine)
    return engine


def init_db() -> None:
    """Conecta ao banco e cria as tabelas que ainda não existem."""
    import app.iam.models  # noqa: F401  (registra os modelos no metadata)

    Base.metadata.create_all(bind=get_engine())
