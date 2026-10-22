"""Ambiente do Alembic.

Reaproveita a configuração da aplicação (`app.core.config.settings`) para
obter a DATABASE_URL e os metadados dos modelos, garantindo que migrações
autogeradas e execução da API usem a mesma definição de schema.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import MetaData, engine_from_config, pool

# Registra explicitamente os módulos de modelos no metadata do SQLAlchemy.
from app.core.config import settings
from app.core.database import Base

config = context.config

# A URL do banco vem do .env da aplicação, não do alembic.ini.
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Quando chamado pela aplicação (configure_logger=False), o logging dela é
# mantido; pela linha de comando `alembic`, vale o [loggers] do alembic.ini.
if config.config_file_name is not None and config.attributes.get(
    "configure_logger", True
):
    # disable_existing_loggers=False preserva os loggers da aplicação
    # quando as migrações são executadas a partir do código (CLI).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata: MetaData = Base.metadata


def run_migrations_offline() -> None:
    """Executa migrações no modo 'offline' (apenas SQL, sem conexão)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Executa migrações conectando diretamente ao banco."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
