"""Testes das migrações do Alembic (fonte única de verdade do schema)."""

import os

os.environ["DATABASE_URL"] = "sqlite://"

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.cli.iam_commands import _run_migrations
from app.core.config import settings
from app.core.database import Base

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
TABLES = {"users", "audit_log", "files", "file_permissions"}


@pytest.fixture
def db_url(monkeypatch, tmp_path):
    """Banco SQLite em arquivo; o env.py do Alembic lê a URL de `settings`."""
    url = f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}"
    monkeypatch.setattr(settings, "DATABASE_URL", url)
    return url


def _columns(url: str) -> dict[str, set[str]]:
    engine = create_engine(url)
    try:
        inspector = inspect(engine)
        return {
            table: {c["name"] for c in inspector.get_columns(table)}
            for table in inspector.get_table_names()
            if table != "alembic_version"
        }
    finally:
        engine.dispose()


def test_upgrade_creates_all_tables(db_url):
    _run_migrations()
    assert set(_columns(db_url)) == TABLES


def test_migrated_schema_matches_models(db_url):
    """As migrações e os modelos SQLAlchemy descrevem as mesmas colunas."""
    _run_migrations()
    migrated = _columns(db_url)
    for table in TABLES:
        model_columns = {c.name for c in Base.metadata.tables[table].columns}
        assert migrated[table] == model_columns, table


def test_upgrade_is_idempotent(db_url):
    """Cada comando da CLI aplica as migrações; reaplicar não pode falhar."""
    _run_migrations()
    _run_migrations()
    assert set(_columns(db_url)) == TABLES


def test_downgrade_to_base_removes_tables(db_url):
    _run_migrations()
    command.downgrade(Config(str(ALEMBIC_INI)), "base")
    assert _columns(db_url) == {}


# Integração com PostgreSQL (opcional) ------------------------------------- #
POSTGRES_TEST_URL = os.environ.get("CRIPTOFILE_TEST_POSTGRES_URL")


@pytest.mark.skipif(
    not POSTGRES_TEST_URL,
    reason="defina CRIPTOFILE_TEST_POSTGRES_URL com um banco PostgreSQL DESCARTÁVEL",
)
def test_migrations_roundtrip_on_postgresql(monkeypatch):
    """Aplica e desfaz as migrações no PostgreSQL real (APAGA as tabelas do banco).

    Ex.: CRIPTOFILE_TEST_POSTGRES_URL=postgresql+psycopg2://ps_user:senha@localhost:5432/criptofile_test
    """
    monkeypatch.setattr(settings, "DATABASE_URL", POSTGRES_TEST_URL)
    config = Config(str(ALEMBIC_INI))
    command.downgrade(config, "base")
    try:
        _run_migrations()
        migrated = _columns(POSTGRES_TEST_URL)
        assert set(migrated) == TABLES
        for table in TABLES:
            assert migrated[table] == {
                c.name for c in Base.metadata.tables[table].columns
            }
    finally:
        command.downgrade(config, "base")
    assert _columns(POSTGRES_TEST_URL) == {}
