"""Testes do núcleo: sessão em memória e criação da conexão com o banco."""

import os

os.environ["DATABASE_URL"] = "sqlite://"

import pytest
from sqlalchemy import create_engine, text

from app.core import database
from app.core.config import settings
from app.core.session import SessionManager
from app.model.user_model import Role


# Sessão em memória (4.2.1) ------------------------------------------------- #
def test_session_role_helpers():
    manager = SessionManager()
    admin = manager.create("u1", "admin", Role.ADMIN, b"\x01" * 32)
    user = manager.create("u2", "bob", Role.USER, b"\x02" * 32)
    assert admin.is_admin and not user.is_admin


def test_revoke_all_wipes_every_kek():
    manager = SessionManager()
    sessions = [manager.create(f"u{i}", f"user{i}", Role.USER, b"\x07" * 32) for i in range(3)]
    manager.revoke_all()
    assert all(not any(s.kek) for s in sessions)


def test_revoking_a_copy_also_wipes_the_registered_session():
    """Revogar por uma cópia do objeto zera também a KEK guardada no registro."""
    manager = SessionManager()
    registered = manager.create("u1", "bob", Role.USER, b"\x09" * 32)
    copy = type(registered)(**{**registered.__dict__, "kek": bytearray(registered.kek)})
    manager.revoke(copy)
    assert not any(registered.kek) and not any(copy.kek)


# Conexão com o banco ------------------------------------------------------- #
@pytest.fixture
def fresh_engine(monkeypatch):
    database.get_engine.cache_clear()
    yield
    engine_cache = database.get_engine.cache_info().currsize
    if engine_cache:
        database.get_engine().dispose()
    database.get_engine.cache_clear()


def test_get_engine_binds_session_factory(fresh_engine, monkeypatch):
    monkeypatch.setattr(settings, "DATABASE_URL", "sqlite://")
    engine = database.get_engine()
    assert database.get_engine() is engine  # criado uma única vez
    with database.SessionLocal() as db:
        assert db.execute(text("select 1")).scalar() == 1


def test_get_engine_sets_postgres_connect_timeout(fresh_engine, monkeypatch):
    """Sem timeout o psycopg esperaria ~2 min por um banco inacessível."""
    captured = {}

    def fake_create_engine(url, **kwargs):
        captured.update(kwargs)
        return create_engine("sqlite://")

    monkeypatch.setattr(settings, "DATABASE_URL", "postgresql+psycopg2://u:p@localhost:1/db")
    monkeypatch.setattr(database, "create_engine", fake_create_engine)
    database.get_engine()
    assert captured["connect_args"] == {"connect_timeout": database.CONNECT_TIMEOUT}


def test_get_engine_without_url_raises_clear_error(fresh_engine, monkeypatch):
    monkeypatch.setattr(settings, "DATABASE_URL", None)
    with pytest.raises(ValueError, match="DATABASE_URL não configurada"):
        database.get_engine()
